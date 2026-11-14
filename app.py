"""
Files Access & Storage Management Portal
Main Flask Application Server
"""

import os
import io
import re
import uuid
import mimetypes
import shutil
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, jsonify, send_file, abort
)
from flask.json.provider import DefaultJSONProvider
from bson import ObjectId
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

import database
import otp_service
import document_generator

class CustomJSONProvider(DefaultJSONProvider):
    """Custom JSON provider that transparently serializes BSON ObjectId instances to strings."""
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)

# Initialize application
app = Flask(__name__)
app.json_provider_class = CustomJSONProvider
app.json = CustomJSONProvider(app)
app.secret_key = os.environ.get('SECRET_KEY', 'files-access-secure-token-2026-supersecret')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configure file storage path and limits
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max per request

# Ensure base uploads folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Cache DB info at startup to avoid per-request DB calls
_cached_db_info = None

# ----------------- Helper Functions & Decorators -----------------

def format_bytes(size):
    """Format byte integers into human-readable strings (e.g., 2.4 MB)."""
    if not size or size < 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    idx = 0
    s = float(size)
    while s >= 1024.0 and idx < len(units) - 1:
        s /= 1024.0
        idx += 1
    return f"{s:.1f} {units[idx]}" if idx > 0 else f"{int(s)} B"

# Register filter for Jinja templates
app.jinja_env.filters['format_bytes'] = format_bytes

@app.context_processor
def inject_db_info():
    """Inject active MongoDB connection details into all templates (cached)."""
    global _cached_db_info
    if _cached_db_info is None:
        _cached_db_info = database.get_active_connection_info()
    return {
        'db_info': _cached_db_info
    }

@app.after_request
def add_cache_headers(response):
    """Add cache headers for static assets to eliminate redundant requests."""
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    else:
        response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

def detect_file_category(filename):
    """
    Categorize files based on extensions:
    1. image: jpg, jpeg, png, gif, webp, svg, bmp, ico, tiff, avif
    2. word: doc, docx, dot, dotx, odt, rtf
    3. powerpoint: ppt, pptx, pps, ppsx, pot, potx, odp
    4. spreadsheet: xls, xlsx, xlsm, csv, tsv, ods
    5. pdf: pdf
    6. text: txt, md, json, xml, html, css, js, py, java, c, cpp, sql, log, yaml, yml, sh, env
    7. media: mp3, wav, ogg, flac, m4a, mp4, mov, avi, mkv, webm
    8. archive: zip, rar, 7z, tar, gz, bz2
    9. other: anything else
    """
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    
    mapping = {
        'image': {'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'tif', 'avif', 'heic'},
        'word': {'doc', 'docx', 'dot', 'dotx', 'odt', 'rtf'},
        'powerpoint': {'ppt', 'pptx', 'pps', 'ppsx', 'pot', 'potx', 'odp'},
        'spreadsheet': {'xls', 'xlsx', 'xlsm', 'csv', 'tsv', 'ods'},
        'pdf': {'pdf'},
        'text': {'txt', 'md', 'json', 'xml', 'html', 'css', 'js', 'ts', 'jsx', 'tsx', 'py', 'java', 'c', 'cpp', 'h', 'cs', 'php', 'sql', 'log', 'yaml', 'yml', 'sh', 'bat', 'env', 'config', 'ini'},
        'media': {'mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'mp4', 'mov', 'avi', 'mkv', 'webm', 'wmv', 'm4v'},
        'archive': {'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso'}
    }

    for category, extensions in mapping.items():
        if ext in extensions:
            return category, ext
    return 'other', ext

def login_required(f):
    """Decorator ensuring a user is logged in and active (with cached verification for high speed)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access your file vault.", "warning")
            return redirect(url_for('login', next=request.path))
        
        # Fast path: check cached session status to avoid repeated DB round-trips on every click
        import time
        now = time.time()
        last_checked = session.get('_status_checked_at', 0)
        
        # Verify from database at most once every 5 minutes
        if (now - last_checked > 300) or ('_user_status' not in session):
            user = database.get_user_by_id(session['user_id'])
            if not user or user['status'] != 'approved':
                session.clear()
                flash("Your account is not active or has been suspended.", "danger")
                return redirect(url_for('login'))
            session['_user_status'] = user['status']
            session['_status_checked_at'] = now
        elif session.get('_user_status') != 'approved':
            session.clear()
            flash("Your account is not active or has been suspended.", "danger")
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator restricting route access exclusively to Administrators."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Administrator login required.", "warning")
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash("Access denied: Administrative privileges required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Public & Authentication Routes -----------------

@app.route('/')
def index():
    """Landing page introducing the File Storage Portal."""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route with real-time OTP verification & admin alert flow."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        raw_username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone_number = request.form.get('phone_number', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        otp_channel = request.form.get('otp_channel', 'email')  # 'email' or 'sms'

        # Validations
        if not email or '@' not in email:
            flash("Please enter a valid Gmail / Email address.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        # Automatically determine username from Gmail ID (or use provided if given)
        base_username = raw_username if raw_username else email.split('@')[0].strip()
        clean_username = re.sub(r'[^a-zA-Z0-9._-]', '', base_username) or 'user'
        if len(clean_username) < 3:
            clean_username = f"{clean_username}123"

        # Ensure uniqueness across users
        candidate = clean_username
        counter = 1
        while database.get_user_by_identifier(candidate):
            candidate = f"{clean_username}{counter}"
            counter += 1
        username = candidate

        if not phone_number or len(phone_number.replace(' ', '')) < 8:
            flash("Please enter a valid mobile phone number.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        # Check existing user credentials
        if database.get_user_by_identifier(email):
            flash("An account with this email address already exists.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        if database.get_user_by_phone(phone_number):
            flash("An account with this mobile phone number already exists.", "danger")
            return render_template('register.html', email=email, phone_number=phone_number)

        # Generate Real-Time Cryptographic 6-digit OTP
        otp_code = otp_service.generate_otp(6)
        target = email if otp_channel == 'email' else phone_number

        reg_data = {
            'username': username,
            'email': email,
            'phone_number': phone_number,
            'password': password
        }

        # Store pending OTP in MongoDB
        database.save_otp_record(
            target=target,
            otp_code=otp_code,
            channel=otp_channel,
            reg_data=reg_data
        )

        # Dispatch real-time OTP via chosen channel
        if otp_channel == 'email':
            dispatch_res = otp_service.send_email_otp(email, otp_code, username)
        else:
            dispatch_res = otp_service.send_sms_otp(phone_number, otp_code)

        session['pending_otp_target'] = target
        session['pending_otp_channel'] = otp_channel

        if dispatch_res.get('success'):
            dest = "your Gmail / Email" if otp_channel == 'email' else f"your phone (+91 {phone_number[-10:]})"
            flash(f"Real-time verification OTP successfully dispatched to {dest}! Please check your messages.", "success")
        else:
            err_msg = dispatch_res.get('error') or "Gateway could not deliver message."
            channel_label = "Email Delivery" if otp_channel == 'email' else "SMS Gateway"
            flash(f"{channel_label} Notice: {err_msg}", "warning")

        return redirect(url_for('verify_otp', target=target, channel=otp_channel))

    return render_template(
        'register.html',
        is_sms_configured=otp_service.is_sms_configured(),
        is_smtp_configured=otp_service.is_smtp_configured()
    )

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """Verify submitted 6-digit OTP code before completing user registration."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    target = request.args.get('target') or session.get('pending_otp_target')
    channel = request.args.get('channel') or session.get('pending_otp_channel', 'email')

    if not target:
        flash("No active registration verification session found. Please register.", "warning")
        return redirect(url_for('register'))

    if request.method == 'POST':
        submitted_target = request.form.get('target', '').strip()
        otp_code = request.form.get('otp_code', '').strip()

        if not otp_code or len(otp_code) != 6:
            flash("Please enter the complete 6-digit verification code.", "danger")
            return render_template('verify_otp.html', target=submitted_target, channel=channel)

        is_valid, reg_data, err_msg = database.verify_otp_code(submitted_target, otp_code)

        if not is_valid:
            flash(err_msg or "Invalid verification code. Please check and re-enter.", "danger")
            return render_template('verify_otp.html', target=submitted_target, channel=channel)

        # OTP is VALID! Commit user to MongoDB in PENDING status
        try:
            user_id = database.create_user(
                username=reg_data['username'],
                email=reg_data['email'],
                password=reg_data['password'],
                phone_number=reg_data['phone_number'],
                role='user',
                status='pending',
                email_verified=True,
                phone_verified=True
            )

            # Create personal upload directory
            user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
            os.makedirs(user_dir, exist_ok=True)

            # Audit log
            database.log_action(user_id, 'USER_REGISTER_VERIFIED', f"Verified OTP. Phone: {reg_data['phone_number']}, Email: {reg_data['email']}", request.remote_addr)

            # Trigger real-time notification to Administrator's Phone Number & Email!
            otp_service.notify_admin_new_registration(reg_data)

            # Clear session OTP tracking
            session.pop('pending_otp_target', None)
            session.pop('pending_otp_channel', None)

            flash(f" Phone & Email verified successfully! Your account has been submitted to the Admin for approval. The Admin has been notified.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Error finalizing account creation: {str(e)}", "danger")
            return render_template('verify_otp.html', target=submitted_target, channel=channel)

    return render_template('verify_otp.html', target=target, channel=channel)

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Regenerate and resend real-time OTP code to email or phone."""
    target = request.form.get('target', '').strip()
    channel = request.form.get('channel', 'email')

    record = database.get_otp_record(target)
    if not record:
        flash("Registration session expired. Please register again.", "warning")
        return redirect(url_for('register'))

    reg_data = record.get('reg_data', {})
    new_otp = otp_service.generate_otp(6)

    # Determine destination based on channel
    new_target = reg_data.get('email') if channel == 'email' else reg_data.get('phone_number')
    if not new_target:
        new_target = target

    # Update in MongoDB
    database.save_otp_record(
        target=new_target,
        otp_code=new_otp,
        channel=channel,
        reg_data=reg_data
    )

    # Dispatch
    if channel == 'email':
        dispatch_res = otp_service.send_email_otp(new_target, new_otp, reg_data.get('username', 'User'))
    else:
        dispatch_res = otp_service.send_sms_otp(new_target, new_otp)

    session['pending_otp_target'] = new_target
    session['pending_otp_channel'] = channel

    if dispatch_res.get('success'):
        dest_name = "Gmail / Email" if channel == 'email' else "Mobile SMS"
        flash(f"A fresh real-time verification code has been dispatched via {dest_name} to {new_target}!", "success")
    else:
        err_msg = dispatch_res.get('error') or "Could not dispatch code."
        flash(f"Gateway Notice: {err_msg}", "warning")

    return redirect(url_for('verify_otp', target=new_target, channel=channel))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Sign-in route checking approval status and credentials."""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        if not identifier or not password:
            flash("Please provide your username/email and password.", "danger")
            return render_template('login.html', identifier=identifier)

        user = database.get_user_by_identifier(identifier)
        if not user or not check_password_hash(user['password_hash'], password):
            flash("Invalid credentials. Please verify your username and password.", "danger")
            return render_template('login.html', identifier=identifier)

        # Check approval status
        if user['status'] == 'pending':
            flash("⏳ Your account is currently pending Administrator approval. Please check back later or contact the administrator.", "warning")
            return render_template('login.html', identifier=identifier)

        if user['status'] == 'rejected':
            flash("🚫 Your registration request was rejected by the administrator.", "danger")
            return render_template('login.html', identifier=identifier)

        if user['status'] == 'suspended':
            flash("⛔ Your account has been suspended by the administrator.", "danger")
            return render_template('login.html', identifier=identifier)

        # Login approved! Set session
        import time
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['_user_status'] = user['status']
        session['_status_checked_at'] = time.time()
        session.permanent = True

        database.log_action(user['id'], 'USER_LOGIN', "Successful login.", request.remote_addr, username=user['username'])

        next_url = request.args.get('next')
        if user['role'] == 'admin':
            return redirect(next_url or url_for('admin_dashboard'))
        return redirect(next_url or url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Clear session and log out."""
    user_id = session.get('user_id')
    if user_id:
        database.log_action(user_id, 'USER_LOGOUT', "User logged out.", request.remote_addr)
    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for('login'))

# ----------------- User Dashboard & File Management -----------------

@app.route('/dashboard')
@login_required
def dashboard():
    """Main user portal displaying personal files, folders, storage quota, and document creation."""
    user = database.get_user_by_id(session['user_id'])
    stats = database.get_user_storage_stats(user['id'])

    # Category, search, and folder filter parameters
    category = request.args.get('category', 'all')
    search = request.args.get('q', '')
    sort_by = request.args.get('sort', 'newest')
    folder_id = request.args.get('folder_id')

    folders = database.get_user_folders(user['id'])
    current_folder = database.get_folder_by_id(folder_id) if folder_id else None

    files = database.get_user_files(user['id'], category=category, search=search, sort_by=sort_by, folder_id=folder_id)

    # Calculate quota percentage
    quota_bytes = stats['storage_quota'] or 1073741824
    used_bytes = stats['used_bytes'] or 0
    quota_percent = min(100, round((used_bytes / quota_bytes) * 100, 1)) if quota_bytes > 0 else 0

    return render_template(
        'dashboard.html',
        user=user,
        files=files,
        folders=folders,
        current_folder=current_folder,
        current_folder_id=folder_id,
        stats=stats,
        quota_percent=quota_percent,
        active_category=category,
        search_query=search,
        current_sort=sort_by
    )

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle multi-file or single-file uploads for the authenticated user."""
    user_id = session['user_id']
    user = database.get_user_by_id(user_id)
    stats = database.get_user_storage_stats(user_id)

    if 'files' not in request.files and 'file' not in request.files:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'No files detected in upload request.'}), 400
        flash("No file selected.", "danger")
        return redirect(url_for('dashboard'))

    # Collect uploaded file items
    files_to_upload = request.files.getlist('files')
    if not files_to_upload or files_to_upload[0].filename == '':
        single = request.files.get('file')
        if single and single.filename != '':
            files_to_upload = [single]

    if not files_to_upload or files_to_upload[0].filename == '':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Please select at least one file to upload.'}), 400
        flash("Please select at least one file to upload.", "warning")
        return redirect(url_for('dashboard'))

    uploaded_count = 0
    errors = []
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)

    folder_id = request.form.get('folder_id') or None
    current_used = stats['used_bytes']
    quota = stats['storage_quota']

    # Optional custom filenames specified by the user
    custom_names = request.form.getlist('custom_filenames')
    if not custom_names:
        single_custom = request.form.get('custom_filename')
        if single_custom:
            custom_names = [single_custom]

    for idx, file_obj in enumerate(files_to_upload):
        if not file_obj or file_obj.filename == '':
            continue

        orig_filename = file_obj.filename
        _, orig_ext = os.path.splitext(orig_filename)

        # Apply user-specified custom name if provided
        if idx < len(custom_names) and custom_names[idx].strip():
            chosen_name = custom_names[idx].strip()
            c_base, c_ext = os.path.splitext(chosen_name)
            if not c_ext and orig_ext:
                chosen_name = f"{chosen_name}{orig_ext}"
            raw_filename = chosen_name
        else:
            raw_filename = orig_filename

        safe_name = secure_filename(raw_filename)
        if not safe_name:
            safe_name = f"unnamed_{uuid.uuid4().hex[:8]}"
            if orig_ext and not safe_name.endswith(orig_ext):
                safe_name = f"{safe_name}{orig_ext}"

        # Categorize
        category, ext = detect_file_category(raw_filename)

        # Guess MIME type
        mime_type, _ = mimetypes.guess_type(raw_filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        # Generate unique storage filename
        unique_prefix = uuid.uuid4().hex[:12]
        stored_filename = f"{unique_prefix}_{safe_name}"

        # Save file directly to MongoDB GridFS cluster
        try:
            file_bytes = file_obj.read()
            file_size = len(file_bytes)

            # Quota check
            if current_used + file_size > quota:
                errors.append(f"Storage quota exceeded for '{raw_filename}'.")
                continue

            current_used += file_size

            # Record and stream binary directly into MongoDB Atlas Cluster GridFS
            file_id = database.add_file(
                user_id=user_id,
                filename=raw_filename,
                stored_filename=stored_filename,
                file_path=None,  # 100% Cloud-native storage in MongoDB GridFS, zero local disk dependency
                file_size=file_size,
                file_ext=ext,
                mime_type=mime_type,
                category=category,
                file_bytes=file_bytes,
                folder_id=folder_id
            )

            database.log_action(user_id, 'FILE_UPLOAD', f"Uploaded '{raw_filename}' ({format_bytes(file_size)}) to MongoDB", request.remote_addr)
            uploaded_count += 1

        except Exception as e:
            if os.path.exists(destination_path):
                try:
                    os.remove(destination_path)
                except Exception:
                    pass
            errors.append(f"Failed to save '{raw_filename}': {str(e)}")

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': uploaded_count > 0,
            'uploaded_count': uploaded_count,
            'errors': errors,
            'message': f"Uploaded {uploaded_count} file(s) successfully to MongoDB." if uploaded_count > 0 else "Upload failed."
        })

    if uploaded_count > 0:
        flash(f"Successfully uploaded {uploaded_count} file(s) to MongoDB cluster!", "success")
    if errors:
        for err in errors:
            flash(err, "warning")

    return redirect(url_for('dashboard', folder_id=folder_id) if folder_id else url_for('dashboard'))

# ----------------- Native Folder & Office Document Creation Routes -----------------

@app.route('/folders/create', methods=['POST'])
@login_required
def create_folder():
    """Create a new folder in user's vault."""
    name = request.form.get('folder_name', '').strip()
    color = request.form.get('folder_color', 'indigo')
    if not name:
        flash("Folder name cannot be empty.", "warning")
        return redirect(request.referrer or url_for('dashboard'))

    database.create_folder(session['user_id'], name, color=color)
    database.log_action(session['user_id'], 'FOLDER_CREATE', f"Created folder '{name}'", request.remote_addr)
    flash(f"Folder '{name}' created successfully!", "success")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/folders/delete/<folder_id>', methods=['POST'])
@login_required
def delete_folder_route(folder_id):
    """Delete a folder and move files to root vault."""
    database.delete_folder(folder_id, session['user_id'])
    database.log_action(session['user_id'], 'FOLDER_DELETE', f"Deleted folder ID {folder_id}", request.remote_addr)
    flash("Folder removed. Files inside have been moved to root vault.", "info")
    return redirect(url_for('dashboard'))

@app.route('/create/word', methods=['POST'])
@login_required
def create_word_file():
    """Create a working Microsoft Word (.docx) document directly in MongoDB cluster."""
    user_id = session['user_id']
    raw_name = request.form.get('filename', 'Document').strip()
    if not raw_name.lower().endswith('.docx'):
        raw_name = f"{raw_name}.docx"
    title = request.form.get('title', 'Untitled Document').strip()
    description = request.form.get('description', '').strip()
    content = request.form.get('content', '').strip()
    folder_id = request.form.get('folder_id') or None

    user = database.get_user_by_id(user_id)
    author = user['username'] if user else "CloudVault User"
    file_bytes = document_generator.generate_word_document(title, description, content, author=author)
    file_size = len(file_bytes)

    unique_prefix = uuid.uuid4().hex[:12]
    safe_name = secure_filename(raw_name) or "document.docx"
    stored_filename = f"{unique_prefix}_{safe_name}"
    rel_path = os.path.join(f"user_{user_id}", stored_filename)

    file_id = database.add_file(
        user_id=user_id,
        filename=raw_name,
        stored_filename=stored_filename,
        file_path=rel_path,
        file_size=file_size,
        file_ext='docx',
        mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        category='word',
        file_bytes=file_bytes,
        folder_id=folder_id
    )

    database.log_action(user_id, 'FILE_CREATE', f"Created Word document '{raw_name}' in MongoDB", request.remote_addr)
    flash(f"Microsoft Word document '{raw_name}' created in your MongoDB vault!", "success")
    return redirect(url_for('dashboard', folder_id=folder_id) if folder_id else url_for('dashboard'))

@app.route('/create/excel', methods=['POST'])
@login_required
def create_excel_file():
    """Create a working Microsoft Excel (.xlsx) spreadsheet directly in MongoDB cluster."""
    user_id = session['user_id']
    raw_name = request.form.get('filename', 'Spreadsheet').strip()
    if not raw_name.lower().endswith('.xlsx'):
        raw_name = f"{raw_name}.xlsx"
    sheet_name = request.form.get('sheet_name', 'DataSheet').strip()
    title = request.form.get('title', 'CloudVault Data Sheet').strip()
    headers_raw = request.form.get('headers', '').strip()
    headers = [h.strip() for h in headers_raw.split(',') if h.strip()] if headers_raw else None
    folder_id = request.form.get('folder_id') or None

    file_bytes = document_generator.generate_excel_spreadsheet(sheet_name, title, headers)
    file_size = len(file_bytes)

    unique_prefix = uuid.uuid4().hex[:12]
    safe_name = secure_filename(raw_name) or "spreadsheet.xlsx"
    stored_filename = f"{unique_prefix}_{safe_name}"
    rel_path = os.path.join(f"user_{user_id}", stored_filename)

    file_id = database.add_file(
        user_id=user_id,
        filename=raw_name,
        stored_filename=stored_filename,
        file_path=rel_path,
        file_size=file_size,
        file_ext='xlsx',
        mime_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        category='spreadsheet',
        file_bytes=file_bytes,
        folder_id=folder_id
    )

    database.log_action(user_id, 'FILE_CREATE', f"Created Excel sheet '{raw_name}' in MongoDB", request.remote_addr)
    flash(f"Microsoft Excel spreadsheet '{raw_name}' created in your MongoDB vault!", "success")
    return redirect(url_for('dashboard', folder_id=folder_id) if folder_id else url_for('dashboard'))

@app.route('/create/powerpoint', methods=['POST'])
@login_required
def create_powerpoint_file():
    """Create a working Microsoft PowerPoint (.pptx) presentation directly in MongoDB cluster."""
    user_id = session['user_id']
    raw_name = request.form.get('filename', 'Presentation').strip()
    if not raw_name.lower().endswith('.pptx'):
        raw_name = f"{raw_name}.pptx"
    title = request.form.get('title', 'Presentation Title').strip()
    subtitle = request.form.get('subtitle', '').strip()
    bullets_raw = request.form.get('bullets', '').strip()
    folder_id = request.form.get('folder_id') or None

    slides_content = None
    if bullets_raw:
        bullets_list = [b.strip() for b in bullets_raw.split('\n') if b.strip()]
        slides_content = [{
            "title": title,
            "bullets": bullets_list
        }]

    user = database.get_user_by_id(user_id)
    presenter = user['username'] if user else "CloudVault User"
    file_bytes = document_generator.generate_powerpoint_presentation(title, subtitle, slides_content=slides_content, presenter=presenter)
    file_size = len(file_bytes)

    unique_prefix = uuid.uuid4().hex[:12]
    safe_name = secure_filename(raw_name) or "presentation.pptx"
    stored_filename = f"{unique_prefix}_{safe_name}"
    rel_path = os.path.join(f"user_{user_id}", stored_filename)

    file_id = database.add_file(
        user_id=user_id,
        filename=raw_name,
        stored_filename=stored_filename,
        file_path=rel_path,
        file_size=file_size,
        file_ext='pptx',
        mime_type='application/vnd.openxmlformats-officedocument.presentationml.presentation',
        category='powerpoint',
        file_bytes=file_bytes,
        folder_id=folder_id
    )

    database.log_action(user_id, 'FILE_CREATE', f"Created PowerPoint '{raw_name}' in MongoDB", request.remote_addr)
    flash(f"Microsoft PowerPoint presentation '{raw_name}' created in your MongoDB vault!", "success")
    return redirect(url_for('dashboard', folder_id=folder_id) if folder_id else url_for('dashboard'))

@app.route('/create/text', methods=['POST'])
@login_required
def create_text_file():
    """Create a text / markdown file directly in MongoDB cluster."""
    user_id = session['user_id']
    raw_name = request.form.get('filename', 'Note').strip()
    if not ('.' in raw_name):
        raw_name = f"{raw_name}.txt"
    title = request.form.get('title', 'Quick Note').strip()
    content = request.form.get('content', '').strip()
    folder_id = request.form.get('folder_id') or None

    file_bytes = document_generator.generate_text_document(title, content)
    file_size = len(file_bytes)

    unique_prefix = uuid.uuid4().hex[:12]
    safe_name = secure_filename(raw_name) or "note.txt"
    stored_filename = f"{unique_prefix}_{safe_name}"
    rel_path = os.path.join(f"user_{user_id}", stored_filename)

    file_id = database.add_file(
        user_id=user_id,
        filename=raw_name,
        stored_filename=stored_filename,
        file_path=rel_path,
        file_size=file_size,
        file_ext=raw_name.rsplit('.', 1)[-1].lower(),
        mime_type='text/plain',
        category='text',
        file_bytes=file_bytes,
        folder_id=folder_id
    )

    database.log_action(user_id, 'FILE_CREATE', f"Created text file '{raw_name}' in MongoDB", request.remote_addr)
    flash(f"Text document '{raw_name}' created in your MongoDB vault!", "success")
    return redirect(url_for('dashboard', folder_id=folder_id) if folder_id else url_for('dashboard'))

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    """Serve requested file directly from MongoDB cluster GridFS."""
    file_record = database.get_file_by_id(file_id)
    if not file_record:
        abort(404, description="File not found in vault.")

    # Access control: user must own the file OR be an administrator
    if file_record['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403, description="Unauthorized file access.")

    binary_data = database.get_file_binary(file_record)
    if binary_data is None:
        abort(404, description="File content not found in MongoDB cluster.")

    database.log_action(session['user_id'], 'FILE_DOWNLOAD', f"Downloaded '{file_record['filename']}'", request.remote_addr)

    return send_file(
        io.BytesIO(binary_data),
        as_attachment=True,
        download_name=file_record['filename'],
        mimetype=file_record['mime_type']
    )

@app.route('/preview/<file_id>')
@login_required
def preview_file(file_id):
    """Stream inline file content directly from MongoDB cluster GridFS."""
    file_record = database.get_file_by_id(file_id)
    if not file_record:
        abort(404, description="File not found.")

    if file_record['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403, description="Unauthorized file access.")

    binary_data = database.get_file_binary(file_record)
    if binary_data is None:
        abort(404, description="File content not found in MongoDB cluster.")

    return send_file(
        io.BytesIO(binary_data),
        as_attachment=False,
        mimetype=file_record['mime_type']
    )

@app.route('/api/preview-text/<file_id>')
@login_required
def preview_text_content(file_id):
    """API endpoint to read text/code content directly from MongoDB cluster GridFS."""
    file_record = database.get_file_by_id(file_id)
    if not file_record:
        return jsonify({'success': False, 'message': 'File not found'}), 404

    if file_record['user_id'] != session['user_id'] and session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    # Allow preview for text or code files up to 1 MB
    if file_record['file_size'] > 1024 * 1024:
        return jsonify({'success': False, 'message': 'File is too large for inline text preview (>1MB). Please download to view.'})

    try:
        binary_data = database.get_file_binary(file_record)
        if binary_data is None:
            return jsonify({'success': False, 'message': 'File missing in MongoDB storage'}), 404
        content = binary_data[:500000].decode('utf-8', errors='replace')
        return jsonify({
            'success': True,
            'filename': file_record['filename'],
            'content': content,
            'ext': file_record['file_ext'],
            'size': format_bytes(file_record['file_size'])
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Could not read text file from MongoDB: {str(e)}'})

@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file from database and disk storage."""
    file_record = database.get_file_by_id(file_id)
    if not file_record:
        abort(404, description="File not found.")

    if file_record['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403, description="Unauthorized action.")

    if file_record.get('file_path'):
        full_disk_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['file_path'])
        if os.path.exists(full_disk_path):
            import gc, time
            gc.collect()
            for attempt in range(3):
                try:
                    os.remove(full_disk_path)
                    break
                except Exception as e:
                    time.sleep(0.05)
                    if attempt == 2:
                        print(f"Notice during disk file removal: {e}")

    database.delete_file_record(file_id)
    database.log_action(session['user_id'], 'FILE_DELETE', f"Deleted '{file_record['filename']}'", request.remote_addr)

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'File deleted successfully.'})

    flash(f"'{file_record['filename']}' was removed successfully.", "info")
    if session.get('role') == 'admin' and request.args.get('from') == 'admin':
        return redirect(url_for('admin_files'))
    return redirect(url_for('dashboard'))

@app.route('/rename/<file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    """Rename a file's display name."""
    file_record = database.get_file_by_id(file_id)
    if not file_record:
        abort(404, description="File not found.")

    if file_record['user_id'] != session['user_id'] and session.get('role') != 'admin':
        abort(403, description="Unauthorized.")

    new_name = request.form.get('new_filename', '').strip()
    if not new_name:
        flash("New filename cannot be empty.", "warning")
        return redirect(url_for('dashboard'))

    # Preserve extension if not explicitly typed
    orig_ext = file_record['file_ext']
    if orig_ext and not new_name.lower().endswith(f".{orig_ext}"):
        new_name = f"{new_name}.{orig_ext}"

    database.rename_file_record(file_id, new_name)
    database.log_action(session['user_id'], 'FILE_RENAME', f"Renamed to '{new_name}'", request.remote_addr)
    flash("File renamed successfully.", "success")
    return redirect(url_for('dashboard'))

# ----------------- User & Admin Settings Center -----------------

@app.route('/settings')
@login_required
def user_settings():
    """Account Settings & Personal Preferences Center for All Users & Admin."""
    user_id = session['user_id']
    user = database.get_user_by_id(user_id)
    if not user:
        flash("User profile not found.", "danger")
        return redirect(url_for('login'))

    stats = database.get_user_storage_stats(user_id)
    recent_logs = database.get_user_recent_logs(user_id, limit=6)
    active_tab = request.args.get('tab', 'profile')

    quota_bytes = stats['storage_quota']
    used_bytes = stats['used_bytes']
    quota_percent = min(100.0, round((used_bytes / quota_bytes) * 100, 1)) if quota_bytes > 0 else 0

    return render_template(
        'settings.html',
        user=user,
        stats=stats,
        quota_percent=quota_percent,
        recent_logs=recent_logs,
        active_tab=active_tab,
        client_ip=request.remote_addr
    )

@app.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    """Update profile details (username, full name, email, phone)."""
    user_id = session['user_id']
    username = request.form.get('username', '').strip().lower()
    email = request.form.get('email', '').strip().lower()
    phone_number = request.form.get('phone_number', '').strip()
    full_name = request.form.get('full_name', '').strip()

    if not username:
        flash("Username cannot be empty.", "warning")
        return redirect(url_for('user_settings', tab='profile'))

    if not email or '@' not in email:
        flash("Please provide a valid email address.", "warning")
        return redirect(url_for('user_settings', tab='profile'))

    success, msg = database.update_user_profile(
        user_id=user_id,
        username=username,
        email=email,
        phone_number=phone_number,
        full_name=full_name
    )

    if success:
        session['username'] = username
        database.log_action(user_id, 'PROFILE_UPDATE', f"Updated profile details. Username: @{username}, Email: {email}", request.remote_addr)
        flash(msg, "success")
    else:
        flash(msg, "danger")

    return redirect(url_for('user_settings', tab='profile'))

@app.route('/settings/sync-username-email', methods=['POST'])
@login_required
def sync_username_email():
    """Quick one-click setting to make username match email name (e.g., john@gmail.com -> john)."""
    user_id = session['user_id']
    user = database.get_user_by_id(user_id)
    if not user or not user.get('email'):
        flash("Valid email required to sync username.", "warning")
        return redirect(url_for('user_settings', tab='profile'))

    email = user['email'].strip().lower()
    email_name = email.split('@')[0]

    success, msg = database.update_user_profile(user_id, username=email_name)
    if success:
        session['username'] = email_name
        database.log_action(user_id, 'USERNAME_SYNC', f"Synced username to email name '@{email_name}'", request.remote_addr)
        flash(f"Username successfully updated to '{email_name}' (from your email {email})!", "success")
    else:
        flash(msg, "danger")

    return redirect(url_for('user_settings', tab='profile'))

@app.route('/settings/password', methods=['POST'])
@login_required
def update_password():
    """Update user password with current password verification."""
    user_id = session['user_id']
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    user = database.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    # Verify current password
    if not check_password_hash(user['password_hash'], current_password):
        flash("Current password entered is incorrect.", "danger")
        return redirect(url_for('user_settings', tab='security'))

    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "warning")
        return redirect(url_for('user_settings', tab='security'))

    if new_password != confirm_password:
        flash("New passwords do not match. Please re-type carefully.", "warning")
        return redirect(url_for('user_settings', tab='security'))

    success, msg = database.update_user_password(user_id, new_password)
    if success:
        database.log_action(user_id, 'PASSWORD_CHANGE', "Updated account password", request.remote_addr)
        flash("Password updated successfully! Your new password is now active.", "success")
    else:
        flash(msg, "danger")

    return redirect(url_for('user_settings', tab='security'))

@app.route('/settings/preferences', methods=['POST'])
@login_required
def update_preferences():
    """Update personal UI and vault preferences."""
    user_id = session['user_id']
    default_view = request.form.get('default_view', 'grid')
    default_sort = request.form.get('default_sort', 'newest')
    otp_channel = request.form.get('otp_channel', 'email')

    preferences = {
        'default_view': default_view,
        'default_sort': default_sort,
        'otp_channel': otp_channel
    }

    success, msg = database.update_user_profile(user_id, preferences=preferences)
    if success:
        database.log_action(user_id, 'PREFERENCES_UPDATE', "Updated vault and notification preferences", request.remote_addr)
        flash("Preferences saved successfully.", "success")
    else:
        flash(msg, "danger")

    return redirect(url_for('user_settings', tab='preferences'))

# ----------------- Administrator Control Routes -----------------

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Administrative central control room: approvals, user management, and system telemetry."""
    stats = database.get_system_stats()
    pending_users = database.get_pending_users()
    all_users = database.get_all_users()
    recent_logs = database.get_recent_audit_logs(limit=15)
    gateway_settings = database.get_all_gateway_settings()

    return render_template(
        'admin.html',
        stats=stats,
        pending_users=pending_users,
        users=all_users,
        logs=recent_logs,
        gateway_settings=gateway_settings,
        active_tab=request.args.get('tab', 'approvals')
    )

@app.route('/admin/save-settings', methods=['POST'])
@admin_required
def admin_save_settings():
    """Save live Gmail and SMS gateway credentials to MongoDB and active session."""
    settings_payload = {
        'GMAIL_USER': request.form.get('gmail_user', '').strip(),
        'GMAIL_APP_PASSWORD': request.form.get('gmail_app_password', '').strip(),
        'ADMIN_PHONE': request.form.get('admin_phone', '').strip(),
        'ADMIN_EMAIL': request.form.get('admin_email', '').strip(),
        'FAST2SMS_API_KEY': request.form.get('fast2sms_api_key', '').strip(),
        'TWILIO_ACCOUNT_SID': request.form.get('twilio_account_sid', '').strip(),
        'TWILIO_AUTH_TOKEN': request.form.get('twilio_auth_token', '').strip(),
        'TWILIO_PHONE_NUMBER': request.form.get('twilio_phone_number', '').strip()
    }

    database.save_gateway_settings(settings_payload)
    database.log_action(session['user_id'], 'GATEWAY_SETTINGS_UPDATED', "Updated live Gmail/SMS gateway credentials", request.remote_addr)

    flash(" Live Gateway & OTP Settings updated successfully! Settings are active.", "success")
    return redirect(url_for('admin_dashboard', tab='settings'))

@app.route('/admin/test-email', methods=['POST'])
@admin_required
def admin_test_email():
    """Trigger live test email through configured Gmail credentials."""
    test_email = request.form.get('test_email', '').strip()
    if not test_email:
        flash("Please provide a valid test destination email address.", "danger")
        return redirect(url_for('admin_dashboard', tab='settings'))

    res = otp_service.test_live_email_connection(test_email)
    if res['success']:
        flash(f" Success! Real test email with 6-digit OTP dispatched to {test_email}. Please check your inbox!", "success")
    else:
        flash(f" Live Email Failed: {res.get('error', 'Authentication failed')}", "danger")

    return redirect(url_for('admin_dashboard', tab='settings'))

@app.route('/admin/test-sms', methods=['POST'])
@admin_required
def admin_test_sms():
    """Trigger live test SMS through configured SMS gateway."""
    test_phone = request.form.get('test_phone', '').strip()
    if not test_phone:
        flash("Please provide a mobile phone number for testing.", "danger")
        return redirect(url_for('admin_dashboard', tab='settings'))

    res = otp_service.test_live_sms_connection(test_phone)
    if res['success']:
        flash(f" Success! Real test SMS with 6-digit OTP dispatched to {test_phone}. Check your mobile!", "success")
    else:
        flash(f" Live SMS Failed: {res.get('error', 'Gateway failed')}", "danger")

    return redirect(url_for('admin_dashboard', tab='settings'))

@app.route('/admin/files')
@admin_required
def admin_files():
    """Global File Explorer for Administrator to inspect and audit all files across all users."""
    category = request.args.get('category', 'all')
    search = request.args.get('q', '')
    sort_by = request.args.get('sort', 'newest')
    selected_user_id = request.args.get('user_id', '')

    all_users = database.get_all_users()
    files = database.get_all_files(category=category, search=search, sort_by=sort_by)
    if selected_user_id:
        files = [f for f in files if f.get('user_id') == selected_user_id]

    stats = database.get_system_stats()

    return render_template(
        'admin_files.html',
        files=files,
        all_users=all_users,
        selected_user_id=selected_user_id,
        stats=stats,
        active_category=category,
        search_query=search,
        current_sort=sort_by
    )

@app.route('/admin/approve/<user_id>', methods=['POST'])
@admin_required
def admin_approve_user(user_id):
    """Approve a pending user registration."""
    user = database.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    database.update_user_status(user_id, 'approved', admin_id=session['user_id'])
    database.log_action(session['user_id'], 'USER_APPROVED', f"Approved user '{user['username']}' (ID: {user_id})", request.remote_addr)

    flash(f"User '{user['username']}' has been approved and can now log in!", "success")
    return redirect(url_for('admin_dashboard', tab='approvals'))

@app.route('/admin/reject/<user_id>', methods=['POST'])
@admin_required
def admin_reject_user(user_id):
    """Reject a pending user registration."""
    user = database.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    database.update_user_status(user_id, 'rejected')
    database.log_action(session['user_id'], 'USER_REJECTED', f"Rejected user '{user['username']}'", request.remote_addr)

    flash(f"User '{user['username']}' registration was rejected.", "warning")
    return redirect(url_for('admin_dashboard', tab='approvals'))

@app.route('/admin/toggle-status/<user_id>', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    """Toggle a user's status between approved and suspended."""
    user = database.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard', tab='users'))

    if user['role'] == 'admin':
        flash("Cannot modify root administrator status.", "danger")
        return redirect(url_for('admin_dashboard', tab='users'))

    new_status = 'suspended' if user['status'] == 'approved' else 'approved'
    database.update_user_status(user_id, new_status, admin_id=session['user_id'])
    database.log_action(session['user_id'], 'STATUS_CHANGE', f"Changed {user['username']} status to {new_status}", request.remote_addr)

    flash(f"User '{user['username']}' is now {new_status.capitalize()}.", "info")
    return redirect(url_for('admin_dashboard', tab='users'))

@app.route('/admin/delete-user/<user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user, their database records, and their uploaded files."""
    user = database.get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard', tab='users'))

    if user['role'] == 'admin':
        flash("Cannot delete administrator account.", "danger")
        return redirect(url_for('admin_dashboard', tab='users'))

    # Remove user physical directory
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    if os.path.exists(user_dir):
        try:
            shutil.rmtree(user_dir)
        except Exception as e:
            print(f"Error removing user directory: {e}")

    database.delete_user(user_id)
    database.log_action(session['user_id'], 'USER_DELETED', f"Deleted user '{user['username']}' and all files", request.remote_addr)

    flash(f"User '{user['username']}' and all associated files have been permanently deleted.", "info")
    return redirect(url_for('admin_dashboard', tab='users'))

# ----------------- Error Handlers -----------------

@app.errorhandler(404)
def error_404(e):
    return render_template('error.html', code=404, message="The requested file or page was not found."), 404

@app.errorhandler(403)
def error_403(e):
    return render_template('error.html', code=403, message="Access forbidden. You do not possess permission for this resource."), 403

@app.errorhandler(413)
def error_413(e):
    return render_template('error.html', code=413, message="Uploaded file exceeds the maximum permissible limit (500 MB)."), 413

@app.errorhandler(500)
def error_500(e):
    return render_template('error.html', code=500, message="An internal server error occurred."), 500

# ----------------- Application Entrypoint -----------------

if __name__ == '__main__':
    # Initialize DB and ensure collections are present
    database.init_db()
    print("=" * 60)
    print(" [*] FILE VAULT & STORAGE PORTAL INITIALIZED")
    print(" Running at: http://127.0.0.1:5000")
    print(" Default Administrator: admin | Password: Admin@123")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
