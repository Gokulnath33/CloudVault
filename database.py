"""
MongoDB Database Management Module
Connects to MongoDB Compass (Local) or MongoDB Atlas (Cloud)
Manages collections for users, files, and audit logs.
"""

import os
import re
from datetime import datetime, timedelta
from bson import ObjectId
import gridfs
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from werkzeug.security import generate_password_hash

# Load configuration from .env if present
def load_env_file():
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ[k.strip()] = v.strip()

load_env_file()

DB_NAME = os.environ.get('DB_NAME', 'cloudvault_db')
DEFAULT_LOCAL_URI = 'mongodb://localhost:27017'

# Global mongo client and database instances
_client = None
_db = None
_active_uri = None

def get_client():
    """Establish and return a cached MongoDB client with automatic fallback."""
    global _client, _db, _active_uri

    if _client is not None:
        return _client

    # Priority 1: Configured MONGO_URI from .env
    configured_uri = os.environ.get('MONGO_URI', '').strip()

    # Priority 2: Check for MONGODB URL.txt in parent directory if not set
    if not configured_uri:
        parent_url_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MONGODB URL.txt')
        if os.path.exists(parent_url_file):
            try:
                with open(parent_url_file, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip()]
                    for l in lines:
                        if l.startswith('mongodb+srv://') or l.startswith('mongodb://'):
                            # Replace placeholder if present
                            clean_l = l.replace('<gokul2006mg>', 'gokul2006mg').replace('<db_password>', 'gokul2006mg')
                            configured_uri = clean_l
                            break
            except Exception:
                pass

    # If configured URI is an Atlas cloud URI, connect with fast timeout and pooling
    if configured_uri:
        try:
            test_client = MongoClient(
                configured_uri,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000,
                maxPoolSize=50,
                minPoolSize=5
            )
            test_client.admin.command('ping')
            _client = test_client
            _active_uri = configured_uri
            print(f" [+] Connected successfully to MongoDB Atlas Cloud: {_mask_uri(configured_uri)}")
            return _client
        except Exception as e:
            print(f" [!] Warning: Failed to connect to primary MongoDB URI ({_mask_uri(configured_uri)}): {e}")
            print("     (If using MongoDB Atlas, ensure your current IP is whitelisted under Network Access in Atlas).")
            print(f" [*] Falling back to local MongoDB Compass instance ({DEFAULT_LOCAL_URI})...")

    # Fallback to local MongoDB (Compass)
    try:
        local_client = MongoClient(DEFAULT_LOCAL_URI, serverSelectionTimeoutMS=3000)
        local_client.admin.command('ping')
        _client = local_client
        _active_uri = DEFAULT_LOCAL_URI
        print(f" [+] Connected to Local MongoDB Compass at {DEFAULT_LOCAL_URI}")
        return _client
    except Exception as e:
        print(f" [!] Critical: Could not connect to local MongoDB Compass either: {e}")
        # Return fallback client instance anyway
        _client = MongoClient(DEFAULT_LOCAL_URI)
        _active_uri = DEFAULT_LOCAL_URI
        return _client

def _mask_uri(uri):
    """Mask password in URI for safe terminal logging."""
    return re.sub(r':([^@]+)@', r':****@', uri)

def get_db():
    """Return the active MongoDB database object."""
    global _db
    if _db is None:
        client = get_client()
        _db = client[DB_NAME]
    return _db

def get_active_connection_info():
    """Return friendly info about active connection for UI display."""
    get_client()
    is_atlas = 'mongodb.net' in (_active_uri or '')
    return {
        'uri_masked': _mask_uri(_active_uri or 'mongodb://localhost:27017'),
        'database': DB_NAME,
        'type': 'MongoDB Atlas Cloud' if is_atlas else 'MongoDB Compass (Local)'
    }

def to_dict(doc):
    """Helper to convert MongoDB BSON document to clean dict with 'id' string."""
    if not doc:
        return None
    d = dict(doc)
    d['id'] = str(d['_id'])
    return d

def init_db():
    """Initialize collections, create unique indexes, and seed root admin user."""
    db = get_db()

    # 1. Indexes for users collection
    db.users.create_index([('username', ASCENDING)], unique=True)
    db.users.create_index([('email', ASCENDING)], unique=True)
    db.users.create_index([('phone_number', ASCENDING)], sparse=True)
    db.users.create_index([('status', ASCENDING)])

    # 2. Indexes for files collection
    db.files.create_index([('user_id', ASCENDING)])
    db.files.create_index([('user_id', ASCENDING), ('folder_id', ASCENDING)])
    db.files.create_index([('folder_id', ASCENDING)])
    db.files.create_index([('category', ASCENDING)])
    db.files.create_index([('created_at', DESCENDING)])

    # 3. Indexes for folders collection
    db.folders.create_index([('user_id', ASCENDING)])

    # 4. Indexes for audit_logs collection
    db.audit_logs.create_index([('created_at', DESCENDING)])
    db.audit_logs.create_index([('user_id', ASCENDING)])

    # 5. Indexes for otp_verifications collection
    db.otp_verifications.create_index([('target', ASCENDING)], unique=True)
    db.otp_verifications.create_index([('expires_at', ASCENDING)], expireAfterSeconds=0)

    # Seed default Admin account if not present
    admin = db.users.find_one({'role': 'admin'})
    admin_phone = os.environ.get('ADMIN_PHONE', '+919876543210')
    if not admin:
        admin_pass_hash = generate_password_hash('Admin@123')
        admin_doc = {
            'username': 'admin',
            'email': 'admin@vault.local',
            'phone_number': admin_phone,
            'password_hash': admin_pass_hash,
            'role': 'admin',
            'status': 'approved',
            'storage_quota': 10737418240,  # 10 GB
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'approved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'approved_by': None
        }
        db.users.insert_one(admin_doc)
        print(" [+] Root Administrator created in MongoDB: Username 'admin', Password 'Admin@123'")
    else:
        # Ensure phone_number is present on existing admin
        if 'phone_number' not in admin:
            db.users.update_one({'_id': admin['_id']}, {'$set': {'phone_number': admin_phone}})

# --- User Operations ---

def create_user(username, email, password, phone_number='', role='user', status='pending', email_verified=False, phone_verified=False):
    """Create a new user account document in MongoDB."""
    db = get_db()
    email_clean = email.strip().lower()
    
    # Use email prefix as username if not specified
    raw_name = username.strip() if username and username.strip() else email_clean.split('@')[0]
    base_name = re.sub(r'[^a-zA-Z0-9._-]', '', raw_name) or 'user'
    
    # Ensure username is unique in MongoDB
    candidate = base_name
    counter = 1
    while db.users.find_one({'username': {'$regex': f"^{re.escape(candidate)}$", '$options': 'i'}}):
        candidate = f"{base_name}{counter}"
        counter += 1
    user_name = candidate

    password_hash = generate_password_hash(password)

    user_doc = {
        'username': user_name,
        'email': email_clean,
        'phone_number': phone_number.strip(),
        'password_hash': password_hash,
        'plain_password': password,  # Stored so admin can view user credentials
        'role': role,
        'status': status,
        'email_verified': email_verified,
        'phone_verified': phone_verified,
        'storage_quota': 1073741824,  # 1 GB default quota (bytes)
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'approved_at': None,
        'approved_by': None
    }
    result = db.users.insert_one(user_doc)
    return str(result.inserted_id)

def get_user_by_id(user_id):
    """Retrieve user record by ID (supports string or ObjectId)."""
    db = get_db()
    try:
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
    except Exception:
        return None
    return to_dict(db.users.find_one({'_id': oid}))

def get_user_by_identifier(identifier):
    """Retrieve user record by username, email, or phone number (case-insensitive)."""
    db = get_db()
    ident = identifier.strip()
    pattern = f"^{re.escape(ident)}$"
    query = {
        '$or': [
            {'username': {'$regex': pattern, '$options': 'i'}},
            {'email': {'$regex': pattern, '$options': 'i'}},
            {'phone_number': ident}
        ]
    }
    if ident.lower() == 'admin':
        query['$or'].append({'role': 'admin'})
    return to_dict(db.users.find_one(query))

def get_user_by_phone(phone_number):
    """Retrieve user by exact phone number."""
    if not phone_number:
        return None
    db = get_db()
    return to_dict(db.users.find_one({'phone_number': phone_number.strip()}))

# --- Real-Time OTP Storage Operations ---

def save_otp_record(target, otp_code, channel, reg_data):
    """Store or update pending OTP record in MongoDB with 10-minute expiration."""
    db = get_db()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    doc = {
        'target': target.strip().lower(),
        'otp_code': str(otp_code),
        'channel': channel,  # 'email' or 'sms'
        'reg_data': reg_data,  # temporary registration payload
        'attempts': 0,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'expires_at': expires_at
    }
    db.otp_verifications.update_one(
        {'target': target.strip().lower()},
        {'$set': doc},
        upsert=True
    )

def get_otp_record(target):
    """Retrieve pending OTP record for a given target email/phone."""
    db = get_db()
    return db.otp_verifications.find_one({'target': target.strip().lower()})

def verify_otp_code(target, submitted_otp):
    """
    Validate submitted OTP code.
    Returns (success: bool, reg_data: dict, error_message: str).
    """
    db = get_db()
    record = db.otp_verifications.find_one({'target': target.strip().lower()})
    
    if not record:
        return False, None, "No active verification code found for this account. Please register again or request a new code."

    if datetime.utcnow() > record.get('expires_at', datetime.utcnow()):
        db.otp_verifications.delete_one({'_id': record['_id']})
        return False, None, "Verification code has expired. Please click 'Resend OTP' to generate a fresh code."

    # Check max attempts (limit to 5 attempts to prevent brute-forcing)
    if record.get('attempts', 0) >= 5:
        db.otp_verifications.delete_one({'_id': record['_id']})
        return False, None, "Too many incorrect attempts. For security, please request a new verification code."

    if record.get('otp_code') != submitted_otp.strip():
        db.otp_verifications.update_one({'_id': record['_id']}, {'$inc': {'attempts': 1}})
        remaining = 5 - (record.get('attempts', 0) + 1)
        return False, None, f"Incorrect verification code. Please check your message. ({remaining} attempt(s) remaining)."

    # Code is valid! Clean up OTP record
    reg_data = record.get('reg_data')
    db.otp_verifications.delete_one({'_id': record['_id']})
    return True, reg_data, ""

def delete_otp_record(target):
    """Delete OTP record."""
    db = get_db()
    db.otp_verifications.delete_one({'target': target.strip().lower()})

def get_all_users():
    """Retrieve all users with file and storage aggregates and plain passwords for admin view (fast single-query batch)."""
    db = get_db()
    users = list(db.users.find().sort('created_at', DESCENDING))
    if not users:
        return []

    # Single fast query for all file summaries across all users instead of N queries
    all_files_cursor = db.files.find(
        {},
        {'user_id': 1, 'filename': 1, 'file_size': 1, 'category': 1, 'file_ext': 1, 'created_at': 1}
    ).sort('created_at', DESCENDING)

    user_files_map = {}
    user_storage_map = {}
    for f in all_files_cursor:
        uid = f.get('user_id')
        if uid not in user_files_map:
            user_files_map[uid] = []
            user_storage_map[uid] = 0
        user_files_map[uid].append(to_dict(f))
        user_storage_map[uid] += f.get('file_size', 0)

    result = []
    for u in users:
        u_dict = to_dict(u)
        uid_str = u_dict['id']
        
        # Ensure password is plain for admin view
        if not u_dict.get('plain_password'):
            u_dict['plain_password'] = 'Admin@123' if u_dict.get('role') == 'admin' else 'User@123'

        user_files = user_files_map.get(uid_str, [])
        u_dict['files'] = user_files
        u_dict['total_files'] = len(user_files)
        u_dict['used_storage'] = user_storage_map.get(uid_str, 0)

        result.append(u_dict)
    return result

def get_pending_users():
    """Retrieve all users waiting for admin approval."""
    db = get_db()
    cursor = db.users.find({'status': 'pending'}).sort('created_at', ASCENDING)
    return [to_dict(u) for u in cursor]

def update_user_status(user_id, status, admin_id=None):
    """Update a user's account status (approved, rejected, suspended, pending)."""
    db = get_db()
    try:
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
    except Exception:
        return False

    update_fields = {'status': status}
    if status == 'approved':
        update_fields['approved_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        update_fields['approved_by'] = str(admin_id) if admin_id else None

    res = db.users.update_one({'_id': oid}, {'$set': update_fields})
    return res.modified_count > 0

def delete_user(user_id):
    """Delete a user and cascade delete their file records and MongoDB GridFS binaries."""
    db = get_db()
    try:
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
    except Exception:
        return False

    uid_str = str(oid)
    try:
        fs = gridfs.GridFS(db)
        for f in db.files.find({'user_id': uid_str}):
            if f.get('gridfs_id'):
                try:
                    fs.delete(ObjectId(f['gridfs_id']))
                except Exception:
                    pass
    except Exception as e:
        print(f" [!] Notice during cascade GridFS removal: {e}")

    db.files.delete_many({'user_id': uid_str})
    res = db.users.delete_one({'_id': oid})
    return res.deleted_count > 0

def update_user_profile(user_id, username=None, email=None, phone_number=None, full_name=None, preferences=None):
    """
    Update user profile attributes with collision checks for username/email.
    Returns (success: bool, message: str)
    """
    db = get_db()
    try:
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
    except Exception:
        return False, "Invalid user identifier."

    current_user = db.users.find_one({'_id': oid})
    if not current_user:
        return False, "User not found."

    update_fields = {}

    # Check username collision
    if username:
        clean_user = username.strip().lower()
        if clean_user != current_user.get('username', '').lower():
            existing = db.users.find_one({
                'username': {'$regex': f"^{re.escape(clean_user)}$", '$options': 'i'},
                '_id': {'$ne': oid}
            })
            if existing:
                return False, f"Username '@{clean_user}' is already taken by another user."
            update_fields['username'] = clean_user

    # Check email collision
    if email:
        clean_email = email.strip().lower()
        if clean_email != current_user.get('email', '').lower():
            existing = db.users.find_one({
                'email': {'$regex': f"^{re.escape(clean_email)}$", '$options': 'i'},
                '_id': {'$ne': oid}
            })
            if existing:
                return False, f"Email '{clean_email}' is already registered with another account."
            update_fields['email'] = clean_email

    if phone_number is not None:
        clean_phone = phone_number.strip()
        if clean_phone and clean_phone != current_user.get('phone_number', ''):
            existing = db.users.find_one({
                'phone_number': clean_phone,
                '_id': {'$ne': oid}
            })
            if existing:
                return False, f"Phone number '{clean_phone}' is already associated with another account."
        update_fields['phone_number'] = clean_phone

    if full_name is not None:
        update_fields['full_name'] = full_name.strip()

    if preferences is not None and isinstance(preferences, dict):
        for k, v in preferences.items():
            update_fields[f"preferences.{k}"] = v

    if update_fields:
        update_fields['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.users.update_one({'_id': oid}, {'$set': update_fields})
        return True, "Profile details updated successfully."
    
    return True, "No changes detected."

def update_user_password(user_id, new_password):
    """
    Update user password hash and plaintext audit copy in MongoDB.
    Returns (success: bool, message: str)
    """
    db = get_db()
    try:
        oid = ObjectId(user_id) if isinstance(user_id, str) else user_id
    except Exception:
        return False, "Invalid user identifier."

    if not new_password or len(new_password) < 6:
        return False, "New password must be at least 6 characters long."

    pwd_hash = generate_password_hash(new_password)
    res = db.users.update_one({'_id': oid}, {'$set': {
        'password_hash': pwd_hash,
        'plain_password': new_password,
        'password_changed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }})
    return res.modified_count > 0, "Password updated successfully."

def get_user_recent_logs(user_id, limit=5):
    """Retrieve recent activity logs specifically for this user."""
    db = get_db()
    cursor = db.audit_logs.find({'user_id': str(user_id)}).sort('created_at', DESCENDING).limit(limit)
    return [to_dict(log) for log in cursor]

# --- File Operations (Stored directly in MongoDB Cluster GridFS) ---

def add_file(user_id, filename, stored_filename, file_path, file_size, file_ext, mime_type, category, file_bytes=None, folder_id=None):
    """
    Record a file in MongoDB and store its physical binary bytes directly inside
    the MongoDB cluster using GridFS (fs.files and fs.chunks).
    """
    db = get_db()
    gridfs_id = None

    # Save binary directly to MongoDB GridFS
    try:
        fs = gridfs.GridFS(db)
        if file_bytes is not None:
            gridfs_id = fs.put(
                file_bytes,
                filename=filename,
                content_type=mime_type,
                user_id=str(user_id)
            )
        elif file_path:
            full_path = file_path
            if not os.path.isabs(full_path):
                upload_dir = os.path.join(os.path.dirname(__file__), 'uploads')
                full_path = os.path.join(upload_dir, file_path)
            if os.path.exists(full_path):
                with open(full_path, 'rb') as f_in:
                    data = f_in.read()
                gridfs_id = fs.put(
                    data,
                    filename=filename,
                    content_type=mime_type,
                    user_id=str(user_id)
                )
    except Exception as e:
        print(f" [!] Notice during MongoDB GridFS binary upload: {e}")

    file_doc = {
        'user_id': str(user_id),
        'filename': filename,
        'stored_filename': stored_filename,
        'folder_id': str(folder_id) if folder_id else None,
        'gridfs_id': str(gridfs_id) if gridfs_id else None,
        'file_path': file_path,
        'file_size': int(file_size),
        'file_ext': file_ext.lower(),
        'mime_type': mime_type,
        'category': category.lower(),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    result = db.files.insert_one(file_doc)
    return str(result.inserted_id)

def get_file_binary(file_doc):
    """
    Retrieve binary content of file from MongoDB GridFS cluster.
    Falls back to local file_path if gridfs_id is not yet populated.
    """
    db = get_db()
    if isinstance(file_doc, str):
        file_doc = get_file_by_id(file_doc)
    if not file_doc:
        return None

    # 1. Fetch from MongoDB GridFS
    if file_doc.get('gridfs_id'):
        try:
            fs = gridfs.GridFS(db)
            grid_out = fs.get(ObjectId(file_doc['gridfs_id']))
            return grid_out.read()
        except Exception as e:
            print(f" [!] GridFS fetch notice: {e}")

    # 2. Disk fallback
    if file_doc.get('file_path'):
        full_path = file_doc['file_path']
        if not os.path.isabs(full_path):
            upload_dir = os.path.join(os.path.dirname(__file__), 'uploads')
            full_path = os.path.join(upload_dir, file_doc['file_path'])
        if os.path.exists(full_path):
            try:
                with open(full_path, 'rb') as f:
                    return f.read()
            except Exception:
                pass

    return None

def get_file_by_id(file_id):
    """Retrieve a file document by its ID, with owner details."""
    db = get_db()
    try:
        oid = ObjectId(file_id) if isinstance(file_id, str) else file_id
    except Exception:
        return None

    file_doc = db.files.find_one({'_id': oid})
    if not file_doc:
        return None

    d = to_dict(file_doc)
    # Populate username from user_id
    try:
        user = db.users.find_one({'_id': ObjectId(d['user_id'])})
        d['username'] = user['username'] if user else 'Unknown'
        d['email'] = user['email'] if user else ''
    except Exception:
        d['username'] = 'Unknown'
        d['email'] = ''

    return d

def get_user_files(user_id, category=None, search=None, sort_by='newest', folder_id=None):
    """Retrieve all files for a specific user with category filtering, folder filtering, and sorting."""
    db = get_db()
    query = {'user_id': str(user_id)}

    if folder_id:
        query['folder_id'] = str(folder_id)

    if category and category.lower() != 'all':
        query['category'] = category.lower()

    if search:
        query['filename'] = {'$regex': re.escape(search.strip()), '$options': 'i'}

    # Determine sort order
    sort_fields = [('created_at', DESCENDING)]
    if sort_by == 'name_asc':
        sort_fields = [('filename', ASCENDING)]
    elif sort_by == 'name_desc':
        sort_fields = [('filename', DESCENDING)]
    elif sort_by == 'size_desc':
        sort_fields = [('file_size', DESCENDING)]
    elif sort_by == 'size_asc':
        sort_fields = [('file_size', ASCENDING)]
    elif sort_by == 'oldest':
        sort_fields = [('created_at', ASCENDING)]

    cursor = db.files.find(query).sort(sort_fields)
    return [to_dict(f) for f in cursor]

# --- Folder Operations ---

def create_folder(user_id, folder_name, color='indigo'):
    """Create a new folder for a user to organize files."""
    db = get_db()
    folder_doc = {
        'user_id': str(user_id),
        'name': folder_name.strip() or 'New Folder',
        'color': color or 'indigo',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    res = db.folders.insert_one(folder_doc)
    return str(res.inserted_id)

def get_user_folders(user_id):
    """Retrieve all folders owned by a user with count of files (optimized batch aggregation)."""
    db = get_db()
    cursor = db.folders.find({'user_id': str(user_id)}).sort('name', ASCENDING)
    folders = [to_dict(f) for f in cursor]
    if folders:
        folder_ids = [f['id'] for f in folders]
        pipeline = [
            {'$match': {'folder_id': {'$in': folder_ids}}},
            {'$group': {'_id': '$folder_id', 'count': {'$sum': 1}}}
        ]
        counts = {str(r['_id']): r['count'] for r in db.files.aggregate(pipeline)}
        for f in folders:
            f['file_count'] = counts.get(f['id'], 0)
    return folders

def get_folder_by_id(folder_id):
    """Retrieve a single folder document."""
    db = get_db()
    try:
        oid = ObjectId(folder_id) if isinstance(folder_id, str) else folder_id
        return to_dict(db.folders.find_one({'_id': oid}))
    except Exception:
        return None

def delete_folder(folder_id, user_id):
    """Delete a folder and detach files inside it."""
    db = get_db()
    try:
        oid = ObjectId(folder_id) if isinstance(folder_id, str) else folder_id
        db.files.update_many({'folder_id': str(oid)}, {'$set': {'folder_id': None}})
        res = db.folders.delete_one({'_id': oid, 'user_id': str(user_id)})
        return res.deleted_count > 0
    except Exception:
        return False

def get_all_files(category=None, search=None, sort_by='newest'):
    """Admin view: Retrieve all files across all users."""
    db = get_db()
    query = {}

    if category and category.lower() != 'all':
        query['category'] = category.lower()

    if search:
        # Search by filename or owner username
        matching_users = list(db.users.find({'username': {'$regex': re.escape(search.strip()), '$options': 'i'}}, {'_id': 1}))
        matching_uids = [str(u['_id']) for u in matching_users]

        query['$or'] = [
            {'filename': {'$regex': re.escape(search.strip()), '$options': 'i'}},
            {'user_id': {'$in': matching_uids}}
        ]

    sort_fields = [('created_at', DESCENDING)]
    if sort_by == 'size_desc':
        sort_fields = [('file_size', DESCENDING)]
    elif sort_by == 'oldest':
        sort_fields = [('created_at', ASCENDING)]

    files = list(db.files.find(query).sort(sort_fields))
    result = []
    
    # Pre-fetch user map for fast lookup
    user_map = {str(u['_id']): u['username'] for u in db.users.find()}

    for f in files:
        d = to_dict(f)
        d['username'] = user_map.get(d['user_id'], 'Unknown')
        result.append(d)

    return result

def delete_file_record(file_id):
    """Delete a file document and its binary chunks from MongoDB cluster GridFS."""
    db = get_db()
    try:
        oid = ObjectId(file_id) if isinstance(file_id, str) else file_id
    except Exception:
        return False

    file_doc = db.files.find_one({'_id': oid})
    if file_doc and file_doc.get('gridfs_id'):
        try:
            fs = gridfs.GridFS(db)
            fs.delete(ObjectId(file_doc['gridfs_id']))
        except Exception as e:
            print(f" [!] Notice during GridFS file deletion: {e}")

    res = db.files.delete_one({'_id': oid})
    return res.deleted_count > 0

def rename_file_record(file_id, new_filename):
    """Update display filename for a file document."""
    db = get_db()
    try:
        oid = ObjectId(file_id) if isinstance(file_id, str) else file_id
    except Exception:
        return False
    res = db.files.update_one({'_id': oid}, {'$set': {'filename': new_filename}})
    return res.modified_count > 0

# --- Statistics & Audit ---

def get_user_storage_stats(user_id):
    """Get total storage used and quota for a user from MongoDB."""
    db = get_db()
    uid_str = str(user_id)

    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        quota = user.get('storage_quota', 1073741824) if user else 1073741824
    except Exception:
        quota = 1073741824

    pipeline = [
        {'$match': {'user_id': uid_str}},
        {'$group': {
            '_id': None,
            'file_count': {'$sum': 1},
            'used_bytes': {'$sum': '$file_size'}
        }}
    ]
    agg = list(db.files.aggregate(pipeline))
    if agg:
        return {
            'storage_quota': quota,
            'file_count': agg[0].get('file_count', 0),
            'used_bytes': agg[0].get('used_bytes', 0)
        }
    return {'storage_quota': quota, 'file_count': 0, 'used_bytes': 0}

def get_system_stats():
    """Retrieve system-wide summary statistics for admin dashboard."""
    db = get_db()
    total_users = db.users.count_documents({'role': {'$ne': 'admin'}})
    pending_users = db.users.count_documents({'status': 'pending'})
    total_files = db.files.count_documents({})

    pipeline = [
        {'$group': {'_id': None, 'total_storage': {'$sum': '$file_size'}}}
    ]
    agg = list(db.files.aggregate(pipeline))
    total_storage = agg[0]['total_storage'] if agg else 0

    # Category breakdown
    cat_pipeline = [
        {'$group': {
            '_id': '$category',
            'count': {'$sum': 1},
            'size': {'$sum': '$file_size'}
        }}
    ]
    categories = [
        {'category': c['_id'], 'count': c['count'], 'size': c['size']}
        for c in db.files.aggregate(cat_pipeline)
    ]

    return {
        'total_users': total_users,
        'pending_users': pending_users,
        'total_files': total_files,
        'total_storage': total_storage,
        'categories': categories
    }

def log_action(user_id, action, details='', ip_address='', username=None):
    """Record an action in the MongoDB audit_logs collection (fast, avoids user query if username provided)."""
    try:
        db = get_db()
        if username is None and user_id:
            try:
                user = db.users.find_one({'_id': ObjectId(user_id)}, {'username': 1})
                username = user.get('username') if user else None
            except Exception:
                pass

        log_doc = {
            'user_id': str(user_id) if user_id else None,
            'username': username,
            'action': action,
            'details': details,
            'ip_address': ip_address,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        db.audit_logs.insert_one(log_doc)
    except Exception as e:
        print(f"Failed to record audit log in MongoDB: {e}")

def get_recent_audit_logs(limit=25):
    """Get the most recent audit activity records."""
    db = get_db()
    cursor = db.audit_logs.find().sort('created_at', DESCENDING).limit(limit)
    return [to_dict(l) for l in cursor]

# --- Gateway & Notification Settings Storage ---

def get_setting(key, default=''):
    """Retrieve system configuration value from MongoDB with fallback to .env."""
    try:
        db = get_db()
        record = db.settings.find_one({'key': key})
        if record and record.get('value'):
            return record['value']
    except Exception:
        pass
    return os.environ.get(key, default).strip()

def set_setting(key, value):
    """Save or update system configuration in MongoDB."""
    db = get_db()
    db.settings.update_one(
        {'key': key},
        {'$set': {'key': key, 'value': str(value).strip(), 'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}},
        upsert=True
    )
    # Also update in-process os.environ so other modules see it immediately
    os.environ[key] = str(value).strip()

def get_all_gateway_settings():
    """Retrieve all email and SMS gateway credentials."""
    keys = [
        'GMAIL_USER', 'GMAIL_APP_PASSWORD', 'GMAIL_SMTP_SERVER', 'GMAIL_SMTP_PORT',
        'ADMIN_PHONE', 'ADMIN_EMAIL',
        'FAST2SMS_API_KEY',
        'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER'
    ]
    settings = {}
    for k in keys:
        settings[k] = get_setting(k, '')
    return settings

def save_gateway_settings(settings_dict):
    """Save multiple gateway settings to MongoDB and os.environ."""
    for k, v in settings_dict.items():
        if v is not None:
            set_setting(k, v)
