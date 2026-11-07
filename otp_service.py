"""
Real-Time OTP Verification & Live Communication Service
Handles actual email transmission via Gmail (TLS SMTP) and physical SMS delivery
via Fast2SMS / Twilio, plus real-time notifications to the Administrator.
"""

import os
import secrets
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import requests

import database

# ----------------- Configuration Helpers -----------------

def get_config(key, default=''):
    """Fetch configuration from MongoDB settings or environment variable."""
    return database.get_setting(key, default)

def is_smtp_configured():
    user = get_config('GMAIL_USER') or get_config('SMTP_USER')
    password = get_config('GMAIL_APP_PASSWORD') or get_config('SMTP_PASSWORD')
    return bool(user and password)

def is_sms_configured():
    fast2sms_key = get_config('FAST2SMS_API_KEY')
    twilio_sid = get_config('TWILIO_ACCOUNT_SID')
    twilio_auth = get_config('TWILIO_AUTH_TOKEN')
    return bool(fast2sms_key or (twilio_sid and twilio_auth))

# ----------------- OTP Generation -----------------

def generate_otp(length=6):
    """Generate a cryptographically secure 6-digit numeric OTP."""
    return ''.join(secrets.choice('0123456789') for _ in range(length))

# ----------------- Real Live Gmail / Email Transmission -----------------

def send_email_otp(to_email, otp_code, username):
    """
    Transmit authentic real-time 6-digit OTP code to the recipient's Gmail inbox.
    Uses Google's authenticated SMTP servers with TLS encryption.
    """
    subject = f"CloudVault Verification Code: {otp_code}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; margin: 0; padding: 20px; }}
            .card {{ max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 16px; border: 1px solid #334155; padding: 32px; color: #f8fafc; }}
            .brand {{ font-size: 20px; font-weight: bold; color: #818cf8; margin-bottom: 24px; display: flex; align-items: center; gap: 8px; }}
            .greeting {{ font-size: 16px; color: #cbd5e1; margin-bottom: 16px; }}
            .otp-box {{ background: #0f172a; border: 2px dashed #6366f1; border-radius: 12px; padding: 20px; text-align: center; margin: 24px 0; }}
            .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #ffffff; font-family: monospace; }}
            .expires {{ font-size: 12px; color: #94a3b8; margin-top: 8px; }}
            .footer {{ font-size: 11px; color: #64748b; margin-top: 32px; border-top: 1px solid #334155; padding-top: 16px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="brand">☁️ CloudVault File Storage</div>
            <div class="greeting">Hello <strong>{username}</strong>,</div>
            <p style="color: #94a3b8; font-size: 14px; line-height: 1.5;">
                Thank you for registering on CloudVault. Please enter the authentic verification code below to verify your account:
            </p>
            <div class="otp-box">
                <div class="otp-code">{otp_code}</div>
                <div class="expires">⏱️ Valid for 10 minutes. Do not share this OTP with anyone.</div>
            </div>
            <p style="color: #94a3b8; font-size: 13px;">
                Once verified, your account request will be forwarded to the Administrator for approval.
            </p>
            <div class="footer">
                If you did not request this code, please safely ignore this email.<br>
                © 2026 CloudVault Systems. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

    plain_content = f"Hello {username},\n\nYour CloudVault verification code is: {otp_code}\nValid for 10 minutes.\n\nThank you,\nCloudVault Team"

    smtp_server = get_config('GMAIL_SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(get_config('GMAIL_SMTP_PORT', '587'))
    smtp_user = get_config('GMAIL_USER') or get_config('SMTP_USER')
    smtp_pass = get_config('GMAIL_APP_PASSWORD') or get_config('SMTP_PASSWORD')

    # If Gmail is configured, perform REAL live transmission
    if smtp_user and smtp_pass:
        try:
            # Clean app password from spaces
            clean_pass = smtp_pass.replace(' ', '')
            
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"CloudVault Security <{smtp_user}>"
            msg["To"] = to_email

            msg.attach(MIMEText(plain_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port, timeout=12) as server:
                server.starttls(context=context)
                server.login(smtp_user, clean_pass)
                server.sendmail(smtp_user, to_email, msg.as_string())

            print(f" [+] [REAL LIVE GMAIL SENT] Verification OTP {otp_code} successfully delivered to {to_email}")
            return {
                'success': True,
                'mode': 'live_email',
                'target': to_email,
                'message': f"Real verification email dispatched to {to_email}. Please check your inbox or spam folder."
            }

        except smtplib.SMTPAuthenticationError as e:
            err_msg = "Google SMTP Authentication failed: Invalid Gmail address or App Password. Please check Admin Settings."
            print(f" [!] {err_msg} ({e})")
            _log_terminal_otp("EMAIL (GMAIL)", to_email, otp_code)
            return {
                'success': False,
                'mode': 'auth_error',
                'target': to_email,
                'error': err_msg,
                'dev_otp': otp_code
            }
        except Exception as e:
            # Fallback attempt on SSL port 465
            try:
                ssl_ctx = ssl._create_unverified_context()
                with smtplib.SMTP_SSL(smtp_server, 465, context=ssl_ctx, timeout=6) as server_ssl:
                    server_ssl.login(smtp_user, clean_pass)
                    server_ssl.sendmail(smtp_user, to_email, msg.as_string())
                print(f" [+] [REAL LIVE GMAIL SENT via Port 465] Verification OTP {otp_code} successfully delivered to {to_email}")
                return {
                    'success': True,
                    'mode': 'live_email',
                    'target': to_email,
                    'message': f"Real verification email dispatched to {to_email}."
                }
            except Exception:
                pass

            err_str = str(e)
            if 'timed out' in err_str.lower():
                err_msg = "Google SMTP connection timed out. Outbound email ports (587/465) are blocked on your current Wi-Fi network (common on college/campus Wi-Fi). Please connect to your phone's Mobile Hotspot or unlock Fast2SMS SMS delivery."
            else:
                err_msg = f"Failed to send email via SMTP: {err_str}"
            
            print(f" [!] {err_msg}")
            _log_terminal_otp("EMAIL (GMAIL)", to_email, otp_code)
            return {
                'success': False,
                'mode': 'error',
                'target': to_email,
                'error': err_msg,
                'dev_otp': otp_code
            }
    else:
        # Notice that credentials are required for live sending
        print(f" [!] GMAIL_USER or GMAIL_APP_PASSWORD not configured. Please add them in Admin Settings.")
        _log_terminal_otp("EMAIL (GMAIL)", to_email, otp_code)
        return {
            'success': True,
            'mode': 'simulated_email',
            'target': to_email,
            'dev_otp': otp_code,
            'notice': "Live Gmail credentials not yet configured. Real OTP logged to terminal."
        }

# ----------------- Real Live SMS Transmission -----------------

def send_sms_otp(phone_number, otp_code):
    """
    Transmit authentic real-time 6-digit OTP code to the recipient's mobile phone via SMS.
    Supports Fast2SMS (India) and Twilio (Global).
    """
    clean_phone = phone_number.strip().replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
    # For Indian SMS gateways like Fast2SMS, 10-digit number is standard
    ten_digit_phone = clean_phone[-10:] if len(clean_phone) >= 10 else clean_phone

    sms_text = f"Your CloudVault security verification code is: {otp_code}. Valid for 10 minutes. Do not share."

    # 1. Check Fast2SMS (Instant real SMS delivery in India)
    fast2sms_key = get_config('FAST2SMS_API_KEY')
    if fast2sms_key:
        try:
            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {"authorization": fast2sms_key}
            
            # Step A: Try OTP route (Fast2SMS dedicated transactional OTP route)
            payload_otp = {
                "variables_values": otp_code,
                "route": "otp",
                "numbers": ten_digit_phone
            }
            resp = requests.post(url, data=payload_otp, headers=headers, timeout=12)
            try:
                res_json = resp.json()
            except Exception:
                res_json = {}

            if resp.status_code == 200 and res_json.get('return') is True:
                print(f" [+] [REAL LIVE SMS SENT via Fast2SMS (otp)] OTP delivered to +91 {ten_digit_phone}")
                return {
                    'success': True,
                    'mode': 'live_sms',
                    'target': clean_phone,
                    'message': f"Real SMS dispatched to +91 {ten_digit_phone}. Check your phone messages."
                }
            
            # Step B: If OTP route requires website verification (code 996), try Quick SMS route (route=q)
            otp_code_status = res_json.get('status_code')
            if otp_code_status == 996 or not res_json.get('return'):
                payload_q = {
                    "message": f"CloudVault Verification Code: {otp_code}. Valid for 10 minutes.",
                    "language": "english",
                    "route": "q",
                    "numbers": ten_digit_phone
                }
                resp_q = requests.post(url, data=payload_q, headers=headers, timeout=12)
                try:
                    res_q_json = resp_q.json()
                except Exception:
                    res_q_json = {}

                if resp_q.status_code == 200 and res_q_json.get('return') is True:
                    print(f" [+] [REAL LIVE SMS SENT via Fast2SMS (route=q)] OTP delivered to +91 {ten_digit_phone}")
                    return {
                        'success': True,
                        'mode': 'live_sms',
                        'target': clean_phone,
                        'message': f"Real SMS dispatched to +91 {ten_digit_phone} via Fast2SMS."
                    }
                
                # If route=q returned error code, analyze it
                err_code = res_q_json.get('status_code') or res_json.get('status_code')
                raw_msg = res_q_json.get('message') or res_json.get('message')
                if isinstance(raw_msg, list):
                    raw_msg = ' '.join(raw_msg)

                custom_guidance = ""
                if err_code == 996:
                    custom_guidance = "Fast2SMS requires completing website verification or DLT/Aadhaar KYC in your Fast2SMS panel under the 'OTP Message' menu."
                elif err_code == 999:
                    custom_guidance = "Fast2SMS requires a one-time minimum transaction of Rs. 100 or more to unlock API SMS dispatch (current balance is Rs. 50)."
                
                error_detail = f"{raw_msg}. {custom_guidance}".strip()
                print(f" [!] Fast2SMS Dispatch Blocked: {error_detail}")
                _log_terminal_otp("SMS (PHONE)", clean_phone, otp_code)
                return {
                    'success': False,
                    'mode': 'sms_gateway_error',
                    'target': clean_phone,
                    'error': f"Fast2SMS API Response: {error_detail}",
                    'dev_otp': otp_code
                }

        except Exception as e:
            print(f" [!] Fast2SMS exception: {e}")
            _log_terminal_otp("SMS (PHONE)", clean_phone, otp_code)
            return {
                'success': False,
                'mode': 'error',
                'target': clean_phone,
                'error': f"SMS Gateway Connection Error: {str(e)}",
                'dev_otp': otp_code
            }

    # 2. Check Twilio (Global SMS)
    twilio_sid = get_config('TWILIO_ACCOUNT_SID')
    twilio_auth = get_config('TWILIO_AUTH_TOKEN')
    twilio_from = get_config('TWILIO_PHONE_NUMBER')

    if twilio_sid and twilio_auth and twilio_from:
        try:
            # Ensure international E.164 format for Twilio (e.g. +91...)
            e164_phone = clean_phone if clean_phone.startswith('+') else f"+91{clean_phone}"
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            resp = requests.post(
                url,
                data={'To': e164_phone, 'From': twilio_from, 'Body': sms_text},
                auth=(twilio_sid, twilio_auth),
                timeout=12
            )
            if resp.status_code in (200, 201):
                print(f" [+] [REAL LIVE SMS SENT via Twilio] OTP delivered to {e164_phone}")
                return {
                    'success': True,
                    'mode': 'live_sms',
                    'target': clean_phone,
                    'message': f"Real SMS dispatched via Twilio to {clean_phone}."
                }
            else:
                print(f" [!] Twilio SMS error: {resp.text}")
                _log_terminal_otp("SMS (PHONE)", clean_phone, otp_code)
                return {
                    'success': False,
                    'mode': 'sms_gateway_error',
                    'target': clean_phone,
                    'error': f"Twilio SMS Error: {resp.text[:80]}",
                    'dev_otp': otp_code
                }
        except Exception as e:
            print(f" [!] Twilio exception: {e}")
            _log_terminal_otp("SMS (PHONE)", clean_phone, otp_code)
            return {
                'success': False,
                'mode': 'error',
                'target': clean_phone,
                'error': str(e),
                'dev_otp': otp_code
            }

    # Neither configured
    print(f" [!] Live SMS Gateway key not configured in Admin Settings / .env.")
    _log_terminal_otp("SMS (PHONE)", clean_phone, otp_code)
    return {
        'success': True,
        'mode': 'simulated_sms',
        'target': clean_phone,
        'dev_otp': otp_code,
        'notice': "Live SMS key not yet configured. Real OTP logged to terminal."
    }

# ----------------- Admin Real-Time Alert -----------------

def notify_admin_new_registration(user_data):
    """
    Sends real-time SMS alert to Admin's mobile phone number and email when a user
    completes OTP verification and enters the approval queue.
    """
    admin_phone = get_config('ADMIN_PHONE', '+919876543210')
    admin_email = get_config('ADMIN_EMAIL', 'admin@vault.local')
    
    username = user_data.get('username')
    email = user_data.get('email')
    phone = user_data.get('phone_number')

    alert_message = (
        f"[CloudVault Alert] New user verified OTP:\n"
        f"User: {username}\n"
        f"Phone: {phone}\n"
        f"Email: {email}\n"
        f"Action: Please login to Admin Panel to Approve or Reject."
    )

    print("\n" + "=" * 60)
    print(" [REAL-TIME ADMIN NOTIFICATION TRIGGERED]")
    print(f" -> Admin Phone: {admin_phone}")
    print(f" -> Admin Email: {admin_email}")
    print(f" -> Message: {alert_message}")
    print("=" * 60 + "\n")

    # 1. Send Real Email Alert to Admin Gmail
    smtp_user = get_config('GMAIL_USER') or get_config('SMTP_USER')
    smtp_pass = get_config('GMAIL_APP_PASSWORD') or get_config('SMTP_PASSWORD')
    if smtp_user and smtp_pass and admin_email:
        try:
            smtp_server = get_config('GMAIL_SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(get_config('GMAIL_SMTP_PORT', '587'))
            clean_pass = smtp_pass.replace(' ', '')

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[CloudVault Alert] New User Awaiting Approval: {username}"
            msg["From"] = f"CloudVault Security <{smtp_user}>"
            msg["To"] = admin_email

            admin_html = f"""
            <!DOCTYPE html>
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155;">
                    <h2 style="color: #818cf8; margin-top: 0;">New User Verified & Awaiting Approval</h2>
                    <p style="color: #cbd5e1; font-size: 14px;">A new user has just completed real-time OTP verification:</p>
                    <table style="width: 100%; font-size: 13px; color: #f8fafc; border-collapse: collapse; margin: 16px 0;">
                        <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">Username:</td><td style="font-weight: bold;">{username}</td></tr>
                        <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">Email:</td><td style="font-weight: bold;">{email}</td></tr>
                        <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">Phone:</td><td style="font-weight: bold;">{phone}</td></tr>
                        <tr><td style="padding: 8px 0; color: #94a3b8;">Status:</td><td style="color: #fbbf24; font-weight: bold;">PENDING APPROVAL</td></tr>
                    </table>
                    <p style="font-size: 13px; color: #94a3b8;">Please sign in to the Admin Control Center to approve or reject this account.</p>
                </div>
            </body>
            </html>
            """
            msg.attach(MIMEText(alert_message, "plain"))
            msg.attach(MIMEText(admin_html, "html"))

            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port, timeout=12) as server:
                server.starttls(context=context)
                server.login(smtp_user, clean_pass)
                server.sendmail(smtp_user, admin_email, msg.as_string())

            print(f" [+] Real Email Alert sent to Admin ({admin_email})")
        except Exception as e:
            print(f" [!] Could not deliver live email to admin: {e}")

    # 2. If Fast2SMS configured, send real SMS to Admin Phone
    fast2sms_key = get_config('FAST2SMS_API_KEY')
    if fast2sms_key:
        try:
            clean_admin_phone = admin_phone.strip().replace(' ', '').replace('-', '')[-10:]
            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {"authorization": fast2sms_key}
            payload = {
                "message": alert_message,
                "language": "english",
                "route": "q",
                "numbers": clean_admin_phone
            }
            requests.post(url, data=payload, headers=headers, timeout=10)
            print(f" [+] Real SMS Alert sent to Admin Phone ({clean_admin_phone}) via Fast2SMS")
        except Exception as e:
            print(f" [!] Could not deliver live SMS to admin phone: {e}")

    # If Twilio configured, send real SMS
    twilio_sid = get_config('TWILIO_ACCOUNT_SID')
    twilio_auth = get_config('TWILIO_AUTH_TOKEN')
    twilio_from = get_config('TWILIO_PHONE_NUMBER')
    if twilio_sid and twilio_auth and twilio_from:
        try:
            e164_admin = admin_phone if admin_phone.startswith('+') else f"+91{admin_phone}"
            url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            requests.post(
                url,
                data={'To': e164_admin, 'From': twilio_from, 'Body': alert_message},
                auth=(twilio_sid, twilio_auth),
                timeout=10
            )
            print(f" [+] Real SMS Alert sent to Admin Phone ({e164_admin}) via Twilio")
        except Exception as e:
            print(f" [!] Could not deliver live Twilio SMS to admin phone: {e}")

    return True

# ----------------- Live Gateway Test Utilities -----------------

def test_live_email_connection(target_email):
    """Send a live test verification email to confirm Gmail SMTP credentials."""
    test_otp = generate_otp(6)
    return send_email_otp(target_email, test_otp, "Administrator (Test)")

def test_live_sms_connection(target_phone):
    """Send a live test SMS to confirm SMS Gateway credentials."""
    test_otp = generate_otp(6)
    return send_sms_otp(target_phone, test_otp)

# ----------------- Internal Terminal Logger -----------------

def _log_terminal_otp(channel, target, otp_code):
    print("\n" + "#" * 60)
    print(f" [REAL-TIME {channel} OTP DISPATCH]")
    print(f" Destination : {target}")
    print(f" 6-Digit OTP : >>> {otp_code} <<<")
    print(f" Timestamp   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(" Valid for 10 minutes.")
    print("#" * 60 + "\n")
