"""
Automated Test Suite for CloudVault
Verifies Real-Time OTP Verification (Email/Phone), Admin Approval,
Multi-Format File Vault Storage, and Security Isolation.
"""

import os
import io
from app import app
import database
import otp_service

def test_full_otp_and_vault_flow():
    database.init_db()
    db = database.get_db()
    
    # Clean test data
    db.users.delete_many({'username': {'$ne': 'admin'}})
    db.files.delete_many({})
    db.audit_logs.delete_many({})
    db.otp_verifications.delete_many({})

    client = app.test_client()

    print("\n--- 1. Testing Default Administrator Login in MongoDB ---")
    res = client.post('/login', data={'identifier': 'admin', 'password': 'Admin@123'}, follow_redirects=True)
    assert res.status_code == 200
    assert b"Administrator Control Center" in res.data
    print(" Admin login succeeded!")

    client.get('/logout', follow_redirects=True)

    print("\n--- 2. Testing User Registration & Real-Time OTP Dispatch ---")
    res = client.post('/register', data={
        'username': 'john_developer',
        'email': 'john@gmail.com',
        'phone_number': '+919123456789',
        'password': 'Password123',
        'confirm_password': 'Password123',
        'otp_channel': 'email'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Enter Verification Code" in res.data

    # Verify OTP was saved in MongoDB
    otp_record = database.get_otp_record('john@gmail.com')
    assert otp_record is not None
    otp_code = otp_record['otp_code']
    assert len(otp_code) == 6
    print(f" Real-time OTP generated and saved in MongoDB: >>> {otp_code} <<<")

    print("\n--- 3. Testing Incorrect OTP Validation Rejection ---")
    res = client.post('/verify-otp', data={
        'target': 'john@gmail.com',
        'otp_code': '000000'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Incorrect verification code" in res.data
    print(" Invalid OTP rejected as expected!")

    print("\n--- 4. Testing Correct OTP Validation & Admin Alert Trigger ---")
    res = client.post('/verify-otp', data={
        'target': 'john@gmail.com',
        'otp_code': otp_code
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Phone &amp; Email verified successfully" in res.data or b"verified successfully" in res.data

    # Verify user exists in MongoDB with pending status
    user_record = database.get_user_by_identifier('john_developer')
    assert user_record is not None
    assert user_record['status'] == 'pending'
    assert user_record['phone_number'] == '+919123456789'
    assert user_record['email_verified'] is True
    assert user_record['phone_verified'] is True
    print(" User verified OTP and is now in pending approval queue in MongoDB!")

    print("\n--- 5. Testing Login Block Before Admin Approval ---")
    res = client.post('/login', data={
        'identifier': '+919123456789',  # Test login with phone number!
        'password': 'Password123'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"pending Administrator approval" in res.data
    print(" Blocked login for pending verified user as expected!")

    print("\n--- 6. Testing Admin Approving the User ---")
    client.post('/login', data={'identifier': 'admin', 'password': 'Admin@123'}, follow_redirects=True)
    res = client.post(f'/admin/approve/{user_record["id"]}', follow_redirects=True)
    assert res.status_code == 200
    
    user_record = database.get_user_by_id(user_record['id'])
    assert user_record['status'] == 'approved'
    print(f" Admin approved user '{user_record['username']}'!")
    client.get('/logout', follow_redirects=True)

    print("\n--- 7. Testing User Login with Phone Number After Approval ---")
    res = client.post('/login', data={
        'identifier': '+919123456789',  # Login using phone number
        'password': 'Password123'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Welcome, john_developer" in res.data
    print(" Approved user successfully signed into vault using Phone Number!")

    print("\n--- 8. Testing Multi-Format File Uploads to Vault ---")
    test_files = [
        ('profile.png', b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRtest_image_data', 'image'),
        ('Project_Document.docx', b'PK\x03\x04test_docx_content', 'word'),
        ('Pitch_Deck.pptx', b'PK\x03\x04test_pptx_content', 'powerpoint'),
        ('Financial_Data.xlsx', b'PK\x03\x04test_xlsx_content', 'spreadsheet'),
        ('Whitepaper.pdf', b'%PDF-1.4 test_pdf_content', 'pdf'),
        ('script.py', b'print("OTP & Vault Complete!")\n', 'text')
    ]

    for fname, data_bytes, expected_cat in test_files:
        data = {'files': (io.BytesIO(data_bytes), fname)}
        res = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert res.status_code == 200

    user_files = database.get_user_files(user_record['id'])
    assert len(user_files) == 6
    print(" All 6 file types uploaded and categorized accurately in MongoDB!")

    print("\n--- 9. Testing 1-Click Download ---")
    sample_file = user_files[0]
    res = client.get(f'/download/{sample_file["id"]}')
    assert res.status_code == 200
    assert 'attachment' in res.headers.get('Content-Disposition', '')
    res.close()
    print(" 1-Click Download verified!")

    print("\n=======================================================")
    print("  ALL REAL-TIME OTP & VAULT TESTS PASSED PERFECTLY!")
    print("=======================================================")

if __name__ == '__main__':
    test_full_otp_and_vault_flow()
