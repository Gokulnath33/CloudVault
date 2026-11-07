# 🌐 CloudVault - Secure Multi-User File Storage & Management Portal
### Powered by MongoDB with Real-Time OTP Verification (Gmail & Phone SMS)

> **Yes, it is 100% possible!** This project provides a complete, modern web application where each user gets an **isolated private storage vault** to store, view, and download all their files. It features **MongoDB (MongoDB Compass & MongoDB Atlas)** for database persistence, **Real-Time OTP Verification** via **Gmail** or **Mobile Phone SMS**, **instant SMS notification to the Administrator's Phone**, an **Admin Approval Queue**, and universal support for all file formats.

---

## 📱 Real-Time OTP Verification & Admin Phone Alerts

### 1. User Registration Flow with OTP
1. **User enters details**: Username, Email (Gmail), Mobile Phone Number, and Password.
2. **Delivery Channel Choice**:
   - 📧 **Send OTP to Gmail / Email**
   - 📱 **Send OTP to Phone (SMS)**
3. **Real-Time 6-Digit OTP Dispatch**:
   - Cryptographically secure 6-digit OTP generated (`otp_service.py`).
   - Dispatched immediately via Gmail SMTP or SMS Gateway.
   - Saved in MongoDB `otp_verifications` collection with a 10-minute expiration countdown.
4. **Interactive Verification Screen (`/verify-otp`)**:
   - 6 individual numeric auto-focus digit boxes.
   - 60-second resend countdown timer.
   - 1-click option to switch channel (*"Send via SMS instead"* / *"Send via Gmail instead"*).
   - Maximum 5 attempts protection against brute-force attacks.
5. **Real-Time Alert to Administrator's Phone**:
   - As soon as the user validates their OTP, the system triggers an **instant SMS alert to the Admin's Phone Number** (`ADMIN_PHONE`):
     ```text
     [CloudVault Alert] New user verified OTP:
     User: johndoe
     Phone: +91 98765 43210
     Email: john@gmail.com
     Action: Please login to Admin Panel to Approve or Reject.
     ```
   - User account is placed into MongoDB in **`PENDING`** status.
   - Administrator reviews and approves them in the **Admin Control Center**.
   - User can then log in using their **Username**, **Email**, OR **Phone Number**!

---

## ⚙️ Configuration in `.env`

Open the [`.env`](file:///d:/PROJECT%20DETAILS/PROJECTS/FILES%20ACCESS/.env) file to configure live Gmail and SMS:

```env
# 1. MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/cloudvault_db
DB_NAME=cloudvault_db
SECRET_KEY=files-access-secure-token-2026-supersecret

# 2. Administrator Phone (Receives real-time alerts when users verify)
ADMIN_PHONE=+919876543210
ADMIN_EMAIL=admin@vault.local

# 3. Live Gmail SMTP (For real-time emails to users)
GMAIL_USER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password
GMAIL_SMTP_SERVER=smtp.gmail.com
GMAIL_SMTP_PORT=587

# 4. Live SMS Gateway (Twilio or Fast2SMS)
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=
# Or for Fast2SMS:
FAST2SMS_API_KEY=
```

> **Smart Developer Fallback**: If live Gmail or SMS credentials are left blank in `.env`, CloudVault automatically logs the real-time generated OTP code clearly to the server terminal and displays it on the verification screen, allowing immediate testing without delay!

---

## 📁 Support for Every File Format

- 🖼️ **All Image Formats**: `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.svg`, `.bmp`, `.ico`, `.tiff`, `.avif`. Instant browser previews and thumbnails.
- 📝 **All Microsoft Word Documents**: `.doc`, `.docx`, `.dotx`, `.odt`, `.rtf`.
- 📊 **Microsoft PowerPoint Presentations**: `.ppt`, `.pptx`, `.pps`, `.ppsx`, `.potx`, `.odp`.
- 📈 **Spreadsheets**: `.xls`, `.xlsx`, `.xlsm`, `.csv`, `.tsv`, `.ods`.
- 📄 **PDF Documents**: In-browser PDF reader modal and 1-click download.
- 💻 **Code & Text Files**: `.py`, `.js`, `.json`, `.txt`, `.html`, `.css`, `.sql`, `.md`, `.yaml`, etc.
- 🎥 **Media & Archives**: `.mp3`, `.wav`, `.mp4`, `.mov`, `.mkv`, `.zip`, `.rar`, `.7z`, and more.

---

## 🚀 Running the Project

1. **One-Click Launch**: Double-click [`run.bat`](file:///d:/PROJECT%20DETAILS/PROJECTS/FILES%20ACCESS/run.bat) in the project folder.
2. **Or via Terminal**:
   ```powershell
   python app.py
   ```
3. Open your browser at:
   👉 **http://localhost:5000** (or `http://127.0.0.1:5000`)

---

## 🔑 Administrator Credentials

- **Username**: `admin`
- **Password**: `Admin@123`
- **Admin Phone**: Configurable in `.env` (Default: `+919876543210`)

---

## 🧪 Automated Test Suite

A complete test suite is included in `test_app.py` verifying all OTP and Vault scenarios:
```powershell
python test_app.py
```
