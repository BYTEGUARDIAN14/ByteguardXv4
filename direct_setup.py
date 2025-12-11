#!/usr/bin/env python3
"""
Direct ByteGuardX Setup with User Credentials
"""

import os
import sqlite3
import secrets
import hashlib
from pathlib import Path

def setup_byteguardx():
    """Setup ByteGuardX with provided credentials"""
    print("🛡️ ByteGuardX Direct Setup")
    print("=" * 40)
    
    # User credentials
    gmail = "jmmunnerahmed@gmail.com"
    gmail_password = "Aduu1410@8190022160"  # Note: This should be App Password
    admin_email = "jmmunnerahmed@gmail.com"
    admin_username = "BYTEGUARDIAN"
    admin_password = "Aduu1410@8190022160"
    
    print(f"📧 Gmail: {gmail}")
    print(f"👤 Admin: {admin_username} ({admin_email})")
    
    # Generate secure keys
    print("\n🔐 Generating secure keys...")
    secret_key = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    print("✅ Secure keys generated")
    
    # Create database
    print("\n🗄️ Creating database...")
    conn = sqlite3.connect('byteguardx.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'developer',
            subscription_tier TEXT DEFAULT 'free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            email_verified BOOLEAN DEFAULT 1,
            verification_token TEXT,
            scans_this_month INTEGER DEFAULT 0,
            total_scans INTEGER DEFAULT 0
        )
    ''')
    
    # Scan results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            file_path TEXT,
            scan_type TEXT,
            status TEXT,
            findings_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Findings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_result_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            confidence REAL,
            file_path TEXT,
            line_number INTEGER,
            scanner_name TEXT,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results (id)
        )
    ''')
    
    print("✅ Database schema created")
    
    # Create admin user
    print("\n👤 Creating admin user...")
    user_id = secrets.token_urlsafe(16)
    
    # Use bcrypt for password hashing (more secure than SHA256)
    try:
        import bcrypt
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except ImportError:
        # Fallback to SHA256 if bcrypt not available
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
    
    try:
        cursor.execute('''
            INSERT INTO users (id, email, username, password_hash, role, is_active, email_verified)
            VALUES (?, ?, ?, ?, 'admin', 1, 1)
        ''', (user_id, admin_email, admin_username, password_hash))
        
        conn.commit()
        print(f"✅ Admin user created: {admin_username}")
    except sqlite3.IntegrityError:
        print("⚠️ Admin user already exists")
    
    conn.close()
    
    # Create directories
    print("\n📁 Creating directories...")
    dirs = ['logs', 'reports', 'backups', 'data', 'data/secure']
    for directory in dirs:
        Path(directory).mkdir(parents=True, exist_ok=True)
    print("✅ Directories created")
    
    # Update .env file
    print("\n⚙️ Updating configuration...")
    env_content = f"""# ByteGuardX Production Configuration
# Generated automatically - DO NOT SHARE

# Core Application
FLASK_ENV=production
FLASK_DEBUG=false
SECRET_KEY={secret_key}
JWT_SECRET_KEY={jwt_secret}

# Database
DATABASE_URL=sqlite:///byteguardx.db

# Gmail Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USE_SSL=false
MAIL_USERNAME={gmail}
MAIL_PASSWORD={gmail_password}
MAIL_DEFAULT_SENDER={gmail}
MAIL_ADMIN={admin_email}

# Email Settings
MAIL_SUBJECT_PREFIX=[ByteGuardX]
ENABLE_EMAIL_NOTIFICATIONS=true
ENABLE_LOGIN_ALERTS=true
ENABLE_SCAN_REPORTS=true

# JWT Settings
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=2592000
JWT_ALGORITHM=HS256

# Security
MIN_PASSWORD_LENGTH=8
REQUIRE_UPPERCASE=true
REQUIRE_LOWERCASE=true
REQUIRE_NUMBERS=true
REQUIRE_SPECIAL_CHARS=true

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
CORS_SUPPORTS_CREDENTIALS=true

# Scanning
MAX_FILE_SIZE=5242880
MAX_FILES_PER_SCAN=100
SCAN_TIMEOUT=300
ENABLE_AI_SCANNING=true

# Development
HOST=0.0.0.0
PORT=5000
VITE_API_URL=http://localhost:5000
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ Configuration file updated")
    
    print("\n🎉 Setup Complete!")
    print("=" * 30)
    print(f"✅ Gmail: {gmail}")
    print(f"✅ Admin: {admin_username} ({admin_email})")
    print(f"✅ Database: byteguardx.db")
    print(f"✅ Config: .env")
    
    print("\n⚠️ IMPORTANT NOTES:")
    print("1. Your Gmail password should be an App-Specific Password")
    print("2. Enable 2FA on your Gmail account")
    print("3. Generate App Password at: https://myaccount.google.com/security")
    
    print("\n🚀 Next Steps:")
    print("1. Get Gmail App Password (if not already done)")
    print("2. Update .env file with App Password")
    print("3. Start backend: python byteguardx_auth_api_server.py")
    print("4. Start frontend: npm run dev")
    print("5. Login at http://localhost:3000")
    
    print(f"\n🔑 Login Credentials:")
    print(f"   Username: {admin_username}")
    print(f"   Email: {admin_email}")
    print(f"   Password: {admin_password}")

if __name__ == "__main__":
    setup_byteguardx()
