#!/usr/bin/env python3
"""
Manual ByteGuardX Setup - No problematic imports
Configure Gmail, database, and security manually
"""

import os
import sqlite3
import secrets
import getpass
import smtplib
from email.mime.text import MIMEText
from pathlib import Path

def print_banner():
    print("🛡️" + "=" * 60)
    print("    ByteGuardX Manual Setup")
    print("    Configure Gmail & Database")
    print("=" * 62)
    print()

def setup_gmail():
    """Setup Gmail configuration"""
    print("📧 Gmail Configuration")
    print("-" * 30)
    print("You need:")
    print("1. Gmail account with 2FA enabled")
    print("2. App-specific password (16 characters)")
    print()
    print("To get app password:")
    print("1. Go to https://myaccount.google.com/security")
    print("2. Enable 2-Factor Authentication")
    print("3. Go to 'App passwords'")
    print("4. Generate password for 'Mail'")
    print()
    
    gmail = input("Enter your Gmail address: ").strip()
    if not gmail or '@gmail.com' not in gmail:
        print("❌ Invalid Gmail address")
        return None
    
    password = getpass.getpass("Enter Gmail app password: ").strip()
    if len(password) < 16:
        print("❌ App password should be 16 characters")
        return None
    
    return gmail, password

def test_gmail(gmail, password):
    """Test Gmail configuration"""
    print("📧 Testing Gmail connection...")
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail, password)
        
        # Send test email
        msg = MIMEText("ByteGuardX setup test - Gmail working!")
        msg['Subject'] = "ByteGuardX Test"
        msg['From'] = gmail
        msg['To'] = gmail
        
        server.send_message(msg)
        server.quit()
        
        print("✅ Gmail test successful!")
        return True
    except Exception as e:
        print(f"❌ Gmail test failed: {e}")
        return False

def create_database():
    """Create SQLite database"""
    print("🗄️ Creating database...")
    
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
            email_verified BOOLEAN DEFAULT 0,
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
    
    conn.commit()
    conn.close()
    
    print("✅ Database created successfully!")

def create_admin_user():
    """Create admin user"""
    print("👤 Creating admin user...")
    
    email = input("Admin email: ").strip()
    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password: ").strip()
    
    if not all([email, username, password]):
        print("❌ All fields required")
        return None
    
    # Simple password hashing (for demo - use proper hashing in production)
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = sqlite3.connect('byteguardx.db')
    cursor = conn.cursor()
    
    user_id = secrets.token_urlsafe(16)
    
    try:
        cursor.execute('''
            INSERT INTO users (id, email, username, password_hash, role, is_active, email_verified)
            VALUES (?, ?, ?, ?, 'admin', 1, 1)
        ''', (user_id, email, username, password_hash))
        
        conn.commit()
        print(f"✅ Admin user created: {username}")
        return email, username
    except sqlite3.IntegrityError:
        print("❌ User already exists")
        return None
    finally:
        conn.close()

def update_env_file(gmail, password, admin_email):
    """Update .env file"""
    print("⚙️ Updating configuration...")
    
    # Generate secure keys
    secret_key = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    
    # Read current .env
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path, 'r') as f:
            content = f.read()
    else:
        content = ""
    
    # Update values
    updates = {
        'SECRET_KEY': secret_key,
        'JWT_SECRET_KEY': jwt_secret,
        'MAIL_USERNAME': gmail,
        'MAIL_PASSWORD': password,
        'MAIL_DEFAULT_SENDER': gmail,
        'MAIL_ADMIN': admin_email,
        'DATABASE_URL': 'sqlite:///byteguardx.db',
        'ENABLE_EMAIL_NOTIFICATIONS': 'true'
    }
    
    for key, value in updates.items():
        if f"{key}=" in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = f"{key}={value}"
                    break
            content = '\n'.join(lines)
        else:
            content += f"\n{key}={value}"
    
    with open(env_path, 'w') as f:
        f.write(content)
    
    print("✅ Configuration updated!")

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    dirs = ['logs', 'reports', 'backups', 'data']
    for directory in dirs:
        Path(directory).mkdir(exist_ok=True)
    
    print("✅ Directories created!")

def main():
    """Main setup function"""
    print_banner()
    
    # Gmail setup
    gmail_config = setup_gmail()
    if not gmail_config:
        print("❌ Gmail setup failed")
        return
    
    gmail, password = gmail_config
    
    # Test Gmail
    if not test_gmail(gmail, password):
        print("❌ Gmail test failed")
        return
    
    # Create database
    create_database()
    
    # Create admin user
    admin_config = create_admin_user()
    if not admin_config:
        print("❌ Admin user creation failed")
        return
    
    admin_email, admin_username = admin_config
    
    # Create directories
    create_directories()
    
    # Update .env file
    update_env_file(gmail, password, admin_email)
    
    print("\n🎉 Setup Complete!")
    print("=" * 30)
    print(f"✅ Gmail: {gmail}")
    print(f"✅ Admin: {admin_username} ({admin_email})")
    print(f"✅ Database: byteguardx.db")
    print(f"✅ Configuration: .env")
    
    print("\n🚀 Next Steps:")
    print("1. Start backend: python byteguardx_auth_api_server.py")
    print("2. Start frontend: npm run dev")
    print("3. Open http://localhost:3000")
    print("4. Login with your admin credentials")
    
    print("\n📧 Email notifications are ready!")
    print("🔐 Real authentication is configured!")

if __name__ == "__main__":
    main()
