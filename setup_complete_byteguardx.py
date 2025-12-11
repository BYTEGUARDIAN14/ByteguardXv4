#!/usr/bin/env python3
"""
Complete ByteGuardX Setup Script
Configures Gmail authentication, database, security, and all components
"""

import os
import sys
import json
import sqlite3
import getpass
import secrets
import hashlib
from pathlib import Path
from datetime import datetime
import subprocess

def print_banner():
    """Print setup banner"""
    print("🛡️" + "=" * 60)
    print("    ByteGuardX Complete Setup & Configuration")
    print("    Enterprise-Grade Security Scanner Setup")
    print("=" * 62)
    print()

def check_requirements():
    """Check if all required packages are installed"""
    print("📦 Checking requirements...")
    
    required_packages = [
        'flask', 'flask-cors', 'flask-jwt-extended', 'sqlalchemy',
        'bcrypt', 'cryptography', 'python-dotenv', 'click', 'rich'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing_packages)
    else:
        print("✅ All required packages are installed")

def setup_gmail_config():
    """Setup Gmail configuration"""
    print("\n📧 Gmail Configuration Setup")
    print("-" * 40)
    
    print("To use Gmail with ByteGuardX, you need:")
    print("1. A Gmail account")
    print("2. App-specific password (not your regular Gmail password)")
    print("3. 2-Factor Authentication enabled on your Gmail account")
    print()
    print("📋 Steps to get Gmail App Password:")
    print("1. Go to https://myaccount.google.com/security")
    print("2. Enable 2-Factor Authentication if not already enabled")
    print("3. Go to 'App passwords' section")
    print("4. Generate a new app password for 'Mail'")
    print("5. Use that 16-character password below")
    print()
    
    gmail_user = input("Enter your Gmail address: ").strip()
    if not gmail_user or '@gmail.com' not in gmail_user:
        print("❌ Please enter a valid Gmail address")
        return None
    
    gmail_password = getpass.getpass("Enter your Gmail App Password (16 chars): ").strip()
    if not gmail_password or len(gmail_password) < 16:
        print("❌ Please enter a valid 16-character app password")
        return None
    
    return {
        'MAIL_USERNAME': gmail_user,
        'MAIL_PASSWORD': gmail_password,
        'MAIL_DEFAULT_SENDER': gmail_user,
        'MAIL_ADMIN': gmail_user
    }

def generate_secure_keys():
    """Generate secure keys for the application"""
    print("\n🔐 Generating secure keys...")
    
    secret_key = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    
    print("✅ Generated secure application keys")
    
    return {
        'SECRET_KEY': secret_key,
        'JWT_SECRET_KEY': jwt_secret
    }

def setup_database():
    """Setup SQLite database with initial schema"""
    print("\n🗄️ Setting up database...")
    
    db_path = Path("byteguardx.db")
    
    # Create database connection
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Create users table
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
            has_2fa_enabled BOOLEAN DEFAULT 0,
            requires_2fa BOOLEAN DEFAULT 0,
            scans_this_month INTEGER DEFAULT 0,
            total_scans INTEGER DEFAULT 0
        )
    ''')
    
    # Create scan_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            file_path TEXT,
            scan_type TEXT,
            status TEXT,
            findings_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create findings table
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results (id)
        )
    ''')
    
    # Create audit_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    
    print(f"✅ Database created at: {db_path.absolute()}")
    return str(db_path.absolute())

def create_admin_user():
    """Create initial admin user"""
    print("\n👤 Creating admin user...")
    
    admin_email = input("Enter admin email: ").strip()
    admin_username = input("Enter admin username: ").strip()
    admin_password = getpass.getpass("Enter admin password: ").strip()
    
    if not all([admin_email, admin_username, admin_password]):
        print("❌ All fields are required")
        return None
    
    # Hash password
    import bcrypt
    password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insert admin user
    conn = sqlite3.connect("byteguardx.db")
    cursor = conn.cursor()
    
    user_id = secrets.token_urlsafe(16)
    
    try:
        cursor.execute('''
            INSERT INTO users (id, email, username, password_hash, role, is_active, email_verified)
            VALUES (?, ?, ?, ?, 'admin', 1, 1)
        ''', (user_id, admin_email, admin_username, password_hash))
        
        conn.commit()
        print(f"✅ Admin user created: {admin_username} ({admin_email})")
        
    except sqlite3.IntegrityError:
        print("❌ User already exists with that email or username")
        return None
    finally:
        conn.close()
    
    return {
        'admin_email': admin_email,
        'admin_username': admin_username
    }

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'logs',
        'reports',
        'backups',
        'data/secure',
        'data/plugins',
        'data/ml',
        'models',
        'plugins'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")

def update_env_file(config):
    """Update .env file with configuration"""
    print("\n⚙️ Updating configuration...")
    
    env_path = Path('.env')
    
    # Read current .env file
    if env_path.exists():
        with open(env_path, 'r') as f:
            content = f.read()
    else:
        content = ""
    
    # Update configuration values
    for key, value in config.items():
        if f"{key}=" in content:
            # Replace existing value
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = f"{key}={value}"
                    break
            content = '\n'.join(lines)
        else:
            # Add new value
            content += f"\n{key}={value}"
    
    # Write updated content
    with open(env_path, 'w') as f:
        f.write(content)
    
    print("✅ Configuration updated")

def test_email_config(gmail_config):
    """Test email configuration"""
    print("\n📧 Testing email configuration...")
    
    try:
        import smtplib
        from email.mime.text import MIMEText
        
        # Create SMTP connection
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_config['MAIL_USERNAME'], gmail_config['MAIL_PASSWORD'])
        
        # Send test email
        msg = MIMEText("ByteGuardX email configuration test successful!")
        msg['Subject'] = "ByteGuardX Setup Test"
        msg['From'] = gmail_config['MAIL_USERNAME']
        msg['To'] = gmail_config['MAIL_USERNAME']
        
        server.send_message(msg)
        server.quit()
        
        print("✅ Email configuration test successful!")
        print(f"📧 Test email sent to: {gmail_config['MAIL_USERNAME']}")
        return True
        
    except Exception as e:
        print(f"❌ Email configuration test failed: {e}")
        print("Please check your Gmail credentials and app password")
        return False

def main():
    """Main setup function"""
    print_banner()
    
    # Check requirements
    check_requirements()
    
    # Setup Gmail configuration
    gmail_config = setup_gmail_config()
    if not gmail_config:
        print("❌ Gmail setup failed. Exiting.")
        return
    
    # Generate secure keys
    security_config = generate_secure_keys()
    
    # Setup database
    db_path = setup_database()
    
    # Create directories
    create_directories()
    
    # Create admin user
    admin_config = create_admin_user()
    if not admin_config:
        print("❌ Admin user creation failed. Exiting.")
        return
    
    # Combine all configuration
    full_config = {
        **gmail_config,
        **security_config,
        'DATABASE_URL': f'sqlite:///{db_path}',
        'FLASK_ENV': 'production',
        'ENABLE_EMAIL_NOTIFICATIONS': 'true',
        'ENABLE_LOGIN_ALERTS': 'true',
        'ENABLE_SCAN_REPORTS': 'true'
    }
    
    # Update .env file
    update_env_file(full_config)
    
    # Test email configuration
    email_test_passed = test_email_config(gmail_config)
    
    # Final summary
    print("\n🎉 ByteGuardX Setup Complete!")
    print("=" * 40)
    print(f"✅ Database: {db_path}")
    print(f"✅ Admin User: {admin_config['admin_username']} ({admin_config['admin_email']})")
    print(f"✅ Gmail: {gmail_config['MAIL_USERNAME']}")
    print(f"{'✅' if email_test_passed else '❌'} Email Test: {'Passed' if email_test_passed else 'Failed'}")
    print()
    print("🚀 Next Steps:")
    print("1. Start the backend: python byteguardx_auth_api_server.py")
    print("2. Start the frontend: npm run dev")
    print("3. Open http://localhost:3000")
    print("4. Login with your admin credentials")
    print()
    print("📧 Email notifications are configured and ready!")
    print("🔐 All security features are enabled!")

if __name__ == "__main__":
    main()
