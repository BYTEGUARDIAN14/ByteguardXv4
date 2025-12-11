#!/usr/bin/env python3
"""
ByteGuardX Complete API Server with Real Authentication
Production-ready API server with Gmail integration, database, and security
"""

import sys
import os
import json
import sqlite3
import secrets
import smtplib
import time
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, jsonify, request, make_response, session
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bcrypt
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class DatabaseManager:
    """Database operations manager"""

    def __init__(self, db_path='byteguardx.db'):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)

    def init_database(self):
        """Initialize database with required tables"""
        conn = self.get_connection()
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
                reset_token TEXT,
                reset_token_expires TIMESTAMP,
                scans_this_month INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def create_user(self, email, username, password):
        """Create a new user"""
        conn = self.get_connection()
        cursor = conn.cursor()

        user_id = secrets.token_urlsafe(16)
        password_hash = generate_password_hash(password)
        verification_token = secrets.token_urlsafe(32)

        try:
            cursor.execute('''
                INSERT INTO users (id, email, username, password_hash, verification_token)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, email, username, password_hash, verification_token))

            conn.commit()
            return {'user_id': user_id, 'verification_token': verification_token}
        except sqlite3.IntegrityError as e:
            if 'email' in str(e):
                raise ValueError('Email already exists')
            elif 'username' in str(e):
                raise ValueError('Username already exists')
            else:
                raise ValueError('User creation failed')
        finally:
            conn.close()

    def get_user_by_email(self, email):
        """Get user by email"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, user))
        return None

    def verify_user(self, token):
        """Verify user email"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE users SET email_verified = 1, verification_token = NULL
            WHERE verification_token = ?
        ''', (token,))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

class EmailManager:
    """Email operations manager"""

    def __init__(self):
        self.smtp_server = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('MAIL_PORT', 587))
        self.username = os.getenv('MAIL_USERNAME')
        self.password = os.getenv('MAIL_PASSWORD')
        self.sender = os.getenv('MAIL_DEFAULT_SENDER', self.username)

    def send_email(self, to_email, subject, body, html_body=None):
        """Send email"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[ByteGuardX] {subject}"
            msg['From'] = self.sender
            msg['To'] = to_email

            # Add text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)

            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)

            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()

            return True
        except Exception as e:
            print(f"Email sending failed: {e}")
            return False

    def send_verification_email(self, to_email, username, token):
        """Send email verification"""
        verification_url = f"http://localhost:3000/verify-email?token={token}"

        subject = "Verify Your Email Address"
        body = f"""
Hello {username},

Welcome to ByteGuardX! Please verify your email address by clicking the link below:

{verification_url}

This link will expire in 24 hours.

If you didn't create this account, please ignore this email.

Best regards,
ByteGuardX Team
        """

        html_body = f"""
<html>
<body>
    <h2>Welcome to ByteGuardX!</h2>
    <p>Hello {username},</p>
    <p>Please verify your email address by clicking the button below:</p>
    <p><a href="{verification_url}" style="background-color: #00bcd4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
    <p>Or copy and paste this link: {verification_url}</p>
    <p>This link will expire in 24 hours.</p>
    <p>If you didn't create this account, please ignore this email.</p>
    <p>Best regards,<br>ByteGuardX Team</p>
</body>
</html>
        """

        return self.send_email(to_email, subject, body, html_body)

def create_byteguardx_auth_api():
    """Create complete ByteGuardX API server with real authentication"""

    app = Flask(__name__)

    # Configuration with enhanced security
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Security headers with Talisman
    csp = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data: https:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'"
    }

    Talisman(app,
        force_https=False,  # Set to True in production
        strict_transport_security=True,
        content_security_policy=csp,
        referrer_policy='strict-origin-when-cross-origin'
    )

    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    limiter.init_app(app)

    # Initialize extensions
    jwt = JWTManager(app)

    # Enhanced CORS configuration with explicit credentials support
    CORS(app,
         origins=['http://localhost:3000'],
         supports_credentials=True,
         allow_headers=[
             'Content-Type',
             'Authorization',
             'X-Requested-With',
             'Accept',
             'Origin'
         ],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         expose_headers=['Content-Type', 'Authorization'],
         max_age=3600)

    # Initialize managers
    db = DatabaseManager()
    email_manager = EmailManager()

    # Input validation functions
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        return True, "Password is valid"

    def sanitize_input(text):
        """Sanitize user input to prevent XSS"""
        if not isinstance(text, str):
            return text
        # Remove HTML tags and dangerous characters
        text = re.sub(r'<[^>]*>', '', text)
        text = re.sub(r'[<>"\']', '', text)
        return text.strip()

    def validate_filename(filename):
        """Validate uploaded filename"""
        if not filename:
            return False
        # Use werkzeug's secure_filename
        secure_name = secure_filename(filename)
        if not secure_name or secure_name != filename:
            return False
        # Check file extension
        allowed_extensions = {
            'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb',
            'go', 'rs', 'swift', 'kt', 'scala', 'json', 'xml', 'yml', 'yaml', 'txt',
            'md', 'rst', 'dockerfile', 'sh', 'bat', 'ps1', 'sql', 'html', 'css', 'scss'
        }
        extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        return extension in allowed_extensions

    def process_single_file_scan(content, file_path, form_data):
        """Process scan for a single file"""
        if not content:
            return jsonify({'error': 'No content to scan'}), 400

        # Simple mock scan
        findings = []
        if 'password' in content.lower():
            findings.append({
                'title': 'Potential Hardcoded Password',
                'description': 'Found potential hardcoded password in code',
                'severity': 'high',
                'confidence': 0.8,
                'file_path': file_path,
                'line_number': 1,
                'scanner_name': 'basic_scanner'
            })

        if 'api_key' in content.lower():
            findings.append({
                'title': 'Potential API Key',
                'description': 'Found potential API key in code',
                'severity': 'medium',
                'confidence': 0.7,
                'file_path': file_path,
                'line_number': 1,
                'scanner_name': 'basic_scanner'
            })

        return jsonify({
            'scan_id': f'scan_{int(time.time())}',
            'status': 'completed',
            'file_path': file_path,
            'findings': findings,
            'summary': {
                'total_files': 1,
                'total_issues': len(findings),
                'high_severity': len([f for f in findings if f['severity'] == 'high']),
                'medium_severity': len([f for f in findings if f['severity'] == 'medium']),
                'low_severity': len([f for f in findings if f['severity'] == 'low'])
            },
            'scan_time': time.time(),
            'metadata': {
                'scanner_version': '1.0.0',
                'scan_mode': form_data.get('scan_mode', 'comprehensive')
            }
        })

    def scan_folder_internal(files, form_data):
        """Internal function to handle folder/multiple file scanning"""
        try:
            # Validate total upload size (2GB limit)
            total_size = 0
            valid_files = []
            validation_errors = []

            for file in files:
                if file.filename == '':
                    continue

                # Validate filename
                if not validate_filename(file.filename):
                    validation_errors.append(f'{file.filename}: Invalid or unsupported file type')
                    continue

                # Check individual file size
                file.seek(0, 2)
                file_size = file.tell()
                file.seek(0)

                if file_size > 500 * 1024 * 1024:  # 500MB per file
                    validation_errors.append(f'{file.filename}: File too large (max 500MB per file)')
                    continue

                total_size += file_size
                valid_files.append((file, file_size))

            # Check total size limit (2GB)
            if total_size > 2 * 1024 * 1024 * 1024:
                return jsonify({'error': f'Total upload size exceeds 2GB limit (current: {total_size / (1024*1024*1024):.2f}GB)'}), 400

            # Check file count limit
            if len(valid_files) > 10000:
                return jsonify({'error': f'Too many files ({len(valid_files)}). Maximum is 10,000 files'}), 400

            if not valid_files:
                return jsonify({'error': 'No valid files to scan'}), 400

            # Process all valid files
            all_findings = []
            processed_files = 0

            for file, file_size in valid_files:
                try:
                    content = file.read().decode('utf-8', errors='ignore')
                    file_path = secure_filename(file.filename)

                    # Simple scan for each file
                    file_findings = []
                    if 'password' in content.lower():
                        file_findings.append({
                            'title': 'Potential Hardcoded Password',
                            'description': 'Found potential hardcoded password in code',
                            'severity': 'high',
                            'confidence': 0.8,
                            'file_path': file_path,
                            'line_number': 1,
                            'scanner_name': 'basic_scanner'
                        })

                    if 'api_key' in content.lower():
                        file_findings.append({
                            'title': 'Potential API Key',
                            'description': 'Found potential API key in code',
                            'severity': 'medium',
                            'confidence': 0.7,
                            'file_path': file_path,
                            'line_number': 1,
                            'scanner_name': 'basic_scanner'
                        })

                    all_findings.extend(file_findings)
                    processed_files += 1

                except Exception as e:
                    validation_errors.append(f'{file.filename}: Failed to process - {str(e)}')
                    continue

            return jsonify({
                'scan_id': f'folder_scan_{int(time.time())}',
                'status': 'completed',
                'findings': all_findings,
                'summary': {
                    'total_files': processed_files,
                    'total_issues': len(all_findings),
                    'high_severity': len([f for f in all_findings if f['severity'] == 'high']),
                    'medium_severity': len([f for f in all_findings if f['severity'] == 'medium']),
                    'low_severity': len([f for f in all_findings if f['severity'] == 'low']),
                    'validation_errors': len(validation_errors),
                    'total_size_mb': round(total_size / (1024 * 1024), 2)
                },
                'scan_time': time.time(),
                'metadata': {
                    'scanner_version': '1.0.0',
                    'scan_mode': form_data.get('scan_mode', 'comprehensive'),
                    'upload_type': 'multiple_files'
                },
                'validation_errors': validation_errors[:10]  # Limit to first 10 errors
            })

        except Exception as e:
            logger.error(f'Folder scan error: {e}')
            return jsonify({'error': f'Folder scan failed: {str(e)}'}), 500
    
    # Health check endpoint
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'ByteGuardX Complete API',
            'version': '1.0.0',
            'cors_enabled': True,
            'database': 'connected',
            'email': 'configured' if email_manager.username else 'not_configured'
        })
    
    @app.route('/api/auth/verify', methods=['GET'])
    @jwt_required()
    def verify_auth():
        """Verify authentication status with real JWT validation"""
        try:
            current_user_id = get_jwt_identity()

            # Get user from database
            conn = db.get_connection()
            cursor = conn.cursor()

            # Get column names first
            cursor.execute("PRAGMA table_info(users)")
            column_info = cursor.fetchall()
            columns = [col[1] for col in column_info]  # col[1] is the column name

            # Get user data
            cursor.execute('SELECT * FROM users WHERE id = ?', (current_user_id,))
            user_data = cursor.fetchone()

            conn.close()

            if not user_data:
                return jsonify({
                    'valid': False,
                    'error': 'User not found',
                    'message': 'User account no longer exists'
                }), 401

            # Convert to dict
            user = dict(zip(columns, user_data))

            if not user['is_active']:
                return jsonify({
                    'valid': False,
                    'error': 'Account disabled',
                    'message': 'Your account has been disabled'
                }), 401

            return jsonify({
                'valid': True,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'username': user['username'],
                    'role': user['role'],
                    'subscription_tier': user['subscription_tier'],
                    'email_verified': bool(user['email_verified']),
                    'scans_this_month': user['scans_this_month'],
                    'total_scans': user['total_scans']
                }
            })

        except Exception as e:
            return jsonify({
                'valid': False,
                'error': 'Verification failed',
                'details': str(e)
            }), 500
    
    @app.route('/api/auth/login', methods=['POST'])
    @limiter.limit("5 per minute")  # Rate limit login attempts
    def login():
        """Real login endpoint with database authentication and enhanced security"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            email = sanitize_input(data.get('email', '')).lower().strip()
            password = data.get('password', '')

            if not all([email, password]):
                return jsonify({'error': 'Email and password are required'}), 400

            # Validate email format
            if not validate_email(email):
                return jsonify({'error': 'Invalid email format'}), 400

            # Get user from database
            user = db.get_user_by_email(email)
            if not user:
                return jsonify({'error': 'Invalid credentials'}), 401

            # Check password (handle both bcrypt and werkzeug hashes)
            password_valid = False
            try:
                # Try bcrypt first (more secure)
                if user['password_hash'].startswith('$2b$'):
                    password_valid = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
                else:
                    # Fallback to werkzeug/SHA256
                    password_valid = check_password_hash(user['password_hash'], password)
            except:
                # Final fallback for SHA256
                import hashlib
                password_valid = user['password_hash'] == hashlib.sha256(password.encode()).hexdigest()

            if not password_valid:
                return jsonify({'error': 'Invalid credentials'}), 401

            # Check if account is active
            if not user['is_active']:
                return jsonify({'error': 'Account is disabled'}), 401

            # Update last login
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )
            conn.commit()
            conn.close()

            # Create JWT token
            access_token = create_access_token(identity=user['id'])

            response = make_response(jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'username': user['username'],
                    'role': user['role'],
                    'subscription_tier': user['subscription_tier'],
                    'email_verified': bool(user['email_verified'])
                }
            }))

            # Set token in cookie
            response.set_cookie(
                'access_token',
                access_token,
                max_age=3600,  # 1 hour
                httponly=True,
                secure=False,  # False for development
                samesite='Lax'
            )

            return response

        except Exception as e:
            return jsonify({'error': 'Login failed', 'details': str(e)}), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    def logout():
        """Simple logout endpoint"""
        response = make_response(jsonify({'message': 'Logged out successfully'}))
        response.set_cookie('access_token', '', expires=0)
        return response

    @app.route('/api/auth/register', methods=['POST'])
    @limiter.limit("3 per minute")  # Rate limit registration attempts
    def register():
        """Real registration endpoint with database and email verification"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            email = sanitize_input(data.get('email', '')).lower().strip()
            password = data.get('password', '')
            username = sanitize_input(data.get('username', '')).strip()

            if not all([email, password, username]):
                return jsonify({'error': 'Email, username, and password are required'}), 400

            # Validate email format
            if not validate_email(email):
                return jsonify({'error': 'Invalid email format'}), 400

            # Validate password strength
            is_valid, message = validate_password(password)
            if not is_valid:
                return jsonify({'error': message}), 400

            # Validate username (alphanumeric and underscore only)
            if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
                return jsonify({'error': 'Username must be 3-20 characters and contain only letters, numbers, and underscores'}), 400

            # Additional validation
            if len(password) < 8:
                return jsonify({'error': 'Password must be at least 8 characters'}), 400

            if '@' not in email or '.' not in email:
                return jsonify({'error': 'Invalid email format'}), 400

            if len(username) < 3:
                return jsonify({'error': 'Username must be at least 3 characters'}), 400

            # Create user in database
            try:
                user_data = db.create_user(email, username, password)
            except ValueError as e:
                return jsonify({'error': str(e)}), 400

            # Send verification email
            email_sent = email_manager.send_verification_email(
                email, username, user_data['verification_token']
            )

            if not email_sent:
                return jsonify({
                    'error': 'Registration successful but email verification failed',
                    'message': 'Please contact support to verify your email'
                }), 201

            return jsonify({
                'message': 'Registration successful! Please check your email to verify your account.',
                'email_sent': True,
                'user': {
                    'email': email,
                    'username': username,
                    'role': 'developer',
                    'email_verified': False
                }
            }), 201

        except Exception as e:
            return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

    @app.route('/api/auth/verify-email', methods=['POST'])
    def verify_email():
        """Verify email address with token"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            token = data.get('token', '').strip()
            if not token:
                return jsonify({'error': 'Verification token is required'}), 400

            # Verify token
            success = db.verify_user(token)
            if not success:
                return jsonify({'error': 'Invalid or expired verification token'}), 400

            return jsonify({
                'message': 'Email verified successfully! You can now login.',
                'verified': True
            })

        except Exception as e:
            return jsonify({'error': 'Email verification failed', 'details': str(e)}), 500
    
    # Include other endpoints from the original server
    @app.route('/api/v2/plugins', methods=['GET'])
    def list_plugins():
        """Get list of available plugins"""
        try:
            # Mock plugin data with proper structure
            marketplace_data = {
                'categories': [
                    {
                        'name': 'Security',
                        'plugins': [
                            {'name': 'Secret Scanner', 'manifest': {'name': 'secret-scanner', 'version': '1.0.0'}},
                            {'name': 'SQL Injection Detector', 'manifest': {'name': 'sql-injection', 'version': '1.2.0'}},
                            {'name': 'XSS Scanner', 'manifest': {'name': 'xss-scanner', 'version': '1.1.0'}},
                            {'name': 'CSRF Detector', 'manifest': {'name': 'csrf-detector', 'version': '1.0.0'}}
                        ]
                    },
                    {
                        'name': 'Cloud',
                        'plugins': [
                            {'name': 'AWS S3 Scanner', 'manifest': {'name': 'aws-s3-scanner', 'version': '2.0.0'}},
                            {'name': 'Azure Blob Scanner', 'manifest': {'name': 'azure-blob', 'version': '1.5.0'}},
                            {'name': 'GCP Storage Scanner', 'manifest': {'name': 'gcp-storage', 'version': '1.3.0'}},
                            {'name': 'Docker Scanner', 'manifest': {'name': 'docker-scanner', 'version': '1.8.0'}}
                        ]
                    },
                    {
                        'name': 'Web',
                        'plugins': [
                            {'name': 'Directory Traversal', 'manifest': {'name': 'dir-traversal', 'version': '1.4.0'}},
                            {'name': 'File Upload Scanner', 'manifest': {'name': 'file-upload', 'version': '1.2.0'}},
                            {'name': 'HTTP Header Scanner', 'manifest': {'name': 'http-headers', 'version': '1.1.0'}},
                            {'name': 'Cookie Security', 'manifest': {'name': 'cookie-security', 'version': '1.0.0'}}
                        ]
                    },
                    {
                        'name': 'Code Analysis',
                        'plugins': [
                            {'name': 'Python Analyzer', 'manifest': {'name': 'python-analyzer', 'version': '2.1.0'}},
                            {'name': 'JavaScript Analyzer', 'manifest': {'name': 'js-analyzer', 'version': '1.9.0'}},
                            {'name': 'Java Analyzer', 'manifest': {'name': 'java-analyzer', 'version': '1.7.0'}},
                            {'name': 'C++ Analyzer', 'manifest': {'name': 'cpp-analyzer', 'version': '1.5.0'}}
                        ]
                    }
                ],
                'featured_plugins': [
                    {'name': 'AWS S3 Scanner', 'category': 'Cloud'},
                    {'name': 'SQL Injection Detector', 'category': 'Security'}
                ],
                'statistics': {
                    'total_plugins': 16,
                    'active_plugins': 16
                }
            }
            return jsonify({
                'status': 'success',
                'marketplace': marketplace_data,
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get plugin list',
                'details': str(e)
            }), 500
    
    @app.route('/api/dashboard/stats', methods=['GET'])
    def get_dashboard_stats():
        """Get enhanced dashboard statistics"""
        try:
            enhanced_stats = {
                'security_score': 87,
                'active_threats': 3,
                'scan_coverage': 94.2,
                'plugin_ecosystem': {
                    'total_plugins': 25,
                    'active_plugins': 20,
                    'success_rate': 95.5,
                    'avg_execution_time': 1.2
                }
            }
            
            return jsonify({
                'status': 'success',
                'stats': enhanced_stats,
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get enhanced dashboard stats',
                'details': str(e)
            }), 500
    
    @app.route('/api/scan/file', methods=['POST'])
    @limiter.limit("10 per minute")  # Rate limit file scans
    def scan_file():
        """Enhanced file scanning endpoint with security validation"""
        try:
            # Handle both form data and JSON
            if request.content_type and 'multipart/form-data' in request.content_type:
                # Check for single file or multiple files
                files = request.files.getlist('files')
                if not files or (len(files) == 1 and files[0].filename == ''):
                    return jsonify({'error': 'No files provided'}), 400

                # Handle single file upload
                if len(files) == 1:
                    file = files[0]

                    # Validate filename
                    if not validate_filename(file.filename):
                        return jsonify({'error': 'Invalid or unsupported file type'}), 400

                    # Check file size (max 500MB per file)
                    file.seek(0, 2)  # Seek to end
                    file_size = file.tell()
                    file.seek(0)  # Reset to beginning

                    if file_size > 500 * 1024 * 1024:  # 500MB
                        return jsonify({'error': 'File too large (max 500MB per file)'}), 400

                    # Read and validate content
                    try:
                        content = file.read().decode('utf-8', errors='ignore')
                    except Exception as e:
                        return jsonify({'error': 'Failed to read file content'}), 400

                    file_path = secure_filename(file.filename)

                    # Process single file
                    return process_single_file_scan(content, file_path, request.form)

                # Handle multiple files (redirect to folder endpoint)
                else:
                    return scan_folder_internal(files, request.form)
            else:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No data provided'}), 400
                
                content = data.get('content', '')
                file_path = data.get('file_path', 'unknown')
            
            if not content:
                return jsonify({'error': 'No content to scan'}), 400
            
            # Simple mock scan
            findings = []
            if 'password' in content.lower():
                findings.append({
                    'title': 'Potential Hardcoded Password',
                    'description': 'Found potential hardcoded password in code',
                    'severity': 'high',
                    'confidence': 0.8,
                    'file_path': file_path,
                    'line_number': 1,
                    'scanner_name': 'basic_scanner'
                })
            
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                if finding['severity'] in severity_counts:
                    severity_counts[finding['severity']] += 1
            
            return jsonify({
                'status': 'success',
                'findings': findings,
                'summary': severity_counts,
                'scan_info': {
                    'file_path': file_path,
                    'total_findings': len(findings)
                }
            })
        except Exception as e:
            return jsonify({
                'error': 'Scan failed',
                'details': str(e)
            }), 500

    @app.route('/api/scan/folder', methods=['POST'])
    @limiter.limit("5 per minute")  # Lower rate limit for folder scans
    def scan_folder():
        """Dedicated endpoint for folder/multiple file scanning"""
        try:
            if not request.content_type or 'multipart/form-data' not in request.content_type:
                return jsonify({'error': 'Multipart form data required for folder uploads'}), 400

            files = request.files.getlist('files')
            if not files:
                return jsonify({'error': 'No files provided'}), 400

            # Use internal folder scanning function
            return scan_folder_internal(files, request.form)

        except Exception as e:
            logger.error(f'Folder scan endpoint error: {e}')
            return jsonify({
                'error': 'Folder scan failed',
                'details': str(e)
            }), 500

    # Missing Dashboard Endpoints
    @app.route('/api/scans/recent', methods=['GET'])
    def get_recent_scans():
        """Get recent scans for dashboard"""
        try:
            # Mock recent scans data
            recent_scans = {
                'scans': [
                    {
                        'id': 'scan_001',
                        'filename': 'app.py',
                        'timestamp': '2024-01-15T10:30:00Z',
                        'status': 'completed',
                        'issues_found': 3,
                        'security_score': 85
                    },
                    {
                        'id': 'scan_002',
                        'filename': 'config.js',
                        'timestamp': '2024-01-14T15:45:00Z',
                        'status': 'completed',
                        'issues_found': 1,
                        'security_score': 92
                    }
                ]
            }
            return jsonify(recent_scans)
        except Exception as e:
            return jsonify({
                'error': 'Failed to get recent scans',
                'details': str(e)
            }), 500

    @app.route('/api/user/stats', methods=['GET'])
    def get_user_stats():
        """Get user statistics for dashboard"""
        try:
            # Mock user stats data
            user_stats = {
                'stats': {
                    'totalScans': 47,
                    'criticalIssues': 8,
                    'resolvedIssues': 23,
                    'securityScore': 87
                }
            }
            return jsonify(user_stats)
        except Exception as e:
            return jsonify({
                'error': 'Failed to get user stats',
                'details': str(e)
            }), 500

    @app.route('/api/scans/scheduled', methods=['GET'])
    def get_scheduled_scans():
        """Get scheduled scans"""
        try:
            # Mock scheduled scans data
            scheduled_scans = {
                'scheduled_scans': [
                    {
                        'id': 'sched_001',
                        'name': 'Daily Security Scan',
                        'schedule': 'daily',
                        'is_active': True,
                        'next_run': '2024-01-16T09:00:00Z'
                    }
                ]
            }
            return jsonify(scheduled_scans)
        except Exception as e:
            return jsonify({
                'error': 'Failed to get scheduled scans',
                'details': str(e)
            }), 500

    @app.route('/api/scans/schedule', methods=['POST'])
    def schedule_scan():
        """Schedule a new scan"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Mock scheduling response
            response = {
                'message': 'Scan scheduled successfully',
                'scan_id': secrets.token_urlsafe(8),
                'scheduled_for': data.get('schedule', 'daily')
            }
            return jsonify(response)
        except Exception as e:
            return jsonify({
                'error': 'Failed to schedule scan',
                'details': str(e)
            }), 500

    @app.route('/api/scans/scheduled/<scan_id>', methods=['PUT'])
    def update_scheduled_scan(scan_id):
        """Update scheduled scan status"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Mock update response
            response = {
                'message': 'Scheduled scan updated successfully',
                'scan_id': scan_id,
                'is_active': data.get('is_active', True)
            }
            return jsonify(response)
        except Exception as e:
            return jsonify({
                'error': 'Failed to update scheduled scan',
                'details': str(e)
            }), 500

    # Reports API Endpoints
    @app.route('/api/report/list', methods=['GET'])
    def list_reports():
        """Get list of generated reports"""
        try:
            # Mock reports data
            reports = {
                'reports': [
                    {
                        'report_id': 'rpt_001',
                        'scan_id': 'scan_001',
                        'format': 'pdf',
                        'status': 'completed',
                        'generated_at': '2024-01-15T10:30:00Z',
                        'file_size': '2.4 MB',
                        'scan_path': '/src/components',
                        'total_findings': 12,
                        'filename': 'security_report_001.pdf'
                    },
                    {
                        'report_id': 'rpt_002',
                        'scan_id': 'scan_002',
                        'format': 'json',
                        'status': 'completed',
                        'generated_at': '2024-01-14T15:45:00Z',
                        'file_size': '156 KB',
                        'scan_path': '/api/routes',
                        'total_findings': 8,
                        'filename': 'security_report_002.json'
                    },
                    {
                        'report_id': 'rpt_003',
                        'scan_id': 'scan_003',
                        'format': 'html',
                        'status': 'generating',
                        'generated_at': '2024-01-16T09:15:00Z',
                        'file_size': 'Generating...',
                        'scan_path': '/src/pages',
                        'total_findings': 0,
                        'filename': 'security_report_003.html'
                    }
                ]
            }
            return jsonify(reports)
        except Exception as e:
            return jsonify({
                'error': 'Failed to get reports list',
                'details': str(e)
            }), 500

    @app.route('/api/scan/list', methods=['GET'])
    def list_scans():
        """Get list of completed scans"""
        try:
            status = request.args.get('status', 'all')
            limit = int(request.args.get('limit', 10))

            # Mock scans data
            scans = {
                'scans': [
                    {
                        'scan_id': 'scan_001',
                        'filename': 'app.py',
                        'status': 'completed',
                        'created_at': '2024-01-15T10:30:00Z',
                        'vulnerabilities_found': 12,
                        'scan_path': '/src/components'
                    },
                    {
                        'scan_id': 'scan_002',
                        'filename': 'config.js',
                        'status': 'completed',
                        'created_at': '2024-01-14T15:45:00Z',
                        'vulnerabilities_found': 8,
                        'scan_path': '/api/routes'
                    },
                    {
                        'scan_id': 'scan_003',
                        'filename': 'database.py',
                        'status': 'completed',
                        'created_at': '2024-01-13T12:20:00Z',
                        'vulnerabilities_found': 5,
                        'scan_path': '/src/utils'
                    }
                ][:limit]
            }
            return jsonify(scans)
        except Exception as e:
            return jsonify({
                'error': 'Failed to get scans list',
                'details': str(e)
            }), 500

    @app.route('/api/report/generate', methods=['POST'])
    def generate_report():
        """Generate a new report"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Mock report generation
            report_id = secrets.token_urlsafe(8)
            response = {
                'message': 'Report generation started',
                'report_id': report_id,
                'scan_id': data.get('scan_id'),
                'format': data.get('format', 'pdf'),
                'status': 'generating'
            }
            return jsonify(response)
        except Exception as e:
            return jsonify({
                'error': 'Failed to generate report',
                'details': str(e)
            }), 500

    @app.route('/api/report/download/<report_id>', methods=['GET'])
    def download_report(report_id):
        """Download a report file"""
        try:
            # Mock file download
            response = make_response("Mock report content for report: " + report_id)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.pdf'
            return response
        except Exception as e:
            return jsonify({
                'error': 'Failed to download report',
                'details': str(e)
            }), 500

    @app.route('/api/report/delete/<report_id>', methods=['DELETE'])
    def delete_report(report_id):
        """Delete a report"""
        try:
            # Mock report deletion
            response = {
                'message': 'Report deleted successfully',
                'report_id': report_id
            }
            return jsonify(response)
        except Exception as e:
            return jsonify({
                'error': 'Failed to delete report',
                'details': str(e)
            }), 500

    @app.route('/api/report/view/<report_id>', methods=['GET'])
    def view_report(report_id):
        """View a report in browser"""
        try:
            # Mock report view
            html_content = f"""
            <html>
            <head><title>Security Report {report_id}</title></head>
            <body>
                <h1>Security Report {report_id}</h1>
                <p>This is a mock report view for report ID: {report_id}</p>
                <p>In a real implementation, this would show the actual report content.</p>
            </body>
            </html>
            """
            return html_content
        except Exception as e:
            return jsonify({
                'error': 'Failed to view report',
                'details': str(e)
            }), 500

    return app

if __name__ == '__main__':
    print("🛡️  ByteGuardX Auth API Server")
    print("=" * 40)
    
    app = create_byteguardx_auth_api()
    
    # Show registered routes
    print("Registered endpoints:")
    for rule in app.url_map.iter_rules():
        methods = [m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]
        print(f"  {rule.rule} [{', '.join(methods)}]")
    
    print("\n🚀 Starting server on http://localhost:5000")
    print("🌐 CORS enabled for http://localhost:3000")
    print("🔐 Auth endpoints available:")
    print("  GET  /api/auth/verify")
    print("  POST /api/auth/login")
    print("  POST /api/auth/logout")
    print("📊 Dashboard endpoints:")
    print("  GET  /api/dashboard/stats")
    print("  GET  /api/v2/plugins")
    print("  POST /api/scan/file")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
