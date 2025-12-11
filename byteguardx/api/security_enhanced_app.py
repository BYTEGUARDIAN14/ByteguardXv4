"""
Security-Enhanced Flask Application for ByteGuardX
Integrates all new security features: 2FA, rate limiting, audit logging, encryption, etc.
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, send_file, make_response
from flask_cors import CORS
import uuid
import tempfile
import shutil
from pathlib import Path

# ByteGuardX core imports
from ..core.file_processor import FileProcessor
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner
from ..scanners.intelligent_fallback import intelligent_fallback, FallbackReason
from ..ai_suggestions.fix_engine import FixEngine
from ..reports.pdf_report import PDFReportGenerator

# Enhanced security imports
from ..security.enhanced_auth_middleware import (
    enhanced_auth_middleware, enhanced_auth_required, admin_required_enhanced,
    rate_limited, audit_logged
)
from ..security.two_factor_auth import two_factor_auth
from ..security.password_policy import password_validator
from ..security.rate_limiter import rate_limiter, brute_force_protection
from ..security.audit_logger import audit_logger, SecurityEventType, EventSeverity
from ..security.encryption import data_encryption, secure_storage

# Database and monitoring
from ..database.connection_pool import db_manager, init_db
from ..database.models import User, ScanResult, Finding
from ..monitoring.enhanced_health_checker import enhanced_health_checker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_security_enhanced_app(config=None):
    """Create security-enhanced Flask application"""
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production'),
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
        'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB max file size
        'DATABASE_URL': os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db'),
        'ENABLE_2FA': os.environ.get('ENABLE_2FA', 'true').lower() == 'true',
        'ENABLE_AUDIT_LOGGING': os.environ.get('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true',
        'ENABLE_RATE_LIMITING': os.environ.get('ENABLE_RATE_LIMITING', 'true').lower() == 'true',
        'ENABLE_ENCRYPTION': os.environ.get('ENABLE_ENCRYPTION', 'true').lower() == 'true'
    })
    
    if config:
        app.config.update(config)
    
    # Initialize database
    init_db(app.config['DATABASE_URL'])
    
    # Initialize CORS
    # Initialize CORS
    cors_origins = app.config.get('CORS_ORIGINS')
    if not cors_origins:
         cors_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001').split(',')
         
    CORS(app, 
         origins=cors_origins,
         supports_credentials=True,
         max_age=3600)
    
    # Initialize components
    file_processor = FileProcessor()
    secret_scanner = SecretScanner()
    dependency_scanner = DependencyScanner()
    ai_pattern_scanner = AIPatternScanner()
    fix_engine = FixEngine()
    pdf_generator = PDFReportGenerator()
    
    # Start health monitoring
    enhanced_health_checker.start_monitoring()

    # Register new API blueprints
    from .admin_routes import admin_bp
    from .scheduler_routes import scheduler_bp
    from .plugin_routes import plugin_bp
    from .deploy_routes import deploy_bp

    app.register_blueprint(admin_bp)
    app.register_blueprint(scheduler_bp)
    app.register_blueprint(plugin_bp)
    app.register_blueprint(deploy_bp)
    
    # Manual Preflight Handler (Fixes persistent CORS issues)
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            response = make_response()
            origin = request.headers.get('Origin')
            if origin:
                allowed_origins = app.config.get('CORS_ORIGINS')
                if not allowed_origins:
                    allowed_origins = os.environ.get('ALLOWED_ORIGINS', '').split(',')
                
                if origin in allowed_origins:
                    response.headers['Access-Control-Allow-Origin'] = origin
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    response.headers['Access-Control-Allow-Headers'] = "Content-Type,Authorization,X-CSRF-Token,X-Requested-With"
                    response.headers['Access-Control-Allow-Methods'] = "GET,PUT,POST,DELETE,OPTIONS,PATCH"
            return response

    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Manual CORS handling/failsafe
        origin = request.headers.get('Origin')
        if origin:
            allowed_origins = app.config.get('CORS_ORIGINS')
            if not allowed_origins:
                allowed_origins = os.environ.get('ALLOWED_ORIGINS', '').split(',')
            
            if origin in allowed_origins:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.headers['Access-Control-Allow-Headers'] = "Content-Type,Authorization,X-CSRF-Token,X-Requested-With"
                response.headers['Access-Control-Allow-Methods'] = "GET,PUT,POST,DELETE,OPTIONS,PATCH"
        
        return response
    
    # Enhanced health endpoint
    @app.route('/api/health', methods=['GET'])
    @rate_limited(limit=30, window=60, per='ip')
    def enhanced_health_check():
        """Enhanced health check with system monitoring"""
        try:
            health_data = enhanced_health_checker.get_current_health()
            return jsonify(health_data)
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Health check failed',
                'timestamp': datetime.now().isoformat()
            }), 500
    
    @app.route('/api/health/summary', methods=['GET'])
    @enhanced_auth_required()
    def health_summary():
        """Get health summary (requires authentication)"""
        try:
            summary = enhanced_health_checker.get_health_summary()
            return jsonify(summary)
        except Exception as e:
            logger.error(f"Health summary failed: {e}")
            return jsonify({'error': 'Failed to get health summary'}), 500
    
    # Enhanced authentication endpoints
    @app.route('/api/auth/register', methods=['POST'])
    @rate_limited(limit=5, window=3600, per='ip')  # 5 registrations per hour per IP
    def register():
        """Enhanced user registration with comprehensive validation and secure cookies"""
        try:
            data = request.get_json()
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

            if not data:
                return jsonify({'error': 'No data provided'}), 400

            email = data.get('email', '').lower().strip()
            username = data.get('username', '').strip()
            password = data.get('password', '')

            if not all([email, username, password]):
                return jsonify({'error': 'Email, username, and password are required'}), 400

            # Enhanced email validation
            import re
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                return jsonify({'error': 'Invalid email format'}), 400

            if len(email) > 255:
                return jsonify({'error': 'Email too long'}), 400

            # Enhanced username validation
            if not re.match(r'^[a-zA-Z0-9_-]{3,30}$', username):
                return jsonify({'error': 'Username must be 3-30 characters, alphanumeric, underscore, or dash only'}), 400

            # Validate password strength
            user_info = {'email': email, 'username': username}
            is_valid, validation_result = enhanced_auth_middleware.validate_password_strength(
                password, user_info
            )

            if not is_valid:
                return jsonify({
                    'error': 'Password does not meet security requirements',
                    'validation': validation_result
                }), 400

            # Check if user already exists
            with db_manager.get_session() as session:
                existing_user = session.query(User).filter(
                    (User.email == email) | (User.username == username)
                ).first()

                if existing_user:
                    # Log failed registration attempt
                    from ..security.audit_logger import SecurityEvent
                    event = SecurityEvent(
                        event_id=None,
                        event_type=SecurityEventType.USER_CREATED,
                        severity=EventSeverity.MEDIUM,
                        timestamp=datetime.now(),
                        ip_address=client_ip,
                        action="register",
                        result="failure",
                        details={'reason': 'user_already_exists', 'email': email}
                    )
                    audit_logger.log_event(event)

                    if existing_user.email == email:
                        return jsonify({'error': 'Email already registered'}), 409
                    else:
                        return jsonify({'error': 'Username already taken'}), 409

                # Create new user
                new_user = User(
                    email=email,
                    username=username,
                    is_active=True,
                    email_verified=False,
                    created_at=datetime.now()
                )
                new_user.set_password(password)

                session.add(new_user)
                session.commit()

                # Generate JWT tokens
                from ..security.jwt_utils import jwt_manager
                user_data = {
                    'email': new_user.email,
                    'username': new_user.username,
                    'role': new_user.role,
                    'subscription_tier': new_user.subscription_tier
                }

                tokens = jwt_manager.generate_tokens(str(new_user.id), user_data)

                # Log successful registration
                from ..security.audit_logger import SecurityEvent
                event = SecurityEvent(
                    event_id=None,
                    event_type=SecurityEventType.USER_CREATED,
                    severity=EventSeverity.LOW,
                    timestamp=datetime.now(),
                    user_id=str(new_user.id),
                    username=username,
                    ip_address=client_ip,
                    action="register",
                    result="success",
                    details={'email': email}
                )
                audit_logger.log_event(event)

                # Create secure response with HttpOnly cookies
                response = make_response(jsonify({
                    'message': 'User registered successfully',
                    'user': {
                        'id': str(new_user.id),
                        'email': new_user.email,
                        'username': new_user.username,
                        'role': new_user.role,
                        'subscription_tier': new_user.subscription_tier
                    },
                    'requires_email_verification': True
                }), 201)

                # Set secure HTTP-only cookies
                is_production = os.environ.get('FLASK_ENV') == 'production'
                response.set_cookie(
                    'access_token',
                    tokens['access_token'],
                    max_age=3600,  # 1 hour
                    httponly=True,
                    secure=is_production,
                    samesite='Strict'
                )

                response.set_cookie(
                    'refresh_token',
                    tokens['refresh_token'],
                    max_age=604800,  # 7 days
                    httponly=True,
                    secure=is_production,
                    samesite='Strict'
                )

                return response

        except Exception as e:
            logger.error(f"Registration failed: {e}")
            from ..security.audit_logger import SecurityEvent
            event = SecurityEvent(
                event_id=None,
                event_type=SecurityEventType.USER_CREATED,
                severity=EventSeverity.HIGH,
                timestamp=datetime.now(),
                ip_address=client_ip,
                action="register",
                result="error",
                details={'error': str(e), 'email': data.get('email', 'unknown')}
            )
            audit_logger.log_event(event)
            return jsonify({'error': f'Registration failed: {str(e)}'}), 500
    
    @app.route('/api/auth/login', methods=['POST'])
    @rate_limited(limit=5, window=300, per='ip')  # 5 attempts per 5 minutes per IP
    def login():
        """Enhanced login with brute force protection"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            email = data.get('email', '').lower().strip()
            password = data.get('password', '')
            totp_token = data.get('totp_token', '')
            
            if not all([email, password]):
                return jsonify({'error': 'Email and password are required'}), 400
            
            client_ip = request.remote_addr
            
            # Check for brute force attempts
            if brute_force_protection.is_brute_force_detected(client_ip):
                audit_logger.log_login_failure(
                    username=email,
                    ip_address=client_ip,
                    reason="brute_force_protection",
                    user_agent=request.headers.get('User-Agent')
                )
                return jsonify({'error': 'Too many failed attempts. Please try again later.'}), 429
            
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.email == email).first()
                
                if not user or not user.check_password(password):
                    # Record failed attempt
                    brute_force_protection.record_failed_attempt(client_ip)
                    audit_logger.log_login_failure(
                        username=email,
                        ip_address=client_ip,
                        reason="invalid_credentials",
                        user_agent=request.headers.get('User-Agent')
                    )
                    return jsonify({'error': 'Invalid credentials'}), 401
                
                if not user.is_active:
                    audit_logger.log_login_failure(
                        username=email,
                        ip_address=client_ip,
                        reason="account_deactivated",
                        user_agent=request.headers.get('User-Agent')
                    )
                    return jsonify({'error': 'Account is deactivated'}), 401
                
                # Check 2FA if enabled
                if app.config['ENABLE_2FA'] and two_factor_auth.is_2fa_enabled(str(user.id)):
                    if not totp_token:
                        return jsonify({
                            'error': 'Two-factor authentication required',
                            'requires_2fa': True
                        }), 401
                    
                    if not two_factor_auth.verify_2fa(str(user.id), totp_token):
                        audit_logger.log_2fa_event(
                            event_type=SecurityEventType.TWO_FA_FAILURE,
                            user_id=str(user.id),
                            username=user.username,
                            ip_address=client_ip,
                            success=False
                        )
                        return jsonify({'error': 'Invalid 2FA token'}), 401
                    
                    # Log successful 2FA
                    audit_logger.log_2fa_event(
                        event_type=SecurityEventType.TWO_FA_SUCCESS,
                        user_id=str(user.id),
                        username=user.username,
                        ip_address=client_ip,
                        success=True
                    )
                
                # Clear failed attempts on successful login
                brute_force_protection.record_successful_attempt(client_ip)
                
                # Update last login
                user.last_login = datetime.now()
                session.commit()
                
                # Generate JWT tokens
                from ..security.jwt_utils import jwt_manager
                user_data = {
                    'email': user.email,
                    'username': user.username,
                    'role': user.role,
                    'subscription_tier': user.subscription_tier
                }
                
                tokens = jwt_manager.generate_tokens(str(user.id), user_data)
                
                # Log successful login
                audit_logger.log_login_success(
                    user_id=str(user.id),
                    username=user.username,
                    ip_address=client_ip,
                    user_agent=request.headers.get('User-Agent')
                )
                
                # Create secure response with HttpOnly cookies
                response = make_response(jsonify({
                    'message': 'Login successful',
                    'user': {
                        'id': str(user.id),
                        'email': user.email,
                        'username': user.username,
                        'role': user.role,
                        'subscription_tier': user.subscription_tier,
                        'has_2fa': two_factor_auth.is_2fa_enabled(str(user.id)),
                        'last_login': user.last_login.isoformat() if user.last_login else None
                    }
                }))

                # Set secure HTTP-only cookies
                is_production = os.environ.get('FLASK_ENV') == 'production'
                response.set_cookie(
                    'access_token',
                    tokens['access_token'],
                    max_age=3600,  # 1 hour
                    httponly=True,
                    secure=is_production,
                    samesite='Strict'
                )

                response.set_cookie(
                    'refresh_token',
                    tokens['refresh_token'],
                    max_age=604800,  # 7 days
                    httponly=True,
                    secure=is_production,
                    samesite='Strict'
                )

                return response
                
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return jsonify({'error': 'Login failed'}), 500

    @app.route('/api/auth/logout', methods=['POST'])
    @enhanced_auth_required()
    def logout():
        """Secure logout with token blacklisting and cookie clearing"""
        try:
            user_id = g.user_id
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

            # Get tokens from cookies or headers
            access_token = request.cookies.get('access_token') or request.headers.get('Authorization', '').replace('Bearer ', '')
            refresh_token = request.cookies.get('refresh_token')

            # Blacklist tokens if they exist
            from ..security.jwt_utils import jwt_manager, token_blacklist
            if access_token:
                token_blacklist.blacklist_token(access_token)
            if refresh_token:
                token_blacklist.blacklist_token(refresh_token)

            # Log logout event
            from ..security.audit_logger import SecurityEvent
            event = SecurityEvent(
                event_id=None,
                event_type=SecurityEventType.LOGOUT,
                severity=EventSeverity.LOW,
                timestamp=datetime.now(),
                user_id=user_id,
                username=g.username,
                ip_address=client_ip,
                action="logout",
                result="success",
                details={'logout_method': 'manual'}
            )
            audit_logger.log_event(event)

            # Create response and clear cookies
            response = make_response(jsonify({'message': 'Logged out successfully'}))
            response.set_cookie('access_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
            response.set_cookie('refresh_token', '', expires=0, httponly=True, secure=True, samesite='Strict')

            return response

        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return jsonify({'error': 'Logout failed'}), 500

    @app.route('/api/auth/refresh', methods=['POST'])
    @rate_limited(limit=10, window=300, per='ip')  # 10 refresh attempts per 5 minutes
    def refresh_token():
        """Refresh access token using refresh token from cookie"""
        try:
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

            # Get refresh token from cookie or request body
            refresh_token = request.cookies.get('refresh_token')
            if not refresh_token:
                data = request.get_json()
                refresh_token = data.get('refresh_token') if data else None

            if not refresh_token:
                return jsonify({'error': 'Refresh token required'}), 400

            # Refresh the token
            from ..security.jwt_utils import jwt_manager, token_blacklist
            new_tokens = jwt_manager.refresh_access_token(refresh_token, token_blacklist)

            if not new_tokens:
                # Log failed refresh attempt
                from ..security.audit_logger import SecurityEvent
                event = SecurityEvent(
                    event_id=None,
                    event_type=SecurityEventType.LOGIN_FAILURE,  # Use existing event type
                    severity=EventSeverity.MEDIUM,
                    timestamp=datetime.now(),
                    ip_address=client_ip,
                    action="token_refresh",
                    result="failure",
                    details={'reason': 'invalid_refresh_token'}
                )
                audit_logger.log_event(event)
                return jsonify({'error': 'Invalid or expired refresh token'}), 401

            # Log successful token refresh
            from ..security.audit_logger import SecurityEvent
            event = SecurityEvent(
                event_id=None,
                event_type=SecurityEventType.LOGIN_SUCCESS,  # Use existing event type
                severity=EventSeverity.LOW,
                timestamp=datetime.now(),
                ip_address=client_ip,
                action="token_refresh",
                result="success",
                details={'token_type': 'access_token'}
            )
            audit_logger.log_event(event)

            # Create response with new tokens in cookies
            response = make_response(jsonify({
                'message': 'Token refreshed successfully',
                'expires_in': new_tokens.get('expires_in', 3600)
            }))

            is_production = os.environ.get('FLASK_ENV') == 'production'
            response.set_cookie(
                'access_token',
                new_tokens['access_token'],
                max_age=3600,  # 1 hour
                httponly=True,
                secure=is_production,
                samesite='Strict'
            )

            # Update refresh token if provided
            if 'refresh_token' in new_tokens:
                response.set_cookie(
                    'refresh_token',
                    new_tokens['refresh_token'],
                    max_age=604800,  # 7 days
                    httponly=True,
                    secure=is_production,
                    samesite='Strict'
                )

            return response

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return jsonify({'error': 'Token refresh failed'}), 500

    @app.route('/api/auth/verify', methods=['GET'])
    def verify_token():
        """Verify current authentication status"""
        try:
            # Get token from cookie or header
            access_token = request.cookies.get('access_token') or request.headers.get('Authorization', '').replace('Bearer ', '')

            if not access_token:
                return jsonify({'valid': False, 'error': 'No token provided'}), 401

            # Verify token
            from ..security.jwt_utils import jwt_manager, token_blacklist

            # Check if token is blacklisted
            if token_blacklist.is_blacklisted(access_token):
                return jsonify({'valid': False, 'error': 'Token is blacklisted'}), 401

            try:
                payload = jwt_manager.decode_token(access_token)
                user_id = payload.get('sub')

                # Get fresh user data
                with db_manager.get_session() as session:
                    user = session.query(User).filter(User.id == user_id).first()
                    if not user or not user.is_active:
                        return jsonify({'valid': False, 'error': 'User not found or inactive'}), 401

                    return jsonify({
                        'valid': True,
                        'user': {
                            'id': str(user.id),
                            'email': user.email,
                            'username': user.username,
                            'role': user.role,
                            'subscription_tier': user.subscription_tier,
                            'has_2fa': two_factor_auth.is_2fa_enabled(str(user.id))
                        }
                    })

            except Exception as token_error:
                return jsonify({'valid': False, 'error': 'Invalid token'}), 401

        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return jsonify({'valid': False, 'error': 'Verification failed'}), 500

    @app.route('/api/user/profile', methods=['PUT'])
    @enhanced_auth_required()
    def update_profile():
        """Update user profile information"""
        try:
            data = request.get_json()
            user_id = g.user_id
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

            if not data:
                return jsonify({'error': 'No data provided'}), 400

            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user:
                    return jsonify({'error': 'User not found'}), 404

                # Update allowed fields
                if 'username' in data:
                    # Check if username is already taken
                    existing_user = session.query(User).filter(
                        User.username == data['username'],
                        User.id != user_id
                    ).first()
                    if existing_user:
                        return jsonify({'error': 'Username already taken'}), 409
                    user.username = data['username']

                if 'email' in data:
                    # Check if email is already taken
                    existing_user = session.query(User).filter(
                        User.email == data['email'],
                        User.id != user_id
                    ).first()
                    if existing_user:
                        return jsonify({'error': 'Email already taken'}), 409
                    user.email = data['email']

                if 'first_name' in data:
                    user.first_name = data['first_name']

                if 'last_name' in data:
                    user.last_name = data['last_name']

                user.updated_at = datetime.now()
                session.commit()

                # Log profile update
                from ..security.audit_logger import SecurityEvent
                event = SecurityEvent(
                    event_id=None,
                    event_type=SecurityEventType.USER_MODIFIED,
                    severity=EventSeverity.LOW,
                    timestamp=datetime.now(),
                    user_id=str(user.id),
                    username=user.username,
                    ip_address=client_ip,
                    action="profile_update",
                    result="success",
                    details={'updated_fields': list(data.keys())}
                )
                audit_logger.log_event(event)

                return jsonify({
                    'message': 'Profile updated successfully',
                    'user': {
                        'id': str(user.id),
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'role': user.role,
                        'subscription_tier': user.subscription_tier
                    }
                })

        except Exception as e:
            logger.error(f"Profile update failed: {e}")
            return jsonify({'error': 'Profile update failed'}), 500

    @app.route('/api/auth/change-password', methods=['POST'])
    @enhanced_auth_required()
    def change_password():
        """Change user password"""
        try:
            data = request.get_json()
            user_id = g.user_id
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

            if not data or 'current_password' not in data or 'new_password' not in data:
                return jsonify({'error': 'Current password and new password required'}), 400

            current_password = data['current_password']
            new_password = data['new_password']

            # Validate new password strength
            user_info = {'user_id': user_id}
            is_valid, validation_result = enhanced_auth_middleware.validate_password_strength(
                new_password, user_info
            )

            if not is_valid:
                return jsonify({
                    'error': 'New password does not meet security requirements',
                    'validation': validation_result
                }), 400

            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user:
                    return jsonify({'error': 'User not found'}), 404

                # Verify current password
                if not user.check_password(current_password):
                    # Log failed password change attempt
                    from ..security.audit_logger import SecurityEvent
                    event = SecurityEvent(
                        event_id=None,
                        event_type=SecurityEventType.PASSWORD_CHANGE,
                        severity=EventSeverity.MEDIUM,
                        timestamp=datetime.now(),
                        user_id=str(user.id),
                        username=user.username,
                        ip_address=client_ip,
                        action="password_change",
                        result="failure",
                        details={'reason': 'invalid_current_password'}
                    )
                    audit_logger.log_event(event)
                    return jsonify({'error': 'Current password is incorrect'}), 401

                # Update password
                user.set_password(new_password)
                user.updated_at = datetime.now()
                session.commit()

                # Log successful password change
                from ..security.audit_logger import SecurityEvent
                event = SecurityEvent(
                    event_id=None,
                    event_type=SecurityEventType.PASSWORD_CHANGE,
                    severity=EventSeverity.LOW,
                    timestamp=datetime.now(),
                    user_id=str(user.id),
                    username=user.username,
                    ip_address=client_ip,
                    action="password_change",
                    result="success"
                )
                audit_logger.log_event(event)

                return jsonify({'message': 'Password changed successfully'})

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return jsonify({'error': 'Password change failed'}), 500

    @app.route('/api/auth/2fa/status', methods=['GET'])
    @enhanced_auth_required()
    def get_2fa_status():
        """Get 2FA status for current user"""
        try:
            user_id = g.user_id
            is_enabled = two_factor_auth.is_2fa_enabled(user_id)

            return jsonify({
                'enabled': is_enabled,
                'user_id': user_id
            })

        except Exception as e:
            logger.error(f"2FA status check failed: {e}")
            return jsonify({'error': '2FA status check failed'}), 500

    # 2FA Management Endpoints
    @app.route('/api/auth/2fa/setup', methods=['POST'])
    @enhanced_auth_required()
    def setup_2fa():
        """Setup 2FA for user"""
        try:
            user_id = g.user_id
            
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user:
                    return jsonify({'error': 'User not found'}), 404
                
                # Setup TOTP
                setup_data = two_factor_auth.setup_totp(user_id, user.email)
                
                return jsonify({
                    'message': '2FA setup initiated',
                    'qr_code': setup_data['qr_code'].decode('latin-1'),  # Convert bytes to string
                    'manual_entry_key': setup_data['manual_entry_key'],
                    'backup_codes': setup_data['backup_codes']
                })
                
        except Exception as e:
            logger.error(f"2FA setup failed: {e}")
            return jsonify({'error': '2FA setup failed'}), 500
    
    @app.route('/api/auth/2fa/enable', methods=['POST'])
    @enhanced_auth_required()
    def enable_2fa():
        """Enable 2FA after verification"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            totp_token = data.get('totp_token', '')
            if not totp_token:
                return jsonify({'error': 'TOTP token required'}), 400
            
            user_id = g.user_id
            
            if two_factor_auth.enable_totp(user_id, totp_token):
                # Log 2FA enabled
                audit_logger.log_event(
                    event_type=SecurityEventType.TWO_FA_ENABLED,
                    severity=EventSeverity.MEDIUM,
                    user_id=user_id,
                    username=g.username,
                    ip_address=request.remote_addr
                )
                
                return jsonify({'message': '2FA enabled successfully'})
            else:
                return jsonify({'error': 'Invalid TOTP token'}), 400
                
        except Exception as e:
            logger.error(f"2FA enable failed: {e}")
            return jsonify({'error': '2FA enable failed'}), 500
    
    @app.route('/api/auth/2fa/disable', methods=['POST'])
    @enhanced_auth_required(require_2fa=True)
    def disable_2fa():
        """Disable 2FA (requires 2FA verification)"""
        try:
            user_id = g.user_id
            
            if two_factor_auth.disable_2fa(user_id):
                # Log 2FA disabled
                audit_logger.log_event(
                    event_type=SecurityEventType.TWO_FA_DISABLED,
                    severity=EventSeverity.MEDIUM,
                    user_id=user_id,
                    username=g.username,
                    ip_address=request.remote_addr
                )
                
                return jsonify({'message': '2FA disabled successfully'})
            else:
                return jsonify({'error': 'Failed to disable 2FA'}), 500
                
        except Exception as e:
            logger.error(f"2FA disable failed: {e}")
            return jsonify({'error': '2FA disable failed'}), 500
    
    # Enhanced scanning endpoint with fallback
    @app.route('/api/scan', methods=['POST'])
    @enhanced_auth_required()
    @rate_limited(limit=10, window=300, per='user')  # 10 scans per 5 minutes per user
    @audit_logged(SecurityEventType.SCAN_INITIATED)
    def enhanced_scan():
        """Enhanced scanning with intelligent fallback"""
        try:
            # Handle file upload or direct content
            if 'file' in request.files:
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                # Save uploaded file temporarily
                temp_dir = tempfile.mkdtemp()
                file_path = os.path.join(temp_dir, file.filename)
                file.save(file_path)
                
                try:
                    # Process the file
                    processed_files = file_processor.process_file(file_path)
                    
                    all_findings = []
                    all_fixes = []
                    scan_id = str(uuid.uuid4())
                    
                    for processed_file in processed_files:
                        content = processed_file.get('content', '')
                        file_name = processed_file.get('name', file.filename)
                        
                        # Try AI scanning first
                        try:
                            # Secret scanning
                            secret_findings = secret_scanner.scan_content(content, file_name)
                            all_findings.extend(secret_findings)
                            
                            # Dependency scanning
                            if file_name.endswith(('.json', '.txt', '.yml', '.yaml')):
                                dep_findings = dependency_scanner.scan_content(content, file_name)
                                all_findings.extend(dep_findings)
                            
                            # AI pattern scanning
                            ai_findings = ai_pattern_scanner.scan_content(content, file_name)
                            all_findings.extend(ai_findings)
                            
                        except Exception as ai_error:
                            logger.warning(f"AI scanning failed, using fallback: {ai_error}")
                            
                            # Use intelligent fallback
                            fallback_result = intelligent_fallback.scan_with_fallback(
                                content=content,
                                file_path=file_name,
                                scan_type="comprehensive",
                                fallback_reason=FallbackReason.ML_MODEL_ERROR
                            )
                            
                            all_findings.extend(fallback_result.findings)
                        
                        # Generate fixes
                        if all_findings:
                            fixes = fix_engine.generate_fixes(all_findings, content)
                            all_fixes.extend(fixes)
                    
                    # Store results
                    scan_result = {
                        'scan_id': scan_id,
                        'timestamp': datetime.now().isoformat(),
                        'user_id': g.user_id,
                        'file_name': file.filename,
                        'total_files': len(processed_files),
                        'findings': all_findings,
                        'fixes': all_fixes,
                        'total_findings': len(all_findings),
                        'total_fixes': len(all_fixes)
                    }
                    
                    # Save to database
                    with db_manager.get_session() as session:
                        db_scan_result = ScanResult(
                            id=uuid.UUID(scan_id),
                            user_id=uuid.UUID(g.user_id),
                            file_path=file.filename,
                            scan_type='comprehensive',
                            findings_count=len(all_findings),
                            status='completed',
                            created_at=datetime.now()
                        )
                        session.add(db_scan_result)
                        session.commit()
                    
                    # Log scan completion
                    audit_logger.log_scan_event(
                        event_type=SecurityEventType.SCAN_COMPLETED,
                        user_id=g.user_id,
                        username=g.username,
                        scan_id=scan_id,
                        ip_address=request.remote_addr,
                        details={
                            'file_name': file.filename,
                            'findings_count': len(all_findings),
                            'processing_method': 'enhanced_with_fallback'
                        }
                    )
                    
                    return jsonify(scan_result)
                    
                finally:
                    # Clean up temporary files
                    shutil.rmtree(temp_dir, ignore_errors=True)
            
            else:
                return jsonify({'error': 'No file provided'}), 400
                
        except Exception as e:
            logger.error(f"Enhanced scan failed: {e}")
            return jsonify({'error': 'Scan failed'}), 500
    
    # Admin endpoints
    @app.route('/api/admin/audit-logs', methods=['GET'])
    @admin_required_enhanced
    def get_audit_logs():
        """Get audit logs (admin only)"""
        try:
            # Parse query parameters
            start_time = request.args.get('start_time')
            end_time = request.args.get('end_time')
            event_type = request.args.get('event_type')
            user_id = request.args.get('user_id')
            limit = int(request.args.get('limit', 100))
            
            # Convert string parameters
            if start_time:
                start_time = datetime.fromisoformat(start_time)
            if end_time:
                end_time = datetime.fromisoformat(end_time)
            if event_type:
                event_type = [SecurityEventType(event_type)]
            
            # Search events
            events = audit_logger.search_events(
                start_time=start_time,
                end_time=end_time,
                event_types=event_type,
                user_id=user_id,
                limit=limit
            )
            
            # Convert to JSON-serializable format
            events_data = []
            for event in events:
                event_dict = {
                    'event_id': event.event_id,
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'timestamp': event.timestamp.isoformat(),
                    'user_id': event.user_id,
                    'username': event.username,
                    'ip_address': event.ip_address,
                    'endpoint': event.endpoint,
                    'resource': event.resource,
                    'action': event.action,
                    'result': event.result,
                    'details': event.details
                }
                events_data.append(event_dict)
            
            return jsonify({
                'events': events_data,
                'total': len(events_data)
            })
            
        except Exception as e:
            logger.error(f"Failed to get audit logs: {e}")
            return jsonify({'error': 'Failed to get audit logs'}), 500
    
    @app.route('/api/admin/security-stats', methods=['GET'])
    @admin_required_enhanced
    def get_security_stats():
        """Get security statistics (admin only)"""
        try:
            # Get audit statistics
            audit_stats = audit_logger.get_event_statistics()
            
            # Get rate limiting statistics
            rate_limit_stats = rate_limiter.get_blocked_entities()
            
            # Get fallback statistics
            fallback_stats = intelligent_fallback.get_fallback_stats()
            
            return jsonify({
                'audit_statistics': audit_stats,
                'blocked_entities': len(rate_limit_stats),
                'fallback_statistics': fallback_stats,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Failed to get security stats: {e}")
            return jsonify({'error': 'Failed to get security stats'}), 500
    
    # Error handlers
    @app.errorhandler(429)
    def rate_limit_handler(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.'
        }), 429
    
    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({
            'error': 'File too large',
            'message': 'File size exceeds the maximum allowed limit.'
        }), 413
    
    return app

if __name__ == '__main__':
    app = create_security_enhanced_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
