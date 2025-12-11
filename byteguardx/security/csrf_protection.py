"""
CSRF Protection for ByteGuardX
Implements Cross-Site Request Forgery protection with token validation
"""

import os
import secrets
import hmac
import hashlib
import time
import logging
from typing import Optional, Tuple
from functools import wraps
from flask import request, session, jsonify, current_app

logger = logging.getLogger(__name__)

class CSRFProtection:
    """CSRF protection implementation"""
    
    def __init__(self, app=None, secret_key: str = None):
        self.secret_key = secret_key or os.environ.get('SECRET_KEY', 'dev-secret-key')
        self.token_lifetime = 3600  # 1 hour
        self.header_name = 'X-CSRF-Token'
        self.form_field_name = 'csrf_token'
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize CSRF protection with Flask app"""
        app.config.setdefault('CSRF_ENABLED', True)
        app.config.setdefault('CSRF_TIME_LIMIT', self.token_lifetime)
        
        # Add CSRF token generation endpoint
        @app.route('/api/csrf-token', methods=['GET'])
        def get_csrf_token():
            token = self.generate_csrf_token()
            response = jsonify({'csrf_token': token})
            
            # Set CSRF token in cookie as well
            is_production = os.environ.get('ENV', '').lower() == 'production'
            response.set_cookie(
                'csrf_token',
                token,
                httponly=False,  # Allow JavaScript access for AJAX
                secure=is_production,  # Secure flag in production
                samesite='Strict'
            )
            
            return response
    
    def generate_csrf_token(self) -> str:
        """Generate a new CSRF token"""
        # Create token with timestamp
        timestamp = str(int(time.time()))
        random_data = secrets.token_urlsafe(32)
        
        # Create token payload
        token_data = f"{timestamp}:{random_data}"
        
        # Sign the token
        signature = self._sign_token(token_data)
        
        # Combine token data and signature
        token = f"{token_data}:{signature}"
        
        # Store in session for validation
        session['csrf_token'] = token
        
        return token
    
    def validate_csrf_token(self, token: str) -> bool:
        """Validate CSRF token"""
        if not token:
            return False
        
        try:
            # Parse token
            parts = token.split(':')
            if len(parts) != 3:
                return False
            
            timestamp_str, random_data, signature = parts
            token_data = f"{timestamp_str}:{random_data}"
            
            # Verify signature
            if not self._verify_token_signature(token_data, signature):
                logger.warning("CSRF token signature verification failed")
                return False
            
            # Check timestamp
            timestamp = int(timestamp_str)
            current_time = int(time.time())
            
            if current_time - timestamp > self.token_lifetime:
                logger.warning("CSRF token expired")
                return False
            
            # Check against session token
            session_token = session.get('csrf_token')
            if not session_token or not hmac.compare_digest(token, session_token):
                logger.warning("CSRF token does not match session")
                return False
            
            return True
            
        except (ValueError, TypeError) as e:
            logger.warning(f"CSRF token validation error: {e}")
            return False
    
    def _sign_token(self, token_data: str) -> str:
        """Sign token data with secret key"""
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def _verify_token_signature(self, token_data: str, signature: str) -> bool:
        """Verify token signature"""
        expected_signature = self._sign_token(token_data)
        return hmac.compare_digest(signature, expected_signature)
    
    def get_csrf_token_from_request(self) -> Optional[str]:
        """Extract CSRF token from request"""
        # Check header first
        token = request.headers.get(self.header_name)
        
        if not token:
            # Check form data
            token = request.form.get(self.form_field_name)
        
        if not token:
            # Check JSON data
            if request.is_json:
                json_data = request.get_json(silent=True)
                if json_data:
                    token = json_data.get(self.form_field_name)
        
        if not token:
            # Check cookie as fallback
            token = request.cookies.get('csrf_token')
        
        return token

# Global CSRF protection instance
csrf = CSRFProtection()

def csrf_required(f):
    """Decorator to require CSRF token validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF for GET, HEAD, OPTIONS requests
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return f(*args, **kwargs)

        # Skip if CSRF is disabled
        if not current_app.config.get('CSRF_ENABLED', True):
            return f(*args, **kwargs)

        # Skip CSRF validation in development mode for easier testing
        is_development = os.environ.get('FLASK_ENV') != 'production'
        if is_development:
            logger.info(f"Development mode: Skipping CSRF validation for {request.method} {request.path}")
            return f(*args, **kwargs)

        # Get token from request
        token = csrf.get_csrf_token_from_request()

        if not token:
            logger.warning(f"CSRF token missing for {request.method} {request.path}")
            return jsonify({
                'error': 'CSRF token missing',
                'message': 'CSRF token is required for this request'
            }), 403

        # Validate token
        if not csrf.validate_csrf_token(token):
            logger.warning(f"Invalid CSRF token for {request.method} {request.path}")
            return jsonify({
                'error': 'Invalid CSRF token',
                'message': 'CSRF token validation failed'
            }), 403

        return f(*args, **kwargs)

    return decorated_function

def init_csrf_protection(app):
    """Initialize CSRF protection for Flask app"""
    csrf.init_app(app)
    
    # Add CSRF token to all responses
    @app.after_request
    def add_csrf_token_header(response):
        if request.endpoint and not request.endpoint.startswith('static'):
            # Generate new token for next request
            token = csrf.generate_csrf_token()
            response.headers['X-CSRF-Token'] = token
        
        return response
    
    return csrf

# Global CSRF protection instance
csrf_protection = CSRFProtection()
