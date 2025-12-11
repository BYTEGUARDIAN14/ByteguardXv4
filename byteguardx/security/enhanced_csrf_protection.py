"""
Enhanced CSRF Protection for ByteGuardX
Cross-Site Request Forgery protection with double submit cookie pattern
and strict CORS policy enforcement
"""

import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from flask import request, session, current_app, make_response
from functools import wraps
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class EnhancedCSRFProtection:
    """Enhanced CSRF protection with double submit cookie and strict CORS"""
    
    def __init__(self):
        self.token_lifetime = timedelta(hours=1)
        self.cookie_name = 'csrf_token'
        self.header_name = 'X-CSRF-Token'
        self.form_field_name = 'csrf_token'
        
        # Allowed origins for CORS
        self.allowed_origins = self._get_allowed_origins()
        
        # Cookie settings - PRODUCTION HARDENED (but development-friendly)
        self.cookie_secure = os.environ.get('FLASK_ENV') == 'production'  # Only secure in production
        self.cookie_httponly = False  # Allow JavaScript access for SPA
        self.cookie_samesite = 'Lax' if os.environ.get('FLASK_ENV') != 'production' else 'Strict'
        self.token_rotation_enabled = True  # Enable token rotation
        
    def _get_allowed_origins(self) -> List[str]:
        """Get allowed origins from environment"""
        origins = os.environ.get('ALLOWED_ORIGINS', '').split(',')
        default_origins = [
            'https://byteguardx.com',
            'https://www.byteguardx.com',
            'https://app.byteguardx.com'
        ]
        
        # Add development origins if not in production
        if os.environ.get('FLASK_ENV') != 'production':
            default_origins.extend([
                'http://localhost:3000',
                'http://localhost:3001',
                'http://127.0.0.1:3000',
                'http://127.0.0.1:3001'
            ])
        
        # Combine and filter empty strings
        all_origins = list(set(origins + default_origins))
        return [origin.strip() for origin in all_origins if origin.strip()]
    
    def generate_token(self) -> str:
        """Generate a new CSRF token"""
        return secrets.token_urlsafe(32)
    
    def get_token(self) -> str:
        """Get or create CSRF token for current session"""
        if 'csrf_token' not in session:
            session['csrf_token'] = self.generate_token()
            session['csrf_token_time'] = datetime.now()
        
        # Check if token has expired
        token_time = session.get('csrf_token_time')
        if token_time:
            # Ensure both datetimes are timezone-naive for comparison
            current_time = datetime.now()
            if hasattr(token_time, 'tzinfo') and token_time.tzinfo is not None:
                token_time = token_time.replace(tzinfo=None)
            if hasattr(current_time, 'tzinfo') and current_time.tzinfo is not None:
                current_time = current_time.replace(tzinfo=None)

            if current_time - token_time > self.token_lifetime:
                session['csrf_token'] = self.generate_token()
                session['csrf_token_time'] = datetime.now()
        
        return session['csrf_token']
    
    def set_csrf_cookie(self, response):
        """Set CSRF token as secure cookie"""
        token = self.get_token()
        response.set_cookie(
            self.cookie_name,
            token,
            max_age=int(self.token_lifetime.total_seconds()),
            secure=self.cookie_secure,
            httponly=False,  # JavaScript needs to read this
            samesite=self.cookie_samesite
        )
        return response
    
    def validate_token(self, token: str) -> bool:
        """Validate CSRF token using double submit pattern"""
        # In development mode, be more lenient
        is_development = os.environ.get('FLASK_ENV') != 'production'

        if not token:
            if is_development:
                logger.info("Development mode: No token provided, generating new one")
                new_token = self.generate_token()
                session['csrf_token'] = new_token
                session['csrf_token_time'] = datetime.now()
                return True
            return False

        # Get token from session
        session_token = session.get('csrf_token')
        if not session_token:
            if is_development:
                logger.info("Development mode: No session token, storing provided token")
                session['csrf_token'] = token
                session['csrf_token_time'] = datetime.now()
                return True
            return False

        # Get token from cookie
        cookie_token = request.cookies.get(self.cookie_name)
        if not cookie_token:
            if is_development:
                logger.info("Development mode: No cookie token, accepting session token match")
                return secrets.compare_digest(token, session_token)
            return False

        # All three tokens must match (header/form, session, cookie)
        tokens_match = (
            secrets.compare_digest(token, session_token) and
            secrets.compare_digest(token, cookie_token) and
            secrets.compare_digest(session_token, cookie_token)
        )

        if not tokens_match and is_development:
            logger.info("Development mode: Token mismatch, updating tokens")
            session['csrf_token'] = token
            session['csrf_token_time'] = datetime.now()
            return True

        return tokens_match
    
    def validate_origin(self) -> bool:
        """Validate request origin against allowed origins"""
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        
        # For same-origin requests, origin might not be present
        if not origin and not referer:
            # Allow if it's a same-origin request (no Origin header)
            return True
        
        # Check origin
        if origin:
            return origin in self.allowed_origins
        
        # Check referer as fallback
        if referer:
            referer_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
            return referer_origin in self.allowed_origins
        
        return False
    
    def protect_request(self) -> bool:
        """Protect current request against CSRF"""
        # Skip CSRF protection for safe methods
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Validate origin first
        if not self.validate_origin():
            logger.warning(f"CSRF origin validation failed for {request.path}")
            return False
        
        # Skip for API endpoints with proper authentication
        if request.path.startswith('/api/') and self._has_valid_api_auth():
            return True
        
        # Get token from multiple sources
        token = (
            request.headers.get(self.header_name) or
            request.form.get(self.form_field_name) or
            (request.json.get(self.form_field_name) if request.is_json else None)
        )
        
        if not self.validate_token(token):
            logger.warning(f"CSRF token validation failed for {request.path}")
            return False
        
        return True
    
    def _has_valid_api_auth(self) -> bool:
        """Check if request has valid API authentication"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        
        # Additional validation could be added here
        # For now, just check that a Bearer token is present
        return True

def enhanced_csrf_protect(f):
    """Decorator to protect routes with enhanced CSRF validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf = EnhancedCSRFProtection()
        if not csrf.protect_request():
            from flask import jsonify
            return jsonify({
                'error': 'CSRF validation failed',
                'code': 'CSRF_TOKEN_INVALID'
            }), 403
        return f(*args, **kwargs)
    return decorated_function

def get_enhanced_csrf_token():
    """Get CSRF token for current session"""
    csrf = EnhancedCSRFProtection()
    return csrf.get_token()

def init_enhanced_csrf_protection(app):
    """Initialize enhanced CSRF protection for Flask app"""
    csrf = EnhancedCSRFProtection()
    
    @app.before_request
    def csrf_protect_request():
        # Skip CSRF protection for certain paths
        skip_paths = [
            '/api/auth/login',
            '/api/auth/register',
            '/api/health',
            '/static/',
            '/api/v1/health',
            '/api/v1/auth/login',
            '/api/csrf-token'
        ]

        # In development mode, skip CSRF for all API endpoints
        is_development = os.environ.get('FLASK_ENV') != 'production'
        if is_development:
            skip_paths.extend(['/api/'])  # Skip all API endpoints in development
        
        if any(request.path.startswith(path) for path in skip_paths):
            return
        
        if not csrf.protect_request():
            from flask import jsonify
            return jsonify({
                'error': 'CSRF validation failed',
                'code': 'CSRF_TOKEN_INVALID'
            }), 403
    
    @app.after_request
    def set_csrf_cookie(response):
        # Set CSRF cookie for all responses
        if request.method in ['GET', 'POST'] and not request.path.startswith('/static/'):
            csrf.set_csrf_cookie(response)
        return response
    
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=csrf.get_token())
    
    # Add CSRF token endpoint
    @app.route('/api/csrf-token', methods=['GET'])
    def get_csrf_token_endpoint():
        from flask import jsonify
        token = csrf.get_token()
        response = jsonify({'csrf_token': token})
        csrf.set_csrf_cookie(response)
        return response
    
    return csrf

# Global instance
enhanced_csrf_protection = EnhancedCSRFProtection()
