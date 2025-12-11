"""
Enhanced authentication middleware with JWT validation and token rotation
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from functools import wraps
import jwt
from flask import request, jsonify, current_app, g
from werkzeug.exceptions import Unauthorized

from ..database.connection_pool import db_manager
from ..database.models import User, AuditLog
from .jwt_utils import JWTManager, TokenBlacklist

logger = logging.getLogger(__name__)

class TokenValidator:
    """Advanced JWT token validation with blacklisting and rotation"""
    
    def __init__(self, jwt_manager: JWTManager, token_blacklist: TokenBlacklist):
        self.jwt_manager = jwt_manager
        self.token_blacklist = token_blacklist
    
    def validate_token(self, token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Validate JWT token with comprehensive checks
        Returns: (is_valid, payload, error_message)
        """
        try:
            # Check if token is blacklisted
            if self.token_blacklist.is_blacklisted(token):
                return False, None, "Token has been revoked"
            
            # Decode and validate token
            payload = self.jwt_manager.decode_token(token)
            
            # Check token expiration with grace period
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp) < datetime.now():
                return False, None, "Token has expired"
            
            # Check if token needs rotation
            iat = payload.get('iat')
            if iat:
                token_age = datetime.now() - datetime.fromtimestamp(iat)
                if token_age > timedelta(hours=12):  # Rotate tokens older than 12 hours
                    payload['needs_rotation'] = True
            
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, None, "Token validation failed"
    
    def extract_user_info(self, payload: Dict) -> Optional[Dict]:
        """Extract user information from token payload"""
        try:
            user_id = payload.get('sub')
            if not user_id:
                return None
            
            # Get user from database
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user or not user.is_active:
                    return None
                
                return {
                    'user_id': str(user.id),
                    'email': user.email,
                    'username': user.username,
                    'role': user.role,
                    'subscription_tier': user.subscription_tier,
                    'organization_id': str(user.organization_id) if user.organization_id else None
                }
        except Exception as e:
            logger.error(f"Error extracting user info: {e}")
            return None

class AuthMiddleware:
    """Enhanced authentication middleware with comprehensive security features"""
    
    def __init__(self):
        self.jwt_manager = JWTManager()
        self.token_blacklist = TokenBlacklist()
        self.token_validator = TokenValidator(self.jwt_manager, self.token_blacklist)
        
        # Rate limiting tracking
        self._failed_attempts = {}
        self._max_attempts = 5
        self._lockout_duration = timedelta(minutes=15)
    
    def authenticate_request(self, require_auth: bool = True) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Authenticate incoming request
        Returns: (is_authenticated, user_info, error_message)
        """
        try:
            # Extract token from request
            token = self._extract_token()
            
            if not token:
                if require_auth:
                    return False, None, "Authentication token required"
                return True, None, None  # Allow unauthenticated access
            
            # Validate token
            is_valid, payload, error = self.token_validator.validate_token(token)
            
            if not is_valid:
                self._log_failed_attempt()
                return False, None, error
            
            # Extract user information
            user_info = self.token_validator.extract_user_info(payload)
            if not user_info:
                return False, None, "User not found or inactive"
            
            # Check for IP-based restrictions
            if not self._check_ip_restrictions(user_info):
                return False, None, "Access denied from this IP address"
            
            # Store user info in Flask g for request context
            g.current_user = user_info
            g.token_payload = payload
            
            # Log successful authentication
            self._log_successful_auth(user_info)
            
            return True, user_info, None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, None, "Authentication failed"
    
    def _extract_token(self) -> Optional[str]:
        """Extract JWT token from request headers"""
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Also check for token in cookies (for web interface)
        return request.cookies.get('access_token')
    
    def _check_ip_restrictions(self, user_info: Dict) -> bool:
        """Check IP-based access restrictions"""
        # Get client IP
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Check if IP is in failed attempts lockout
        if client_ip in self._failed_attempts:
            attempts, last_attempt = self._failed_attempts[client_ip]
            if attempts >= self._max_attempts:
                if datetime.now() - last_attempt < self._lockout_duration:
                    logger.warning(f"IP {client_ip} is locked out due to failed attempts")
                    return False
                else:
                    # Reset failed attempts after lockout period
                    del self._failed_attempts[client_ip]
        
        # TODO: Add organization-specific IP whitelisting
        # This would check user's organization settings for allowed IP ranges
        
        return True
    
    def _log_failed_attempt(self):
        """Log failed authentication attempt"""
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Track failed attempts per IP
        if client_ip not in self._failed_attempts:
            self._failed_attempts[client_ip] = [0, datetime.now()]
        
        self._failed_attempts[client_ip][0] += 1
        self._failed_attempts[client_ip][1] = datetime.now()
        
        logger.warning(f"Failed authentication attempt from IP: {client_ip}")
    
    def _log_successful_auth(self, user_info: Dict):
        """Log successful authentication"""
        try:
            with db_manager.get_session() as session:
                audit_log = AuditLog(
                    user_id=user_info['user_id'],
                    action='authentication_success',
                    resource_type='auth',
                    ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                    user_agent=request.headers.get('User-Agent', ''),
                    endpoint=request.endpoint,
                    method=request.method,
                    success=True
                )
                session.add(audit_log)
                session.commit()
        except Exception as e:
            logger.error(f"Failed to log authentication: {e}")

# Decorator functions for Flask routes
def auth_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_middleware = AuthMiddleware()
        is_authenticated, user_info, error = auth_middleware.authenticate_request(require_auth=True)
        
        if not is_authenticated:
            return jsonify({'error': error or 'Authentication required'}), 401
        
        return f(*args, **kwargs)
    return decorated

def optional_auth(f):
    """Decorator for optional authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_middleware = AuthMiddleware()
        auth_middleware.authenticate_request(require_auth=False)
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_middleware = AuthMiddleware()
        is_authenticated, user_info, error = auth_middleware.authenticate_request(require_auth=True)
        
        if not is_authenticated:
            return jsonify({'error': error or 'Authentication required'}), 401
        
        if user_info.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated
