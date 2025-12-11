"""
Enhanced Authentication Middleware with comprehensive security features
Integrates 2FA, rate limiting, audit logging, and brute force protection
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from functools import wraps
from flask import request, jsonify, current_app, g

from .auth_middleware import AuthMiddleware
from .two_factor_auth import two_factor_auth
from .rate_limiter import rate_limiter, brute_force_protection
from .audit_logger import audit_logger, SecurityEventType, EventSeverity
from .password_policy import password_validator
from ..database.connection_pool import db_manager
from ..database.models import User

logger = logging.getLogger(__name__)

class EnhancedAuthMiddleware(AuthMiddleware):
    """Enhanced authentication middleware with comprehensive security"""
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = two_factor_auth
        self.rate_limiter = rate_limiter
        self.brute_force_protection = brute_force_protection
        self.audit_logger = audit_logger
        self.password_validator = password_validator
    
    def authenticate_request(self, require_auth: bool = True, require_2fa: bool = None) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Enhanced authentication with rate limiting and audit logging
        Returns: (is_authenticated, user_info, error_message)
        """
        client_ip = self._get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        endpoint = request.endpoint or request.path
        
        try:
            # Check rate limits first
            is_allowed, rate_limit_reason, retry_after = self.rate_limiter.check_rate_limit(
                identifier=client_ip,
                endpoint=endpoint,
                user_id=g.get('user_id')
            )
            
            if not is_allowed:
                self.audit_logger.log_rate_limit_exceeded(
                    identifier=client_ip,
                    endpoint=endpoint,
                    limit_type="request",
                    ip_address=client_ip
                )
                return False, None, f"Rate limit exceeded: {rate_limit_reason}"
            
            # Perform standard authentication
            is_authenticated, user_info, error = super().authenticate_request(require_auth)
            
            if not is_authenticated:
                if require_auth and error:
                    # Log failed authentication attempt
                    username = request.json.get('email', 'unknown') if request.is_json else 'unknown'
                    self.audit_logger.log_login_failure(
                        username=username,
                        ip_address=client_ip,
                        reason=error,
                        user_agent=user_agent
                    )
                    
                    # Record brute force attempt for login endpoints
                    if 'login' in endpoint.lower():
                        self.brute_force_protection.record_failed_attempt(client_ip, endpoint)
                
                return False, user_info, error
            
            # If authenticated, check 2FA if required
            if user_info and (require_2fa or self._should_require_2fa(user_info, endpoint)):
                if not self._verify_2fa_if_required(user_info, client_ip):
                    return False, None, "Two-factor authentication required"
            
            # Log successful authentication
            if user_info:
                self.audit_logger.log_login_success(
                    user_id=user_info.get('user_id'),
                    username=user_info.get('username'),
                    ip_address=client_ip,
                    user_agent=user_agent,
                    session_id=g.get('session_id')
                )
                
                # Clear brute force attempts on successful login
                self.brute_force_protection.record_successful_attempt(client_ip)
            
            return True, user_info, None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, None, "Authentication service error"
    
    def _get_client_ip(self) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers (when behind proxy/load balancer)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or 'unknown'
    
    def _should_require_2fa(self, user_info: Dict[str, Any], endpoint: str) -> bool:
        """Determine if 2FA should be required for this request"""
        user_id = user_info.get('user_id')
        if not user_id:
            return False
        
        # Check if user has 2FA enabled
        if not self.two_factor_auth.is_2fa_enabled(user_id):
            return False
        
        # Always require 2FA for sensitive endpoints
        sensitive_endpoints = [
            'admin', 'config', 'user', 'delete', 'export', 'backup'
        ]
        
        if any(sensitive in endpoint.lower() for sensitive in sensitive_endpoints):
            return True
        
        # Check if 2FA was already verified in this session
        return not g.get('2fa_verified', False)
    
    def _verify_2fa_if_required(self, user_info: Dict[str, Any], client_ip: str) -> bool:
        """Verify 2FA token if provided"""
        user_id = user_info.get('user_id')
        username = user_info.get('username')
        
        # Check for 2FA token in request
        token = None
        if request.is_json:
            token = request.json.get('totp_token') or request.json.get('2fa_token')
        else:
            token = request.form.get('totp_token') or request.form.get('2fa_token')
        
        # Also check headers
        if not token:
            token = request.headers.get('X-TOTP-Token') or request.headers.get('X-2FA-Token')
        
        if not token:
            return False
        
        # Verify the token
        is_valid = self.two_factor_auth.verify_2fa(user_id, token)
        
        # Log 2FA attempt
        self.audit_logger.log_2fa_event(
            event_type=SecurityEventType.TWO_FA_SUCCESS if is_valid else SecurityEventType.TWO_FA_FAILURE,
            user_id=user_id,
            username=username,
            ip_address=client_ip,
            success=is_valid
        )
        
        if is_valid:
            # Mark 2FA as verified for this session
            g.twofa_verified = True
        
        return is_valid
    
    def validate_password_strength(self, password: str, user_info: Dict[str, str] = None) -> Tuple[bool, Dict[str, Any]]:
        """Validate password strength using policy"""
        result = self.password_validator.validate_password(password, user_info)
        
        return result.is_valid, {
            'strength': result.strength.value,
            'score': result.score,
            'errors': result.errors,
            'warnings': result.warnings,
            'suggestions': result.suggestions
        }
    
    def log_security_event(self, event_type: SecurityEventType, user_id: str = None,
                          username: str = None, details: Dict[str, Any] = None):
        """Log a security event"""
        client_ip = self._get_client_ip()
        
        if event_type in [SecurityEventType.SECURITY_VIOLATION, SecurityEventType.SUSPICIOUS_ACTIVITY]:
            self.audit_logger.log_security_violation(
                violation_type=event_type.value,
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                details=details
            )
        else:
            # Use appropriate logging method based on event type
            if event_type == SecurityEventType.ACCESS_DENIED:
                self.audit_logger.log_access_denied(
                    user_id=user_id,
                    username=username,
                    resource=details.get('resource', 'unknown'),
                    action=details.get('action', 'unknown'),
                    ip_address=client_ip,
                    reason=details.get('reason', 'unknown')
                )

# Enhanced decorators
from typing import Optional, Dict, Any, Tuple, Union, Callable

# ... imports ...

def _authenticate_and_execute(f, require_2fa, *args, **kwargs):
    """Helper to execute authentication logic"""
    auth_middleware = EnhancedAuthMiddleware()
    is_authenticated, user_info, error = auth_middleware.authenticate_request(
        require_auth=True, 
        require_2fa=require_2fa
    )
    
    if not is_authenticated:
        return jsonify({'error': error or 'Authentication required'}), 401
    
    # Store user info in Flask's g object
    g.current_user = user_info
    g.user_id = user_info.get('user_id')
    g.username = user_info.get('username')
    
    return f(*args, **kwargs)

def enhanced_auth_required(require_2fa: Union[bool, Callable] = False):
    """Enhanced authentication decorator with 2FA support.
    Can be used as @enhanced_auth_required or @enhanced_auth_required(require_2fa=True)
    """
    if callable(require_2fa):
        # Used as @enhanced_auth_required (without parens)
        func = require_2fa
        @wraps(func)
        def decorated(*args, **kwargs):
            return _authenticate_and_execute(func, False, *args, **kwargs)
        return decorated

    # Used as factory @enhanced_auth_required(...)
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            return _authenticate_and_execute(f, require_2fa, *args, **kwargs)
        return decorated
    return decorator

def admin_required_enhanced(f):
    """Enhanced admin-only decorator with audit logging"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_middleware = EnhancedAuthMiddleware()
        is_authenticated, user_info, error = auth_middleware.authenticate_request(
            require_auth=True, 
            require_2fa=True  # Always require 2FA for admin actions
        )
        
        if not is_authenticated:
            return jsonify({'error': error or 'Authentication required'}), 401
        
        # Check admin role
        user_role = user_info.get('role', '').lower()
        if user_role != 'admin':
            # Log access denied
            auth_middleware.log_security_event(
                event_type=SecurityEventType.ACCESS_DENIED,
                user_id=user_info.get('user_id'),
                username=user_info.get('username'),
                details={
                    'resource': f.__name__,
                    'action': 'admin_access',
                    'reason': 'insufficient_privileges'
                }
            )
            return jsonify({'error': 'Admin privileges required'}), 403
        
        g.current_user = user_info
        g.user_id = user_info.get('user_id')
        g.username = user_info.get('username')
        
        return f(*args, **kwargs)
    return decorated

def rate_limited(limit: int = 10, window: int = 60, per: str = 'ip'):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr or 'unknown'
            user_id = g.get('user_id')
            endpoint = request.endpoint or request.path
            
            # Determine identifier based on 'per' parameter
            if per == 'user' and user_id:
                identifier = user_id
            else:
                identifier = client_ip
            
            # Check rate limit
            is_allowed, reason, retry_after = rate_limiter.check_rate_limit(
                identifier=identifier,
                endpoint=endpoint,
                user_id=user_id
            )
            
            if not is_allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def _execute_and_audit(f, event_type, resource, *args, **kwargs):
    """Helper to execute and audit function call"""
    user_id = g.get('user_id')
    username = g.get('username')
    
    # Execute the function
    result = f(*args, **kwargs)
    
    # Log the event
    audit_logger.log_event(
        event_type=event_type,
        user_id=user_id,
        username=username,
        ip_address=request.remote_addr,
        endpoint=request.endpoint,
        resource=resource or f.__name__,
        action=f.__name__,
        result="success"
    )
    
    return result

def audit_logged(event_type_or_func: Union[SecurityEventType, Callable] = SecurityEventType.ACCESS_GRANTED, resource: str = None):
    """Decorator to automatically log security events.
    Can be used as @audit_logged or @audit_logged(event_type=...)
    """
    if callable(event_type_or_func) and not isinstance(event_type_or_func, SecurityEventType):
        # Used as @audit_logged (without parens)
        func = event_type_or_func
        @wraps(func)
        def decorated(*args, **kwargs):
            return _execute_and_audit(func, SecurityEventType.ACCESS_GRANTED, resource, *args, **kwargs)
        return decorated

    # Used as factory @audit_logged(...)
    event_type = event_type_or_func
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            return _execute_and_audit(f, event_type, resource, *args, **kwargs)
        return decorated
    return decorator

# Global instance
enhanced_auth_middleware = EnhancedAuthMiddleware()
