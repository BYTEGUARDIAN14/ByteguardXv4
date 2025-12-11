"""
Zero Trust API Enforcement for ByteGuardX
Implements deny-by-default security model for all API routes
"""

import logging
import functools
from typing import Dict, List, Optional, Callable, Any
from flask import request, jsonify, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from dataclasses import dataclass
from enum import Enum

from .rbac import rbac, Permission, AccessContext
from .audit_logger import audit_logger, SecurityEvent
from ..auth.models import UserManager, UserRole

logger = logging.getLogger(__name__)

class AccessDecision(Enum):
    """Access control decisions"""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"

@dataclass
class RoutePolicy:
    """Route-specific access policy"""
    route_pattern: str
    required_permissions: List[Permission]
    required_roles: List[UserRole]
    allow_anonymous: bool = False
    require_2fa: bool = False
    rate_limit: Optional[int] = None
    audit_level: str = "info"
    custom_validator: Optional[Callable] = None

class ZeroTrustEnforcer:
    """
    Zero Trust enforcement engine that denies access by default
    and requires explicit authorization for all API routes
    """
    
    def __init__(self):
        self.route_policies: Dict[str, RoutePolicy] = {}
        self.default_policy = RoutePolicy(
            route_pattern="*",
            required_permissions=[],
            required_roles=[UserRole.VIEWER],
            allow_anonymous=False,
            require_2fa=False,
            audit_level="warning"
        )
        self.user_manager = UserManager()
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default route policies"""
        # Public routes (minimal set)
        self.route_policies["/health"] = RoutePolicy(
            route_pattern="/health",
            required_permissions=[],
            required_roles=[],
            allow_anonymous=True,
            audit_level="debug"
        )
        
        self.route_policies["/auth/login"] = RoutePolicy(
            route_pattern="/auth/login",
            required_permissions=[],
            required_roles=[],
            allow_anonymous=True,
            audit_level="info"
        )
        
        self.route_policies["/auth/register"] = RoutePolicy(
            route_pattern="/auth/register",
            required_permissions=[],
            required_roles=[],
            allow_anonymous=True,
            audit_level="info"
        )
        
        # Admin routes require admin role and 2FA
        self.route_policies["/api/v1/admin/*"] = RoutePolicy(
            route_pattern="/api/v1/admin/*",
            required_permissions=[Permission.API_ADMIN, Permission.SYSTEM_ADMIN],
            required_roles=[UserRole.ADMIN],
            require_2fa=True,
            audit_level="critical"
        )
        
        # Scan routes require appropriate permissions
        self.route_policies["/api/v1/scan/*"] = RoutePolicy(
            route_pattern="/api/v1/scan/*",
            required_permissions=[Permission.SCAN_CREATE, Permission.SCAN_READ],
            required_roles=[UserRole.DEVELOPER, UserRole.MANAGER, UserRole.ADMIN],
            audit_level="info"
        )
        
        # Plugin routes require elevated permissions
        self.route_policies["/api/v1/plugins/*"] = RoutePolicy(
            route_pattern="/api/v1/plugins/*",
            required_permissions=[Permission.SYSTEM_CONFIG],
            required_roles=[UserRole.MANAGER, UserRole.ADMIN],
            audit_level="warning"
        )
    
    def register_route_policy(self, route_pattern: str, policy: RoutePolicy):
        """Register a custom route policy"""
        self.route_policies[route_pattern] = policy
        logger.info(f"Registered zero trust policy for route: {route_pattern}")
    
    def _find_matching_policy(self, route_path: str) -> RoutePolicy:
        """Find the most specific matching policy for a route"""
        # Exact match first
        if route_path in self.route_policies:
            return self.route_policies[route_path]
        
        # Pattern matching (wildcard support)
        for pattern, policy in self.route_policies.items():
            if pattern.endswith("/*"):
                prefix = pattern[:-2]
                if route_path.startswith(prefix):
                    return policy
            elif "*" in pattern:
                # Simple wildcard matching
                import re
                regex_pattern = pattern.replace("*", ".*")
                if re.match(regex_pattern, route_path):
                    return policy
        
        # Return default deny policy
        return self.default_policy
    
    def _validate_authentication(self, policy: RoutePolicy) -> tuple[bool, Optional[str], Optional[dict]]:
        """Validate user authentication"""
        if policy.allow_anonymous:
            return True, None, None
        
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            if not user_id:
                return False, "Invalid token", None
            
            user = self.user_manager.get_user_by_id(user_id)
            if not user or not user.is_active:
                return False, "User not found or inactive", None
            
            # Check 2FA requirement
            if policy.require_2fa:
                # Check if user has 2FA enabled and verified in this session
                if not getattr(g, 'two_factor_verified', False):
                    return False, "Two-factor authentication required", None
            
            return True, None, {
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'organization_id': user.organization_id
            }
            
        except Exception as e:
            logger.warning(f"Authentication validation failed: {e}")
            return False, "Authentication failed", None
    
    def _validate_authorization(self, user_info: dict, policy: RoutePolicy) -> tuple[bool, Optional[str]]:
        """Validate user authorization"""
        if policy.allow_anonymous:
            return True, None
        
        user_role = user_info.get('role')
        user_id = user_info.get('user_id')
        
        # Check role requirements
        if policy.required_roles and user_role not in policy.required_roles:
            return False, f"Required role not met. Need one of: {[r.value for r in policy.required_roles]}"
        
        # Check permission requirements
        if policy.required_permissions:
            context = AccessContext(
                user_id=user_id,
                organization_id=user_info.get('organization_id'),
                resource_type=request.endpoint or '',
                action=request.method.lower(),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            
            for permission in policy.required_permissions:
                if not rbac.check_permission(user_id, permission, context):
                    return False, f"Missing required permission: {permission.value}"
        
        # Custom validation
        if policy.custom_validator:
            try:
                is_valid, error_msg = policy.custom_validator(user_info, request)
                if not is_valid:
                    return False, error_msg or "Custom validation failed"
            except Exception as e:
                logger.error(f"Custom validator failed: {e}")
                return False, "Custom validation error"
        
        return True, None
    
    def _audit_access_attempt(self, policy: RoutePolicy, user_info: Optional[dict], 
                            decision: AccessDecision, error_msg: Optional[str] = None):
        """Audit access attempt"""
        try:
            event_type = SecurityEvent.ACCESS_GRANTED if decision == AccessDecision.ALLOW else SecurityEvent.ACCESS_DENIED
            
            audit_logger.log_security_event(
                event_type=event_type,
                user_id=user_info.get('user_id') if user_info else None,
                resource_type="api_route",
                resource_id=request.endpoint or request.path,
                action=request.method,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                details={
                    'route_pattern': policy.route_pattern,
                    'required_permissions': [p.value for p in policy.required_permissions],
                    'required_roles': [r.value for r in policy.required_roles],
                    'decision': decision.value,
                    'error_message': error_msg,
                    'request_data': {
                        'method': request.method,
                        'path': request.path,
                        'query_params': dict(request.args),
                        'content_type': request.content_type
                    }
                },
                severity=policy.audit_level
            )
        except Exception as e:
            logger.error(f"Failed to audit access attempt: {e}")
    
    def enforce_zero_trust(self, f):
        """
        Zero trust decorator that enforces deny-by-default access control
        """
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            route_path = request.path
            policy = self._find_matching_policy(route_path)
            
            # Validate authentication
            is_authenticated, auth_error, user_info = self._validate_authentication(policy)
            if not is_authenticated:
                self._audit_access_attempt(policy, user_info, AccessDecision.DENY, auth_error)
                return jsonify({'error': auth_error or 'Authentication required'}), 401
            
            # Validate authorization
            is_authorized, authz_error = self._validate_authorization(user_info, policy)
            if not is_authorized:
                self._audit_access_attempt(policy, user_info, AccessDecision.DENY, authz_error)
                return jsonify({'error': authz_error or 'Access denied'}), 403
            
            # Store user info in Flask's g object for use in the route
            if user_info:
                g.current_user = user_info
                g.user_id = user_info.get('user_id')
                g.username = user_info.get('username')
                g.user_role = user_info.get('role')
            
            # Audit successful access
            self._audit_access_attempt(policy, user_info, AccessDecision.ALLOW)
            
            return f(*args, **kwargs)
        
        return decorated

# Global instance
zero_trust_enforcer = ZeroTrustEnforcer()

def deny_by_default(f):
    """
    Convenience decorator that applies zero trust enforcement
    """
    return zero_trust_enforcer.enforce_zero_trust(f)

def register_route_policy(route_pattern: str, policy: RoutePolicy):
    """
    Register a custom route policy
    """
    zero_trust_enforcer.register_route_policy(route_pattern, policy)
