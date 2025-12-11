"""
Authentication and authorization decorators
"""

from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from .models import UserManager, PermissionType, SubscriptionTier
import logging

logger = logging.getLogger(__name__)

def auth_required(f):
    """Require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
            return jsonify({'error': 'Authentication required'}), 401
    return decorated

def permission_required(permission: PermissionType):
    """Require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                user_manager = UserManager()
                user = user_manager.get_user_by_id(user_id)
                
                if not user or not user.is_active:
                    return jsonify({'error': 'User not found or inactive'}), 401
                
                if not user.has_permission(permission):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                # Log the action
                user_manager.log_audit(
                    user_id=user.id,
                    action=f"permission_check:{permission.value}",
                    resource_type="api",
                    resource_id=request.endpoint or "",
                    ip_address=request.remote_addr or "",
                    user_agent=request.headers.get('User-Agent', '')
                )
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Permission check failed: {e}")
                return jsonify({'error': 'Authorization failed'}), 403
        return decorated
    return decorator

def subscription_required(min_tier: SubscriptionTier):
    """Require minimum subscription tier"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                user_manager = UserManager()
                user = user_manager.get_user_by_id(user_id)
                
                if not user:
                    return jsonify({'error': 'User not found'}), 401
                
                tier_levels = {
                    SubscriptionTier.FREE: 0,
                    SubscriptionTier.PRO: 1,
                    SubscriptionTier.ENTERPRISE: 2
                }
                
                user_level = tier_levels.get(user.subscription_tier, 0)
                required_level = tier_levels.get(min_tier, 0)
                
                if user_level < required_level:
                    return jsonify({
                        'error': 'Subscription upgrade required',
                        'current_tier': user.subscription_tier.value,
                        'required_tier': min_tier.value
                    }), 402  # Payment Required
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Subscription check failed: {e}")
                return jsonify({'error': 'Subscription verification failed'}), 403
        return decorated
    return decorator

def rate_limit_check(f):
    """Check rate limits based on subscription tier"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            user_manager = UserManager()
            user = user_manager.get_user_by_id(user_id)
            
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            # Check if user can perform more scans
            if not user.can_scan():
                return jsonify({
                    'error': 'Scan limit exceeded',
                    'scans_this_month': user.scans_this_month,
                    'subscription_tier': user.subscription_tier.value,
                    'upgrade_message': 'Upgrade to Pro for unlimited scans'
                }), 429  # Too Many Requests
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return jsonify({'error': 'Rate limit check failed'}), 500
    return decorated

def admin_required(f):
    """Require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            user_manager = UserManager()
            user = user_manager.get_user_by_id(user_id)
            
            if not user or user.role.value != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Admin check failed: {e}")
            return jsonify({'error': 'Admin verification failed'}), 403
    return decorated

def audit_log(action: str, resource_type: str):
    """Decorator to automatically log actions"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                # Execute the function first
                result = f(*args, **kwargs)
                
                # Log the action if successful
                try:
                    verify_jwt_in_request()
                    user_id = get_jwt_identity()
                    
                    user_manager = UserManager()
                    user_manager.log_audit(
                        user_id=user_id,
                        action=action,
                        resource_type=resource_type,
                        resource_id=request.view_args.get('id', '') if request.view_args else '',
                        details={
                            'method': request.method,
                            'endpoint': request.endpoint,
                            'args': dict(request.args),
                            'success': True
                        },
                        ip_address=request.remote_addr or "",
                        user_agent=request.headers.get('User-Agent', '')
                    )
                except Exception as e:
                    logger.warning(f"Failed to log audit: {e}")
                
                return result
            except Exception as e:
                # Log failed action
                try:
                    verify_jwt_in_request()
                    user_id = get_jwt_identity()
                    
                    user_manager = UserManager()
                    user_manager.log_audit(
                        user_id=user_id,
                        action=f"{action}_failed",
                        resource_type=resource_type,
                        resource_id="",
                        details={
                            'method': request.method,
                            'endpoint': request.endpoint,
                            'error': str(e),
                            'success': False
                        },
                        ip_address=request.remote_addr or "",
                        user_agent=request.headers.get('User-Agent', '')
                    )
                except Exception:
                    pass
                
                raise e
        return decorated
    return decorator

def organization_access(f):
    """Check organization access for multi-tenant features"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            
            user_manager = UserManager()
            user = user_manager.get_user_by_id(user_id)
            
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            # Get organization ID from request
            org_id = request.args.get('org_id') or request.json.get('organization_id') if request.json else None
            
            # If organization ID is specified, check access
            if org_id and user.organization_id != org_id:
                return jsonify({'error': 'Organization access denied'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Organization access check failed: {e}")
            return jsonify({'error': 'Organization access verification failed'}), 403
    return decorated
