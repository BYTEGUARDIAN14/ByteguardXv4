"""
Admin 2FA Enforcement Module
Ensures all admin users have 2FA enabled and enforces 2FA requirements
"""

import os
import logging
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from ..database.connection_pool import db_manager
from ..database.models import User, UserRole
from .two_factor_auth import two_factor_auth
from .audit_logger import audit_logger, SecurityEventType, EventSeverity

logger = logging.getLogger(__name__)

class Admin2FAEnforcer:
    """Enforces 2FA requirements for admin users"""
    
    def __init__(self):
        self.grace_period_hours = int(os.environ.get('ADMIN_2FA_GRACE_PERIOD', '24'))  # 24 hours default
        self.is_production = os.environ.get('ENV', '').lower() == 'production'
        
    def validate_admin_2fa_requirement(self, user_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate that admin user has 2FA enabled
        Returns: (is_valid, error_message)
        """
        try:
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                
                if not user:
                    return False, "User not found"
                
                # Only enforce for admin users
                if user.role != UserRole.ADMIN.value:
                    return True, None
                
                # Check if 2FA is enabled
                if two_factor_auth.is_2fa_enabled(user_id):
                    return True, None
                
                # In production, admin users MUST have 2FA
                if self.is_production:
                    # Check grace period for new admin users
                    grace_period_end = user.created_at + timedelta(hours=self.grace_period_hours)
                    
                    if datetime.now() > grace_period_end:
                        # Grace period expired
                        audit_logger.log_event(
                            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                            level=EventSeverity.HIGH,
                            user_id=user_id,
                            details={
                                'reason': 'Admin user without 2FA after grace period',
                                'grace_period_end': grace_period_end.isoformat(),
                                'user_role': user.role
                            }
                        )
                        return False, "Admin users must enable 2FA. Grace period expired."
                    else:
                        # Still in grace period - warn but allow
                        remaining_hours = int((grace_period_end - datetime.now()).total_seconds() / 3600)
                        logger.warning(f"Admin user {user_id} has {remaining_hours} hours to enable 2FA")
                        return True, f"Warning: Enable 2FA within {remaining_hours} hours"
                else:
                    # Development mode - warn but allow
                    logger.warning(f"Admin user {user_id} should enable 2FA")
                    return True, "Warning: Admin users should enable 2FA"
                    
        except Exception as e:
            logger.error(f"Error validating admin 2FA requirement: {e}")
            return False, "Validation error"
    
    def enforce_admin_2fa_on_login(self, user_id: str, ip_address: str = None) -> Tuple[bool, Optional[str]]:
        """
        Enforce 2FA requirement during admin login
        Returns: (allow_login, message)
        """
        is_valid, message = self.validate_admin_2fa_requirement(user_id)
        
        if not is_valid:
            # Log security event
            audit_logger.log_event(
                event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                level=EventSeverity.HIGH,
                user_id=user_id,
                ip_address=ip_address,
                details={
                    'reason': 'Admin login blocked - 2FA not enabled',
                    'message': message
                }
            )
            
            logger.warning(f"Admin login blocked for user {user_id}: {message}")
            return False, message
        
        return True, message
    
    def check_and_enforce_2fa_setup(self, user_id: str) -> Dict[str, Any]:
        """
        Check 2FA status and provide setup instructions if needed
        Returns: status information and setup instructions
        """
        try:
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                
                if not user:
                    return {'error': 'User not found'}
                
                if user.role != UserRole.ADMIN.value:
                    return {
                        'required': False,
                        'enabled': two_factor_auth.is_2fa_enabled(user_id),
                        'message': '2FA is optional for non-admin users'
                    }
                
                is_enabled = two_factor_auth.is_2fa_enabled(user_id)
                
                if is_enabled:
                    return {
                        'required': True,
                        'enabled': True,
                        'message': '2FA is properly configured'
                    }
                
                # 2FA not enabled for admin user
                grace_period_end = user.created_at + timedelta(hours=self.grace_period_hours)
                remaining_time = grace_period_end - datetime.now()
                
                if remaining_time.total_seconds() > 0:
                    # Still in grace period
                    remaining_hours = int(remaining_time.total_seconds() / 3600)
                    return {
                        'required': True,
                        'enabled': False,
                        'grace_period_remaining_hours': remaining_hours,
                        'message': f'2FA setup required within {remaining_hours} hours',
                        'setup_url': '/auth/2fa/setup',
                        'urgency': 'high' if remaining_hours < 6 else 'medium'
                    }
                else:
                    # Grace period expired
                    return {
                        'required': True,
                        'enabled': False,
                        'grace_period_expired': True,
                        'message': '2FA setup is overdue. Account access restricted.',
                        'setup_url': '/auth/2fa/setup',
                        'urgency': 'critical'
                    }
                    
        except Exception as e:
            logger.error(f"Error checking 2FA setup status: {e}")
            return {'error': 'Status check failed'}
    
    def promote_user_to_admin(self, user_id: str, promoted_by: str) -> Tuple[bool, Optional[str]]:
        """
        Promote user to admin with 2FA enforcement
        Returns: (success, message)
        """
        try:
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                
                if not user:
                    return False, "User not found"
                
                # Check if user already has 2FA enabled
                has_2fa = two_factor_auth.is_2fa_enabled(user_id)
                
                if self.is_production and not has_2fa:
                    return False, "Cannot promote to admin: 2FA must be enabled first"
                
                # Update user role
                old_role = user.role
                user.role = UserRole.ADMIN.value
                session.commit()
                
                # Log the promotion
                audit_logger.log_event(
                    event_type=SecurityEventType.ROLE_CHANGE,
                    level=EventSeverity.HIGH,
                    user_id=promoted_by,
                    details={
                        'target_user_id': user_id,
                        'old_role': old_role,
                        'new_role': UserRole.ADMIN.value,
                        'target_has_2fa': has_2fa,
                        'production_mode': self.is_production
                    }
                )
                
                if not has_2fa:
                    message = f"User promoted to admin. 2FA must be enabled within {self.grace_period_hours} hours."
                    logger.warning(f"Admin promotion without 2FA: {user_id}")
                else:
                    message = "User successfully promoted to admin."
                
                return True, message
                
        except Exception as e:
            logger.error(f"Error promoting user to admin: {e}")
            return False, "Promotion failed"
    
    def get_admin_users_without_2fa(self) -> list:
        """Get list of admin users without 2FA enabled"""
        try:
            with db_manager.get_session() as session:
                admin_users = session.query(User).filter(
                    User.role == UserRole.ADMIN.value,
                    User.is_active == True
                ).all()
                
                users_without_2fa = []
                
                for user in admin_users:
                    if not two_factor_auth.is_2fa_enabled(str(user.id)):
                        grace_period_end = user.created_at + timedelta(hours=self.grace_period_hours)
                        remaining_time = grace_period_end - datetime.now()
                        
                        users_without_2fa.append({
                            'user_id': str(user.id),
                            'username': user.username,
                            'email': user.email,
                            'created_at': user.created_at.isoformat(),
                            'grace_period_end': grace_period_end.isoformat(),
                            'grace_period_expired': remaining_time.total_seconds() <= 0,
                            'remaining_hours': max(0, int(remaining_time.total_seconds() / 3600))
                        })
                
                return users_without_2fa
                
        except Exception as e:
            logger.error(f"Error getting admin users without 2FA: {e}")
            return []
    
    def send_2fa_reminder_notifications(self):
        """Send reminder notifications to admin users without 2FA"""
        users_without_2fa = self.get_admin_users_without_2fa()
        
        for user_info in users_without_2fa:
            remaining_hours = user_info['remaining_hours']
            
            if remaining_hours <= 0:
                # Grace period expired
                logger.critical(f"Admin user {user_info['username']} 2FA grace period expired")
            elif remaining_hours <= 6:
                # Critical reminder (6 hours or less)
                logger.warning(f"Admin user {user_info['username']} has {remaining_hours} hours to enable 2FA")
            elif remaining_hours <= 24:
                # Warning reminder (24 hours or less)
                logger.info(f"Admin user {user_info['username']} should enable 2FA soon ({remaining_hours} hours remaining)")
        
        return len(users_without_2fa)

# Global instance
admin_2fa_enforcer = Admin2FAEnforcer()
