"""
Enhanced Authentication System for ByteGuardX
Implements 2FA for all users, token revocation, and automated key rotation
"""

import os
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import pyotp
import qrcode
from io import BytesIO
import base64

from ..database.connection_pool import db_manager
from ..database.models import User, TokenRevocation, KeyRotation
from .jwt_utils import JWTManager
from .audit_logger import audit_logger

logger = logging.getLogger(__name__)

class AuthenticationLevel(Enum):
    """Authentication security levels"""
    BASIC = "basic"
    TWO_FACTOR = "two_factor"
    ADMIN = "admin"

@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user_id: Optional[str] = None
    auth_level: Optional[AuthenticationLevel] = None
    requires_2fa: bool = False
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

class EnhancedAuthManager:
    """Enhanced authentication manager with 2FA and security features"""
    
    def __init__(self):
        self.jwt_manager = JWTManager()
        self.grace_period_days = int(os.environ.get('TWO_FA_GRACE_PERIOD_DAYS', '30'))
        self.key_rotation_days = int(os.environ.get('JWT_KEY_ROTATION_DAYS', '30'))
        
    def authenticate_user(self, email: str, password: str, totp_code: Optional[str] = None,
                         ip_address: str = None, user_agent: str = None) -> AuthResult:
        """
        Authenticate user with enhanced security checks
        
        Args:
            email: User email
            password: User password
            totp_code: TOTP code for 2FA
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            AuthResult with authentication status
        """
        try:
            with db_manager.get_session() as session:
                # Find user
                user = session.query(User).filter(User.email == email).first()
                if not user:
                    audit_logger.log_security_event(
                        event_type='login_failed',
                        user_id=None,
                        ip_address=ip_address,
                        details={'reason': 'user_not_found', 'email': email}
                    )
                    return AuthResult(
                        success=False,
                        error_message="Invalid credentials"
                    )
                
                # Check if user is active
                if not user.is_active:
                    audit_logger.log_security_event(
                        event_type='login_failed',
                        user_id=user.id,
                        ip_address=ip_address,
                        details={'reason': 'user_inactive'}
                    )
                    return AuthResult(
                        success=False,
                        error_message="Account is inactive"
                    )
                
                # Verify password
                if not user.check_password(password):
                    audit_logger.log_security_event(
                        event_type='login_failed',
                        user_id=user.id,
                        ip_address=ip_address,
                        details={'reason': 'invalid_password'}
                    )
                    return AuthResult(
                        success=False,
                        error_message="Invalid credentials"
                    )
                
                # Check if 2FA is required
                requires_2fa = self._requires_2fa(user)
                
                if requires_2fa and not totp_code:
                    return AuthResult(
                        success=False,
                        user_id=user.id,
                        requires_2fa=True,
                        error_message="2FA code required"
                    )
                
                # Verify 2FA if provided
                if requires_2fa and totp_code:
                    if not self._verify_totp(user, totp_code):
                        audit_logger.log_security_event(
                            event_type='login_failed',
                            user_id=user.id,
                            ip_address=ip_address,
                            details={'reason': 'invalid_2fa_code'}
                        )
                        return AuthResult(
                            success=False,
                            error_message="Invalid 2FA code"
                        )
                
                # Update last login
                user.last_login = datetime.now()
                user.last_login_ip = ip_address
                session.commit()
                
                # Determine authentication level
                auth_level = AuthenticationLevel.ADMIN if user.is_admin else AuthenticationLevel.TWO_FACTOR
                
                audit_logger.log_security_event(
                    event_type='login_success',
                    user_id=user.id,
                    ip_address=ip_address,
                    details={
                        'auth_level': auth_level.value,
                        '2fa_used': requires_2fa and totp_code is not None
                    }
                )
                
                return AuthResult(
                    success=True,
                    user_id=user.id,
                    auth_level=auth_level,
                    metadata={
                        'user_email': user.email,
                        'is_admin': user.is_admin,
                        '2fa_enabled': user.totp_secret is not None
                    }
                )
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthResult(
                success=False,
                error_message="Authentication failed"
            )
    
    def setup_2fa(self, user_id: str) -> Dict[str, Any]:
        """
        Set up 2FA for a user
        
        Args:
            user_id: User ID
            
        Returns:
            Dict containing QR code and backup codes
        """
        try:
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user:
                    raise ValueError("User not found")
                
                # Generate TOTP secret
                secret = pyotp.random_base32()
                
                # Create TOTP URI
                totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                    name=user.email,
                    issuer_name="ByteGuardX"
                )
                
                # Generate QR code
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(totp_uri)
                qr.make(fit=True)
                
                qr_img = qr.make_image(fill_color="black", back_color="white")
                qr_buffer = BytesIO()
                qr_img.save(qr_buffer, format='PNG')
                qr_code_b64 = base64.b64encode(qr_buffer.getvalue()).decode()
                
                # Generate backup codes
                backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
                
                # Store secret (temporarily, until confirmed)
                user.totp_secret_temp = secret
                user.backup_codes = backup_codes
                session.commit()
                
                audit_logger.log_security_event(
                    event_type='2fa_setup_initiated',
                    user_id=user_id,
                    details={'method': 'totp'}
                )
                
                return {
                    'qr_code': f"data:image/png;base64,{qr_code_b64}",
                    'secret': secret,
                    'backup_codes': backup_codes,
                    'setup_complete': False
                }
                
        except Exception as e:
            logger.error(f"2FA setup error: {e}")
            raise
    
    def confirm_2fa_setup(self, user_id: str, totp_code: str) -> bool:
        """
        Confirm 2FA setup with TOTP code
        
        Args:
            user_id: User ID
            totp_code: TOTP code to verify
            
        Returns:
            True if setup confirmed successfully
        """
        try:
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user or not user.totp_secret_temp:
                    return False
                
                # Verify TOTP code
                totp = pyotp.TOTP(user.totp_secret_temp)
                if not totp.verify(totp_code, valid_window=2):
                    return False
                
                # Confirm setup
                user.totp_secret = user.totp_secret_temp
                user.totp_secret_temp = None
                user.two_factor_enabled = True
                user.two_factor_enabled_at = datetime.now()
                session.commit()
                
                audit_logger.log_security_event(
                    event_type='2fa_setup_completed',
                    user_id=user_id,
                    details={'method': 'totp'}
                )
                
                return True
                
        except Exception as e:
            logger.error(f"2FA confirmation error: {e}")
            return False
    
    def revoke_token(self, token: str, reason: str = "user_logout") -> bool:
        """
        Revoke a JWT token
        
        Args:
            token: JWT token to revoke
            reason: Reason for revocation
            
        Returns:
            True if token revoked successfully
        """
        try:
            # Decode token to get JTI
            payload = self.jwt_manager.decode_token(token, verify_expiration=False)
            if not payload:
                return False
            
            jti = payload.get('jti')
            if not jti:
                return False
            
            with db_manager.get_session() as session:
                # Add to revocation list
                revocation = TokenRevocation(
                    jti=jti,
                    revoked_at=datetime.now(),
                    reason=reason
                )
                session.add(revocation)
                session.commit()
                
                audit_logger.log_security_event(
                    event_type='token_revoked',
                    user_id=payload.get('sub'),
                    details={'jti': jti, 'reason': reason}
                )
                
                return True
                
        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            return False
    
    def is_token_revoked(self, jti: str) -> bool:
        """
        Check if a token is revoked
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if token is revoked
        """
        try:
            with db_manager.get_session() as session:
                revocation = session.query(TokenRevocation).filter(
                    TokenRevocation.jti == jti
                ).first()
                return revocation is not None
                
        except Exception as e:
            logger.error(f"Token revocation check error: {e}")
            return True  # Fail secure
    
    def rotate_jwt_key(self) -> bool:
        """
        Rotate JWT signing key
        
        Returns:
            True if key rotated successfully
        """
        try:
            # Generate new key
            new_key = secrets.token_urlsafe(64)
            
            with db_manager.get_session() as session:
                # Store old key for verification during transition
                old_key = os.environ.get('JWT_SECRET_KEY')
                if old_key:
                    key_rotation = KeyRotation(
                        old_key_hash=hashlib.sha256(old_key.encode()).hexdigest(),
                        rotated_at=datetime.now(),
                        reason='scheduled_rotation'
                    )
                    session.add(key_rotation)
                    session.commit()
                
                # Update environment (this would typically update a secrets manager)
                os.environ['JWT_SECRET_KEY'] = new_key
                
                audit_logger.log_security_event(
                    event_type='jwt_key_rotated',
                    user_id=None,
                    details={'rotation_type': 'scheduled'}
                )
                
                logger.info("JWT key rotated successfully")
                return True
                
        except Exception as e:
            logger.error(f"JWT key rotation error: {e}")
            return False
    
    def check_key_rotation_needed(self) -> bool:
        """
        Check if JWT key rotation is needed
        
        Returns:
            True if rotation is needed
        """
        try:
            with db_manager.get_session() as session:
                last_rotation = session.query(KeyRotation).order_by(
                    KeyRotation.rotated_at.desc()
                ).first()
                
                if not last_rotation:
                    return True  # No previous rotation
                
                days_since_rotation = (datetime.now() - last_rotation.rotated_at).days
                return days_since_rotation >= self.key_rotation_days
                
        except Exception as e:
            logger.error(f"Key rotation check error: {e}")
            return False
    
    def _requires_2fa(self, user: User) -> bool:
        """Check if user requires 2FA"""
        # Admin users always require 2FA
        if user.is_admin:
            return True
        
        # Check if user has 2FA enabled
        if user.two_factor_enabled:
            return True
        
        # Check if user is in grace period
        if user.created_at:
            days_since_creation = (datetime.now() - user.created_at).days
            if days_since_creation > self.grace_period_days:
                return True
        
        return False
    
    def _verify_totp(self, user: User, totp_code: str) -> bool:
        """Verify TOTP code"""
        if not user.totp_secret:
            return False
        
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(totp_code, valid_window=2)

# Global instance
enhanced_auth_manager = EnhancedAuthManager()
