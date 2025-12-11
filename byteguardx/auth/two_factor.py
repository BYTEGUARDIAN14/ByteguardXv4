"""
Two-Factor Authentication (2FA) Implementation for ByteGuardX
Provides TOTP-based 2FA with QR code generation and backup codes
"""

import pyotp
import qrcode
import io
import base64
import secrets
import logging
from typing import List, Tuple, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class TwoFactorAuth:
    """Two-Factor Authentication manager"""
    
    def __init__(self):
        self.issuer_name = "ByteGuardX"
        self.backup_codes_count = 10
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email: str, secret: str) -> str:
        """
        Generate QR code for TOTP setup
        Returns: base64 encoded QR code image
        """
        try:
            # Create TOTP URI
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_email,
                issuer_name=self.issuer_name
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            img_buffer = io.BytesIO()
            img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
            return f"data:image/png;base64,{img_base64}"
            
        except Exception as e:
            logger.error(f"QR code generation error: {e}")
            return ""
    
    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP token
        Args:
            secret: User's TOTP secret
            token: 6-digit token from authenticator app
            window: Time window tolerance (default 1 = ±30 seconds)
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return False
    
    def generate_backup_codes(self) -> List[str]:
        """Generate backup codes for 2FA recovery"""
        backup_codes = []
        for _ in range(self.backup_codes_count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            backup_codes.append(code)
        
        return backup_codes
    
    def verify_backup_code(self, user_backup_codes: List[str], provided_code: str) -> Tuple[bool, List[str]]:
        """
        Verify backup code and remove it from the list
        Returns: (is_valid, updated_backup_codes_list)
        """
        provided_code = provided_code.upper().strip()
        
        if provided_code in user_backup_codes:
            # Remove used backup code
            updated_codes = [code for code in user_backup_codes if code != provided_code]
            return True, updated_codes
        
        return False, user_backup_codes
    
    def is_setup_required(self, user) -> bool:
        """Check if 2FA setup is required for user"""
        return user.requires_2fa and not user.has_2fa_enabled
    
    def get_setup_instructions(self) -> dict:
        """Get 2FA setup instructions"""
        return {
            "step1": "Install an authenticator app (Google Authenticator, Authy, etc.)",
            "step2": "Scan the QR code with your authenticator app",
            "step3": "Enter the 6-digit code from your app to verify setup",
            "step4": "Save your backup codes in a secure location",
            "apps": [
                "Google Authenticator",
                "Authy",
                "Microsoft Authenticator",
                "1Password",
                "Bitwarden"
            ]
        }

class TwoFactorAuthManager:
    """Manager for 2FA operations with user integration"""
    
    def __init__(self):
        self.tfa = TwoFactorAuth()
        self.max_failed_attempts = 3
        self.lockout_duration = timedelta(minutes=15)
    
    def initiate_2fa_setup(self, user) -> dict:
        """
        Initiate 2FA setup for user
        Returns: setup data including QR code and backup codes
        """
        try:
            # Generate new secret
            secret = self.tfa.generate_secret()
            
            # Generate QR code
            qr_code = self.tfa.generate_qr_code(user.email, secret)
            
            # Generate backup codes
            backup_codes = self.tfa.generate_backup_codes()
            
            # Store secret temporarily (not yet activated)
            user.temp_2fa_secret = secret
            user.temp_backup_codes = backup_codes
            
            return {
                'secret': secret,
                'qr_code': qr_code,
                'backup_codes': backup_codes,
                'instructions': self.tfa.get_setup_instructions()
            }
            
        except Exception as e:
            logger.error(f"2FA setup initiation error: {e}")
            raise Exception("Failed to initiate 2FA setup")
    
    def complete_2fa_setup(self, user, verification_token: str) -> bool:
        """
        Complete 2FA setup by verifying the initial token
        """
        try:
            if not hasattr(user, 'temp_2fa_secret') or not user.temp_2fa_secret:
                return False
            
            # Verify the token
            if self.tfa.verify_token(user.temp_2fa_secret, verification_token):
                # Activate 2FA
                user.tfa_secret = user.temp_2fa_secret
                user.backup_codes = user.temp_backup_codes
                user.has_2fa_enabled = True
                user.tfa_setup_completed_at = datetime.now()
                
                # Clear temporary data
                user.temp_2fa_secret = None
                user.temp_backup_codes = None
                
                logger.info(f"2FA setup completed for user {user.email}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"2FA setup completion error: {e}")
            return False
    
    def verify_2fa_login(self, user, token: str, is_backup_code: bool = False) -> Tuple[bool, str]:
        """
        Verify 2FA token during login
        Returns: (is_valid, message)
        """
        try:
            if not user.has_2fa_enabled:
                return False, "2FA not enabled for user"
            
            # Check if user is locked out
            if self._is_user_locked_out(user):
                return False, "Account temporarily locked due to failed 2FA attempts"
            
            if is_backup_code:
                # Verify backup code
                is_valid, updated_codes = self.tfa.verify_backup_code(
                    user.backup_codes or [], token
                )
                
                if is_valid:
                    user.backup_codes = updated_codes
                    self._reset_failed_attempts(user)
                    logger.info(f"Backup code used for user {user.email}")
                    return True, "Backup code verified"
                else:
                    self._increment_failed_attempts(user)
                    return False, "Invalid backup code"
            else:
                # Verify TOTP token
                if self.tfa.verify_token(user.tfa_secret, token):
                    self._reset_failed_attempts(user)
                    return True, "2FA token verified"
                else:
                    self._increment_failed_attempts(user)
                    return False, "Invalid 2FA token"
                    
        except Exception as e:
            logger.error(f"2FA verification error: {e}")
            return False, "2FA verification failed"
    
    def disable_2fa(self, user, current_token: str) -> bool:
        """
        Disable 2FA for user (requires current token verification)
        """
        try:
            if not user.has_2fa_enabled:
                return True  # Already disabled
            
            # Verify current token before disabling
            if self.tfa.verify_token(user.tfa_secret, current_token):
                user.has_2fa_enabled = False
                user.tfa_secret = None
                user.backup_codes = None
                user.tfa_failed_attempts = 0
                user.tfa_locked_until = None
                
                logger.info(f"2FA disabled for user {user.email}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"2FA disable error: {e}")
            return False
    
    def regenerate_backup_codes(self, user, current_token: str) -> Optional[List[str]]:
        """
        Regenerate backup codes (requires current token verification)
        """
        try:
            if not user.has_2fa_enabled:
                return None
            
            # Verify current token
            if self.tfa.verify_token(user.tfa_secret, current_token):
                new_backup_codes = self.tfa.generate_backup_codes()
                user.backup_codes = new_backup_codes
                
                logger.info(f"Backup codes regenerated for user {user.email}")
                return new_backup_codes
            
            return None
            
        except Exception as e:
            logger.error(f"Backup code regeneration error: {e}")
            return None
    
    def _is_user_locked_out(self, user) -> bool:
        """Check if user is locked out due to failed 2FA attempts"""
        if not hasattr(user, 'tfa_locked_until') or not user.tfa_locked_until:
            return False
        
        return datetime.now() < user.tfa_locked_until
    
    def _increment_failed_attempts(self, user):
        """Increment failed 2FA attempts and lock if necessary"""
        if not hasattr(user, 'tfa_failed_attempts'):
            user.tfa_failed_attempts = 0
        
        user.tfa_failed_attempts += 1
        
        if user.tfa_failed_attempts >= self.max_failed_attempts:
            user.tfa_locked_until = datetime.now() + self.lockout_duration
            logger.warning(f"User {user.email} locked out due to failed 2FA attempts")
    
    def _reset_failed_attempts(self, user):
        """Reset failed 2FA attempts"""
        user.tfa_failed_attempts = 0
        user.tfa_locked_until = None

# Global instance
tfa_manager = TwoFactorAuthManager()
