"""
Two-Factor Authentication (2FA) implementation for ByteGuardX
Supports TOTP (Time-based One-Time Password) authentication
"""

import os
import qrcode
import pyotp
import secrets
import logging
from io import BytesIO
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class TwoFactorMethod(Enum):
    """Supported 2FA methods"""
    TOTP = "totp"
    SMS = "sms"  # Future implementation
    EMAIL = "email"  # Future implementation

@dataclass
class TwoFactorConfig:
    """2FA configuration for a user"""
    user_id: str
    method: TwoFactorMethod
    secret_key: str
    backup_codes: list
    is_enabled: bool = False
    created_at: datetime = None
    last_used: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class TOTPManager:
    """Time-based One-Time Password manager"""
    
    def __init__(self, issuer_name: str = "ByteGuardX"):
        self.issuer_name = issuer_name
        self.window = 1  # Allow 1 time step tolerance (30 seconds)
        
    def generate_secret(self) -> str:
        """Generate a new TOTP secret key"""
        return pyotp.random_base32()
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for account recovery"""
        return [secrets.token_hex(4).upper() for _ in range(count)]
    
    def get_provisioning_uri(self, secret: str, user_email: str) -> str:
        """Generate provisioning URI for QR code"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, secret: str, user_email: str) -> bytes:
        """Generate QR code image for TOTP setup"""
        uri = self.get_provisioning_uri(secret, user_email)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def verify_token(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=self.window)
        except Exception as e:
            logger.error(f"TOTP verification failed: {e}")
            return False
    
    def get_current_token(self, secret: str) -> str:
        """Get current TOTP token (for testing)"""
        totp = pyotp.TOTP(secret)
        return totp.now()

class TwoFactorAuth:
    """Main 2FA management class"""
    
    def __init__(self, storage_path: str = "data/2fa"):
        self.storage_path = storage_path
        self.totp_manager = TOTPManager()
        self._ensure_storage_directory()
        
        # In-memory cache for active 2FA sessions
        self._active_sessions = {}
        self._session_timeout = timedelta(minutes=5)
    
    def _ensure_storage_directory(self):
        """Ensure storage directory exists"""
        os.makedirs(self.storage_path, exist_ok=True)
    
    def _get_user_2fa_file(self, user_id: str) -> str:
        """Get file path for user's 2FA config"""
        return os.path.join(self.storage_path, f"{user_id}_2fa.json")
    
    def _load_user_config(self, user_id: str) -> Optional[TwoFactorConfig]:
        """Load user's 2FA configuration"""
        import json
        
        config_file = self._get_user_2fa_file(user_id)
        if not os.path.exists(config_file):
            return None
        
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            return TwoFactorConfig(
                user_id=data['user_id'],
                method=TwoFactorMethod(data['method']),
                secret_key=data['secret_key'],
                backup_codes=data['backup_codes'],
                is_enabled=data['is_enabled'],
                created_at=datetime.fromisoformat(data['created_at']),
                last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None
            )
        except Exception as e:
            logger.error(f"Failed to load 2FA config for user {user_id}: {e}")
            return None
    
    def _save_user_config(self, config: TwoFactorConfig):
        """Save user's 2FA configuration"""
        import json
        
        config_file = self._get_user_2fa_file(config.user_id)
        
        data = {
            'user_id': config.user_id,
            'method': config.method.value,
            'secret_key': config.secret_key,
            'backup_codes': config.backup_codes,
            'is_enabled': config.is_enabled,
            'created_at': config.created_at.isoformat(),
            'last_used': config.last_used.isoformat() if config.last_used else None
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save 2FA config for user {config.user_id}: {e}")
            raise
    
    def setup_totp(self, user_id: str, user_email: str) -> Dict[str, Any]:
        """Setup TOTP for a user"""
        # Generate secret and backup codes
        secret = self.totp_manager.generate_secret()
        backup_codes = self.totp_manager.generate_backup_codes()
        
        # Create configuration (not enabled yet)
        config = TwoFactorConfig(
            user_id=user_id,
            method=TwoFactorMethod.TOTP,
            secret_key=secret,
            backup_codes=backup_codes,
            is_enabled=False
        )
        
        # Save configuration
        self._save_user_config(config)
        
        # Generate QR code
        qr_code = self.totp_manager.generate_qr_code(secret, user_email)
        
        return {
            'secret': secret,
            'qr_code': qr_code,
            'backup_codes': backup_codes,
            'manual_entry_key': secret
        }
    
    def enable_totp(self, user_id: str, verification_token: str) -> bool:
        """Enable TOTP after verification"""
        config = self._load_user_config(user_id)
        if not config:
            return False
        
        # Verify the token
        if not self.totp_manager.verify_token(config.secret_key, verification_token):
            return False
        
        # Enable 2FA
        config.is_enabled = True
        config.last_used = datetime.now()
        self._save_user_config(config)
        
        logger.info(f"2FA enabled for user {user_id}")
        return True
    
    def disable_2fa(self, user_id: str) -> bool:
        """Disable 2FA for a user"""
        config = self._load_user_config(user_id)
        if not config:
            return False
        
        config.is_enabled = False
        self._save_user_config(config)
        
        logger.info(f"2FA disabled for user {user_id}")
        return True
    
    def is_2fa_enabled(self, user_id: str) -> bool:
        """Check if 2FA is enabled for a user"""
        config = self._load_user_config(user_id)
        return config and config.is_enabled
    
    def verify_2fa(self, user_id: str, token: str) -> bool:
        """Verify 2FA token"""
        config = self._load_user_config(user_id)
        if not config or not config.is_enabled:
            return False
        
        # Check if it's a backup code
        if token.upper() in config.backup_codes:
            # Remove used backup code
            config.backup_codes.remove(token.upper())
            config.last_used = datetime.now()
            self._save_user_config(config)
            logger.info(f"Backup code used for user {user_id}")
            return True
        
        # Verify TOTP token
        if config.method == TwoFactorMethod.TOTP:
            if self.totp_manager.verify_token(config.secret_key, token):
                config.last_used = datetime.now()
                self._save_user_config(config)
                return True
        
        return False
    
    def get_backup_codes(self, user_id: str) -> Optional[list]:
        """Get remaining backup codes for a user"""
        config = self._load_user_config(user_id)
        if not config:
            return None
        return config.backup_codes.copy()
    
    def regenerate_backup_codes(self, user_id: str) -> Optional[list]:
        """Regenerate backup codes for a user"""
        config = self._load_user_config(user_id)
        if not config:
            return None
        
        config.backup_codes = self.totp_manager.generate_backup_codes()
        self._save_user_config(config)
        
        return config.backup_codes.copy()

# Global instance
two_factor_auth = TwoFactorAuth()
