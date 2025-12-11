"""
Enhanced Refresh Token Management with Rotation and Blacklisting
Implements secure token rotation and invalidation mechanisms
"""

import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

class RefreshTokenManager:
    """Manages refresh tokens with rotation and blacklisting"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.tokens_file = self.data_dir / "refresh_tokens.json"
        self.blacklist_file = self.data_dir / "token_blacklist.json"
        
        # Token settings
        self.token_length = 64
        self.expiry_days = 7
        self.rotation_threshold_hours = 24  # Rotate if token expires within 24 hours
        
        # Initialize files
        self._init_files()
    
    def _init_files(self):
        """Initialize token storage files"""
        for file_path in [self.tokens_file, self.blacklist_file]:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump({}, f)
    
    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def generate_refresh_token(self, user_id: str, device_info: str = "") -> str:
        """Generate a new refresh token for user"""
        token = secrets.token_urlsafe(self.token_length)
        token_hash = self._hash_token(token)
        
        expires_at = datetime.now() + timedelta(days=self.expiry_days)
        
        token_data = {
            'user_id': user_id,
            'token_hash': token_hash,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat(),
            'device_info': device_info,
            'is_active': True,
            'rotation_count': 0
        }
        
        # Store token data
        tokens = self._load_tokens()
        tokens[token_hash] = token_data
        self._save_tokens(tokens)
        
        logger.info(f"Generated refresh token for user {user_id}")
        return token
    
    def validate_refresh_token(self, token: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Validate refresh token and return user info
        Returns: (is_valid, user_id, token_data)
        """
        if not token:
            return False, None, None
        
        token_hash = self._hash_token(token)
        
        # Check if token is blacklisted
        if self._is_blacklisted(token_hash):
            logger.warning(f"Attempted use of blacklisted token: {token_hash[:16]}...")
            return False, None, None
        
        # Load and validate token
        tokens = self._load_tokens()
        token_data = tokens.get(token_hash)
        
        if not token_data:
            logger.warning(f"Invalid refresh token: {token_hash[:16]}...")
            return False, None, None
        
        if not token_data.get('is_active', False):
            logger.warning(f"Inactive refresh token used: {token_hash[:16]}...")
            return False, None, None
        
        # Check expiration
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expires_at:
            logger.warning(f"Expired refresh token used: {token_hash[:16]}...")
            self._deactivate_token(token_hash)
            return False, None, None
        
        return True, token_data['user_id'], token_data
    
    def rotate_token_if_needed(self, token: str, user_id: str) -> Optional[str]:
        """
        Rotate token if it's close to expiry
        Returns new token if rotated, None otherwise
        """
        is_valid, token_user_id, token_data = self.validate_refresh_token(token)
        
        if not is_valid or token_user_id != user_id:
            return None
        
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        time_until_expiry = expires_at - datetime.now()
        
        # Rotate if token expires within threshold
        if time_until_expiry < timedelta(hours=self.rotation_threshold_hours):
            logger.info(f"Rotating refresh token for user {user_id}")
            
            # Invalidate old token
            self.invalidate_token(token)
            
            # Generate new token
            device_info = token_data.get('device_info', '')
            new_token = self.generate_refresh_token(user_id, device_info)
            
            return new_token
        
        return None
    
    def invalidate_token(self, token: str):
        """Invalidate a specific refresh token"""
        token_hash = self._hash_token(token)
        
        # Add to blacklist
        self._add_to_blacklist(token_hash)
        
        # Deactivate token
        self._deactivate_token(token_hash)
        
        logger.info(f"Invalidated refresh token: {token_hash[:16]}...")
    
    def invalidate_all_user_tokens(self, user_id: str):
        """Invalidate all refresh tokens for a user (logout from all devices)"""
        tokens = self._load_tokens()
        invalidated_count = 0
        
        for token_hash, token_data in tokens.items():
            if token_data.get('user_id') == user_id and token_data.get('is_active'):
                self._add_to_blacklist(token_hash)
                token_data['is_active'] = False
                invalidated_count += 1
        
        self._save_tokens(tokens)
        logger.info(f"Invalidated {invalidated_count} refresh tokens for user {user_id}")
    
    def cleanup_expired_tokens(self):
        """Clean up expired tokens and old blacklist entries"""
        tokens = self._load_tokens()
        blacklist = self._load_blacklist()
        
        current_time = datetime.now()
        
        # Clean up expired tokens
        expired_tokens = []
        for token_hash, token_data in tokens.items():
            expires_at = datetime.fromisoformat(token_data['expires_at'])
            if current_time > expires_at:
                expired_tokens.append(token_hash)
        
        for token_hash in expired_tokens:
            del tokens[token_hash]
        
        # Clean up old blacklist entries (older than 30 days)
        cutoff_date = current_time - timedelta(days=30)
        expired_blacklist = []
        
        for token_hash, blacklist_data in blacklist.items():
            blacklisted_at = datetime.fromisoformat(blacklist_data['blacklisted_at'])
            if blacklisted_at < cutoff_date:
                expired_blacklist.append(token_hash)
        
        for token_hash in expired_blacklist:
            del blacklist[token_hash]
        
        # Save cleaned data
        self._save_tokens(tokens)
        self._save_blacklist(blacklist)
        
        logger.info(f"Cleaned up {len(expired_tokens)} expired tokens and {len(expired_blacklist)} old blacklist entries")

    def force_rotate_user_tokens(self, user_id: str, reason: str = "Security event"):
        """Force rotation of all tokens for a user (security breach response)"""
        try:
            tokens_data = self._load_tokens()
            user_tokens = []

            # Find all tokens for user
            for token_hash, token_info in tokens_data.items():
                if token_info.get('user_id') == user_id:
                    user_tokens.append(token_hash)

            # Invalidate all existing tokens
            for token_hash in user_tokens:
                self._add_to_blacklist(token_hash, reason)
                if token_hash in tokens_data:
                    tokens_data[token_hash]['is_active'] = False

            self._save_tokens(tokens_data)

            logger.warning(f"Force rotated {len(user_tokens)} tokens for user {user_id} - Reason: {reason}")

        except Exception as e:
            logger.error(f"Force token rotation failed for user {user_id}: {e}")

    def _is_blacklisted(self, token_hash: str) -> bool:
        """Check if token is blacklisted"""
        blacklist = self._load_blacklist()
        return token_hash in blacklist
    
    def _add_to_blacklist(self, token_hash: str, reason: str = 'invalidated'):
        """Add token to blacklist"""
        blacklist = self._load_blacklist()
        blacklist[token_hash] = {
            'blacklisted_at': datetime.now().isoformat(),
            'reason': reason
        }
        self._save_blacklist(blacklist)
    
    def _deactivate_token(self, token_hash: str):
        """Deactivate a token"""
        tokens = self._load_tokens()
        if token_hash in tokens:
            tokens[token_hash]['is_active'] = False
            self._save_tokens(tokens)
    
    def _load_tokens(self) -> Dict:
        """Load tokens from file"""
        try:
            with open(self.tokens_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_tokens(self, tokens: Dict):
        """Save tokens to file"""
        with open(self.tokens_file, 'w') as f:
            json.dump(tokens, f, indent=2)
    
    def _load_blacklist(self) -> Dict:
        """Load blacklist from file"""
        try:
            with open(self.blacklist_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_blacklist(self, blacklist: Dict):
        """Save blacklist to file"""
        with open(self.blacklist_file, 'w') as f:
            json.dump(blacklist, f, indent=2)

# Global instance
refresh_token_manager = RefreshTokenManager()
