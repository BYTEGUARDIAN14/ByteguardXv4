"""
Enhanced JWT utilities with token rotation, blacklisting, and security features
"""

import os
import jwt
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Set
import secrets
import threading
from dataclasses import dataclass
import json
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class TokenInfo:
    """Token information for tracking"""
    token_id: str
    user_id: str
    issued_at: datetime
    expires_at: datetime
    token_type: str  # 'access' or 'refresh'

class TokenBlacklist:
    """Thread-safe token blacklist for revoked tokens"""
    
    def __init__(self, storage_path: str = "data/token_blacklist.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(exist_ok=True)
        
        self._blacklisted_tokens: Set[str] = set()
        self._token_info: Dict[str, TokenInfo] = {}
        self._lock = threading.RLock()
        
        # Load existing blacklist
        self._load_blacklist()
        
        # Cleanup interval (remove expired tokens)
        self._last_cleanup = datetime.now()
        self._cleanup_interval = timedelta(hours=1)
    
    def blacklist_token(self, token: str, token_info: Optional[TokenInfo] = None):
        """Add token to blacklist"""
        with self._lock:
            self._blacklisted_tokens.add(token)
            if token_info:
                self._token_info[token] = token_info
            
            self._save_blacklist()
            logger.info(f"Token blacklisted: {token[:20]}...")
    
    def is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        with self._lock:
            # Cleanup expired tokens periodically
            if datetime.now() - self._last_cleanup > self._cleanup_interval:
                self._cleanup_expired_tokens()
            
            return token in self._blacklisted_tokens
    
    def blacklist_user_tokens(self, user_id: str):
        """Blacklist all tokens for a specific user"""
        with self._lock:
            tokens_to_blacklist = [
                token for token, info in self._token_info.items()
                if info.user_id == user_id and token not in self._blacklisted_tokens
            ]
            
            for token in tokens_to_blacklist:
                self._blacklisted_tokens.add(token)
            
            self._save_blacklist()
            logger.info(f"Blacklisted {len(tokens_to_blacklist)} tokens for user {user_id}")
    
    def _cleanup_expired_tokens(self):
        """Remove expired tokens from blacklist"""
        current_time = datetime.now()
        expired_tokens = []
        
        for token, info in self._token_info.items():
            if info.expires_at < current_time:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            self._blacklisted_tokens.discard(token)
            self._token_info.pop(token, None)
        
        if expired_tokens:
            self._save_blacklist()
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens from blacklist")
        
        self._last_cleanup = current_time
    
    def _load_blacklist(self):
        """Load blacklist from storage"""
        try:
            if self.storage_path.exists():
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    
                self._blacklisted_tokens = set(data.get('tokens', []))
                
                # Load token info
                for token_data in data.get('token_info', []):
                    token_info = TokenInfo(
                        token_id=token_data['token_id'],
                        user_id=token_data['user_id'],
                        issued_at=datetime.fromisoformat(token_data['issued_at']),
                        expires_at=datetime.fromisoformat(token_data['expires_at']),
                        token_type=token_data['token_type']
                    )
                    self._token_info[token_data['token']] = token_info
                
                logger.info(f"Loaded {len(self._blacklisted_tokens)} blacklisted tokens")
        except Exception as e:
            logger.error(f"Failed to load token blacklist: {e}")
    
    def _save_blacklist(self):
        """Save blacklist to storage"""
        try:
            data = {
                'tokens': list(self._blacklisted_tokens),
                'token_info': [
                    {
                        'token': token,
                        'token_id': info.token_id,
                        'user_id': info.user_id,
                        'issued_at': info.issued_at.isoformat(),
                        'expires_at': info.expires_at.isoformat(),
                        'token_type': info.token_type
                    }
                    for token, info in self._token_info.items()
                ]
            }
            
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save token blacklist: {e}")

class JWTManager:
    """Enhanced JWT manager with rotation and security features"""
    
    def __init__(self):
        self.secret_key = self._get_secret_key()
        self.algorithm = 'HS256'
        self.access_token_expires = timedelta(hours=1)
        self.refresh_token_expires = timedelta(days=7)
        
        # Token rotation settings
        self.rotation_threshold = timedelta(minutes=30)  # Rotate if token expires in 30 min
        
    def _get_secret_key(self) -> str:
        """Get JWT secret key from environment or generate one"""
        secret = os.environ.get('JWT_SECRET_KEY')
        if not secret:
            # Generate a secure random secret for development
            secret = secrets.token_urlsafe(32)
            logger.warning("Using generated JWT secret key. Set JWT_SECRET_KEY environment variable for production.")
        return secret
    
    def generate_tokens(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate access and refresh token pair"""
        now = datetime.now()
        token_id = secrets.token_urlsafe(16)
        
        # Access token payload
        access_payload = {
            'sub': user_id,
            'iat': now,
            'exp': now + self.access_token_expires,
            'type': 'access',
            'jti': token_id,
            **user_data
        }
        
        # Refresh token payload
        refresh_payload = {
            'sub': user_id,
            'iat': now,
            'exp': now + self.refresh_token_expires,
            'type': 'refresh',
            'jti': token_id + '_refresh'
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': int(self.access_token_expires.total_seconds())
        }
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise jwt.ExpiredSignatureError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str, token_blacklist: TokenBlacklist) -> Optional[Dict[str, str]]:
        """Generate new access token using refresh token"""
        try:
            # Validate refresh token
            if token_blacklist.is_blacklisted(refresh_token):
                raise jwt.InvalidTokenError("Refresh token has been revoked")
            
            payload = self.decode_token(refresh_token)
            
            if payload.get('type') != 'refresh':
                raise jwt.InvalidTokenError("Invalid token type for refresh")
            
            user_id = payload.get('sub')
            if not user_id:
                raise jwt.InvalidTokenError("Invalid token payload")
            
            # Get fresh user data from database
            from ..database.connection_pool import db_manager
            from ..database.models import User
            
            with db_manager.get_session() as session:
                user = session.query(User).filter(User.id == user_id).first()
                if not user or not user.is_active:
                    raise jwt.InvalidTokenError("User not found or inactive")
                
                user_data = {
                    'email': user.email,
                    'username': user.username,
                    'role': user.role,
                    'subscription_tier': user.subscription_tier
                }
            
            # Generate new token pair
            new_tokens = self.generate_tokens(user_id, user_data)
            
            # Blacklist old refresh token
            token_info = TokenInfo(
                token_id=payload.get('jti', ''),
                user_id=user_id,
                issued_at=datetime.fromtimestamp(payload.get('iat', 0)),
                expires_at=datetime.fromtimestamp(payload.get('exp', 0)),
                token_type='refresh'
            )
            token_blacklist.blacklist_token(refresh_token, token_info)
            
            return new_tokens
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None
    
    def should_rotate_token(self, payload: Dict[str, Any]) -> bool:
        """Check if token should be rotated based on expiration time"""
        exp = payload.get('exp')
        if not exp:
            return False
        
        expires_at = datetime.fromtimestamp(exp)
        time_until_expiry = expires_at - datetime.now()
        
        return time_until_expiry <= self.rotation_threshold
    
    def revoke_user_tokens(self, user_id: str, token_blacklist: TokenBlacklist):
        """Revoke all tokens for a user (e.g., on password change)"""
        token_blacklist.blacklist_user_tokens(user_id)
        logger.info(f"Revoked all tokens for user {user_id}")

# Global instances
jwt_manager = JWTManager()
token_blacklist = TokenBlacklist()
