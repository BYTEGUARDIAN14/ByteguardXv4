"""
Rate Limiting and Brute Force Protection for ByteGuardX
Implements per-IP and per-user rate limiting with intelligent blocking
"""

import time
import logging
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
import threading
import json
import os

logger = logging.getLogger(__name__)

class RateLimitType(Enum):
    """Types of rate limiting"""
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"

class BlockReason(Enum):
    """Reasons for blocking"""
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MANUAL_BLOCK = "manual_block"

@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    name: str
    limit: int  # Number of requests
    window: int  # Time window in seconds
    block_duration: int  # Block duration in seconds
    rule_type: RateLimitType = RateLimitType.PER_IP
    endpoints: List[str] = field(default_factory=list)  # Specific endpoints (empty = all)
    
@dataclass
class BlockEntry:
    """Blocked entity entry"""
    identifier: str  # IP address or user ID
    reason: BlockReason
    blocked_at: datetime
    expires_at: datetime
    attempt_count: int = 0
    last_attempt: datetime = None

class RateLimiter:
    """Advanced rate limiter with multiple strategies"""
    
    def __init__(self, storage_path: str = "data/rate_limits"):
        self.storage_path = storage_path
        self._ensure_storage_directory()
        
        # In-memory tracking
        self._request_counts = defaultdict(lambda: defaultdict(deque))
        self._blocked_entities = {}
        self._lock = threading.RLock()
        
        # Default rules
        self.rules = self._get_default_rules()
        
        # Load persistent blocks
        self._load_persistent_blocks()
        
        # Cleanup thread
        self._start_cleanup_thread()
    
    def _ensure_storage_directory(self):
        """Ensure storage directory exists"""
        os.makedirs(self.storage_path, exist_ok=True)
    
    def _get_default_rules(self) -> List[RateLimitRule]:
        """Get default rate limiting rules"""
        return [
            # Authentication endpoints - stricter limits
            RateLimitRule(
                name="auth_login",
                limit=5,
                window=300,  # 5 minutes
                block_duration=900,  # 15 minutes
                rule_type=RateLimitType.PER_IP,
                endpoints=["/auth/login", "/api/auth/login"]
            ),
            RateLimitRule(
                name="auth_register",
                limit=3,
                window=3600,  # 1 hour
                block_duration=3600,  # 1 hour
                rule_type=RateLimitType.PER_IP,
                endpoints=["/auth/register", "/api/auth/register"]
            ),
            
            # API endpoints - moderate limits
            RateLimitRule(
                name="api_general",
                limit=100,
                window=60,  # 1 minute
                block_duration=300,  # 5 minutes
                rule_type=RateLimitType.PER_USER
            ),
            RateLimitRule(
                name="scan_endpoints",
                limit=10,
                window=300,  # 5 minutes
                block_duration=600,  # 10 minutes
                rule_type=RateLimitType.PER_USER,
                endpoints=["/scan", "/api/scan"]
            ),
            
            # Global limits
            RateLimitRule(
                name="global_limit",
                limit=1000,
                window=60,  # 1 minute
                block_duration=60,  # 1 minute
                rule_type=RateLimitType.GLOBAL
            )
        ]
    
    def add_rule(self, rule: RateLimitRule):
        """Add a new rate limiting rule"""
        with self._lock:
            # Remove existing rule with same name
            self.rules = [r for r in self.rules if r.name != rule.name]
            self.rules.append(rule)
            logger.info(f"Added rate limit rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """Remove a rate limiting rule"""
        with self._lock:
            original_count = len(self.rules)
            self.rules = [r for r in self.rules if r.name != rule_name]
            if len(self.rules) < original_count:
                logger.info(f"Removed rate limit rule: {rule_name}")
    
    def check_rate_limit(self, identifier: str, endpoint: str, 
                        user_id: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if request should be rate limited
        Returns: (is_allowed, reason, retry_after_seconds)
        """
        with self._lock:
            current_time = time.time()
            
            # Check if already blocked
            if self._is_blocked(identifier):
                block_entry = self._blocked_entities[identifier]
                retry_after = int((block_entry.expires_at - datetime.now()).total_seconds())
                return False, f"Blocked: {block_entry.reason.value}", max(retry_after, 0)
            
            # Check each applicable rule
            for rule in self.rules:
                if not self._rule_applies(rule, endpoint):
                    continue
                
                # Determine the key to use for this rule
                key = self._get_rate_limit_key(rule, identifier, user_id)
                if not key:
                    continue
                
                # Check rate limit for this rule
                is_allowed, retry_after = self._check_rule(rule, key, current_time)
                if not is_allowed:
                    # Block the entity
                    self._block_entity(identifier, BlockReason.RATE_LIMIT_EXCEEDED, rule.block_duration)
                    return False, f"Rate limit exceeded: {rule.name}", retry_after
            
            # All checks passed
            return True, None, None
    
    def _rule_applies(self, rule: RateLimitRule, endpoint: str) -> bool:
        """Check if rule applies to the endpoint"""
        if not rule.endpoints:
            return True  # Rule applies to all endpoints
        
        return any(endpoint.startswith(ep) for ep in rule.endpoints)
    
    def _get_rate_limit_key(self, rule: RateLimitRule, identifier: str, user_id: Optional[str]) -> Optional[str]:
        """Get the key to use for rate limiting based on rule type"""
        if rule.rule_type == RateLimitType.PER_IP:
            return f"ip:{identifier}"
        elif rule.rule_type == RateLimitType.PER_USER and user_id:
            return f"user:{user_id}"
        elif rule.rule_type == RateLimitType.GLOBAL:
            return "global"
        elif rule.rule_type == RateLimitType.PER_ENDPOINT:
            return f"endpoint:{identifier}"
        
        return None
    
    def _check_rule(self, rule: RateLimitRule, key: str, current_time: float) -> Tuple[bool, int]:
        """Check a specific rule against the key"""
        # Get request history for this key and rule
        requests = self._request_counts[key][rule.name]
        
        # Remove old requests outside the window
        cutoff_time = current_time - rule.window
        while requests and requests[0] <= cutoff_time:
            requests.popleft()
        
        # Check if limit exceeded
        if len(requests) >= rule.limit:
            # Calculate retry after
            oldest_request = requests[0]
            retry_after = int(oldest_request + rule.window - current_time)
            return False, max(retry_after, 1)
        
        # Add current request
        requests.append(current_time)
        return True, 0
    
    def _is_blocked(self, identifier: str) -> bool:
        """Check if identifier is currently blocked"""
        if identifier not in self._blocked_entities:
            return False
        
        block_entry = self._blocked_entities[identifier]
        
        # Check if block has expired
        if datetime.now() >= block_entry.expires_at:
            del self._blocked_entities[identifier]
            return False
        
        return True
    
    def _block_entity(self, identifier: str, reason: BlockReason, duration: int):
        """Block an entity for a specified duration"""
        now = datetime.now()
        expires_at = now + timedelta(seconds=duration)
        
        block_entry = BlockEntry(
            identifier=identifier,
            reason=reason,
            blocked_at=now,
            expires_at=expires_at,
            attempt_count=1,
            last_attempt=now
        )
        
        # If already blocked, increment attempt count and extend block
        if identifier in self._blocked_entities:
            existing = self._blocked_entities[identifier]
            block_entry.attempt_count = existing.attempt_count + 1
            # Exponential backoff for repeated violations
            extended_duration = duration * (2 ** min(block_entry.attempt_count - 1, 5))
            block_entry.expires_at = now + timedelta(seconds=extended_duration)
        
        self._blocked_entities[identifier] = block_entry
        self._save_persistent_block(block_entry)
        
        logger.warning(f"Blocked {identifier} for {reason.value}, expires at {expires_at}")
    
    def unblock_entity(self, identifier: str) -> bool:
        """Manually unblock an entity"""
        with self._lock:
            if identifier in self._blocked_entities:
                del self._blocked_entities[identifier]
                self._remove_persistent_block(identifier)
                logger.info(f"Manually unblocked {identifier}")
                return True
            return False
    
    def get_blocked_entities(self) -> List[BlockEntry]:
        """Get list of currently blocked entities"""
        with self._lock:
            # Clean up expired blocks
            current_time = datetime.now()
            expired = [k for k, v in self._blocked_entities.items() 
                      if current_time >= v.expires_at]
            
            for k in expired:
                del self._blocked_entities[k]
            
            return list(self._blocked_entities.values())
    
    def get_rate_limit_status(self, identifier: str, user_id: Optional[str] = None) -> Dict:
        """Get current rate limit status for an identifier"""
        with self._lock:
            status = {
                'blocked': self._is_blocked(identifier),
                'rules': {}
            }
            
            if status['blocked']:
                block_entry = self._blocked_entities[identifier]
                status['block_info'] = {
                    'reason': block_entry.reason.value,
                    'blocked_at': block_entry.blocked_at.isoformat(),
                    'expires_at': block_entry.expires_at.isoformat(),
                    'attempt_count': block_entry.attempt_count
                }
            
            # Get status for each rule
            current_time = time.time()
            for rule in self.rules:
                key = self._get_rate_limit_key(rule, identifier, user_id)
                if not key:
                    continue
                
                requests = self._request_counts[key][rule.name]
                cutoff_time = current_time - rule.window
                
                # Count recent requests
                recent_requests = sum(1 for req_time in requests if req_time > cutoff_time)
                
                status['rules'][rule.name] = {
                    'limit': rule.limit,
                    'window': rule.window,
                    'current_count': recent_requests,
                    'remaining': max(0, rule.limit - recent_requests),
                    'reset_time': int(cutoff_time + rule.window) if requests else None
                }
            
            return status
    
    def _load_persistent_blocks(self):
        """Load persistent blocks from storage"""
        blocks_file = os.path.join(self.storage_path, "blocks.json")
        if not os.path.exists(blocks_file):
            return
        
        try:
            with open(blocks_file, 'r') as f:
                data = json.load(f)
            
            current_time = datetime.now()
            for block_data in data:
                expires_at = datetime.fromisoformat(block_data['expires_at'])
                
                # Skip expired blocks
                if current_time >= expires_at:
                    continue
                
                block_entry = BlockEntry(
                    identifier=block_data['identifier'],
                    reason=BlockReason(block_data['reason']),
                    blocked_at=datetime.fromisoformat(block_data['blocked_at']),
                    expires_at=expires_at,
                    attempt_count=block_data.get('attempt_count', 1),
                    last_attempt=datetime.fromisoformat(block_data['last_attempt']) if block_data.get('last_attempt') else None
                )
                
                self._blocked_entities[block_entry.identifier] = block_entry
            
            logger.info(f"Loaded {len(self._blocked_entities)} persistent blocks")
            
        except Exception as e:
            logger.error(f"Failed to load persistent blocks: {e}")
    
    def _save_persistent_block(self, block_entry: BlockEntry):
        """Save a block entry to persistent storage"""
        blocks_file = os.path.join(self.storage_path, "blocks.json")
        
        # Load existing blocks
        blocks = []
        if os.path.exists(blocks_file):
            try:
                with open(blocks_file, 'r') as f:
                    blocks = json.load(f)
            except Exception:
                blocks = []
        
        # Remove existing entry for this identifier
        blocks = [b for b in blocks if b['identifier'] != block_entry.identifier]
        
        # Add new entry
        block_data = {
            'identifier': block_entry.identifier,
            'reason': block_entry.reason.value,
            'blocked_at': block_entry.blocked_at.isoformat(),
            'expires_at': block_entry.expires_at.isoformat(),
            'attempt_count': block_entry.attempt_count,
            'last_attempt': block_entry.last_attempt.isoformat() if block_entry.last_attempt else None
        }
        blocks.append(block_data)
        
        # Save back to file
        try:
            with open(blocks_file, 'w') as f:
                json.dump(blocks, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save persistent block: {e}")
    
    def _remove_persistent_block(self, identifier: str):
        """Remove a block entry from persistent storage"""
        blocks_file = os.path.join(self.storage_path, "blocks.json")
        
        if not os.path.exists(blocks_file):
            return
        
        try:
            with open(blocks_file, 'r') as f:
                blocks = json.load(f)
            
            # Remove the block
            blocks = [b for b in blocks if b['identifier'] != identifier]
            
            with open(blocks_file, 'w') as f:
                json.dump(blocks, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to remove persistent block: {e}")
    
    def _start_cleanup_thread(self):
        """Start background thread for cleanup"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(300)  # Run every 5 minutes
                    self._cleanup_expired_data()
                except Exception as e:
                    logger.error(f"Cleanup thread error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_data(self):
        """Clean up expired rate limit data"""
        with self._lock:
            current_time = time.time()
            
            # Clean up request counts
            for key_dict in self._request_counts.values():
                for rule_name, requests in key_dict.items():
                    # Find the rule to get its window
                    rule = next((r for r in self.rules if r.name == rule_name), None)
                    if not rule:
                        continue
                    
                    cutoff_time = current_time - rule.window
                    while requests and requests[0] <= cutoff_time:
                        requests.popleft()
            
            # Clean up expired blocks
            expired_blocks = [k for k, v in self._blocked_entities.items() 
                            if datetime.now() >= v.expires_at]
            
            for k in expired_blocks:
                del self._blocked_entities[k]
            
            if expired_blocks:
                logger.info(f"Cleaned up {len(expired_blocks)} expired blocks")

class BruteForceProtection:
    """Specialized brute force protection for authentication"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.failed_attempts = defaultdict(list)
        self.lock = threading.RLock()
        
        # Brute force detection thresholds
        self.max_attempts = 5
        self.time_window = 300  # 5 minutes
        self.block_duration = 900  # 15 minutes
    
    def record_failed_attempt(self, identifier: str, endpoint: str = "login"):
        """Record a failed authentication attempt"""
        with self.lock:
            current_time = time.time()
            
            # Clean old attempts
            cutoff_time = current_time - self.time_window
            self.failed_attempts[identifier] = [
                t for t in self.failed_attempts[identifier] if t > cutoff_time
            ]
            
            # Add current attempt
            self.failed_attempts[identifier].append(current_time)
            
            # Check if threshold exceeded
            if len(self.failed_attempts[identifier]) >= self.max_attempts:
                self.rate_limiter._block_entity(
                    identifier, 
                    BlockReason.BRUTE_FORCE_DETECTED, 
                    self.block_duration
                )
                logger.warning(f"Brute force detected for {identifier}")
    
    def record_successful_attempt(self, identifier: str):
        """Record a successful authentication (clears failed attempts)"""
        with self.lock:
            if identifier in self.failed_attempts:
                del self.failed_attempts[identifier]
    
    def is_brute_force_detected(self, identifier: str) -> bool:
        """Check if brute force is detected for identifier"""
        with self.lock:
            current_time = time.time()
            cutoff_time = current_time - self.time_window
            
            # Clean old attempts
            self.failed_attempts[identifier] = [
                t for t in self.failed_attempts[identifier] if t > cutoff_time
            ]
            
            return len(self.failed_attempts[identifier]) >= self.max_attempts

# Global instances
rate_limiter = RateLimiter()
brute_force_protection = BruteForceProtection(rate_limiter)

def rate_limited(limit: int, window: int, per: str = 'ip'):
    """
    Decorator for rate limiting Flask endpoints

    Args:
        limit: Number of requests allowed
        window: Time window in seconds
        per: Rate limit per 'ip', 'user', or 'endpoint'
    """
    def decorator(func):
        from functools import wraps
        from flask import request, jsonify, g

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Determine identifier based on 'per' parameter
            if per == 'ip':
                identifier = request.remote_addr
            elif per == 'user':
                identifier = getattr(g, 'user_id', request.remote_addr)
            elif per == 'endpoint':
                identifier = f"{request.endpoint}:{request.remote_addr}"
            else:
                identifier = request.remote_addr

            endpoint = request.endpoint or func.__name__
            user_id = getattr(g, 'user_id', None)

            # Check rate limit
            is_allowed, reason, retry_after = rate_limiter.check_rate_limit(
                identifier=identifier,
                endpoint=endpoint,
                user_id=user_id
            )

            if not is_allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': reason,
                    'retry_after': retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response

            return func(*args, **kwargs)

        return wrapper
    return decorator
