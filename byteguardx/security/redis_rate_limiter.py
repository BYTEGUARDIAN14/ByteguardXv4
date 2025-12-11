#!/usr/bin/env python3
"""
Redis-Based Production Rate Limiter for ByteGuardX
Implements distributed rate limiting with Redis backend
"""

import logging
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import os

try:
    import redis
    from redis.exceptions import RedisError, ConnectionError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    name: str
    requests: int
    window_seconds: int
    scope: str  # 'ip', 'user', 'endpoint', 'global'
    endpoints: List[str]
    block_duration_seconds: int
    is_active: bool

@dataclass
class RateLimitViolation:
    """Rate limit violation record"""
    identifier: str
    rule_name: str
    violation_time: datetime
    requests_made: int
    limit: int
    window_seconds: int
    blocked_until: datetime

class RedisRateLimiter:
    """
    Production-grade Redis-based rate limiter
    """
    
    def __init__(self, redis_url: str = None):
        if not REDIS_AVAILABLE:
            logger.error("Redis not available - install redis package")
            self.redis_client = None
            self.fallback_mode = True
            return
        
        # Redis configuration
        redis_url = redis_url or os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        
        try:
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            self.redis_client.ping()
            self.fallback_mode = False
            logger.info("Redis rate limiter initialized successfully")
            
        except (RedisError, ConnectionError) as e:
            logger.warning(f"Redis connection failed, using fallback: {e}")
            self.redis_client = None
            self.fallback_mode = True
            self._init_fallback_storage()
        
        # Rate limiting rules
        self.rules = self._load_default_rules()
        
        # Fallback storage (in-memory)
        if self.fallback_mode:
            self._init_fallback_storage()
    
    def _init_fallback_storage(self):
        """Initialize fallback in-memory storage"""
        self.fallback_storage = {}
        self.fallback_blocks = {}
        logger.warning("Using in-memory fallback for rate limiting - not suitable for production")
    
    def _load_default_rules(self) -> List[RateLimitRule]:
        """Load default rate limiting rules"""
        return [
            # Authentication endpoints - strict limits
            RateLimitRule(
                name="auth_login",
                requests=3,
                window_seconds=900,  # 15 minutes
                scope="ip",
                endpoints=["/api/auth/login", "/auth/login"],
                block_duration_seconds=1800,  # 30 minutes
                is_active=True
            ),
            
            # Registration - prevent spam
            RateLimitRule(
                name="auth_register",
                requests=2,
                window_seconds=3600,  # 1 hour
                scope="ip",
                endpoints=["/api/auth/register", "/auth/register"],
                block_duration_seconds=3600,  # 1 hour
                is_active=True
            ),
            
            # Password reset - prevent abuse
            RateLimitRule(
                name="password_reset",
                requests=3,
                window_seconds=3600,  # 1 hour
                scope="ip",
                endpoints=["/api/auth/reset-password", "/auth/reset-password"],
                block_duration_seconds=3600,  # 1 hour
                is_active=True
            ),
            
            # File upload - resource intensive
            RateLimitRule(
                name="file_upload",
                requests=5,
                window_seconds=300,  # 5 minutes
                scope="user",
                endpoints=["/scan/upload", "/api/v1/scan/upload"],
                block_duration_seconds=600,  # 10 minutes
                is_active=True
            ),
            
            # Directory scanning - resource intensive
            RateLimitRule(
                name="directory_scan",
                requests=3,
                window_seconds=300,  # 5 minutes
                scope="user",
                endpoints=["/api/v1/scan/directory"],
                block_duration_seconds=900,  # 15 minutes
                is_active=True
            ),
            
            # API endpoints - general limits
            RateLimitRule(
                name="api_general",
                requests=100,
                window_seconds=300,  # 5 minutes
                scope="user",
                endpoints=["/api/v1/*"],
                block_duration_seconds=300,  # 5 minutes
                is_active=True
            ),
            
            # Global rate limit - DDoS protection
            RateLimitRule(
                name="global_requests",
                requests=1000,
                window_seconds=3600,  # 1 hour
                scope="ip",
                endpoints=["*"],
                block_duration_seconds=3600,  # 1 hour
                is_active=True
            )
        ]
    
    def check_rate_limit(self, identifier: str, endpoint: str, 
                        user_id: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if request should be rate limited
        Returns: (is_allowed, reason, retry_after_seconds)
        """
        try:
            # Check if blocked
            if self._is_blocked(identifier):
                block_info = self._get_block_info(identifier)
                if block_info:
                    retry_after = int((block_info['blocked_until'] - time.time()))
                    return False, f"Blocked: {block_info['reason']}", max(retry_after, 0)
            
            # Check applicable rules
            for rule in self.rules:
                if not rule.is_active:
                    continue
                
                if not self._rule_applies(rule, endpoint):
                    continue
                
                # Get the appropriate identifier for this rule
                rule_identifier = self._get_rule_identifier(rule, identifier, user_id)
                if not rule_identifier:
                    continue
                
                # Check rate limit for this rule
                is_allowed, current_count = self._check_rule_limit(rule, rule_identifier)
                
                if not is_allowed:
                    # Block the identifier
                    self._block_identifier(identifier, rule, current_count)
                    
                    # Log violation
                    violation = RateLimitViolation(
                        identifier=identifier,
                        rule_name=rule.name,
                        violation_time=datetime.now(),
                        requests_made=current_count,
                        limit=rule.requests,
                        window_seconds=rule.window_seconds,
                        blocked_until=datetime.now() + timedelta(seconds=rule.block_duration_seconds)
                    )
                    
                    self._log_violation(violation)
                    
                    return False, f"Rate limit exceeded: {rule.name}", rule.block_duration_seconds
            
            return True, None, None
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            # Fail open for availability
            return True, None, None
    
    def _rule_applies(self, rule: RateLimitRule, endpoint: str) -> bool:
        """Check if rule applies to endpoint"""
        for rule_endpoint in rule.endpoints:
            if rule_endpoint == "*":
                return True
            elif rule_endpoint.endswith("*"):
                prefix = rule_endpoint[:-1]
                if endpoint.startswith(prefix):
                    return True
            elif rule_endpoint == endpoint:
                return True
        return False
    
    def _get_rule_identifier(self, rule: RateLimitRule, identifier: str, user_id: Optional[str]) -> Optional[str]:
        """Get identifier for rule scope"""
        if rule.scope == "ip":
            return identifier
        elif rule.scope == "user" and user_id:
            return f"user:{user_id}"
        elif rule.scope == "endpoint":
            return f"endpoint:{rule.name}"
        elif rule.scope == "global":
            return "global"
        return None
    
    def _check_rule_limit(self, rule: RateLimitRule, identifier: str) -> Tuple[bool, int]:
        """Check rate limit for specific rule and identifier"""
        if self.fallback_mode:
            return self._check_rule_limit_fallback(rule, identifier)
        
        try:
            key = f"rate_limit:{rule.name}:{identifier}"
            current_time = int(time.time())
            window_start = current_time - rule.window_seconds
            
            # Use Redis sorted set for sliding window
            pipe = self.redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiration
            pipe.expire(key, rule.window_seconds + 60)  # Extra buffer
            
            results = pipe.execute()
            current_count = results[1] + 1  # +1 for current request
            
            return current_count <= rule.requests, current_count
            
        except RedisError as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fallback to in-memory
            return self._check_rule_limit_fallback(rule, identifier)
    
    def _check_rule_limit_fallback(self, rule: RateLimitRule, identifier: str) -> Tuple[bool, int]:
        """Fallback in-memory rate limit check"""
        key = f"{rule.name}:{identifier}"
        current_time = time.time()
        window_start = current_time - rule.window_seconds
        
        # Clean old entries
        if key in self.fallback_storage:
            self.fallback_storage[key] = [
                t for t in self.fallback_storage[key] if t > window_start
            ]
        else:
            self.fallback_storage[key] = []
        
        # Add current request
        self.fallback_storage[key].append(current_time)
        
        current_count = len(self.fallback_storage[key])
        return current_count <= rule.requests, current_count
    
    def _is_blocked(self, identifier: str) -> bool:
        """Check if identifier is currently blocked"""
        if self.fallback_mode:
            return self._is_blocked_fallback(identifier)
        
        try:
            key = f"blocked:{identifier}"
            block_info = self.redis_client.get(key)
            
            if block_info:
                block_data = json.loads(block_info)
                if time.time() < block_data['blocked_until']:
                    return True
                else:
                    # Block expired, remove it
                    self.redis_client.delete(key)
            
            return False
            
        except RedisError as e:
            logger.error(f"Redis block check failed: {e}")
            return self._is_blocked_fallback(identifier)
    
    def _is_blocked_fallback(self, identifier: str) -> bool:
        """Fallback in-memory block check"""
        if identifier in self.fallback_blocks:
            if time.time() < self.fallback_blocks[identifier]['blocked_until']:
                return True
            else:
                del self.fallback_blocks[identifier]
        return False
    
    def _get_block_info(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get block information for identifier"""
        if self.fallback_mode:
            return self.fallback_blocks.get(identifier)
        
        try:
            key = f"blocked:{identifier}"
            block_info = self.redis_client.get(key)
            return json.loads(block_info) if block_info else None
            
        except RedisError as e:
            logger.error(f"Redis block info failed: {e}")
            return self.fallback_blocks.get(identifier)
    
    def _block_identifier(self, identifier: str, rule: RateLimitRule, request_count: int):
        """Block identifier for rule violation"""
        block_until = time.time() + rule.block_duration_seconds
        block_info = {
            'blocked_until': block_until,
            'reason': f"Rate limit exceeded: {rule.name}",
            'rule_name': rule.name,
            'request_count': request_count,
            'limit': rule.requests,
            'blocked_at': time.time()
        }
        
        if self.fallback_mode:
            self.fallback_blocks[identifier] = block_info
        else:
            try:
                key = f"blocked:{identifier}"
                self.redis_client.setex(
                    key, 
                    rule.block_duration_seconds + 60,  # Extra buffer
                    json.dumps(block_info)
                )
            except RedisError as e:
                logger.error(f"Redis block failed: {e}")
                self.fallback_blocks[identifier] = block_info
        
        logger.warning(f"Blocked {identifier} for {rule.block_duration_seconds}s due to {rule.name}")
    
    def _log_violation(self, violation: RateLimitViolation):
        """Log rate limit violation"""
        logger.warning(
            f"Rate limit violation: {violation.identifier} "
            f"exceeded {violation.rule_name} "
            f"({violation.requests_made}/{violation.limit} in {violation.window_seconds}s)"
        )
        
        # Store violation for analytics (optional)
        if not self.fallback_mode:
            try:
                key = f"violations:{violation.identifier}:{int(violation.violation_time.timestamp())}"
                self.redis_client.setex(
                    key,
                    86400,  # Keep for 24 hours
                    json.dumps(asdict(violation), default=str)
                )
            except RedisError:
                pass  # Non-critical
    
    def get_rate_limit_status(self, identifier: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get current rate limit status for identifier"""
        status = {
            'identifier': identifier,
            'is_blocked': self._is_blocked(identifier),
            'block_info': self._get_block_info(identifier),
            'rule_status': {}
        }
        
        for rule in self.rules:
            if not rule.is_active:
                continue
            
            rule_identifier = self._get_rule_identifier(rule, identifier, user_id)
            if rule_identifier:
                is_allowed, current_count = self._check_rule_limit(rule, rule_identifier)
                
                status['rule_status'][rule.name] = {
                    'current_count': current_count,
                    'limit': rule.requests,
                    'window_seconds': rule.window_seconds,
                    'is_allowed': is_allowed,
                    'remaining': max(0, rule.requests - current_count)
                }
        
        return status
    
    def clear_rate_limit(self, identifier: str, rule_name: Optional[str] = None):
        """Clear rate limits for identifier (admin function)"""
        if rule_name:
            # Clear specific rule
            if self.fallback_mode:
                key = f"{rule_name}:{identifier}"
                self.fallback_storage.pop(key, None)
            else:
                try:
                    key = f"rate_limit:{rule_name}:{identifier}"
                    self.redis_client.delete(key)
                except RedisError as e:
                    logger.error(f"Redis clear failed: {e}")
        else:
            # Clear all rules for identifier
            if self.fallback_mode:
                keys_to_remove = [k for k in self.fallback_storage.keys() if k.endswith(f":{identifier}")]
                for key in keys_to_remove:
                    del self.fallback_storage[key]
                self.fallback_blocks.pop(identifier, None)
            else:
                try:
                    # Clear rate limits
                    for rule in self.rules:
                        rule_identifier = self._get_rule_identifier(rule, identifier, None)
                        if rule_identifier:
                            key = f"rate_limit:{rule.name}:{rule_identifier}"
                            self.redis_client.delete(key)
                    
                    # Clear blocks
                    block_key = f"blocked:{identifier}"
                    self.redis_client.delete(block_key)
                    
                except RedisError as e:
                    logger.error(f"Redis clear all failed: {e}")
        
        logger.info(f"Cleared rate limits for {identifier} (rule: {rule_name or 'all'})")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        stats = {
            'redis_available': not self.fallback_mode,
            'active_rules': len([r for r in self.rules if r.is_active]),
            'total_rules': len(self.rules)
        }
        
        if self.fallback_mode:
            stats.update({
                'active_rate_limits': len(self.fallback_storage),
                'active_blocks': len(self.fallback_blocks)
            })
        else:
            try:
                # Get Redis stats
                info = self.redis_client.info()
                stats.update({
                    'redis_memory_used': info.get('used_memory_human', 'unknown'),
                    'redis_connected_clients': info.get('connected_clients', 0),
                    'redis_uptime_seconds': info.get('uptime_in_seconds', 0)
                })
            except RedisError:
                stats['redis_error'] = True
        
        return stats

# Global Redis rate limiter instance
redis_rate_limiter = RedisRateLimiter()
