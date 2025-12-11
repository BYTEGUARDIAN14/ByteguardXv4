"""
Micro-Firewall Rule Engine
Provides intelligent request filtering and velocity attack protection
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from collections import defaultdict, deque
import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

class ActionType(Enum):
    """Firewall action types"""
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    LOG_ONLY = "log_only"

class RuleType(Enum):
    """Firewall rule types"""
    IP_BLACKLIST = "ip_blacklist"
    IP_WHITELIST = "ip_whitelist"
    GEO_BLOCK = "geo_block"
    RATE_LIMIT = "rate_limit"
    PATTERN_MATCH = "pattern_match"
    VELOCITY_CHECK = "velocity_check"
    REPUTATION = "reputation"

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class FirewallRule:
    """Firewall rule definition"""
    rule_id: str
    name: str
    rule_type: RuleType
    action: ActionType
    priority: int  # Lower number = higher priority
    conditions: Dict[str, Any]
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0

@dataclass
class RequestInfo:
    """Information about incoming request"""
    ip_address: str
    user_agent: str
    path: str
    method: str
    headers: Dict[str, str]
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    country_code: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False

@dataclass
class FirewallDecision:
    """Firewall decision result"""
    action: ActionType
    rule_id: Optional[str]
    rule_name: Optional[str]
    reason: str
    threat_level: ThreatLevel
    additional_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VelocityTracker:
    """Track request velocity for an IP"""
    ip_address: str
    request_times: deque = field(default_factory=deque)
    total_requests: int = 0
    blocked_requests: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    threat_score: float = 0.0

class MicroFirewall:
    """
    Intelligent micro-firewall with velocity attack protection
    """
    
    def __init__(self, geoip_db_path: str = None):
        self.rules: Dict[str, FirewallRule] = {}
        self.velocity_trackers: Dict[str, VelocityTracker] = {}
        self.ip_reputation: Dict[str, float] = {}  # IP -> reputation score (0-100)
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> block expiry time
        self._lock = threading.RLock()
        
        # GeoIP database for country detection
        self.geoip_reader = None
        if geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'(?i)(union\s+select|select\s+.*\s+from)',  # SQL injection
            r'(?i)(<script|javascript:|vbscript:)',       # XSS
            r'(?i)(\.\.\/|\.\.\\)',                       # Path traversal
            r'(?i)(cmd\.exe|/bin/sh|/bin/bash)',         # Command injection
            r'(?i)(eval\s*\(|exec\s*\()',               # Code injection
        ]
        
        # Suspicious user agents
        self.suspicious_user_agents = [
            r'(?i)(bot|crawler|spider|scraper)',
            r'(?i)(sqlmap|nmap|nikto|dirb|gobuster)',
            r'(?i)(curl|wget|python-requests)',
        ]
        
        # Initialize default rules
        self._initialize_default_rules()
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _initialize_default_rules(self):
        """Initialize default firewall rules"""
        
        # High-velocity rate limiting
        self.add_rule(FirewallRule(
            rule_id="high_velocity_rate_limit",
            name="High Velocity Rate Limit",
            rule_type=RuleType.VELOCITY_CHECK,
            action=ActionType.RATE_LIMIT,
            priority=10,
            conditions={
                'requests_per_minute': 100,
                'requests_per_hour': 1000,
                'block_duration_minutes': 15
            }
        ))
        
        # Suspicious pattern blocking
        self.add_rule(FirewallRule(
            rule_id="malicious_pattern_block",
            name="Malicious Pattern Block",
            rule_type=RuleType.PATTERN_MATCH,
            action=ActionType.BLOCK,
            priority=5,
            conditions={
                'patterns': self.malicious_patterns,
                'check_path': True,
                'check_headers': True,
                'block_duration_minutes': 60
            }
        ))
        
        # Suspicious user agent blocking
        self.add_rule(FirewallRule(
            rule_id="suspicious_user_agent",
            name="Suspicious User Agent",
            rule_type=RuleType.PATTERN_MATCH,
            action=ActionType.CHALLENGE,
            priority=20,
            conditions={
                'patterns': self.suspicious_user_agents,
                'check_user_agent': True
            }
        ))
        
        # Geographic blocking (example: block certain countries)
        self.add_rule(FirewallRule(
            rule_id="geo_block_high_risk",
            name="Geographic Block - High Risk Countries",
            rule_type=RuleType.GEO_BLOCK,
            action=ActionType.BLOCK,
            priority=15,
            conditions={
                'blocked_countries': [],  # Add country codes as needed
                'block_duration_minutes': 30
            }
        ))
        
        # Low reputation IP blocking
        self.add_rule(FirewallRule(
            rule_id="low_reputation_block",
            name="Low Reputation IP Block",
            rule_type=RuleType.REPUTATION,
            action=ActionType.BLOCK,
            priority=25,
            conditions={
                'reputation_threshold': 20,  # Block IPs with reputation < 20
                'block_duration_minutes': 30
            }
        ))
    
    def add_rule(self, rule: FirewallRule):
        """Add a firewall rule"""
        with self._lock:
            self.rules[rule.rule_id] = rule
            logger.info(f"Added firewall rule: {rule.name}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule"""
        with self._lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                logger.info(f"Removed firewall rule: {rule_id}")
                return True
            return False
    
    def evaluate_request(self, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate a request against firewall rules"""
        try:
            with self._lock:
                # Check if IP is currently blocked
                if self._is_ip_blocked(request_info.ip_address):
                    return FirewallDecision(
                        action=ActionType.BLOCK,
                        rule_id="ip_blocked",
                        rule_name="IP Temporarily Blocked",
                        reason="IP address is temporarily blocked",
                        threat_level=ThreatLevel.HIGH
                    )
                
                # Update velocity tracking
                self._update_velocity_tracker(request_info)
                
                # Enhance request info with geolocation
                self._enhance_request_info(request_info)
                
                # Evaluate rules in priority order
                sorted_rules = sorted(
                    [rule for rule in self.rules.values() if rule.is_active],
                    key=lambda r: r.priority
                )
                
                for rule in sorted_rules:
                    decision = self._evaluate_rule(rule, request_info)
                    if decision.action != ActionType.ALLOW:
                        # Update rule statistics
                        rule.last_triggered = datetime.now()
                        rule.trigger_count += 1
                        
                        # Apply action
                        self._apply_action(decision, request_info)
                        
                        logger.info(f"Firewall rule triggered: {rule.name} for IP {request_info.ip_address}")
                        return decision
                
                # Default allow
                return FirewallDecision(
                    action=ActionType.ALLOW,
                    rule_id=None,
                    rule_name=None,
                    reason="No blocking rules matched",
                    threat_level=ThreatLevel.LOW
                )
                
        except Exception as e:
            logger.error(f"Error evaluating firewall request: {e}")
            # Fail open for availability
            return FirewallDecision(
                action=ActionType.ALLOW,
                rule_id=None,
                rule_name=None,
                reason=f"Firewall evaluation error: {e}",
                threat_level=ThreatLevel.LOW
            )
    
    def _is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is currently blocked"""
        if ip_address in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip_address]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[ip_address]
        return False
    
    def _update_velocity_tracker(self, request_info: RequestInfo):
        """Update velocity tracking for IP"""
        ip = request_info.ip_address
        now = datetime.now()
        
        if ip not in self.velocity_trackers:
            self.velocity_trackers[ip] = VelocityTracker(ip_address=ip)
        
        tracker = self.velocity_trackers[ip]
        tracker.request_times.append(now)
        tracker.total_requests += 1
        tracker.last_seen = now
        
        # Keep only requests from last hour
        cutoff_time = now - timedelta(hours=1)
        while tracker.request_times and tracker.request_times[0] < cutoff_time:
            tracker.request_times.popleft()
        
        # Calculate threat score based on velocity
        requests_per_minute = len([t for t in tracker.request_times if t > now - timedelta(minutes=1)])
        requests_per_hour = len(tracker.request_times)
        
        # Simple threat scoring
        threat_score = 0
        if requests_per_minute > 50:
            threat_score += 30
        if requests_per_hour > 500:
            threat_score += 40
        if tracker.blocked_requests > 0:
            threat_score += 20
        
        tracker.threat_score = min(threat_score, 100)
    
    def _enhance_request_info(self, request_info: RequestInfo):
        """Enhance request info with additional data"""
        if self.geoip_reader:
            try:
                response = self.geoip_reader.country(request_info.ip_address)
                request_info.country_code = response.country.iso_code
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"GeoIP lookup failed for {request_info.ip_address}: {e}")
    
    def _evaluate_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate a single rule against request"""
        
        if rule.rule_type == RuleType.VELOCITY_CHECK:
            return self._evaluate_velocity_rule(rule, request_info)
        elif rule.rule_type == RuleType.PATTERN_MATCH:
            return self._evaluate_pattern_rule(rule, request_info)
        elif rule.rule_type == RuleType.GEO_BLOCK:
            return self._evaluate_geo_rule(rule, request_info)
        elif rule.rule_type == RuleType.REPUTATION:
            return self._evaluate_reputation_rule(rule, request_info)
        elif rule.rule_type == RuleType.IP_BLACKLIST:
            return self._evaluate_ip_blacklist_rule(rule, request_info)
        elif rule.rule_type == RuleType.IP_WHITELIST:
            return self._evaluate_ip_whitelist_rule(rule, request_info)
        
        # Default allow if rule type not implemented
        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="Rule type not implemented",
            threat_level=ThreatLevel.LOW
        )
    
    def _evaluate_velocity_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate velocity-based rule"""
        tracker = self.velocity_trackers.get(request_info.ip_address)
        if not tracker:
            return FirewallDecision(
                action=ActionType.ALLOW,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason="No velocity data",
                threat_level=ThreatLevel.LOW
            )
        
        now = datetime.now()
        conditions = rule.conditions
        
        # Check requests per minute
        if 'requests_per_minute' in conditions:
            recent_requests = len([t for t in tracker.request_times if t > now - timedelta(minutes=1)])
            if recent_requests > conditions['requests_per_minute']:
                return FirewallDecision(
                    action=rule.action,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    reason=f"Exceeded {conditions['requests_per_minute']} requests per minute",
                    threat_level=ThreatLevel.HIGH,
                    additional_info={'requests_per_minute': recent_requests}
                )
        
        # Check requests per hour
        if 'requests_per_hour' in conditions:
            if len(tracker.request_times) > conditions['requests_per_hour']:
                return FirewallDecision(
                    action=rule.action,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    reason=f"Exceeded {conditions['requests_per_hour']} requests per hour",
                    threat_level=ThreatLevel.MEDIUM,
                    additional_info={'requests_per_hour': len(tracker.request_times)}
                )
        
        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="Velocity within limits",
            threat_level=ThreatLevel.LOW
        )

    def _evaluate_pattern_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate pattern matching rule"""
        conditions = rule.conditions
        patterns = conditions.get('patterns', [])

        text_to_check = []

        # Check path
        if conditions.get('check_path', False):
            text_to_check.append(request_info.path)

        # Check user agent
        if conditions.get('check_user_agent', False):
            text_to_check.append(request_info.user_agent)

        # Check headers
        if conditions.get('check_headers', False):
            text_to_check.extend(request_info.headers.values())

        # Check patterns
        for text in text_to_check:
            for pattern in patterns:
                if re.search(pattern, text):
                    return FirewallDecision(
                        action=rule.action,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        reason=f"Malicious pattern detected: {pattern[:50]}...",
                        threat_level=ThreatLevel.HIGH,
                        additional_info={'matched_pattern': pattern, 'matched_text': text[:100]}
                    )

        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="No malicious patterns detected",
            threat_level=ThreatLevel.LOW
        )

    def _evaluate_geo_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate geographic blocking rule"""
        if not request_info.country_code:
            return FirewallDecision(
                action=ActionType.ALLOW,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason="Country code not available",
                threat_level=ThreatLevel.LOW
            )

        conditions = rule.conditions
        blocked_countries = conditions.get('blocked_countries', [])

        if request_info.country_code in blocked_countries:
            return FirewallDecision(
                action=rule.action,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason=f"Request from blocked country: {request_info.country_code}",
                threat_level=ThreatLevel.MEDIUM,
                additional_info={'country_code': request_info.country_code}
            )

        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="Country not blocked",
            threat_level=ThreatLevel.LOW
        )

    def _evaluate_reputation_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate IP reputation rule"""
        reputation = self.ip_reputation.get(request_info.ip_address, 50)  # Default neutral reputation
        conditions = rule.conditions
        threshold = conditions.get('reputation_threshold', 0)

        if reputation < threshold:
            return FirewallDecision(
                action=rule.action,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason=f"Low IP reputation: {reputation} < {threshold}",
                threat_level=ThreatLevel.MEDIUM,
                additional_info={'reputation_score': reputation, 'threshold': threshold}
            )

        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="IP reputation acceptable",
            threat_level=ThreatLevel.LOW
        )

    def _evaluate_ip_blacklist_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate IP blacklist rule"""
        conditions = rule.conditions
        blacklisted_ips = conditions.get('blacklisted_ips', [])
        blacklisted_ranges = conditions.get('blacklisted_ranges', [])

        # Check exact IP matches
        if request_info.ip_address in blacklisted_ips:
            return FirewallDecision(
                action=rule.action,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason="IP address is blacklisted",
                threat_level=ThreatLevel.HIGH
            )

        # Check IP ranges
        try:
            request_ip = ipaddress.ip_address(request_info.ip_address)
            for ip_range in blacklisted_ranges:
                if request_ip in ipaddress.ip_network(ip_range):
                    return FirewallDecision(
                        action=rule.action,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        reason=f"IP address in blacklisted range: {ip_range}",
                        threat_level=ThreatLevel.HIGH,
                        additional_info={'blacklisted_range': ip_range}
                    )
        except ValueError:
            logger.warning(f"Invalid IP address: {request_info.ip_address}")

        return FirewallDecision(
            action=ActionType.ALLOW,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="IP not blacklisted",
            threat_level=ThreatLevel.LOW
        )

    def _evaluate_ip_whitelist_rule(self, rule: FirewallRule, request_info: RequestInfo) -> FirewallDecision:
        """Evaluate IP whitelist rule"""
        conditions = rule.conditions
        whitelisted_ips = conditions.get('whitelisted_ips', [])
        whitelisted_ranges = conditions.get('whitelisted_ranges', [])

        # Check exact IP matches
        if request_info.ip_address in whitelisted_ips:
            return FirewallDecision(
                action=ActionType.ALLOW,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                reason="IP address is whitelisted",
                threat_level=ThreatLevel.LOW
            )

        # Check IP ranges
        try:
            request_ip = ipaddress.ip_address(request_info.ip_address)
            for ip_range in whitelisted_ranges:
                if request_ip in ipaddress.ip_network(ip_range):
                    return FirewallDecision(
                        action=ActionType.ALLOW,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        reason=f"IP address in whitelisted range: {ip_range}",
                        threat_level=ThreatLevel.LOW,
                        additional_info={'whitelisted_range': ip_range}
                    )
        except ValueError:
            logger.warning(f"Invalid IP address: {request_info.ip_address}")

        # If whitelist rule exists but IP not whitelisted, block
        return FirewallDecision(
            action=ActionType.BLOCK,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            reason="IP not in whitelist",
            threat_level=ThreatLevel.MEDIUM
        )

    def _apply_action(self, decision: FirewallDecision, request_info: RequestInfo):
        """Apply firewall action"""
        if decision.action == ActionType.BLOCK:
            # Add IP to blocked list if rule specifies duration
            rule = self.rules.get(decision.rule_id)
            if rule and 'block_duration_minutes' in rule.conditions:
                duration = timedelta(minutes=rule.conditions['block_duration_minutes'])
                self.blocked_ips[request_info.ip_address] = datetime.now() + duration

        elif decision.action == ActionType.RATE_LIMIT:
            # Increment blocked requests counter
            tracker = self.velocity_trackers.get(request_info.ip_address)
            if tracker:
                tracker.blocked_requests += 1

        # Update IP reputation based on action
        self._update_ip_reputation(request_info.ip_address, decision)

    def _update_ip_reputation(self, ip_address: str, decision: FirewallDecision):
        """Update IP reputation based on firewall decision"""
        current_reputation = self.ip_reputation.get(ip_address, 50)

        if decision.action == ActionType.BLOCK:
            # Decrease reputation for blocked requests
            new_reputation = max(0, current_reputation - 10)
        elif decision.action == ActionType.RATE_LIMIT:
            # Slightly decrease reputation for rate limited requests
            new_reputation = max(0, current_reputation - 5)
        elif decision.action == ActionType.ALLOW:
            # Slowly increase reputation for allowed requests
            new_reputation = min(100, current_reputation + 1)
        else:
            new_reputation = current_reputation

        self.ip_reputation[ip_address] = new_reputation

    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_loop():
            while True:
                try:
                    self._cleanup_expired_data()
                    time.sleep(300)  # Run every 5 minutes
                except Exception as e:
                    logger.error(f"Cleanup thread error: {e}")
                    time.sleep(60)

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()

    def _cleanup_expired_data(self):
        """Clean up expired data"""
        now = datetime.now()

        with self._lock:
            # Clean up expired IP blocks
            expired_blocks = [
                ip for ip, expiry in self.blocked_ips.items()
                if now >= expiry
            ]
            for ip in expired_blocks:
                del self.blocked_ips[ip]

            # Clean up old velocity trackers (older than 24 hours)
            cutoff_time = now - timedelta(hours=24)
            expired_trackers = [
                ip for ip, tracker in self.velocity_trackers.items()
                if tracker.last_seen < cutoff_time
            ]
            for ip in expired_trackers:
                del self.velocity_trackers[ip]

            # Clean up old IP reputation entries (older than 7 days)
            # This would need more sophisticated logic in production
            if len(self.ip_reputation) > 10000:
                # Keep only the most recent 5000 entries
                sorted_ips = sorted(
                    self.ip_reputation.items(),
                    key=lambda x: self.velocity_trackers.get(x[0], VelocityTracker(x[0])).last_seen,
                    reverse=True
                )
                self.ip_reputation = dict(sorted_ips[:5000])

            if expired_blocks or expired_trackers:
                logger.info(f"Cleaned up {len(expired_blocks)} expired blocks and {len(expired_trackers)} old trackers")

    def get_statistics(self) -> Dict[str, Any]:
        """Get firewall statistics"""
        with self._lock:
            total_rules = len(self.rules)
            active_rules = len([r for r in self.rules.values() if r.is_active])
            blocked_ips_count = len(self.blocked_ips)
            tracked_ips_count = len(self.velocity_trackers)

            # Rule trigger statistics
            rule_stats = {}
            for rule in self.rules.values():
                rule_stats[rule.rule_id] = {
                    'name': rule.name,
                    'trigger_count': rule.trigger_count,
                    'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None,
                    'is_active': rule.is_active
                }

            return {
                'total_rules': total_rules,
                'active_rules': active_rules,
                'blocked_ips': blocked_ips_count,
                'tracked_ips': tracked_ips_count,
                'rule_statistics': rule_stats,
                'top_blocked_countries': self._get_top_blocked_countries(),
                'threat_level_distribution': self._get_threat_level_distribution()
            }

    def _get_top_blocked_countries(self) -> List[Dict[str, Any]]:
        """Get top blocked countries"""
        # This would be implemented with proper tracking in production
        return []

    def _get_threat_level_distribution(self) -> Dict[str, int]:
        """Get threat level distribution"""
        distribution = {level.value: 0 for level in ThreatLevel}

        for tracker in self.velocity_trackers.values():
            if tracker.threat_score >= 80:
                distribution[ThreatLevel.CRITICAL.value] += 1
            elif tracker.threat_score >= 60:
                distribution[ThreatLevel.HIGH.value] += 1
            elif tracker.threat_score >= 30:
                distribution[ThreatLevel.MEDIUM.value] += 1
            else:
                distribution[ThreatLevel.LOW.value] += 1

        return distribution

# Global instance
micro_firewall = MicroFirewall()
