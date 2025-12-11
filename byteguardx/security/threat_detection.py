#!/usr/bin/env python3
"""
Advanced Threat Detection System for ByteGuardX
Implements ML-based anomaly detection and behavioral analysis
"""

import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, deque
import ipaddress
import re
import math

logger = logging.getLogger(__name__)

@dataclass
class ThreatEvent:
    """Represents a potential security threat"""
    timestamp: datetime
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str
    user_id: Optional[str]
    details: Dict[str, Any]
    risk_score: float
    mitigation_actions: List[str]

class AdvancedThreatDetector:
    """
    Advanced threat detection with ML-based behavioral analysis
    """
    
    def __init__(self):
        self.threat_events = deque(maxlen=10000)  # Keep last 10k events
        self.user_behavior_profiles = {}
        self.ip_reputation_cache = {}
        self.attack_patterns = self._load_attack_patterns()
        self.geolocation_cache = {}
        
        # Threat scoring weights
        self.scoring_weights = {
            'failed_login_rate': 0.3,
            'geographic_anomaly': 0.2,
            'time_anomaly': 0.15,
            'user_agent_anomaly': 0.1,
            'request_pattern_anomaly': 0.15,
            'ip_reputation': 0.1
        }
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load known attack patterns"""
        return {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))"
            ],
            'xss_attempts': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>.*?</iframe>"
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c"
            ],
            'command_injection': [
                r"[;&|`]",
                r"\$\([^)]*\)",
                r"`[^`]*`",
                r"\|\s*\w+"
            ]
        }
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Analyze incoming request for threats
        """
        try:
            risk_score = 0.0
            threat_indicators = []
            mitigation_actions = []
            
            # Extract request details
            ip = request_data.get('ip', 'unknown')
            user_id = request_data.get('user_id')
            user_agent = request_data.get('user_agent', '')
            endpoint = request_data.get('endpoint', '')
            method = request_data.get('method', '')
            payload = request_data.get('payload', {})
            
            # 1. Check for attack patterns in payload
            attack_risk = self._check_attack_patterns(payload)
            if attack_risk > 0:
                risk_score += attack_risk * 0.4
                threat_indicators.append(f"Attack pattern detected (score: {attack_risk})")
                mitigation_actions.append("BLOCK_REQUEST")
            
            # 2. Analyze IP reputation
            ip_risk = self._analyze_ip_reputation(ip)
            risk_score += ip_risk * self.scoring_weights['ip_reputation']
            if ip_risk > 0.7:
                threat_indicators.append(f"Malicious IP detected (score: {ip_risk})")
                mitigation_actions.append("BLOCK_IP")
            
            # 3. Check geographic anomalies
            geo_risk = self._check_geographic_anomaly(ip, user_id)
            risk_score += geo_risk * self.scoring_weights['geographic_anomaly']
            if geo_risk > 0.6:
                threat_indicators.append(f"Geographic anomaly (score: {geo_risk})")
                mitigation_actions.append("REQUIRE_2FA")
            
            # 4. Analyze user behavior
            if user_id:
                behavior_risk = self._analyze_user_behavior(user_id, request_data)
                risk_score += behavior_risk * 0.25
                if behavior_risk > 0.5:
                    threat_indicators.append(f"Behavioral anomaly (score: {behavior_risk})")
                    mitigation_actions.append("INCREASE_MONITORING")
            
            # 5. Check request rate anomalies
            rate_risk = self._check_request_rate_anomaly(ip, endpoint)
            risk_score += rate_risk * 0.2
            if rate_risk > 0.8:
                threat_indicators.append(f"Request rate anomaly (score: {rate_risk})")
                mitigation_actions.append("RATE_LIMIT")
            
            # 6. Time-based anomaly detection
            time_risk = self._check_time_anomaly(user_id)
            risk_score += time_risk * self.scoring_weights['time_anomaly']
            if time_risk > 0.5:
                threat_indicators.append(f"Time anomaly (score: {time_risk})")
            
            # Determine severity based on risk score
            if risk_score >= 0.8:
                severity = "CRITICAL"
                mitigation_actions.append("IMMEDIATE_BLOCK")
            elif risk_score >= 0.6:
                severity = "HIGH"
                mitigation_actions.append("ENHANCED_MONITORING")
            elif risk_score >= 0.4:
                severity = "MEDIUM"
                mitigation_actions.append("LOG_AND_MONITOR")
            elif risk_score >= 0.2:
                severity = "LOW"
            else:
                return None  # No threat detected
            
            # Create threat event
            threat_event = ThreatEvent(
                timestamp=datetime.now(),
                event_type="REQUEST_ANALYSIS",
                severity=severity,
                source_ip=ip,
                user_id=user_id,
                details={
                    'endpoint': endpoint,
                    'method': method,
                    'user_agent': user_agent,
                    'threat_indicators': threat_indicators,
                    'payload_hash': hashlib.sha256(str(payload).encode()).hexdigest()[:16]
                },
                risk_score=risk_score,
                mitigation_actions=list(set(mitigation_actions))
            )
            
            self.threat_events.append(threat_event)
            return threat_event
            
        except Exception as e:
            logger.error(f"Threat analysis error: {e}")
            return None
    
    def _check_attack_patterns(self, payload: Dict[str, Any]) -> float:
        """Check for known attack patterns in request payload"""
        risk_score = 0.0
        payload_str = json.dumps(payload).lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    risk_score += 0.3
                    logger.warning(f"Attack pattern detected: {attack_type}")
        
        return min(risk_score, 1.0)
    
    def _analyze_ip_reputation(self, ip: str) -> float:
        """Analyze IP reputation (simplified - integrate with threat intel feeds)"""
        try:
            # Check if IP is in private ranges (lower risk)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return 0.1
            
            # Check cached reputation
            if ip in self.ip_reputation_cache:
                return self.ip_reputation_cache[ip]
            
            # Simplified reputation scoring (integrate with real threat intel)
            risk_score = 0.0
            
            # Check for known malicious patterns
            if any(bad_range in ip for bad_range in ['10.0.0.', '192.168.', '172.16.']):
                risk_score = 0.1  # Private IPs are generally safer
            else:
                # External IP - moderate risk by default
                risk_score = 0.3
            
            # Cache the result
            self.ip_reputation_cache[ip] = risk_score
            return risk_score
            
        except Exception:
            return 0.5  # Unknown IP format - moderate risk
    
    def _check_geographic_anomaly(self, ip: str, user_id: Optional[str]) -> float:
        """Check for geographic anomalies in user access patterns"""
        if not user_id:
            return 0.0
        
        # Simplified geolocation check (integrate with real GeoIP service)
        # This would normally use MaxMind GeoIP2 or similar
        current_location = self._get_ip_location(ip)
        
        if user_id not in self.user_behavior_profiles:
            self.user_behavior_profiles[user_id] = {
                'typical_locations': [current_location],
                'last_locations': deque(maxlen=10)
            }
            return 0.0
        
        profile = self.user_behavior_profiles[user_id]
        profile['last_locations'].append(current_location)
        
        # Check if current location is typical for this user
        if current_location not in profile['typical_locations']:
            # New location - check distance from typical locations
            return 0.6  # Moderate risk for new location
        
        return 0.0
    
    def _get_ip_location(self, ip: str) -> str:
        """Get approximate location for IP (simplified)"""
        # This would integrate with a real GeoIP service
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return "LOCAL_NETWORK"
        return "EXTERNAL"
    
    def _analyze_user_behavior(self, user_id: str, request_data: Dict[str, Any]) -> float:
        """Analyze user behavioral patterns"""
        if user_id not in self.user_behavior_profiles:
            self.user_behavior_profiles[user_id] = {
                'request_patterns': defaultdict(int),
                'typical_times': [],
                'user_agents': set()
            }
        
        profile = self.user_behavior_profiles[user_id]
        current_time = datetime.now()
        user_agent = request_data.get('user_agent', '')
        endpoint = request_data.get('endpoint', '')
        
        # Update profile
        profile['request_patterns'][endpoint] += 1
        profile['typical_times'].append(current_time.hour)
        profile['user_agents'].add(user_agent)
        
        risk_score = 0.0
        
        # Check for unusual user agent
        if len(profile['user_agents']) > 5:  # Too many different user agents
            risk_score += 0.3
        
        # Check for unusual request patterns
        total_requests = sum(profile['request_patterns'].values())
        if total_requests > 100:  # Enough data for analysis
            endpoint_frequency = profile['request_patterns'][endpoint] / total_requests
            if endpoint_frequency > 0.8:  # Too focused on one endpoint
                risk_score += 0.4
        
        return min(risk_score, 1.0)
    
    def _check_request_rate_anomaly(self, ip: str, endpoint: str) -> float:
        """Check for unusual request rates"""
        # Count recent requests from this IP to this endpoint
        current_time = datetime.now()
        recent_requests = [
            event for event in self.threat_events
            if event.source_ip == ip and 
            event.details.get('endpoint') == endpoint and
            (current_time - event.timestamp).total_seconds() < 300  # Last 5 minutes
        ]
        
        request_count = len(recent_requests)
        
        # Define normal request rates per endpoint type
        normal_rates = {
            '/api/auth/login': 5,
            '/api/v1/scan': 10,
            '/api/v1/reports': 20
        }
        
        normal_rate = normal_rates.get(endpoint, 15)
        
        if request_count > normal_rate * 2:
            return 0.9  # High risk
        elif request_count > normal_rate:
            return 0.5  # Medium risk
        
        return 0.0
    
    def _check_time_anomaly(self, user_id: Optional[str]) -> float:
        """Check for unusual access times"""
        if not user_id or user_id not in self.user_behavior_profiles:
            return 0.0
        
        current_hour = datetime.now().hour
        profile = self.user_behavior_profiles[user_id]
        typical_hours = profile.get('typical_times', [])
        
        if not typical_hours:
            return 0.0
        
        # Calculate if current hour is unusual
        hour_counts = defaultdict(int)
        for hour in typical_hours:
            hour_counts[hour] += 1
        
        total_accesses = len(typical_hours)
        current_hour_frequency = hour_counts[current_hour] / total_accesses
        
        # If user rarely accesses at this hour, it's suspicious
        if current_hour_frequency < 0.1 and total_accesses > 20:
            return 0.6
        
        return 0.0
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat summary for the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_threats = [
            event for event in self.threat_events
            if event.timestamp > cutoff_time
        ]
        
        severity_counts = defaultdict(int)
        top_sources = defaultdict(int)
        threat_types = defaultdict(int)
        
        for threat in recent_threats:
            severity_counts[threat.severity] += 1
            top_sources[threat.source_ip] += 1
            threat_types[threat.event_type] += 1
        
        return {
            'total_threats': len(recent_threats),
            'severity_breakdown': dict(severity_counts),
            'top_threat_sources': dict(sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:10]),
            'threat_types': dict(threat_types),
            'average_risk_score': sum(t.risk_score for t in recent_threats) / len(recent_threats) if recent_threats else 0
        }

# Global threat detector instance
threat_detector = AdvancedThreatDetector()
