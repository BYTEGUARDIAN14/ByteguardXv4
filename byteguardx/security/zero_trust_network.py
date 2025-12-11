#!/usr/bin/env python3
"""
Zero-Trust Network Security for ByteGuardX
Implements comprehensive zero-trust architecture with micro-segmentation
"""

import logging
import ipaddress
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import json
import re

logger = logging.getLogger(__name__)

@dataclass
class NetworkPolicy:
    """Network access policy"""
    policy_id: str
    name: str
    source_networks: List[str]
    destination_networks: List[str]
    allowed_ports: List[int]
    allowed_protocols: List[str]
    required_auth_level: str
    time_restrictions: Optional[Dict[str, Any]]
    geo_restrictions: Optional[List[str]]
    device_requirements: Optional[Dict[str, Any]]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]

@dataclass
class NetworkConnection:
    """Network connection record"""
    connection_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    user_id: Optional[str]
    device_id: Optional[str]
    session_id: Optional[str]
    established_at: datetime
    last_activity: datetime
    bytes_sent: int
    bytes_received: int
    connection_state: str
    risk_score: float
    policy_violations: List[str]

@dataclass
class NetworkThreat:
    """Network-level threat detection"""
    threat_id: str
    threat_type: str
    source_ip: str
    target_ip: str
    severity: str
    confidence: float
    indicators: List[str]
    mitigation_actions: List[str]
    detected_at: datetime
    resolved_at: Optional[datetime]

class ZeroTrustNetworkManager:
    """
    Zero-Trust Network Security Manager
    Implements micro-segmentation and continuous verification
    """
    
    def __init__(self):
        # Network policies and connections
        self.network_policies: Dict[str, NetworkPolicy] = {}
        self.active_connections: Dict[str, NetworkConnection] = {}
        self.network_threats: List[NetworkThreat] = []
        
        # Network segments and zones
        self.network_segments = {
            'dmz': ['10.0.1.0/24', '192.168.1.0/24'],
            'internal': ['10.0.2.0/24', '172.16.0.0/16'],
            'secure': ['10.0.3.0/24'],
            'admin': ['10.0.4.0/24'],
            'external': ['0.0.0.0/0']
        }
        
        # Threat detection patterns
        self.threat_patterns = {
            'port_scan': {
                'pattern': 'multiple_ports_single_source',
                'threshold': 10,
                'timeframe': 60
            },
            'brute_force': {
                'pattern': 'repeated_failed_connections',
                'threshold': 5,
                'timeframe': 300
            },
            'data_exfiltration': {
                'pattern': 'unusual_data_volume',
                'threshold': 100 * 1024 * 1024,  # 100MB
                'timeframe': 3600
            },
            'lateral_movement': {
                'pattern': 'cross_segment_access',
                'threshold': 3,
                'timeframe': 1800
            }
        }
        
        # Initialize default policies
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default zero-trust policies"""
        
        # DMZ to Internal - Restricted
        self.network_policies['dmz_to_internal'] = NetworkPolicy(
            policy_id='dmz_to_internal',
            name='DMZ to Internal Access',
            source_networks=['10.0.1.0/24'],
            destination_networks=['10.0.2.0/24'],
            allowed_ports=[80, 443, 8080],
            allowed_protocols=['TCP', 'HTTPS'],
            required_auth_level='HIGH',
            time_restrictions={'business_hours_only': True},
            geo_restrictions=None,
            device_requirements={'managed_device': True, 'encrypted': True},
            is_active=True,
            created_at=datetime.now(),
            expires_at=None
        )
        
        # Internal to Secure - Very Restricted
        self.network_policies['internal_to_secure'] = NetworkPolicy(
            policy_id='internal_to_secure',
            name='Internal to Secure Zone',
            source_networks=['10.0.2.0/24'],
            destination_networks=['10.0.3.0/24'],
            allowed_ports=[443, 5432],
            allowed_protocols=['HTTPS', 'TLS'],
            required_auth_level='CRITICAL',
            time_restrictions={'business_hours_only': True},
            geo_restrictions=['US', 'CA'],
            device_requirements={
                'managed_device': True,
                'encrypted': True,
                'mfa_required': True,
                'certificate_required': True
            },
            is_active=True,
            created_at=datetime.now(),
            expires_at=None
        )
        
        # Admin Zone - Maximum Security
        self.network_policies['admin_access'] = NetworkPolicy(
            policy_id='admin_access',
            name='Admin Zone Access',
            source_networks=['10.0.2.0/24'],
            destination_networks=['10.0.4.0/24'],
            allowed_ports=[22, 443, 3389],
            allowed_protocols=['SSH', 'HTTPS', 'RDP'],
            required_auth_level='CRITICAL',
            time_restrictions={'business_hours_only': True, 'approval_required': True},
            geo_restrictions=['US'],
            device_requirements={
                'managed_device': True,
                'encrypted': True,
                'mfa_required': True,
                'certificate_required': True,
                'admin_approved': True
            },
            is_active=True,
            created_at=datetime.now(),
            expires_at=None
        )
        
        logger.info("Initialized zero-trust network policies")
    
    def evaluate_connection_request(self, connection_request: Dict[str, Any]) -> Tuple[bool, str, List[str]]:
        """
        Evaluate network connection request against zero-trust policies
        Returns: (allowed, reason, required_actions)
        """
        try:
            source_ip = connection_request.get('source_ip')
            dest_ip = connection_request.get('destination_ip')
            dest_port = connection_request.get('destination_port')
            protocol = connection_request.get('protocol', 'TCP')
            user_id = connection_request.get('user_id')
            device_id = connection_request.get('device_id')
            auth_level = connection_request.get('auth_level', 'LOW')
            
            # Determine network segments
            source_segment = self._get_network_segment(source_ip)
            dest_segment = self._get_network_segment(dest_ip)
            
            # Find applicable policies
            applicable_policies = self._find_applicable_policies(
                source_segment, dest_segment, dest_port, protocol
            )
            
            if not applicable_policies:
                return False, "No applicable network policy found", ["CREATE_POLICY"]
            
            # Evaluate each policy
            for policy in applicable_policies:
                allowed, reason, actions = self._evaluate_policy(
                    policy, connection_request, source_segment, dest_segment
                )
                
                if allowed:
                    # Log successful policy match
                    logger.info(f"Connection allowed by policy {policy.policy_id}: {source_ip}:{dest_port}")
                    return True, f"Allowed by policy: {policy.name}", actions
                else:
                    logger.warning(f"Connection denied by policy {policy.policy_id}: {reason}")
            
            return False, "Connection denied by all applicable policies", ["ENHANCE_AUTH"]
            
        except Exception as e:
            logger.error(f"Connection evaluation error: {e}")
            return False, "Policy evaluation failed", ["MANUAL_REVIEW"]
    
    def _get_network_segment(self, ip_address: str) -> str:
        """Determine which network segment an IP belongs to"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            for segment_name, networks in self.network_segments.items():
                for network_str in networks:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip in network:
                        return segment_name
            
            return 'external'
            
        except Exception:
            return 'unknown'
    
    def _find_applicable_policies(self, source_segment: str, dest_segment: str, 
                                dest_port: int, protocol: str) -> List[NetworkPolicy]:
        """Find policies applicable to the connection request"""
        applicable_policies = []
        
        for policy in self.network_policies.values():
            if not policy.is_active:
                continue
            
            # Check if policy applies to these segments
            source_match = any(
                self._ip_in_networks(self.network_segments.get(source_segment, []), policy.source_networks)
            )
            
            dest_match = any(
                self._ip_in_networks(self.network_segments.get(dest_segment, []), policy.destination_networks)
            )
            
            # Check port and protocol
            port_match = dest_port in policy.allowed_ports
            protocol_match = protocol.upper() in [p.upper() for p in policy.allowed_protocols]
            
            if source_match and dest_match and port_match and protocol_match:
                applicable_policies.append(policy)
        
        return applicable_policies
    
    def _ip_in_networks(self, segment_networks: List[str], policy_networks: List[str]) -> bool:
        """Check if any segment network overlaps with policy networks"""
        try:
            for seg_net in segment_networks:
                seg_network = ipaddress.ip_network(seg_net, strict=False)
                for pol_net in policy_networks:
                    pol_network = ipaddress.ip_network(pol_net, strict=False)
                    if seg_network.overlaps(pol_network):
                        return True
            return False
        except Exception:
            return False
    
    def _evaluate_policy(self, policy: NetworkPolicy, connection_request: Dict[str, Any],
                        source_segment: str, dest_segment: str) -> Tuple[bool, str, List[str]]:
        """Evaluate a specific policy against connection request"""
        required_actions = []
        
        # Check authentication level
        user_auth_level = connection_request.get('auth_level', 'LOW')
        if not self._auth_level_sufficient(user_auth_level, policy.required_auth_level):
            return False, f"Insufficient auth level: {user_auth_level} < {policy.required_auth_level}", ["ENHANCE_AUTH"]
        
        # Check time restrictions
        if policy.time_restrictions:
            if not self._check_time_restrictions(policy.time_restrictions):
                return False, "Time restrictions not met", ["WAIT_FOR_BUSINESS_HOURS"]
        
        # Check geographic restrictions
        if policy.geo_restrictions:
            user_location = connection_request.get('geo_location')
            if user_location not in policy.geo_restrictions:
                return False, f"Geographic restriction: {user_location} not in {policy.geo_restrictions}", ["VPN_REQUIRED"]
        
        # Check device requirements
        if policy.device_requirements:
            device_compliant, device_actions = self._check_device_requirements(
                connection_request, policy.device_requirements
            )
            if not device_compliant:
                return False, "Device requirements not met", device_actions
            required_actions.extend(device_actions)
        
        # Check for policy expiration
        if policy.expires_at and datetime.now() > policy.expires_at:
            return False, "Policy has expired", ["RENEW_POLICY"]
        
        return True, "Policy requirements satisfied", required_actions
    
    def _auth_level_sufficient(self, user_level: str, required_level: str) -> bool:
        """Check if user authentication level meets policy requirement"""
        levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        return levels.get(user_level, 0) >= levels.get(required_level, 4)
    
    def _check_time_restrictions(self, restrictions: Dict[str, Any]) -> bool:
        """Check if current time meets policy restrictions"""
        current_time = datetime.now()
        
        if restrictions.get('business_hours_only'):
            # Business hours: 9 AM to 6 PM, Monday to Friday
            if current_time.weekday() >= 5:  # Weekend
                return False
            if current_time.hour < 9 or current_time.hour >= 18:
                return False
        
        if restrictions.get('approval_required'):
            # This would integrate with approval workflow system
            # For now, assume approval is required but not implemented
            return False
        
        return True
    
    def _check_device_requirements(self, connection_request: Dict[str, Any], 
                                 requirements: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Check if device meets policy requirements"""
        actions = []
        device_info = connection_request.get('device_info', {})
        
        if requirements.get('managed_device') and not device_info.get('is_managed'):
            return False, ["ENROLL_DEVICE"]
        
        if requirements.get('encrypted') and not device_info.get('is_encrypted'):
            return False, ["ENABLE_ENCRYPTION"]
        
        if requirements.get('mfa_required') and not connection_request.get('mfa_verified'):
            return False, ["COMPLETE_MFA"]
        
        if requirements.get('certificate_required') and not device_info.get('has_certificate'):
            return False, ["INSTALL_CERTIFICATE"]
        
        if requirements.get('admin_approved') and not device_info.get('admin_approved'):
            return False, ["REQUEST_ADMIN_APPROVAL"]
        
        return True, actions
    
    def monitor_active_connections(self) -> List[NetworkThreat]:
        """Monitor active connections for threats"""
        detected_threats = []
        current_time = datetime.now()
        
        # Analyze connection patterns
        connection_patterns = self._analyze_connection_patterns()
        
        # Check for various threat patterns
        for pattern_name, pattern_config in self.threat_patterns.items():
            threats = self._detect_threat_pattern(pattern_name, pattern_config, connection_patterns)
            detected_threats.extend(threats)
        
        # Store detected threats
        self.network_threats.extend(detected_threats)
        
        # Clean up old threats (keep last 24 hours)
        cutoff_time = current_time - timedelta(hours=24)
        self.network_threats = [
            threat for threat in self.network_threats
            if threat.detected_at > cutoff_time
        ]
        
        return detected_threats
    
    def _analyze_connection_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in active connections"""
        patterns = {
            'connections_by_source': defaultdict(list),
            'connections_by_dest': defaultdict(list),
            'port_access_by_source': defaultdict(set),
            'data_volume_by_source': defaultdict(int),
            'cross_segment_connections': []
        }
        
        for conn in self.active_connections.values():
            source = conn.source_ip
            dest = conn.destination_ip
            
            patterns['connections_by_source'][source].append(conn)
            patterns['connections_by_dest'][dest].append(conn)
            patterns['port_access_by_source'][source].add(conn.destination_port)
            patterns['data_volume_by_source'][source] += conn.bytes_sent + conn.bytes_received
            
            # Check for cross-segment connections
            source_segment = self._get_network_segment(source)
            dest_segment = self._get_network_segment(dest)
            if source_segment != dest_segment:
                patterns['cross_segment_connections'].append(conn)
        
        return patterns
    
    def _detect_threat_pattern(self, pattern_name: str, pattern_config: Dict[str, Any],
                             connection_patterns: Dict[str, Any]) -> List[NetworkThreat]:
        """Detect specific threat patterns"""
        threats = []
        current_time = datetime.now()
        timeframe = timedelta(seconds=pattern_config['timeframe'])
        cutoff_time = current_time - timeframe
        
        if pattern_name == 'port_scan':
            # Detect port scanning
            for source_ip, ports in connection_patterns['port_access_by_source'].items():
                if len(ports) >= pattern_config['threshold']:
                    # Check if this happened within timeframe
                    recent_connections = [
                        conn for conn in connection_patterns['connections_by_source'][source_ip]
                        if conn.established_at > cutoff_time
                    ]
                    
                    if len(set(conn.destination_port for conn in recent_connections)) >= pattern_config['threshold']:
                        threats.append(NetworkThreat(
                            threat_id=secrets.token_hex(16),
                            threat_type='PORT_SCAN',
                            source_ip=source_ip,
                            target_ip='multiple',
                            severity='HIGH',
                            confidence=0.9,
                            indicators=[f"Accessed {len(ports)} different ports"],
                            mitigation_actions=['BLOCK_SOURCE_IP', 'ALERT_SECURITY_TEAM'],
                            detected_at=current_time,
                            resolved_at=None
                        ))
        
        elif pattern_name == 'data_exfiltration':
            # Detect unusual data volumes
            for source_ip, data_volume in connection_patterns['data_volume_by_source'].items():
                if data_volume >= pattern_config['threshold']:
                    threats.append(NetworkThreat(
                        threat_id=secrets.token_hex(16),
                        threat_type='DATA_EXFILTRATION',
                        source_ip=source_ip,
                        target_ip='multiple',
                        severity='CRITICAL',
                        confidence=0.8,
                        indicators=[f"Transferred {data_volume} bytes"],
                        mitigation_actions=['BLOCK_SOURCE_IP', 'INVESTIGATE_DATA_ACCESS', 'ALERT_DLP_TEAM'],
                        detected_at=current_time,
                        resolved_at=None
                    ))
        
        return threats
    
    def get_network_security_status(self) -> Dict[str, Any]:
        """Get comprehensive network security status"""
        current_time = datetime.now()
        
        # Count active connections by segment
        segment_connections = defaultdict(int)
        high_risk_connections = 0
        
        for conn in self.active_connections.values():
            source_segment = self._get_network_segment(conn.source_ip)
            segment_connections[source_segment] += 1
            
            if conn.risk_score > 0.7:
                high_risk_connections += 1
        
        # Count recent threats by severity
        recent_threats = [
            threat for threat in self.network_threats
            if (current_time - threat.detected_at).total_seconds() < 3600  # Last hour
        ]
        
        threat_counts = defaultdict(int)
        for threat in recent_threats:
            threat_counts[threat.severity] += 1
        
        return {
            'total_active_connections': len(self.active_connections),
            'high_risk_connections': high_risk_connections,
            'connections_by_segment': dict(segment_connections),
            'active_policies': len([p for p in self.network_policies.values() if p.is_active]),
            'recent_threats': {
                'total': len(recent_threats),
                'by_severity': dict(threat_counts)
            },
            'network_segments': list(self.network_segments.keys()),
            'last_updated': current_time.isoformat()
        }

# Global zero-trust network manager
zero_trust_network = ZeroTrustNetworkManager()
