#!/usr/bin/env python3
"""
Advanced Session Management with Device Fingerprinting for ByteGuardX
Implements secure session handling with device tracking and anomaly detection
"""

import logging
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import ipaddress
import re

logger = logging.getLogger(__name__)

@dataclass
class DeviceFingerprint:
    """Represents a device fingerprint"""
    fingerprint_id: str
    user_agent: str
    screen_resolution: str
    timezone: str
    language: str
    platform: str
    canvas_fingerprint: str
    webgl_fingerprint: str
    audio_fingerprint: str
    font_fingerprint: str
    created_at: datetime
    last_seen: datetime
    trust_score: float
    is_trusted: bool

@dataclass
class SecureSession:
    """Represents a secure session"""
    session_id: str
    user_id: str
    device_fingerprint_id: str
    ip_address: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool
    security_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    mfa_verified: bool
    webauthn_verified: bool
    risk_score: float
    session_data: Dict[str, Any]

@dataclass
class SessionEvent:
    """Represents a session security event"""
    event_id: str
    session_id: str
    event_type: str
    timestamp: datetime
    details: Dict[str, Any]
    risk_level: str

class AdvancedSessionManager:
    """
    Advanced session manager with device fingerprinting and security monitoring
    """
    
    def __init__(self):
        # Storage (use Redis/database in production)
        self.sessions: Dict[str, SecureSession] = {}
        self.device_fingerprints: Dict[str, DeviceFingerprint] = {}
        self.user_devices: Dict[str, List[str]] = defaultdict(list)  # user_id -> device_fingerprint_ids
        self.session_events: List[SessionEvent] = []
        
        # Security configuration
        self.max_sessions_per_user = 5
        self.session_timeout = timedelta(hours=8)
        self.idle_timeout = timedelta(minutes=30)
        self.device_trust_threshold = 0.7
        
        # Suspicious patterns
        self.suspicious_user_agents = [
            r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget'
        ]
    
    def generate_device_fingerprint(self, request_data: Dict[str, Any]) -> str:
        """
        Generate device fingerprint from request data
        """
        try:
            # Extract fingerprinting data
            user_agent = request_data.get('user_agent', '')
            screen_resolution = request_data.get('screen_resolution', '')
            timezone = request_data.get('timezone', '')
            language = request_data.get('language', '')
            platform = request_data.get('platform', '')
            canvas_fingerprint = request_data.get('canvas_fingerprint', '')
            webgl_fingerprint = request_data.get('webgl_fingerprint', '')
            audio_fingerprint = request_data.get('audio_fingerprint', '')
            font_fingerprint = request_data.get('font_fingerprint', '')
            
            # Create composite fingerprint
            fingerprint_data = {
                'user_agent': user_agent,
                'screen_resolution': screen_resolution,
                'timezone': timezone,
                'language': language,
                'platform': platform,
                'canvas': canvas_fingerprint,
                'webgl': webgl_fingerprint,
                'audio': audio_fingerprint,
                'fonts': font_fingerprint
            }
            
            # Generate fingerprint hash
            fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
            fingerprint_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            # Check if this is a new device
            if fingerprint_id not in self.device_fingerprints:
                # Calculate initial trust score
                trust_score = self._calculate_device_trust_score(fingerprint_data)
                
                device_fingerprint = DeviceFingerprint(
                    fingerprint_id=fingerprint_id,
                    user_agent=user_agent,
                    screen_resolution=screen_resolution,
                    timezone=timezone,
                    language=language,
                    platform=platform,
                    canvas_fingerprint=canvas_fingerprint,
                    webgl_fingerprint=webgl_fingerprint,
                    audio_fingerprint=audio_fingerprint,
                    font_fingerprint=font_fingerprint,
                    created_at=datetime.now(),
                    last_seen=datetime.now(),
                    trust_score=trust_score,
                    is_trusted=trust_score >= self.device_trust_threshold
                )
                
                self.device_fingerprints[fingerprint_id] = device_fingerprint
                logger.info(f"New device fingerprint created: {fingerprint_id[:16]}... (trust: {trust_score:.2f})")
            else:
                # Update last seen
                self.device_fingerprints[fingerprint_id].last_seen = datetime.now()
            
            return fingerprint_id
            
        except Exception as e:
            logger.error(f"Failed to generate device fingerprint: {e}")
            return secrets.token_hex(32)  # Fallback random fingerprint
    
    def _calculate_device_trust_score(self, fingerprint_data: Dict[str, Any]) -> float:
        """
        Calculate trust score for a device based on its fingerprint
        """
        trust_score = 0.5  # Base score
        
        user_agent = fingerprint_data.get('user_agent', '').lower()
        
        # Check for suspicious user agents
        for pattern in self.suspicious_user_agents:
            if re.search(pattern, user_agent):
                trust_score -= 0.3
                break
        
        # Check for common browsers (higher trust)
        common_browsers = ['chrome', 'firefox', 'safari', 'edge']
        if any(browser in user_agent for browser in common_browsers):
            trust_score += 0.2
        
        # Check for complete fingerprint (higher trust)
        complete_fields = ['screen_resolution', 'timezone', 'language', 'platform']
        complete_count = sum(1 for field in complete_fields if fingerprint_data.get(field))
        trust_score += (complete_count / len(complete_fields)) * 0.2
        
        # Check for advanced fingerprints (higher trust for real browsers)
        advanced_fields = ['canvas_fingerprint', 'webgl_fingerprint', 'audio_fingerprint']
        advanced_count = sum(1 for field in advanced_fields if fingerprint_data.get(field))
        trust_score += (advanced_count / len(advanced_fields)) * 0.1
        
        return max(0.0, min(1.0, trust_score))
    
    def create_session(self, user_id: str, request_data: Dict[str, Any]) -> Optional[SecureSession]:
        """
        Create a new secure session
        """
        try:
            # Generate device fingerprint
            device_fingerprint_id = self.generate_device_fingerprint(request_data)
            
            # Check session limits
            active_sessions = [
                s for s in self.sessions.values()
                if s.user_id == user_id and s.is_active and s.expires_at > datetime.now()
            ]
            
            if len(active_sessions) >= self.max_sessions_per_user:
                # Terminate oldest session
                oldest_session = min(active_sessions, key=lambda s: s.last_activity)
                self.terminate_session(oldest_session.session_id, "Session limit exceeded")
            
            # Calculate security level and risk score
            ip_address = request_data.get('ip_address', 'unknown')
            device_fingerprint = self.device_fingerprints[device_fingerprint_id]
            
            security_level, risk_score = self._calculate_session_security(
                user_id, device_fingerprint, ip_address
            )
            
            # Create session
            session_id = secrets.token_urlsafe(32)
            current_time = datetime.now()
            
            session = SecureSession(
                session_id=session_id,
                user_id=user_id,
                device_fingerprint_id=device_fingerprint_id,
                ip_address=ip_address,
                created_at=current_time,
                last_activity=current_time,
                expires_at=current_time + self.session_timeout,
                is_active=True,
                security_level=security_level,
                mfa_verified=False,
                webauthn_verified=False,
                risk_score=risk_score,
                session_data={}
            )
            
            self.sessions[session_id] = session
            
            # Associate device with user
            if device_fingerprint_id not in self.user_devices[user_id]:
                self.user_devices[user_id].append(device_fingerprint_id)
            
            # Log session creation event
            self._log_session_event(session_id, "SESSION_CREATED", {
                'user_id': user_id,
                'device_fingerprint': device_fingerprint_id[:16],
                'ip_address': ip_address,
                'security_level': security_level,
                'risk_score': risk_score
            })
            
            logger.info(f"Created session {session_id[:16]}... for user {user_id} (security: {security_level})")
            return session
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def _calculate_session_security(self, user_id: str, device_fingerprint: DeviceFingerprint, ip_address: str) -> Tuple[str, float]:
        """
        Calculate session security level and risk score
        """
        risk_score = 0.0
        
        # Device trust factor
        if not device_fingerprint.is_trusted:
            risk_score += 0.3
        
        # New device factor
        user_device_count = len(self.user_devices.get(user_id, []))
        if device_fingerprint.fingerprint_id not in self.user_devices.get(user_id, []):
            risk_score += 0.2  # New device
            if user_device_count == 0:
                risk_score += 0.1  # First device for user
        
        # IP address analysis
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if not ip_obj.is_private:
                risk_score += 0.1  # External IP
        except:
            risk_score += 0.2  # Invalid IP
        
        # Time-based analysis
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            risk_score += 0.1
        
        # Determine security level
        if risk_score >= 0.7:
            security_level = "CRITICAL"
        elif risk_score >= 0.5:
            security_level = "HIGH"
        elif risk_score >= 0.3:
            security_level = "MEDIUM"
        else:
            security_level = "LOW"
        
        return security_level, risk_score
    
    def validate_session(self, session_id: str, request_data: Dict[str, Any]) -> Optional[SecureSession]:
        """
        Validate and update session
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        current_time = datetime.now()
        
        # Check if session is active and not expired
        if not session.is_active or session.expires_at < current_time:
            self.terminate_session(session_id, "Session expired")
            return None
        
        # Check idle timeout
        if (current_time - session.last_activity) > self.idle_timeout:
            self.terminate_session(session_id, "Idle timeout")
            return None
        
        # Validate device fingerprint
        current_fingerprint_id = self.generate_device_fingerprint(request_data)
        if current_fingerprint_id != session.device_fingerprint_id:
            # Device fingerprint changed - potential session hijacking
            self._log_session_event(session_id, "FINGERPRINT_MISMATCH", {
                'expected': session.device_fingerprint_id[:16],
                'actual': current_fingerprint_id[:16],
                'ip_address': request_data.get('ip_address')
            })
            
            self.terminate_session(session_id, "Device fingerprint mismatch")
            return None
        
        # Validate IP address (allow some flexibility for mobile users)
        current_ip = request_data.get('ip_address', 'unknown')
        if current_ip != session.ip_address:
            # IP changed - log but don't terminate (mobile users change IPs)
            self._log_session_event(session_id, "IP_CHANGED", {
                'old_ip': session.ip_address,
                'new_ip': current_ip
            })
            
            # Update session IP
            session.ip_address = current_ip
        
        # Update last activity
        session.last_activity = current_time
        
        return session
    
    def terminate_session(self, session_id: str, reason: str = "Manual termination"):
        """
        Terminate a session
        """
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.is_active = False
            
            self._log_session_event(session_id, "SESSION_TERMINATED", {
                'reason': reason,
                'duration_minutes': (datetime.now() - session.created_at).total_seconds() / 60
            })
            
            logger.info(f"Terminated session {session_id[:16]}... (reason: {reason})")
    
    def terminate_all_user_sessions(self, user_id: str, except_session_id: Optional[str] = None):
        """
        Terminate all sessions for a user
        """
        terminated_count = 0
        for session_id, session in self.sessions.items():
            if (session.user_id == user_id and 
                session.is_active and 
                session_id != except_session_id):
                self.terminate_session(session_id, "All sessions terminated")
                terminated_count += 1
        
        logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
    
    def update_session_security(self, session_id: str, mfa_verified: bool = False, webauthn_verified: bool = False):
        """
        Update session security status
        """
        if session_id in self.sessions:
            session = self.sessions[session_id]
            
            if mfa_verified:
                session.mfa_verified = True
                session.risk_score *= 0.7  # Reduce risk score
                
            if webauthn_verified:
                session.webauthn_verified = True
                session.risk_score *= 0.5  # Significantly reduce risk score
            
            # Recalculate security level
            if session.risk_score < 0.2:
                session.security_level = "LOW"
            elif session.risk_score < 0.4:
                session.security_level = "MEDIUM"
            elif session.risk_score < 0.6:
                session.security_level = "HIGH"
            else:
                session.security_level = "CRITICAL"
            
            self._log_session_event(session_id, "SECURITY_UPDATED", {
                'mfa_verified': mfa_verified,
                'webauthn_verified': webauthn_verified,
                'new_risk_score': session.risk_score,
                'new_security_level': session.security_level
            })
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user
        """
        user_sessions = []
        for session in self.sessions.values():
            if session.user_id == user_id and session.is_active:
                device_fingerprint = self.device_fingerprints.get(session.device_fingerprint_id)
                
                user_sessions.append({
                    'session_id': session.session_id,
                    'created_at': session.created_at.isoformat(),
                    'last_activity': session.last_activity.isoformat(),
                    'ip_address': session.ip_address,
                    'security_level': session.security_level,
                    'mfa_verified': session.mfa_verified,
                    'webauthn_verified': session.webauthn_verified,
                    'risk_score': session.risk_score,
                    'device_info': {
                        'platform': device_fingerprint.platform if device_fingerprint else 'Unknown',
                        'user_agent': device_fingerprint.user_agent[:100] if device_fingerprint else 'Unknown',
                        'is_trusted': device_fingerprint.is_trusted if device_fingerprint else False
                    }
                })
        
        return sorted(user_sessions, key=lambda x: x['last_activity'], reverse=True)
    
    def _log_session_event(self, session_id: str, event_type: str, details: Dict[str, Any]):
        """
        Log session security event
        """
        event = SessionEvent(
            event_id=secrets.token_hex(16),
            session_id=session_id,
            event_type=event_type,
            timestamp=datetime.now(),
            details=details,
            risk_level=self._determine_event_risk_level(event_type, details)
        )
        
        self.session_events.append(event)
        
        # Keep only recent events (last 1000)
        if len(self.session_events) > 1000:
            self.session_events = self.session_events[-1000:]
    
    def _determine_event_risk_level(self, event_type: str, details: Dict[str, Any]) -> str:
        """
        Determine risk level for session event
        """
        high_risk_events = ['FINGERPRINT_MISMATCH', 'SESSION_HIJACK_DETECTED']
        medium_risk_events = ['IP_CHANGED', 'SUSPICIOUS_ACTIVITY']
        
        if event_type in high_risk_events:
            return "HIGH"
        elif event_type in medium_risk_events:
            return "MEDIUM"
        else:
            return "LOW"
    
    def cleanup_expired_sessions(self):
        """
        Clean up expired sessions and old events
        """
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if (not session.is_active or 
                session.expires_at < current_time or
                (current_time - session.last_activity) > self.idle_timeout):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.terminate_session(session_id, "Cleanup - expired")
        
        # Clean up old events (keep last 24 hours)
        cutoff_time = current_time - timedelta(hours=24)
        self.session_events = [
            event for event in self.session_events
            if event.timestamp > cutoff_time
        ]
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

# Global session manager instance
session_manager = AdvancedSessionManager()
