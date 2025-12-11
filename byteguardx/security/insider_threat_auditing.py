"""
Insider Threat Auditing System for ByteGuardX
Monitors and logs privileged access to user data and sensitive operations
"""

import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import threading
from flask import request, g

from .audit_logger import audit_logger, SecurityEvent
from ..auth.models import UserManager, UserRole
from ..database.connection_pool import db_manager

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Insider threat risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AccessType(Enum):
    """Types of privileged access"""
    USER_DATA_ACCESS = "user_data_access"
    SCAN_DATA_ACCESS = "scan_data_access"
    ADMIN_ESCALATION = "admin_escalation"
    BULK_DATA_EXPORT = "bulk_data_export"
    SYSTEM_CONFIG_CHANGE = "system_config_change"
    USER_IMPERSONATION = "user_impersonation"
    AUDIT_LOG_ACCESS = "audit_log_access"

@dataclass
class InsiderThreatEvent:
    """Insider threat event record"""
    event_id: str
    admin_user_id: str
    admin_username: str
    target_user_id: Optional[str]
    target_username: Optional[str]
    access_type: AccessType
    resource_type: str
    resource_id: str
    action: str
    timestamp: str
    ip_address: str
    user_agent: str
    justification: Optional[str]
    approval_required: bool
    approved_by: Optional[str]
    threat_level: ThreatLevel
    risk_factors: List[str]
    additional_context: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['access_type'] = self.access_type.value
        result['threat_level'] = self.threat_level.value
        return result

@dataclass
class JITEscalationRequest:
    """Just-in-time escalation request"""
    request_id: str
    admin_user_id: str
    requested_action: str
    target_resource: str
    justification: str
    requested_at: str
    expires_at: str
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    used: bool = False
    used_at: Optional[str] = None

class InsiderThreatMonitor:
    """
    Monitors and analyzes insider threat activities
    """
    
    def __init__(self, audit_dir: str = "data/insider_threat_audit"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        self.user_manager = UserManager()
        self.threat_events: List[InsiderThreatEvent] = []
        self.escalation_requests: Dict[str, JITEscalationRequest] = {}
        self._lock = threading.Lock()
        
        # Risk scoring weights
        self.risk_weights = {
            'off_hours_access': 0.3,
            'unusual_ip': 0.2,
            'bulk_access': 0.4,
            'cross_org_access': 0.5,
            'repeated_access': 0.3,
            'privileged_escalation': 0.6,
            'data_export': 0.4,
            'audit_tampering': 0.8
        }
        
        # Load existing data
        self._load_audit_data()
    
    def _load_audit_data(self):
        """Load existing audit data"""
        try:
            events_file = self.audit_dir / "threat_events.json"
            if events_file.exists():
                with open(events_file, 'r') as f:
                    events_data = json.load(f)
                    for event_data in events_data:
                        event_data['access_type'] = AccessType(event_data['access_type'])
                        event_data['threat_level'] = ThreatLevel(event_data['threat_level'])
                        self.threat_events.append(InsiderThreatEvent(**event_data))
            
            escalation_file = self.audit_dir / "escalation_requests.json"
            if escalation_file.exists():
                with open(escalation_file, 'r') as f:
                    escalation_data = json.load(f)
                    for req_id, req_data in escalation_data.items():
                        self.escalation_requests[req_id] = JITEscalationRequest(**req_data)
                        
        except Exception as e:
            logger.error(f"Failed to load audit data: {e}")
    
    def _save_audit_data(self):
        """Save audit data to disk"""
        try:
            # Save threat events
            events_file = self.audit_dir / "threat_events.json"
            with open(events_file, 'w') as f:
                events_data = [event.to_dict() for event in self.threat_events]
                json.dump(events_data, f, indent=2)
            
            # Save escalation requests
            escalation_file = self.audit_dir / "escalation_requests.json"
            with open(escalation_file, 'w') as f:
                escalation_data = {req_id: asdict(req) for req_id, req in self.escalation_requests.items()}
                json.dump(escalation_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save audit data: {e}")
    
    def log_privileged_access(self, admin_user_id: str, target_user_id: Optional[str],
                            access_type: AccessType, resource_type: str, resource_id: str,
                            action: str, justification: Optional[str] = None) -> str:
        """Log privileged access event"""
        try:
            import uuid
            
            # Get admin user info
            admin_user = self.user_manager.get_user_by_id(admin_user_id)
            if not admin_user:
                logger.error(f"Admin user not found: {admin_user_id}")
                return ""
            
            # Get target user info if applicable
            target_username = None
            if target_user_id:
                target_user = self.user_manager.get_user_by_id(target_user_id)
                target_username = target_user.username if target_user else "unknown"
            
            # Calculate risk factors and threat level
            risk_factors = self._analyze_risk_factors(admin_user_id, target_user_id, access_type)
            threat_level = self._calculate_threat_level(risk_factors)
            
            # Create threat event
            event = InsiderThreatEvent(
                event_id=str(uuid.uuid4()),
                admin_user_id=admin_user_id,
                admin_username=admin_user.username,
                target_user_id=target_user_id,
                target_username=target_username,
                access_type=access_type,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                timestamp=datetime.now().isoformat(),
                ip_address=request.remote_addr if request else "unknown",
                user_agent=request.headers.get('User-Agent', '') if request else "unknown",
                justification=justification,
                approval_required=threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL],
                approved_by=None,
                threat_level=threat_level,
                risk_factors=risk_factors,
                additional_context=self._gather_additional_context()
            )
            
            with self._lock:
                self.threat_events.append(event)
                self._save_audit_data()
            
            # Log to security audit
            audit_logger.log_security_event(
                event_type=SecurityEvent.PRIVILEGED_ACCESS,
                user_id=admin_user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                details={
                    'target_user_id': target_user_id,
                    'access_type': access_type.value,
                    'threat_level': threat_level.value,
                    'risk_factors': risk_factors,
                    'justification': justification
                },
                severity="warning" if threat_level == ThreatLevel.LOW else "critical"
            )
            
            logger.info(f"Logged privileged access: {event.event_id} (threat level: {threat_level.value})")
            return event.event_id
            
        except Exception as e:
            logger.error(f"Failed to log privileged access: {e}")
            return ""
    
    def _analyze_risk_factors(self, admin_user_id: str, target_user_id: Optional[str],
                            access_type: AccessType) -> List[str]:
        """Analyze risk factors for the access"""
        risk_factors = []
        
        try:
            current_time = datetime.now()
            
            # Check for off-hours access (outside 9 AM - 6 PM)
            if current_time.hour < 9 or current_time.hour > 18:
                risk_factors.append("off_hours_access")
            
            # Check for weekend access
            if current_time.weekday() >= 5:  # Saturday = 5, Sunday = 6
                risk_factors.append("weekend_access")
            
            # Check for unusual IP address
            if request:
                ip_address = request.remote_addr
                # In production, you would check against known admin IP ranges
                if not self._is_known_admin_ip(ip_address):
                    risk_factors.append("unusual_ip")
            
            # Check for cross-organization access
            if target_user_id:
                admin_user = self.user_manager.get_user_by_id(admin_user_id)
                target_user = self.user_manager.get_user_by_id(target_user_id)
                
                if (admin_user and target_user and 
                    admin_user.organization_id != target_user.organization_id):
                    risk_factors.append("cross_org_access")
            
            # Check for repeated access patterns
            recent_events = self._get_recent_events(admin_user_id, hours=1)
            if len(recent_events) > 5:
                risk_factors.append("repeated_access")
            
            # Check for bulk data access
            if access_type == AccessType.BULK_DATA_EXPORT:
                risk_factors.append("bulk_access")
            
            # Check for privileged escalation
            if access_type == AccessType.ADMIN_ESCALATION:
                risk_factors.append("privileged_escalation")
            
            # Check for audit log tampering
            if access_type == AccessType.AUDIT_LOG_ACCESS:
                risk_factors.append("audit_tampering")
            
        except Exception as e:
            logger.error(f"Risk factor analysis failed: {e}")
        
        return risk_factors
    
    def _calculate_threat_level(self, risk_factors: List[str]) -> ThreatLevel:
        """Calculate threat level based on risk factors"""
        risk_score = 0.0
        
        for factor in risk_factors:
            risk_score += self.risk_weights.get(factor, 0.1)
        
        if risk_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.5:
            return ThreatLevel.HIGH
        elif risk_score >= 0.3:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _is_known_admin_ip(self, ip_address: str) -> bool:
        """Check if IP address is from known admin range"""
        # Stub implementation - in production would check against whitelist
        known_ranges = ['127.0.0.1', '192.168.1.0/24', '10.0.0.0/8']
        return True  # For development
    
    def _get_recent_events(self, admin_user_id: str, hours: int = 24) -> List[InsiderThreatEvent]:
        """Get recent events for admin user"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_events = []
        for event in self.threat_events:
            event_time = datetime.fromisoformat(event.timestamp)
            if (event.admin_user_id == admin_user_id and 
                event_time >= cutoff_time):
                recent_events.append(event)
        
        return recent_events
    
    def _gather_additional_context(self) -> Dict[str, Any]:
        """Gather additional context for the access"""
        context = {}
        
        if request:
            context.update({
                'request_method': request.method,
                'request_path': request.path,
                'request_args': dict(request.args),
                'content_type': request.content_type,
                'content_length': request.content_length
            })
        
        return context
    
    def request_jit_escalation(self, admin_user_id: str, requested_action: str,
                             target_resource: str, justification: str,
                             duration_minutes: int = 60) -> str:
        """Request just-in-time privilege escalation"""
        try:
            import uuid
            
            request_id = str(uuid.uuid4())
            expires_at = datetime.now() + timedelta(minutes=duration_minutes)
            
            escalation_request = JITEscalationRequest(
                request_id=request_id,
                admin_user_id=admin_user_id,
                requested_action=requested_action,
                target_resource=target_resource,
                justification=justification,
                requested_at=datetime.now().isoformat(),
                expires_at=expires_at.isoformat()
            )
            
            with self._lock:
                self.escalation_requests[request_id] = escalation_request
                self._save_audit_data()
            
            logger.info(f"JIT escalation requested: {request_id}")
            return request_id
            
        except Exception as e:
            logger.error(f"Failed to request JIT escalation: {e}")
            return ""
    
    def approve_jit_escalation(self, request_id: str, approver_user_id: str) -> bool:
        """Approve just-in-time escalation request"""
        try:
            with self._lock:
                if request_id not in self.escalation_requests:
                    return False
                
                request_obj = self.escalation_requests[request_id]
                
                # Check if request has expired
                expires_at = datetime.fromisoformat(request_obj.expires_at)
                if datetime.now() > expires_at:
                    return False
                
                # Approve the request
                request_obj.approved = True
                request_obj.approved_by = approver_user_id
                request_obj.approved_at = datetime.now().isoformat()
                
                self._save_audit_data()
                
                logger.info(f"JIT escalation approved: {request_id} by {approver_user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to approve JIT escalation: {e}")
            return False
    
    def use_jit_escalation(self, request_id: str) -> bool:
        """Use approved JIT escalation"""
        try:
            with self._lock:
                if request_id not in self.escalation_requests:
                    return False
                
                request_obj = self.escalation_requests[request_id]
                
                if not request_obj.approved or request_obj.used:
                    return False
                
                # Check if approval has expired
                expires_at = datetime.fromisoformat(request_obj.expires_at)
                if datetime.now() > expires_at:
                    return False
                
                # Mark as used
                request_obj.used = True
                request_obj.used_at = datetime.now().isoformat()
                
                self._save_audit_data()
                
                logger.info(f"JIT escalation used: {request_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to use JIT escalation: {e}")
            return False
    
    def get_threat_events(self, admin_user_id: Optional[str] = None,
                         threat_level: Optional[ThreatLevel] = None,
                         hours: int = 24) -> List[InsiderThreatEvent]:
        """Get threat events with optional filtering"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        filtered_events = []
        for event in self.threat_events:
            event_time = datetime.fromisoformat(event.timestamp)
            
            if event_time < cutoff_time:
                continue
            
            if admin_user_id and event.admin_user_id != admin_user_id:
                continue
            
            if threat_level and event.threat_level != threat_level:
                continue
            
            filtered_events.append(event)
        
        return sorted(filtered_events, key=lambda x: x.timestamp, reverse=True)
    
    def get_escalation_requests(self, admin_user_id: Optional[str] = None,
                              pending_only: bool = False) -> List[JITEscalationRequest]:
        """Get escalation requests"""
        requests = list(self.escalation_requests.values())
        
        if admin_user_id:
            requests = [r for r in requests if r.admin_user_id == admin_user_id]
        
        if pending_only:
            requests = [r for r in requests if not r.approved and not r.used]
        
        return sorted(requests, key=lambda x: x.requested_at, reverse=True)

# Global instance
insider_threat_monitor = InsiderThreatMonitor()

def log_admin_access(target_user_id: Optional[str] = None, 
                    access_type: AccessType = AccessType.USER_DATA_ACCESS,
                    resource_type: str = "user_data", resource_id: str = "",
                    action: str = "read", justification: Optional[str] = None):
    """
    Decorator to log admin access to user data
    """
    def decorator(f):
        def wrapper(*args, **kwargs):
            admin_user_id = getattr(g, 'user_id', None)
            if admin_user_id:
                insider_threat_monitor.log_privileged_access(
                    admin_user_id=admin_user_id,
                    target_user_id=target_user_id,
                    access_type=access_type,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=action,
                    justification=justification
                )
            return f(*args, **kwargs)
        return wrapper
    return decorator
