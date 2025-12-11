"""
Role Escalation Alert System
Monitors and alerts on privilege escalation attempts and role changes
"""

import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import json

from ..database.connection_pool import db_manager
from ..database.models import User
from .audit_logger import audit_logger
from ..alerts.alert_engine import alert_engine, AlertType, AlertSeverity

logger = logging.getLogger(__name__)

class EscalationType(Enum):
    """Types of role escalation"""
    PRIVILEGE_ELEVATION = "privilege_elevation"
    ROLE_ASSIGNMENT = "role_assignment"
    PERMISSION_GRANT = "permission_grant"
    ADMIN_ACCESS = "admin_access"
    SYSTEM_ACCESS = "system_access"
    BULK_PERMISSION = "bulk_permission"

class RiskLevel(Enum):
    """Risk levels for escalation events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RoleChange:
    """Role change event"""
    user_id: str
    username: str
    old_roles: List[str]
    new_roles: List[str]
    changed_by: str
    change_reason: str
    timestamp: datetime
    escalation_type: EscalationType
    risk_level: RiskLevel
    additional_context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EscalationRule:
    """Rule for detecting role escalation"""
    rule_id: str
    name: str
    description: str
    escalation_types: List[EscalationType]
    risk_threshold: RiskLevel
    conditions: Dict[str, Any]
    alert_recipients: List[str]
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class EscalationAlert:
    """Alert for role escalation event"""
    alert_id: str
    rule_id: str
    user_id: str
    username: str
    escalation_type: EscalationType
    risk_level: RiskLevel
    description: str
    details: Dict[str, Any]
    timestamp: datetime
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None

class RoleEscalationMonitor:
    """
    Comprehensive role escalation monitoring and alerting system
    """
    
    def __init__(self):
        self.escalation_rules: Dict[str, EscalationRule] = {}
        self.recent_changes: List[RoleChange] = []
        self.active_alerts: Dict[str, EscalationAlert] = {}
        self._lock = threading.RLock()
        
        # Critical roles that require special monitoring
        self.critical_roles = {
            'admin', 'super_admin', 'system_admin', 'security_admin',
            'compliance_officer', 'audit_admin', 'root'
        }
        
        # Sensitive permissions
        self.sensitive_permissions = {
            'user_management', 'role_management', 'system_config',
            'security_settings', 'audit_access', 'backup_access',
            'database_admin', 'api_admin'
        }
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default escalation detection rules"""
        
        # Critical role assignment rule
        self.add_escalation_rule(EscalationRule(
            rule_id="critical_role_assignment",
            name="Critical Role Assignment",
            description="Alert when users are assigned critical administrative roles",
            escalation_types=[EscalationType.ROLE_ASSIGNMENT, EscalationType.ADMIN_ACCESS],
            risk_threshold=RiskLevel.HIGH,
            conditions={
                'critical_roles': list(self.critical_roles),
                'immediate_alert': True
            },
            alert_recipients=['security@byteguardx.com', 'admin@byteguardx.com']
        ))
        
        # Bulk permission grant rule
        self.add_escalation_rule(EscalationRule(
            rule_id="bulk_permission_grant",
            name="Bulk Permission Grant",
            description="Alert when multiple sensitive permissions are granted at once",
            escalation_types=[EscalationType.BULK_PERMISSION],
            risk_threshold=RiskLevel.MEDIUM,
            conditions={
                'permission_threshold': 3,
                'time_window_minutes': 10
            },
            alert_recipients=['security@byteguardx.com']
        ))
        
        # Privilege elevation rule
        self.add_escalation_rule(EscalationRule(
            rule_id="privilege_elevation",
            name="Privilege Elevation",
            description="Alert when user privileges are significantly elevated",
            escalation_types=[EscalationType.PRIVILEGE_ELEVATION],
            risk_threshold=RiskLevel.MEDIUM,
            conditions={
                'elevation_threshold': 2,  # Number of privilege levels
                'monitor_recent_users': True
            },
            alert_recipients=['security@byteguardx.com']
        ))
        
        # System access rule
        self.add_escalation_rule(EscalationRule(
            rule_id="system_access_grant",
            name="System Access Grant",
            description="Alert when system-level access is granted",
            escalation_types=[EscalationType.SYSTEM_ACCESS],
            risk_threshold=RiskLevel.CRITICAL,
            conditions={
                'system_permissions': ['system_config', 'database_admin', 'api_admin'],
                'immediate_alert': True
            },
            alert_recipients=['security@byteguardx.com', 'admin@byteguardx.com', 'cto@byteguardx.com']
        ))
    
    def add_escalation_rule(self, rule: EscalationRule):
        """Add a new escalation detection rule"""
        with self._lock:
            self.escalation_rules[rule.rule_id] = rule
            logger.info(f"Added escalation rule: {rule.name}")
    
    def monitor_role_change(self, user_id: str, old_roles: List[str], new_roles: List[str],
                           changed_by: str, change_reason: str = "",
                           additional_context: Dict[str, Any] = None) -> List[EscalationAlert]:
        """Monitor a role change event and generate alerts if needed"""
        try:
            with self._lock:
                # Get user information
                user = self._get_user_info(user_id)
                if not user:
                    logger.warning(f"User {user_id} not found for role change monitoring")
                    return []
                
                # Analyze the role change
                escalation_type, risk_level = self._analyze_role_change(old_roles, new_roles)
                
                # Create role change record
                role_change = RoleChange(
                    user_id=user_id,
                    username=user.get('username', 'unknown'),
                    old_roles=old_roles,
                    new_roles=new_roles,
                    changed_by=changed_by,
                    change_reason=change_reason,
                    timestamp=datetime.now(),
                    escalation_type=escalation_type,
                    risk_level=risk_level,
                    additional_context=additional_context or {}
                )
                
                # Store recent change
                self.recent_changes.append(role_change)
                
                # Keep only recent changes (last 24 hours)
                cutoff_time = datetime.now() - timedelta(hours=24)
                self.recent_changes = [
                    change for change in self.recent_changes
                    if change.timestamp > cutoff_time
                ]
                
                # Check against escalation rules
                alerts = self._check_escalation_rules(role_change)
                
                # Log the role change
                audit_logger.log_security_event(
                    event_type="role_change_monitored",
                    user_id=user_id,
                    details={
                        'old_roles': old_roles,
                        'new_roles': new_roles,
                        'changed_by': changed_by,
                        'escalation_type': escalation_type.value,
                        'risk_level': risk_level.value,
                        'alerts_generated': len(alerts)
                    }
                )
                
                return alerts
                
        except Exception as e:
            logger.error(f"Error monitoring role change: {e}")
            return []
    
    def _analyze_role_change(self, old_roles: List[str], new_roles: List[str]) -> tuple[EscalationType, RiskLevel]:
        """Analyze role change to determine escalation type and risk level"""
        added_roles = set(new_roles) - set(old_roles)
        removed_roles = set(old_roles) - set(new_roles)
        
        # Check for critical role assignment
        if any(role in self.critical_roles for role in added_roles):
            return EscalationType.ADMIN_ACCESS, RiskLevel.CRITICAL
        
        # Check for system access
        if any(role.endswith('_admin') or 'system' in role.lower() for role in added_roles):
            return EscalationType.SYSTEM_ACCESS, RiskLevel.HIGH
        
        # Check for privilege elevation
        if len(added_roles) > len(removed_roles):
            if len(added_roles) >= 3:
                return EscalationType.BULK_PERMISSION, RiskLevel.MEDIUM
            else:
                return EscalationType.PRIVILEGE_ELEVATION, RiskLevel.MEDIUM
        
        # Default to role assignment
        return EscalationType.ROLE_ASSIGNMENT, RiskLevel.LOW
    
    def _check_escalation_rules(self, role_change: RoleChange) -> List[EscalationAlert]:
        """Check role change against escalation rules"""
        alerts = []
        
        for rule in self.escalation_rules.values():
            if not rule.is_active:
                continue
            
            # Check if escalation type matches
            if role_change.escalation_type not in rule.escalation_types:
                continue
            
            # Check risk threshold
            risk_levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            if risk_levels.index(role_change.risk_level) < risk_levels.index(rule.risk_threshold):
                continue
            
            # Check rule-specific conditions
            if self._check_rule_conditions(rule, role_change):
                alert = self._create_escalation_alert(rule, role_change)
                alerts.append(alert)
                self._send_alert(alert)
        
        return alerts
    
    def _check_rule_conditions(self, rule: EscalationRule, role_change: RoleChange) -> bool:
        """Check if rule conditions are met"""
        conditions = rule.conditions
        
        # Check critical roles condition
        if 'critical_roles' in conditions:
            critical_roles = set(conditions['critical_roles'])
            added_roles = set(role_change.new_roles) - set(role_change.old_roles)
            if not (critical_roles & added_roles):
                return False
        
        # Check permission threshold condition
        if 'permission_threshold' in conditions:
            added_roles = set(role_change.new_roles) - set(role_change.old_roles)
            if len(added_roles) < conditions['permission_threshold']:
                return False
        
        # Check time window condition
        if 'time_window_minutes' in conditions:
            time_window = timedelta(minutes=conditions['time_window_minutes'])
            recent_changes = [
                change for change in self.recent_changes
                if (change.user_id == role_change.user_id and
                    change.timestamp > role_change.timestamp - time_window)
            ]
            if len(recent_changes) < 2:  # Current change plus at least one more
                return False
        
        # Check system permissions condition
        if 'system_permissions' in conditions:
            system_perms = set(conditions['system_permissions'])
            added_roles = set(role_change.new_roles) - set(role_change.old_roles)
            if not any(perm in role.lower() for role in added_roles for perm in system_perms):
                return False
        
        return True
    
    def _create_escalation_alert(self, rule: EscalationRule, role_change: RoleChange) -> EscalationAlert:
        """Create an escalation alert"""
        import uuid
        
        alert_id = str(uuid.uuid4())
        
        description = f"Role escalation detected: {role_change.username} was granted {role_change.escalation_type.value}"
        
        details = {
            'rule_name': rule.name,
            'user_id': role_change.user_id,
            'username': role_change.username,
            'old_roles': role_change.old_roles,
            'new_roles': role_change.new_roles,
            'changed_by': role_change.changed_by,
            'change_reason': role_change.change_reason,
            'escalation_type': role_change.escalation_type.value,
            'risk_level': role_change.risk_level.value,
            'timestamp': role_change.timestamp.isoformat()
        }
        
        alert = EscalationAlert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            user_id=role_change.user_id,
            username=role_change.username,
            escalation_type=role_change.escalation_type,
            risk_level=role_change.risk_level,
            description=description,
            details=details,
            timestamp=datetime.now()
        )
        
        self.active_alerts[alert_id] = alert
        return alert
    
    def _send_alert(self, alert: EscalationAlert):
        """Send escalation alert through alert engine"""
        try:
            # Map risk level to alert severity
            severity_map = {
                RiskLevel.LOW: AlertSeverity.LOW,
                RiskLevel.MEDIUM: AlertSeverity.MEDIUM,
                RiskLevel.HIGH: AlertSeverity.HIGH,
                RiskLevel.CRITICAL: AlertSeverity.CRITICAL
            }
            
            # Send through alert engine
            alert_engine.create_alert(
                alert_type=AlertType.SECURITY_INCIDENT,
                severity=severity_map[alert.risk_level],
                title=f"Role Escalation: {alert.username}",
                message=alert.description,
                details=alert.details,
                user_id=alert.user_id
            )
            
            logger.warning(f"Role escalation alert sent: {alert.description}")
            
        except Exception as e:
            logger.error(f"Failed to send escalation alert: {e}")
    
    def _get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information"""
        try:
            # In production, query from database
            return {'username': f'user_{user_id}', 'email': f'user_{user_id}@example.com'}
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            return None

# Global instance
role_escalation_monitor = RoleEscalationMonitor()
