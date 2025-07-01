"""
Audit trail management for ByteGuardX
Provides comprehensive audit logging and compliance tracking
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

class AuditLevel(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AuditEventType(Enum):
    """Types of audit events"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    ROLE_ASSIGNED = "role_assigned"
    PERMISSION_GRANTED = "permission_granted"
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    DATA_EXPORT = "data_export"
    API_ACCESS = "api_access"

@dataclass
class AuditEvent:
    """Audit event record"""
    event_id: str
    event_type: AuditEventType
    level: AuditLevel
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    outcome: str = "success"  # success, failure, error
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'level': self.level.value,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'action': self.action,
            'details': self.details,
            'outcome': self.outcome,
            'error_message': self.error_message
        }

class AuditTrailManager:
    """
    Comprehensive audit trail manager for compliance and security monitoring
    """
    
    def __init__(self, audit_dir: str = "data/audit"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory buffer for performance
        self.event_buffer: List[AuditEvent] = []
        self.buffer_size = 100
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Configuration
        self.retention_days = 365  # 1 year retention
        self.auto_flush_interval = 60  # seconds
        
        # Start background flushing
        self._start_background_flush()
    
    def log_event(self, event_type: AuditEventType, level: AuditLevel = AuditLevel.INFO,
                  user_id: str = None, session_id: str = None, ip_address: str = None,
                  user_agent: str = None, resource_type: str = None, resource_id: str = None,
                  action: str = None, details: Dict[str, Any] = None, outcome: str = "success",
                  error_message: str = None) -> str:
        """Log an audit event"""
        try:
            import uuid
            
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                level=level,
                timestamp=datetime.now(),
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                details=details or {},
                outcome=outcome,
                error_message=error_message
            )
            
            with self._lock:
                self.event_buffer.append(event)
                
                # Flush if buffer is full
                if len(self.event_buffer) >= self.buffer_size:
                    self._flush_buffer()
            
            logger.debug(f"Logged audit event: {event_type.value}")
            return event.event_id
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return ""
    
    def log_user_login(self, user_id: str, ip_address: str = None, 
                      user_agent: str = None, outcome: str = "success") -> str:
        """Log user login event"""
        return self.log_event(
            event_type=AuditEventType.USER_LOGIN,
            level=AuditLevel.INFO,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            outcome=outcome
        )
    
    def log_scan_event(self, scan_id: str, user_id: str = None, 
                      action: str = "started", details: Dict[str, Any] = None) -> str:
        """Log scan-related event"""
        event_type = AuditEventType.SCAN_STARTED if action == "started" else AuditEventType.SCAN_COMPLETED
        
        return self.log_event(
            event_type=event_type,
            level=AuditLevel.INFO,
            user_id=user_id,
            resource_type="scan",
            resource_id=scan_id,
            action=action,
            details=details
        )
    
    def log_api_access(self, endpoint: str, method: str, user_id: str = None,
                      ip_address: str = None, status_code: int = 200) -> str:
        """Log API access event"""
        level = AuditLevel.WARNING if status_code >= 400 else AuditLevel.INFO
        outcome = "failure" if status_code >= 400 else "success"
        
        return self.log_event(
            event_type=AuditEventType.API_ACCESS,
            level=level,
            user_id=user_id,
            ip_address=ip_address,
            resource_type="api_endpoint",
            resource_id=endpoint,
            action=method.lower(),
            details={"status_code": status_code},
            outcome=outcome
        )
    
    def get_events(self, start_date: datetime = None, end_date: datetime = None,
                  event_type: AuditEventType = None, user_id: str = None,
                  level: AuditLevel = None, limit: int = 1000) -> List[AuditEvent]:
        """Retrieve audit events with filtering"""
        try:
            # Flush current buffer first
            with self._lock:
                self._flush_buffer()
            
            events = []
            
            # Read from audit files
            for audit_file in self.audit_dir.glob("audit_*.json"):
                try:
                    with open(audit_file, 'r') as f:
                        file_events = json.load(f)
                    
                    for event_data in file_events:
                        # Parse event
                        event = AuditEvent(
                            event_id=event_data['event_id'],
                            event_type=AuditEventType(event_data['event_type']),
                            level=AuditLevel(event_data['level']),
                            timestamp=datetime.fromisoformat(event_data['timestamp']),
                            user_id=event_data.get('user_id'),
                            session_id=event_data.get('session_id'),
                            ip_address=event_data.get('ip_address'),
                            user_agent=event_data.get('user_agent'),
                            resource_type=event_data.get('resource_type'),
                            resource_id=event_data.get('resource_id'),
                            action=event_data.get('action'),
                            details=event_data.get('details', {}),
                            outcome=event_data.get('outcome', 'success'),
                            error_message=event_data.get('error_message')
                        )
                        
                        # Apply filters
                        if start_date and event.timestamp < start_date:
                            continue
                        if end_date and event.timestamp > end_date:
                            continue
                        if event_type and event.event_type != event_type:
                            continue
                        if user_id and event.user_id != user_id:
                            continue
                        if level and event.level != level:
                            continue
                        
                        events.append(event)
                        
                        if len(events) >= limit:
                            break
                    
                    if len(events) >= limit:
                        break
                        
                except Exception as e:
                    logger.error(f"Failed to read audit file {audit_file}: {e}")
            
            # Sort by timestamp (newest first)
            events.sort(key=lambda e: e.timestamp, reverse=True)
            
            return events[:limit]
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit events: {e}")
            return []
    
    def export_audit_trail(self, start_date: datetime, end_date: datetime,
                          format: str = "json") -> str:
        """Export audit trail for compliance"""
        try:
            events = self.get_events(start_date=start_date, end_date=end_date, limit=10000)
            
            export_dir = self.audit_dir / "exports"
            export_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format == "json":
                export_file = export_dir / f"audit_export_{timestamp}.json"
                with open(export_file, 'w') as f:
                    json.dump([event.to_dict() for event in events], f, indent=2)
            
            elif format == "csv":
                import csv
                export_file = export_dir / f"audit_export_{timestamp}.csv"
                with open(export_file, 'w', newline='') as f:
                    if events:
                        writer = csv.DictWriter(f, fieldnames=events[0].to_dict().keys())
                        writer.writeheader()
                        for event in events:
                            writer.writerow(event.to_dict())
            
            logger.info(f"Exported {len(events)} audit events to {export_file}")
            return str(export_file)
            
        except Exception as e:
            logger.error(f"Failed to export audit trail: {e}")
            raise
    
    def _flush_buffer(self):
        """Flush event buffer to disk"""
        if not self.event_buffer:
            return
        
        try:
            # Create daily audit file
            today = datetime.now().strftime("%Y%m%d")
            audit_file = self.audit_dir / f"audit_{today}.json"
            
            # Load existing events
            existing_events = []
            if audit_file.exists():
                with open(audit_file, 'r') as f:
                    existing_events = json.load(f)
            
            # Add new events
            new_events = [event.to_dict() for event in self.event_buffer]
            existing_events.extend(new_events)
            
            # Write back to file
            with open(audit_file, 'w') as f:
                json.dump(existing_events, f, indent=2)
            
            # Clear buffer
            self.event_buffer.clear()
            
            logger.debug(f"Flushed {len(new_events)} audit events to {audit_file}")
            
        except Exception as e:
            logger.error(f"Failed to flush audit buffer: {e}")
    
    def _start_background_flush(self):
        """Start background thread for periodic flushing"""
        def flush_worker():
            import time
            while True:
                try:
                    time.sleep(self.auto_flush_interval)
                    with self._lock:
                        self._flush_buffer()
                except Exception as e:
                    logger.error(f"Background flush error: {e}")
        
        import threading
        flush_thread = threading.Thread(target=flush_worker, daemon=True)
        flush_thread.start()
    
    def cleanup_old_events(self):
        """Clean up old audit events based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            cutoff_str = cutoff_date.strftime("%Y%m%d")
            
            for audit_file in self.audit_dir.glob("audit_*.json"):
                # Extract date from filename
                filename = audit_file.stem
                if len(filename) >= 14:  # audit_YYYYMMDD
                    file_date_str = filename[-8:]
                    if file_date_str < cutoff_str:
                        audit_file.unlink()
                        logger.info(f"Deleted old audit file: {audit_file}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old audit events: {e}")

# Global audit trail manager
audit_trail = AuditTrailManager()
