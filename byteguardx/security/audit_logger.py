"""
Comprehensive Audit Logging for ByteGuardX
Tracks security events, user actions, and system changes
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from pathlib import Path
import hashlib
import uuid
import re

logger = logging.getLogger(__name__)

class SecurityEventType(Enum):
    """Types of security events to audit"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    
    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGE = "permission_change"
    ROLE_CHANGE = "role_change"
    
    # 2FA events
    TWO_FA_ENABLED = "2fa_enabled"
    TWO_FA_DISABLED = "2fa_disabled"
    TWO_FA_SUCCESS = "2fa_success"
    TWO_FA_FAILURE = "2fa_failure"
    BACKUP_CODE_USED = "backup_code_used"
    
    # Data access events
    SCAN_INITIATED = "scan_initiated"
    SCAN_COMPLETED = "scan_completed"
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    DATA_EXPORT = "data_export"
    DATA_IMPORT = "data_import"
    
    # Configuration changes
    CONFIG_CHANGE = "config_change"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_MODIFIED = "user_modified"
    
    # Security events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    
    # API events
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_RATE_LIMIT = "api_rate_limit"

class EventSeverity(Enum):
    """Severity levels for audit events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    event_type: SecurityEventType
    severity: EventSeverity
    timestamp: datetime
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    organization_id: Optional[str] = None
    
    def __post_init__(self):
        if self.event_id is None:
            self.event_id = str(uuid.uuid4())
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)

class AuditLogger:
    """Comprehensive audit logging system with enhanced redaction"""

    # Enhanced sensitive data patterns to redact
    SENSITIVE_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
        (r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
        (r'key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'key'),
        (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'secret'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'authorization:\s*bearer\s+([^\s]+)', 'bearer_token'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email'),
        (r'session[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'session_id'),
        (r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'csrf_token'),
        (r'refresh[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'refresh_token'),
        (r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'access_token'),
        (r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', 'ip_address'),
        (r'["\']?(?:first_?name|last_?name|full_?name)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'personal_name'),
        (r'credit[_-]?card["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'credit_card'),
        (r'ssn["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'ssn'),
        (r'phone["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'phone'),
        (r'address["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'address'),
    ]

    def __init__(self, log_dir: str = "data/audit_logs", max_file_size: int = 10 * 1024 * 1024):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.max_file_size = max_file_size
        self.lock = threading.RLock()

        # Current log file
        self.current_log_file = None
        self._initialize_log_file()

        # In-memory buffer for high-frequency events
        self.event_buffer = []
        self.buffer_size = 100
        self.buffer_lock = threading.Lock()

        # Start background flush thread
        self._start_flush_thread()
    
    def _initialize_log_file(self):
        """Initialize the current log file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_log_file = self.log_dir / f"audit_{timestamp}.jsonl"
        
        # Create file with restrictive permissions
        self.current_log_file.touch(mode=0o600)
    
    def _get_current_log_file(self) -> Path:
        """Get current log file, rotating if necessary"""
        if self.current_log_file.exists() and self.current_log_file.stat().st_size > self.max_file_size:
            self._rotate_log_file()
        
        return self.current_log_file
    
    def _rotate_log_file(self):
        """Rotate to a new log file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_log_file = self.log_dir / f"audit_{timestamp}.jsonl"
        self.current_log_file.touch(mode=0o600)
        logger.info(f"Rotated audit log to {self.current_log_file}")
    
    def log_event(self, event: SecurityEvent):
        """Log a security event with sanitization"""
        try:
            # Sanitize event data before logging
            sanitized_event = self._sanitize_event(event)

            with self.buffer_lock:
                self.event_buffer.append(sanitized_event)

                # Flush buffer if it's full or if it's a critical event
                if len(self.event_buffer) >= self.buffer_size or event.severity == EventSeverity.CRITICAL:
                    self._flush_buffer()

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

    def _sanitize_event(self, event: SecurityEvent) -> SecurityEvent:
        """Sanitize a security event"""
        # Create a copy of the event with sanitized data
        sanitized_details = self._sanitize_data(event.details) if event.details else None

        return SecurityEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            severity=event.severity,
            timestamp=event.timestamp,
            user_id=event.user_id,
            username=self._sanitize_string(event.username) if event.username else None,
            ip_address=self._sanitize_string(event.ip_address) if event.ip_address else None,
            user_agent=self._sanitize_string(event.user_agent) if event.user_agent else None,
            session_id=event.session_id,  # Keep session ID for tracking
            action=self._sanitize_string(event.action) if event.action else None,
            resource=self._sanitize_string(event.resource) if event.resource else None,
            result=event.result,
            details=sanitized_details,
            risk_score=event.risk_score
        )
    
    def _flush_buffer(self):
        """Flush event buffer to disk"""
        if not self.event_buffer:
            return
        
        try:
            with self.lock:
                log_file = self._get_current_log_file()
                
                with open(log_file, 'a', encoding='utf-8') as f:
                    for event in self.event_buffer:
                        # Convert event to JSON
                        event_dict = asdict(event)
                        event_dict['timestamp'] = event.timestamp.isoformat()
                        event_dict['event_type'] = event.event_type.value
                        event_dict['severity'] = event.severity.value
                        
                        # Write as JSON line
                        f.write(json.dumps(event_dict, separators=(',', ':')) + '\n')
                
                # Clear buffer
                self.event_buffer.clear()
                
        except Exception as e:
            logger.error(f"Failed to flush audit buffer: {e}")
    
    def _start_flush_thread(self):
        """Start background thread to flush buffer periodically"""
        def flush_worker():
            import time
            while True:
                try:
                    time.sleep(30)  # Flush every 30 seconds
                    with self.buffer_lock:
                        if self.event_buffer:
                            self._flush_buffer()
                except Exception as e:
                    logger.error(f"Audit flush thread error: {e}")
        
        flush_thread = threading.Thread(target=flush_worker, daemon=True)
        flush_thread.start()

    def _sanitize_data(self, data: Any) -> Any:
        """Enhanced sanitization of sensitive data from log entries"""
        if isinstance(data, dict):
            return {k: self._sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        elif isinstance(data, str):
            return self._sanitize_string(data)
        else:
            return data

    def _sanitize_string(self, text: str) -> str:
        """Comprehensive string sanitization"""
        if not text:
            return text

        # Remove/replace control characters and newlines to prevent log injection
        sanitized = re.sub(r'[\r\n]', ' ', text)  # Replace newlines with spaces
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', sanitized)  # Remove control chars

        # Apply sensitive data redaction
        sanitized = self._redact_sensitive_strings(sanitized)

        # Truncate if too long
        if len(sanitized) > 1000:
            sanitized = sanitized[:997] + "..."

        return sanitized

    def _redact_sensitive_strings(self, text: str) -> str:
        """Redact sensitive information from strings"""
        redacted = text

        for pattern, data_type in self.SENSITIVE_PATTERNS:
            def redact_match(match):
                if data_type == 'email':
                    # Partially redact emails
                    email = match.group(0)
                    parts = email.split('@')
                    if len(parts) == 2:
                        username = parts[0]
                        domain = parts[1]
                        if len(username) > 2:
                            redacted_username = username[:2] + '*' * (len(username) - 2)
                        else:
                            redacted_username = '*' * len(username)
                        return f"{redacted_username}@{domain}"
                elif data_type == 'ip_address':
                    # Partially redact IP addresses
                    ip = match.group(0)
                    parts = ip.split('.')
                    return f"{parts[0]}.{parts[1]}.*.***"
                else:
                    # Full redaction for other sensitive data
                    return f"[REDACTED_{data_type.upper()}]"

            redacted = re.sub(pattern, redact_match, redacted, flags=re.IGNORECASE)

        return redacted

    def log_login_success(self, user_id: str, username: str, ip_address: str,
                         user_agent: str = None, session_id: str = None):
        """Log successful login"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.LOGIN_SUCCESS,
            severity=EventSeverity.LOW,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            action="login",
            result="success"
        )
        self.log_event(event)
    
    def log_login_failure(self, username: str, ip_address: str, reason: str,
                         user_agent: str = None):
        """Log failed login attempt"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.LOGIN_FAILURE,
            severity=EventSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            result="failure",
            details={"reason": reason}
        )
        self.log_event(event)
    
    def log_password_change(self, user_id: str, username: str, ip_address: str,
                           initiated_by: str = "user"):
        """Log password change"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.PASSWORD_CHANGE,
            severity=EventSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action="password_change",
            result="success",
            details={"initiated_by": initiated_by}
        )
        self.log_event(event)
    
    def log_2fa_event(self, event_type: SecurityEventType, user_id: str, username: str,
                     ip_address: str, success: bool, method: str = "totp"):
        """Log 2FA related events"""
        severity = EventSeverity.LOW if success else EventSeverity.MEDIUM
        
        event = SecurityEvent(
            event_id=None,
            event_type=event_type,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action="2fa_verification",
            result="success" if success else "failure",
            details={"method": method}
        )
        self.log_event(event)
    
    def log_access_denied(self, user_id: str, username: str, resource: str,
                         action: str, ip_address: str, reason: str):
        """Log access denied events"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.ACCESS_DENIED,
            severity=EventSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource=resource,
            action=action,
            result="denied",
            details={"reason": reason}
        )
        self.log_event(event)
    
    def log_scan_event(self, event_type: SecurityEventType, user_id: str, username: str,
                      scan_id: str, ip_address: str, details: Dict[str, Any] = None):
        """Log scan-related events"""
        event = SecurityEvent(
            event_id=None,
            event_type=event_type,
            severity=EventSeverity.LOW,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource=f"scan:{scan_id}",
            action="scan",
            result="success",
            details=details or {}
        )
        self.log_event(event)
    
    def log_security_violation(self, violation_type: str, user_id: str = None,
                              username: str = None, ip_address: str = None,
                              details: Dict[str, Any] = None):
        """Log security violations"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.SECURITY_VIOLATION,
            severity=EventSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action="security_check",
            result="violation",
            details={"violation_type": violation_type, **(details or {})}
        )
        self.log_event(event)
    
    def log_rate_limit_exceeded(self, identifier: str, endpoint: str, 
                               limit_type: str, ip_address: str = None):
        """Log rate limit exceeded events"""
        event = SecurityEvent(
            event_id=None,
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity=EventSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            endpoint=endpoint,
            action="rate_limit_check",
            result="exceeded",
            details={
                "identifier": identifier,
                "limit_type": limit_type
            }
        )
        self.log_event(event)
    
    def search_events(self, start_time: datetime = None, end_time: datetime = None,
                     event_types: List[SecurityEventType] = None,
                     user_id: str = None, ip_address: str = None,
                     severity: EventSeverity = None, limit: int = 1000) -> List[SecurityEvent]:
        """Search audit events with filters"""
        events = []
        
        try:
            # Get all log files in date range
            log_files = sorted(self.log_dir.glob("audit_*.jsonl"))
            
            for log_file in log_files:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            event_dict = json.loads(line.strip())
                            
                            # Parse timestamp
                            event_timestamp = datetime.fromisoformat(event_dict['timestamp'])
                            
                            # Apply filters
                            if start_time and event_timestamp < start_time:
                                continue
                            if end_time and event_timestamp > end_time:
                                continue
                            if event_types and SecurityEventType(event_dict['event_type']) not in event_types:
                                continue
                            if user_id and event_dict.get('user_id') != user_id:
                                continue
                            if ip_address and event_dict.get('ip_address') != ip_address:
                                continue
                            if severity and EventSeverity(event_dict['severity']) != severity:
                                continue
                            
                            # Create event object
                            event = SecurityEvent(
                                event_id=event_dict['event_id'],
                                event_type=SecurityEventType(event_dict['event_type']),
                                severity=EventSeverity(event_dict['severity']),
                                timestamp=event_timestamp,
                                user_id=event_dict.get('user_id'),
                                username=event_dict.get('username'),
                                ip_address=event_dict.get('ip_address'),
                                user_agent=event_dict.get('user_agent'),
                                endpoint=event_dict.get('endpoint'),
                                resource=event_dict.get('resource'),
                                action=event_dict.get('action'),
                                result=event_dict.get('result'),
                                details=event_dict.get('details'),
                                session_id=event_dict.get('session_id'),
                                organization_id=event_dict.get('organization_id')
                            )
                            
                            events.append(event)
                            
                            if len(events) >= limit:
                                break
                                
                        except (json.JSONDecodeError, KeyError, ValueError) as e:
                            logger.warning(f"Failed to parse audit log line: {e}")
                            continue
                
                if len(events) >= limit:
                    break
            
            # Sort by timestamp (newest first)
            events.sort(key=lambda x: x.timestamp, reverse=True)
            
            return events[:limit]
            
        except Exception as e:
            logger.error(f"Failed to search audit events: {e}")
            return []
    
    def get_event_statistics(self, start_time: datetime = None, 
                           end_time: datetime = None) -> Dict[str, Any]:
        """Get audit event statistics"""
        try:
            events = self.search_events(start_time=start_time, end_time=end_time, limit=10000)
            
            stats = {
                "total_events": len(events),
                "event_types": {},
                "severity_levels": {},
                "top_users": {},
                "top_ips": {},
                "failed_logins": 0,
                "successful_logins": 0,
                "security_violations": 0
            }
            
            for event in events:
                # Count by event type
                event_type = event.event_type.value
                stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                
                # Count by severity
                severity = event.severity.value
                stats["severity_levels"][severity] = stats["severity_levels"].get(severity, 0) + 1
                
                # Count by user
                if event.username:
                    stats["top_users"][event.username] = stats["top_users"].get(event.username, 0) + 1
                
                # Count by IP
                if event.ip_address:
                    stats["top_ips"][event.ip_address] = stats["top_ips"].get(event.ip_address, 0) + 1
                
                # Special counters
                if event.event_type == SecurityEventType.LOGIN_FAILURE:
                    stats["failed_logins"] += 1
                elif event.event_type == SecurityEventType.LOGIN_SUCCESS:
                    stats["successful_logins"] += 1
                elif event.event_type == SecurityEventType.SECURITY_VIOLATION:
                    stats["security_violations"] += 1
            
            # Sort top lists
            stats["top_users"] = dict(sorted(stats["top_users"].items(), key=lambda x: x[1], reverse=True)[:10])
            stats["top_ips"] = dict(sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get event statistics: {e}")
            return {}

# Global instance
audit_logger = AuditLogger()
