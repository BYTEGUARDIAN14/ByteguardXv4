"""
Secure Logging System for ByteGuardX
Provides sanitized logging with PII redaction and injection protection
"""

import re
import logging
import json
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import hashlib

class SecureLogFormatter(logging.Formatter):
    """Custom log formatter with security sanitization"""
    
    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS = {
        'password': [
            r'password["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'"password"\s*:\s*"([^"]+)"',
            r'pwd["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)'
        ],
        'token': [
            r'token["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'jwt["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
            r'authorization["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)'
        ],
        'api_key': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'apikey["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})'
        ],
        'secret': [
            r'secret["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'private[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)'
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ],
        'ip_address': [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ],
        'session_id': [
            r'session[_-]?id["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'sessionid["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)'
        ],
        'credit_card': [
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        ],
        'ssn': [
            r'\b\d{3}-\d{2}-\d{4}\b',
            r'\b\d{9}\b'
        ]
    }
    
    # Injection patterns to sanitize
    INJECTION_PATTERNS = [
        r'[\r\n]',  # Newline injection
        r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',  # Control characters
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',  # JavaScript URLs
        r'data:.*base64',  # Data URLs
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.redaction_enabled = True
        self.hash_pii = True  # Hash PII instead of just redacting
    
    def format(self, record):
        """Format log record with security sanitization"""
        # Get the original formatted message
        original_msg = super().format(record)
        
        if not self.redaction_enabled:
            return original_msg
        
        # Sanitize the message
        sanitized_msg = self.sanitize_for_log(original_msg)
        
        return sanitized_msg
    
    def sanitize_for_log(self, message: str) -> str:
        """Sanitize message for secure logging"""
        if not isinstance(message, str):
            message = str(message)
        
        # Remove injection patterns
        for pattern in self.INJECTION_PATTERNS:
            message = re.sub(pattern, '[SANITIZED]', message, flags=re.IGNORECASE | re.DOTALL)
        
        # Redact sensitive data
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if self.hash_pii and category in ['email', 'ip_address']:
                    # Hash PII data instead of redacting
                    message = re.sub(
                        pattern,
                        lambda m: f'[{category.upper()}_HASH:{self._hash_value(m.group())}]',
                        message,
                        flags=re.IGNORECASE
                    )
                else:
                    # Redact sensitive data
                    message = re.sub(
                        pattern,
                        f'[{category.upper()}_REDACTED]',
                        message,
                        flags=re.IGNORECASE
                    )
        
        return message
    
    def _hash_value(self, value: str) -> str:
        """Create a hash of sensitive value for logging"""
        return hashlib.sha256(value.encode()).hexdigest()[:8]

class SecureLogger:
    """Enhanced logger with security features"""
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.audit_logger = logging.getLogger(f"{name}.audit")
        
        # Set up formatters
        self.secure_formatter = SecureLogFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.audit_formatter = SecureLogFormatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        
        # Set up handlers
        self._setup_handlers(log_file)
    
    def _setup_handlers(self, log_file: Optional[str]):
        """Set up logging handlers"""
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.secure_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(self.secure_formatter)
            self.logger.addHandler(file_handler)
        
        # Audit file handler
        audit_handler = logging.FileHandler('logs/audit.log')
        audit_handler.setFormatter(self.audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        
        # Set levels
        self.logger.setLevel(logging.INFO)
        self.audit_logger.setLevel(logging.INFO)
    
    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log info message"""
        self.logger.info(message, extra=extra)
    
    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log warning message"""
        self.logger.warning(message, extra=extra)
    
    def error(self, message: str, extra: Dict[str, Any] = None):
        """Log error message"""
        self.logger.error(message, extra=extra)
    
    def critical(self, message: str, extra: Dict[str, Any] = None):
        """Log critical message"""
        self.logger.critical(message, extra=extra)
    
    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log debug message"""
        self.logger.debug(message, extra=extra)
    
    def audit(self, event: str, user_id: str = None, details: Dict[str, Any] = None):
        """Log audit event"""
        audit_data = {
            'event': event,
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'details': details or {}
        }
        
        self.audit_logger.info(json.dumps(audit_data))
    
    def security_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log security event"""
        security_data = {
            'event_type': event_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        
        if severity.lower() in ['high', 'critical']:
            self.logger.critical(f"SECURITY EVENT: {json.dumps(security_data)}")
        else:
            self.logger.warning(f"SECURITY EVENT: {json.dumps(security_data)}")
        
        # Also log to audit
        self.audit_logger.warning(f"SECURITY: {json.dumps(security_data)}")

class AuditLogger:
    """Specialized audit logger for compliance and security monitoring"""
    
    def __init__(self, log_file: str = "logs/audit.log"):
        self.log_file = log_file
        self.logger = SecureLogger("audit", log_file)
        
        # Ensure logs directory exists
        import os
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    def log_authentication(self, user_id: str, action: str, success: bool, 
                          ip_address: str = None, user_agent: str = None):
        """Log authentication events"""
        self.logger.audit(
            event="authentication",
            user_id=user_id,
            details={
                'action': action,
                'success': success,
                'ip_address': ip_address,
                'user_agent': user_agent
            }
        )
    
    def log_authorization(self, user_id: str, resource: str, action: str, 
                         granted: bool, reason: str = None):
        """Log authorization events"""
        self.logger.audit(
            event="authorization",
            user_id=user_id,
            details={
                'resource': resource,
                'action': action,
                'granted': granted,
                'reason': reason
            }
        )
    
    def log_data_access(self, user_id: str, resource: str, action: str, 
                       record_count: int = None):
        """Log data access events"""
        self.logger.audit(
            event="data_access",
            user_id=user_id,
            details={
                'resource': resource,
                'action': action,
                'record_count': record_count
            }
        )
    
    def log_security_scan(self, user_id: str, scan_type: str, target: str, 
                         findings_count: int, severity_counts: Dict[str, int]):
        """Log security scan events"""
        self.logger.audit(
            event="security_scan",
            user_id=user_id,
            details={
                'scan_type': scan_type,
                'target': target,
                'findings_count': findings_count,
                'severity_counts': severity_counts
            }
        )
    
    def log_admin_action(self, admin_user_id: str, action: str, target_user_id: str = None,
                        details: Dict[str, Any] = None):
        """Log administrative actions"""
        self.logger.audit(
            event="admin_action",
            user_id=admin_user_id,
            details={
                'action': action,
                'target_user_id': target_user_id,
                'details': details or {}
            }
        )
    
    def log_system_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        """Log system events"""
        self.logger.security_event(event_type, severity, details)

def sanitize_for_log(message: Any) -> str:
    """Utility function to sanitize any message for logging"""
    formatter = SecureLogFormatter()
    return formatter.sanitize_for_log(str(message))

def get_secure_logger(name: str, log_file: str = None) -> SecureLogger:
    """Get a secure logger instance"""
    return SecureLogger(name, log_file)

# Global instances
audit_logger = AuditLogger()
security_logger = get_secure_logger("byteguardx.security")
