"""
Secure Log Redaction System for ByteGuardX
Automatically redacts sensitive information from logs to prevent data leaks
"""

import re
import logging
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class SensitiveDataType(Enum):
    """Types of sensitive data to redact"""
    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    SECRET = "secret"
    PRIVATE_KEY = "private_key"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    URL_WITH_CREDENTIALS = "url_with_credentials"
    JWT_TOKEN = "jwt_token"
    HASH = "hash"

@dataclass
class RedactionRule:
    """Rule for redacting sensitive data"""
    name: str
    pattern: str
    data_type: SensitiveDataType
    replacement: str = "[REDACTED]"
    preserve_length: bool = False
    preserve_format: bool = False
    confidence: float = 1.0

class LogRedactor:
    """Secure log redaction system"""
    
    def __init__(self):
        self.redaction_rules = self._load_default_rules()
        self.custom_rules = []
        self.redaction_stats = {
            "total_redactions": 0,
            "by_type": {},
            "by_rule": {}
        }
    
    def _load_default_rules(self) -> List[RedactionRule]:
        """Load default redaction rules"""
        return [
            # Password patterns
            RedactionRule(
                name="password_field",
                pattern=r'(["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?)([^"\'\\s]+)(["\']?)',
                data_type=SensitiveDataType.PASSWORD,
                replacement=r'\1[REDACTED]\3',
                confidence=0.95
            ),
            
            # API Key patterns
            RedactionRule(
                name="api_key_generic",
                pattern=r'(["\']?(?:api[_-]?key|apikey|key)["\']?\s*[:=]\s*["\']?)([A-Za-z0-9_-]{16,})(["\']?)',
                data_type=SensitiveDataType.API_KEY,
                replacement=r'\1[REDACTED_API_KEY]\3',
                confidence=0.8
            ),
            
            # AWS Keys
            RedactionRule(
                name="aws_access_key",
                pattern=r'(AKIA[0-9A-Z]{16})',
                data_type=SensitiveDataType.API_KEY,
                replacement="[REDACTED_AWS_KEY]",
                confidence=0.99
            ),
            
            RedactionRule(
                name="aws_secret_key",
                pattern=r'(["\']?(?:aws[_-]?secret|secret[_-]?key)["\']?\s*[:=]\s*["\']?)([A-Za-z0-9/+=]{40})(["\']?)',
                data_type=SensitiveDataType.SECRET,
                replacement=r'\1[REDACTED_AWS_SECRET]\3',
                confidence=0.9
            ),
            
            # GitHub tokens
            RedactionRule(
                name="github_token",
                pattern=r'(ghp_[A-Za-z0-9]{36})',
                data_type=SensitiveDataType.TOKEN,
                replacement="[REDACTED_GITHUB_TOKEN]",
                confidence=0.99
            ),
            
            # JWT tokens
            RedactionRule(
                name="jwt_token",
                pattern=r'(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)',
                data_type=SensitiveDataType.JWT_TOKEN,
                replacement="[REDACTED_JWT]",
                confidence=0.95
            ),
            
            # Bearer tokens
            RedactionRule(
                name="bearer_token",
                pattern=r'(Bearer\s+)([A-Za-z0-9_-]+)',
                data_type=SensitiveDataType.TOKEN,
                replacement=r'\1[REDACTED_TOKEN]',
                confidence=0.9
            ),
            
            # Private keys
            RedactionRule(
                name="private_key",
                pattern=r'(-----BEGIN [A-Z ]+PRIVATE KEY-----)(.*?)(-----END [A-Z ]+PRIVATE KEY-----)',
                data_type=SensitiveDataType.PRIVATE_KEY,
                replacement=r'\1[REDACTED_PRIVATE_KEY]\3',
                confidence=0.99
            ),
            
            # Credit card numbers
            RedactionRule(
                name="credit_card",
                pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                data_type=SensitiveDataType.CREDIT_CARD,
                replacement="[REDACTED_CC]",
                confidence=0.8
            ),
            
            # Social Security Numbers
            RedactionRule(
                name="ssn",
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                data_type=SensitiveDataType.SSN,
                replacement="[REDACTED_SSN]",
                confidence=0.9
            ),
            
            # Email addresses (partial redaction)
            RedactionRule(
                name="email_address",
                pattern=r'\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                data_type=SensitiveDataType.EMAIL,
                replacement=r'[REDACTED]@\2',
                confidence=0.7
            ),
            
            # Phone numbers
            RedactionRule(
                name="phone_number",
                pattern=r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                data_type=SensitiveDataType.PHONE,
                replacement="[REDACTED_PHONE]",
                confidence=0.8
            ),
            
            # URLs with credentials
            RedactionRule(
                name="url_with_credentials",
                pattern=r'(https?://)([^:]+):([^@]+)@([^\s]+)',
                data_type=SensitiveDataType.URL_WITH_CREDENTIALS,
                replacement=r'\1[REDACTED]:[REDACTED]@\4',
                confidence=0.95
            ),
            
            # Database connection strings
            RedactionRule(
                name="db_connection",
                pattern=r'((?:postgresql|mysql|mongodb|redis)://[^:]+:)([^@]+)(@[^\s]+)',
                data_type=SensitiveDataType.PASSWORD,
                replacement=r'\1[REDACTED]\3',
                confidence=0.9
            ),
            
            # Generic secrets
            RedactionRule(
                name="generic_secret",
                pattern=r'(["\']?(?:secret|token|key)["\']?\s*[:=]\s*["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
                data_type=SensitiveDataType.SECRET,
                replacement=r'\1[REDACTED]\3',
                confidence=0.6
            ),
            
            # Hash values (partial redaction)
            RedactionRule(
                name="hash_values",
                pattern=r'\b([a-fA-F0-9]{32,128})\b',
                data_type=SensitiveDataType.HASH,
                replacement=lambda m: f"[HASH_{m.group(1)[:8]}...]",
                confidence=0.5
            ),
            
            # IP addresses (partial redaction)
            RedactionRule(
                name="ip_address",
                pattern=r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b',
                data_type=SensitiveDataType.IP_ADDRESS,
                replacement=r'\1.\2.XXX.XXX',
                confidence=0.6
            )
        ]
    
    def add_custom_rule(self, rule: RedactionRule):
        """Add a custom redaction rule"""
        self.custom_rules.append(rule)
        logger.info(f"Added custom redaction rule: {rule.name}")
    
    def redact_text(self, text: str, preserve_structure: bool = True) -> str:
        """Redact sensitive information from text"""
        if not text:
            return text
        
        redacted_text = text
        redactions_made = 0
        
        # Apply all rules
        all_rules = self.redaction_rules + self.custom_rules
        
        for rule in all_rules:
            try:
                # Apply the redaction rule
                if callable(rule.replacement):
                    # Custom replacement function
                    def replace_func(match):
                        self._record_redaction(rule)
                        return rule.replacement(match)
                    
                    redacted_text = re.sub(rule.pattern, replace_func, redacted_text, flags=re.IGNORECASE | re.DOTALL)
                else:
                    # String replacement
                    matches = list(re.finditer(rule.pattern, redacted_text, re.IGNORECASE | re.DOTALL))
                    if matches:
                        redacted_text = re.sub(rule.pattern, rule.replacement, redacted_text, flags=re.IGNORECASE | re.DOTALL)
                        redactions_made += len(matches)
                        
                        # Record redactions
                        for _ in matches:
                            self._record_redaction(rule)
                
            except Exception as e:
                logger.warning(f"Redaction rule '{rule.name}' failed: {e}")
        
        return redacted_text
    
    def redact_dict(self, data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """Redact sensitive information from dictionary"""
        if not isinstance(data, dict):
            return data
        
        # Default sensitive keys
        if sensitive_keys is None:
            sensitive_keys = [
                'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key',
                'access_token', 'refresh_token', 'private_key', 'auth', 'authorization',
                'credential', 'credentials', 'session', 'cookie'
            ]
        
        redacted_data = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key is sensitive
            is_sensitive_key = any(sensitive_key in key_lower for sensitive_key in sensitive_keys)
            
            if is_sensitive_key:
                # Redact the entire value
                if isinstance(value, str) and len(value) > 0:
                    redacted_data[key] = "[REDACTED]"
                    self._record_redaction_by_type(SensitiveDataType.SECRET)
                else:
                    redacted_data[key] = "[REDACTED]"
            elif isinstance(value, str):
                # Apply text redaction
                redacted_data[key] = self.redact_text(value)
            elif isinstance(value, dict):
                # Recursively redact nested dictionaries
                redacted_data[key] = self.redact_dict(value, sensitive_keys)
            elif isinstance(value, list):
                # Redact list items
                redacted_data[key] = [
                    self.redact_dict(item, sensitive_keys) if isinstance(item, dict)
                    else self.redact_text(str(item)) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                redacted_data[key] = value
        
        return redacted_data
    
    def redact_json(self, json_str: str) -> str:
        """Redact sensitive information from JSON string"""
        try:
            data = json.loads(json_str)
            redacted_data = self.redact_dict(data)
            return json.dumps(redacted_data, indent=2)
        except json.JSONDecodeError:
            # If not valid JSON, treat as regular text
            return self.redact_text(json_str)
    
    def redact_log_record(self, record: logging.LogRecord) -> logging.LogRecord:
        """Redact sensitive information from log record"""
        # Redact the message
        if hasattr(record, 'msg') and record.msg:
            record.msg = self.redact_text(str(record.msg))
        
        # Redact arguments
        if hasattr(record, 'args') and record.args:
            redacted_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    redacted_args.append(self.redact_text(arg))
                elif isinstance(arg, dict):
                    redacted_args.append(self.redact_dict(arg))
                else:
                    redacted_args.append(arg)
            record.args = tuple(redacted_args)
        
        return record
    
    def _record_redaction(self, rule: RedactionRule):
        """Record redaction statistics"""
        self.redaction_stats["total_redactions"] += 1
        
        # By type
        data_type = rule.data_type.value
        if data_type not in self.redaction_stats["by_type"]:
            self.redaction_stats["by_type"][data_type] = 0
        self.redaction_stats["by_type"][data_type] += 1
        
        # By rule
        rule_name = rule.name
        if rule_name not in self.redaction_stats["by_rule"]:
            self.redaction_stats["by_rule"][rule_name] = 0
        self.redaction_stats["by_rule"][rule_name] += 1
    
    def _record_redaction_by_type(self, data_type: SensitiveDataType):
        """Record redaction by type only"""
        self.redaction_stats["total_redactions"] += 1
        
        type_name = data_type.value
        if type_name not in self.redaction_stats["by_type"]:
            self.redaction_stats["by_type"][type_name] = 0
        self.redaction_stats["by_type"][type_name] += 1
    
    def get_redaction_stats(self) -> Dict[str, Any]:
        """Get redaction statistics"""
        return self.redaction_stats.copy()
    
    def reset_stats(self):
        """Reset redaction statistics"""
        self.redaction_stats = {
            "total_redactions": 0,
            "by_type": {},
            "by_rule": {}
        }
    
    def create_redacted_hash(self, sensitive_data: str) -> str:
        """Create a consistent hash for redacted data (for correlation)"""
        return hashlib.sha256(sensitive_data.encode()).hexdigest()[:16]

class RedactingLogHandler(logging.Handler):
    """Log handler that automatically redacts sensitive information"""
    
    def __init__(self, target_handler: logging.Handler, redactor: Optional[LogRedactor] = None):
        super().__init__()
        self.target_handler = target_handler
        self.redactor = redactor or LogRedactor()
        
        # Copy settings from target handler
        self.setLevel(target_handler.level)
        self.setFormatter(target_handler.formatter)
    
    def emit(self, record: logging.LogRecord):
        """Emit log record after redacting sensitive information"""
        try:
            # Redact the record
            redacted_record = self.redactor.redact_log_record(record)
            
            # Pass to target handler
            self.target_handler.emit(redacted_record)
            
        except Exception as e:
            # Fallback: log the error but don't expose the original record
            error_record = logging.LogRecord(
                name=record.name,
                level=logging.ERROR,
                pathname=record.pathname,
                lineno=record.lineno,
                msg=f"Log redaction failed: {str(e)}",
                args=(),
                exc_info=None
            )
            self.target_handler.emit(error_record)

class SecureLogFormatter(logging.Formatter):
    """Log formatter that includes redaction"""
    
    def __init__(self, fmt=None, datefmt=None, redactor: Optional[LogRedactor] = None):
        super().__init__(fmt, datefmt)
        self.redactor = redactor or LogRedactor()
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with redaction"""
        # Redact the record first
        redacted_record = self.redactor.redact_log_record(record)
        
        # Format normally
        return super().format(redacted_record)

def setup_secure_logging(logger_name: str = None, redactor: Optional[LogRedactor] = None) -> LogRedactor:
    """Setup secure logging with automatic redaction"""
    if redactor is None:
        redactor = LogRedactor()
    
    # Get logger
    target_logger = logging.getLogger(logger_name) if logger_name else logging.getLogger()
    
    # Replace handlers with redacting handlers
    original_handlers = target_logger.handlers.copy()
    target_logger.handlers.clear()
    
    for handler in original_handlers:
        redacting_handler = RedactingLogHandler(handler, redactor)
        target_logger.addHandler(redacting_handler)
    
    return redactor

# Global instance
log_redactor = LogRedactor()
