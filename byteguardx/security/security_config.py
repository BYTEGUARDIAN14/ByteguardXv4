#!/usr/bin/env python3
"""
Advanced Security Configuration for ByteGuardX
Centralized security settings and policies
"""

import os
from datetime import timedelta
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class SecurityPolicy:
    """Security policy configuration"""
    name: str
    enabled: bool
    severity: str
    action: str
    threshold: float
    parameters: Dict[str, Any]

class SecurityConfig:
    """
    Centralized security configuration management
    """
    
    def __init__(self):
        # Environment-based configuration
        self.environment = os.environ.get('BYTEGUARDX_ENV', 'development')
        self.debug_mode = self.environment == 'development'
        
        # Core security settings
        self.security_level = os.environ.get('SECURITY_LEVEL', 'MAXIMUM')
        self.enable_threat_detection = True
        self.enable_behavioral_analysis = True
        self.enable_device_fingerprinting = True
        self.enable_webauthn = True
        self.enable_advanced_crypto = True
        
        # Authentication settings
        self.password_policy = {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special_chars': True,
            'max_length': 128,
            'prevent_common_passwords': True,
            'password_history_count': 5
        }
        
        # Session management
        self.session_config = {
            'max_sessions_per_user': 5,
            'session_timeout': timedelta(hours=8),
            'idle_timeout': timedelta(minutes=30),
            'require_device_fingerprint': True,
            'allow_concurrent_sessions': True,
            'session_rotation_interval': timedelta(hours=1)
        }
        
        # Rate limiting configuration
        self.rate_limits = {
            'global': {'requests': 1000, 'window': 3600},  # 1000 per hour
            'login': {'requests': 3, 'window': 900},        # 3 per 15 minutes
            'register': {'requests': 2, 'window': 3600},    # 2 per hour
            'password_reset': {'requests': 3, 'window': 3600}, # 3 per hour
            'api_scan': {'requests': 10, 'window': 300},    # 10 per 5 minutes
            'file_upload': {'requests': 5, 'window': 300}   # 5 per 5 minutes
        }
        
        # Account lockout settings
        self.lockout_config = {
            'max_failed_attempts': 5,
            'lockout_duration': timedelta(minutes=30),
            'progressive_lockout': True,
            'lockout_multiplier': 2.0,
            'max_lockout_duration': timedelta(hours=24)
        }
        
        # Threat detection policies
        self.threat_policies = [
            SecurityPolicy(
                name='SQL_INJECTION_DETECTION',
                enabled=True,
                severity='CRITICAL',
                action='BLOCK',
                threshold=0.8,
                parameters={'patterns': ['union', 'select', 'drop', 'insert']}
            ),
            SecurityPolicy(
                name='XSS_DETECTION',
                enabled=True,
                severity='HIGH',
                action='SANITIZE',
                threshold=0.7,
                parameters={'patterns': ['<script', 'javascript:', 'onerror']}
            ),
            SecurityPolicy(
                name='BRUTE_FORCE_DETECTION',
                enabled=True,
                severity='HIGH',
                action='RATE_LIMIT',
                threshold=0.6,
                parameters={'window': 300, 'max_attempts': 10}
            ),
            SecurityPolicy(
                name='GEOGRAPHIC_ANOMALY',
                enabled=True,
                severity='MEDIUM',
                action='REQUIRE_2FA',
                threshold=0.5,
                parameters={'max_distance_km': 1000}
            ),
            SecurityPolicy(
                name='DEVICE_FINGERPRINT_MISMATCH',
                enabled=True,
                severity='HIGH',
                action='TERMINATE_SESSION',
                threshold=0.8,
                parameters={'tolerance': 0.1}
            )
        ]
        
        # Cryptographic settings
        self.crypto_config = {
            'default_symmetric_algorithm': 'AES-256',
            'default_asymmetric_algorithm': 'RSA-4096',
            'key_rotation_interval': timedelta(days=90),
            'max_key_usage': 1000000,
            'kdf_algorithm': 'PBKDF2',
            'kdf_iterations': 100000,
            'hash_algorithm': 'SHA-256'
        }
        
        # WebAuthn configuration
        self.webauthn_config = {
            'rp_id': os.environ.get('WEBAUTHN_RP_ID', 'localhost'),
            'rp_name': 'ByteGuardX Security Platform',
            'require_resident_key': False,
            'require_user_verification': True,
            'timeout': 60000,  # 60 seconds
            'attestation': 'direct'
        }
        
        # Security headers configuration
        self.security_headers = {
            'Content-Security-Policy': self._get_csp_policy(),
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin'
        }
        
        # Audit and logging configuration
        self.audit_config = {
            'log_all_requests': True,
            'log_failed_auth': True,
            'log_privilege_escalation': True,
            'log_data_access': True,
            'log_configuration_changes': True,
            'retention_days': 365,
            'encrypt_logs': True,
            'real_time_alerts': True
        }
        
        # Compliance settings
        self.compliance_config = {
            'gdpr_enabled': True,
            'ccpa_enabled': True,
            'sox_enabled': True,
            'pci_dss_enabled': False,
            'hipaa_enabled': False,
            'data_retention_days': 2555,  # 7 years
            'right_to_erasure': True,
            'data_portability': True
        }
        
        # Monitoring and alerting
        self.monitoring_config = {
            'enable_real_time_monitoring': True,
            'alert_on_critical_threats': True,
            'alert_on_failed_logins': True,
            'alert_on_privilege_escalation': True,
            'alert_on_data_exfiltration': True,
            'notification_channels': ['email', 'webhook'],
            'alert_threshold_critical': 1,
            'alert_threshold_high': 5,
            'alert_threshold_medium': 10
        }
    
    def _get_csp_policy(self) -> str:
        """Generate Content Security Policy based on environment"""
        if self.debug_mode:
            # More permissive CSP for development
            return (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        else:
            # Strict CSP for production
            return (
                "default-src 'none'; "
                "script-src 'self' 'strict-dynamic'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "media-src 'none'; "
                "object-src 'none'; "
                "child-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "upgrade-insecure-requests; "
                "block-all-mixed-content"
            )
    
    def get_policy_by_name(self, policy_name: str) -> SecurityPolicy:
        """Get security policy by name"""
        for policy in self.threat_policies:
            if policy.name == policy_name:
                return policy
        raise ValueError(f"Policy not found: {policy_name}")
    
    def is_policy_enabled(self, policy_name: str) -> bool:
        """Check if a security policy is enabled"""
        try:
            policy = self.get_policy_by_name(policy_name)
            return policy.enabled
        except ValueError:
            return False
    
    def get_rate_limit(self, endpoint: str) -> Dict[str, int]:
        """Get rate limit configuration for endpoint"""
        return self.rate_limits.get(endpoint, self.rate_limits['global'])
    
    def should_require_2fa(self, user_role: str) -> bool:
        """Determine if 2FA should be required for user role"""
        required_roles = ['admin', 'manager', 'security_officer']
        return user_role.lower() in required_roles
    
    def get_session_timeout(self, security_level: str) -> timedelta:
        """Get session timeout based on security level"""
        timeouts = {
            'LOW': timedelta(hours=24),
            'MEDIUM': timedelta(hours=8),
            'HIGH': timedelta(hours=4),
            'CRITICAL': timedelta(hours=1)
        }
        return timeouts.get(security_level, self.session_config['session_timeout'])
    
    def validate_password(self, password: str) -> List[str]:
        """Validate password against policy"""
        errors = []
        policy = self.password_policy
        
        if len(password) < policy['min_length']:
            errors.append(f"Password must be at least {policy['min_length']} characters")
        
        if len(password) > policy['max_length']:
            errors.append(f"Password must be no more than {policy['max_length']} characters")
        
        if policy['require_uppercase'] and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if policy['require_lowercase'] and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if policy['require_numbers'] and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if policy['require_special_chars'] and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            errors.append("Password must contain at least one special character")
        
        if policy['prevent_common_passwords']:
            common_passwords = ['password', '123456', 'admin', 'user', 'test', 'qwerty']
            if password.lower() in common_passwords:
                errors.append("Password is too common")
        
        return errors
    
    def export_config(self) -> Dict[str, Any]:
        """Export configuration for external systems"""
        return {
            'environment': self.environment,
            'security_level': self.security_level,
            'password_policy': self.password_policy,
            'session_config': {
                k: v.total_seconds() if isinstance(v, timedelta) else v
                for k, v in self.session_config.items()
            },
            'rate_limits': self.rate_limits,
            'threat_policies': [
                {
                    'name': p.name,
                    'enabled': p.enabled,
                    'severity': p.severity,
                    'action': p.action,
                    'threshold': p.threshold
                }
                for p in self.threat_policies
            ],
            'compliance_enabled': [
                k for k, v in self.compliance_config.items() if v is True
            ]
        }

# Global security configuration instance
security_config = SecurityConfig()
