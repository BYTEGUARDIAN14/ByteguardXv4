"""
Security Verification Dashboard for ByteGuardX
Provides comprehensive security posture monitoring and verification
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityStatus(Enum):
    """Security check status"""
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"

@dataclass
class SecurityCheck:
    """Individual security check result"""
    name: str
    category: str
    status: SecurityStatus
    description: str
    current_value: Any = None
    expected_value: Any = None
    recommendation: str = ""
    severity: str = "medium"
    last_checked: datetime = None
    
    def __post_init__(self):
        if self.last_checked is None:
            self.last_checked = datetime.utcnow()

@dataclass
class SecurityReport:
    """Complete security verification report"""
    timestamp: datetime
    overall_score: float
    total_checks: int
    passed_checks: int
    warning_checks: int
    failed_checks: int
    categories: Dict[str, List[SecurityCheck]]
    recommendations: List[str]
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class SecurityVerificationDashboard:
    """Main security verification dashboard"""
    
    def __init__(self):
        self.checks = []
        self.last_report = None
        self.config_cache = {}
        
    def run_security_verification(self) -> SecurityReport:
        """Run complete security verification"""
        logger.info("Starting security verification...")
        
        # Clear previous checks
        self.checks = []
        
        # Run all security checks
        self._check_authentication_config()
        self._check_encryption_settings()
        self._check_rate_limiting()
        self._check_audit_logging()
        self._check_security_headers()
        self._check_file_permissions()
        self._check_database_security()
        self._check_network_security()
        self._check_plugin_security()
        self._check_monitoring_config()
        
        # Generate report
        report = self._generate_report()
        self.last_report = report
        
        logger.info(f"Security verification completed. Score: {report.overall_score:.1f}/100")
        return report
    
    def _check_authentication_config(self):
        """Check authentication and authorization configuration"""
        category = "Authentication & Authorization"
        
        # Check JWT configuration
        jwt_secret = os.environ.get('JWT_SECRET_KEY', '')
        if not jwt_secret or jwt_secret == 'your-jwt-secret-key-change-this':
            self.checks.append(SecurityCheck(
                name="JWT Secret Key",
                category=category,
                status=SecurityStatus.FAIL,
                description="JWT secret key is not configured or using default value",
                current_value="Default/Missing",
                expected_value="Strong secret key",
                recommendation="Set a strong, unique JWT_SECRET_KEY in environment variables",
                severity="critical"
            ))
        else:
            self.checks.append(SecurityCheck(
                name="JWT Secret Key",
                category=category,
                status=SecurityStatus.PASS,
                description="JWT secret key is properly configured",
                current_value="Configured",
                expected_value="Strong secret key",
                severity="critical"
            ))
        
        # Check 2FA configuration
        enable_2fa = os.environ.get('ENABLE_2FA', 'false').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Two-Factor Authentication",
            category=category,
            status=SecurityStatus.PASS if enable_2fa else SecurityStatus.WARN,
            description="Two-factor authentication configuration",
            current_value="Enabled" if enable_2fa else "Disabled",
            expected_value="Enabled",
            recommendation="Enable 2FA for enhanced security" if not enable_2fa else "",
            severity="high"
        ))
        
        # Check password policy
        min_length = int(os.environ.get('PASSWORD_MIN_LENGTH', '8'))
        self.checks.append(SecurityCheck(
            name="Password Policy",
            category=category,
            status=SecurityStatus.PASS if min_length >= 12 else SecurityStatus.WARN,
            description="Password minimum length requirement",
            current_value=f"{min_length} characters",
            expected_value="12+ characters",
            recommendation="Set PASSWORD_MIN_LENGTH to at least 12" if min_length < 12 else "",
            severity="medium"
        ))
    
    def _check_encryption_settings(self):
        """Check encryption configuration"""
        category = "Data Encryption"
        
        # Check master encryption key
        master_key = os.environ.get('BYTEGUARDX_MASTER_KEY', '')
        if not master_key or master_key == 'your-base64-encoded-master-key-32-bytes':
            self.checks.append(SecurityCheck(
                name="Master Encryption Key",
                category=category,
                status=SecurityStatus.FAIL,
                description="Master encryption key is not configured",
                current_value="Default/Missing",
                expected_value="Strong encryption key",
                recommendation="Set a strong BYTEGUARDX_MASTER_KEY for data encryption",
                severity="critical"
            ))
        else:
            self.checks.append(SecurityCheck(
                name="Master Encryption Key",
                category=category,
                status=SecurityStatus.PASS,
                description="Master encryption key is configured",
                current_value="Configured",
                expected_value="Strong encryption key",
                severity="critical"
            ))
        
        # Check if encryption is enabled
        enable_encryption = os.environ.get('ENABLE_ENCRYPTION', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Data Encryption",
            category=category,
            status=SecurityStatus.PASS if enable_encryption else SecurityStatus.FAIL,
            description="Data encryption at rest",
            current_value="Enabled" if enable_encryption else "Disabled",
            expected_value="Enabled",
            recommendation="Enable data encryption for sensitive information" if not enable_encryption else "",
            severity="high"
        ))
    
    def _check_rate_limiting(self):
        """Check rate limiting configuration"""
        category = "Rate Limiting & DDoS Protection"
        
        # Check if rate limiting is enabled
        enable_rate_limiting = os.environ.get('ENABLE_RATE_LIMITING', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Rate Limiting",
            category=category,
            status=SecurityStatus.PASS if enable_rate_limiting else SecurityStatus.WARN,
            description="API rate limiting protection",
            current_value="Enabled" if enable_rate_limiting else "Disabled",
            expected_value="Enabled",
            recommendation="Enable rate limiting to prevent abuse" if not enable_rate_limiting else "",
            severity="medium"
        ))
        
        # Check authentication rate limits
        auth_rate_limit = int(os.environ.get('AUTH_RATE_LIMIT', '5'))
        self.checks.append(SecurityCheck(
            name="Authentication Rate Limit",
            category=category,
            status=SecurityStatus.PASS if auth_rate_limit <= 10 else SecurityStatus.WARN,
            description="Login attempt rate limiting",
            current_value=f"{auth_rate_limit} attempts",
            expected_value="≤10 attempts",
            recommendation="Set AUTH_RATE_LIMIT to 10 or lower" if auth_rate_limit > 10 else "",
            severity="medium"
        ))
    
    def _check_audit_logging(self):
        """Check audit logging configuration"""
        category = "Audit Logging & Monitoring"
        
        # Check if audit logging is enabled
        enable_audit = os.environ.get('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Audit Logging",
            category=category,
            status=SecurityStatus.PASS if enable_audit else SecurityStatus.WARN,
            description="Security event audit logging",
            current_value="Enabled" if enable_audit else "Disabled",
            expected_value="Enabled",
            recommendation="Enable audit logging for security monitoring" if not enable_audit else "",
            severity="high"
        ))
        
        # Check log redaction
        enable_redaction = os.environ.get('ENABLE_LOG_REDACTION', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Log Redaction",
            category=category,
            status=SecurityStatus.PASS if enable_redaction else SecurityStatus.WARN,
            description="Automatic secret redaction in logs",
            current_value="Enabled" if enable_redaction else "Disabled",
            expected_value="Enabled",
            recommendation="Enable log redaction to prevent secret exposure" if not enable_redaction else "",
            severity="medium"
        ))
        
        # Check audit log directory permissions
        audit_dir = os.environ.get('AUDIT_LOG_DIRECTORY', 'data/audit_logs')
        if os.path.exists(audit_dir):
            try:
                stat_info = os.stat(audit_dir)
                permissions = oct(stat_info.st_mode)[-3:]
                
                # Check if directory is too permissive (should be 750 or more restrictive)
                if int(permissions) > 750:
                    status = SecurityStatus.WARN
                    recommendation = f"Restrict audit log directory permissions (current: {permissions})"
                else:
                    status = SecurityStatus.PASS
                    recommendation = ""
                
                self.checks.append(SecurityCheck(
                    name="Audit Log Permissions",
                    category=category,
                    status=status,
                    description="Audit log directory file permissions",
                    current_value=permissions,
                    expected_value="750 or more restrictive",
                    recommendation=recommendation,
                    severity="medium"
                ))
            except Exception as e:
                self.checks.append(SecurityCheck(
                    name="Audit Log Permissions",
                    category=category,
                    status=SecurityStatus.UNKNOWN,
                    description="Could not check audit log directory permissions",
                    current_value=f"Error: {e}",
                    expected_value="750 or more restrictive",
                    severity="medium"
                ))
    
    def _check_security_headers(self):
        """Check security headers configuration"""
        category = "Security Headers"
        
        # Check HSTS
        enable_hsts = os.environ.get('ENABLE_HSTS', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="HSTS (HTTP Strict Transport Security)",
            category=category,
            status=SecurityStatus.PASS if enable_hsts else SecurityStatus.WARN,
            description="HTTP Strict Transport Security header",
            current_value="Enabled" if enable_hsts else "Disabled",
            expected_value="Enabled",
            recommendation="Enable HSTS for HTTPS enforcement" if not enable_hsts else "",
            severity="medium"
        ))
        
        # Check Content Security Policy
        csp_default = os.environ.get('CSP_DEFAULT_SRC', "'self'")
        self.checks.append(SecurityCheck(
            name="Content Security Policy",
            category=category,
            status=SecurityStatus.PASS if csp_default else SecurityStatus.WARN,
            description="Content Security Policy configuration",
            current_value=csp_default or "Not configured",
            expected_value="Restrictive CSP",
            recommendation="Configure Content Security Policy" if not csp_default else "",
            severity="medium"
        ))
        
        # Check Frame Options
        enable_frame_options = os.environ.get('ENABLE_FRAME_OPTIONS', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="X-Frame-Options",
            category=category,
            status=SecurityStatus.PASS if enable_frame_options else SecurityStatus.WARN,
            description="Clickjacking protection header",
            current_value="Enabled" if enable_frame_options else "Disabled",
            expected_value="Enabled",
            recommendation="Enable X-Frame-Options for clickjacking protection" if not enable_frame_options else "",
            severity="low"
        ))
    
    def _check_file_permissions(self):
        """Check critical file permissions"""
        category = "File System Security"
        
        critical_files = [
            ('.env', 'Environment configuration'),
            ('data/secure/', 'Secure data directory'),
            ('data/logs/', 'Log directory'),
        ]
        
        for file_path, description in critical_files:
            if os.path.exists(file_path):
                try:
                    stat_info = os.stat(file_path)
                    permissions = oct(stat_info.st_mode)[-3:]
                    
                    # Check permissions based on file type
                    if file_path.endswith('.env'):
                        # Environment files should be 600 (owner read/write only)
                        expected = "600"
                        is_secure = int(permissions) <= 600
                    else:
                        # Directories should be 750 or more restrictive
                        expected = "750 or more restrictive"
                        is_secure = int(permissions) <= 750
                    
                    self.checks.append(SecurityCheck(
                        name=f"File Permissions: {file_path}",
                        category=category,
                        status=SecurityStatus.PASS if is_secure else SecurityStatus.WARN,
                        description=f"File permissions for {description}",
                        current_value=permissions,
                        expected_value=expected,
                        recommendation=f"Restrict permissions for {file_path}" if not is_secure else "",
                        severity="medium"
                    ))
                except Exception as e:
                    self.checks.append(SecurityCheck(
                        name=f"File Permissions: {file_path}",
                        category=category,
                        status=SecurityStatus.UNKNOWN,
                        description=f"Could not check permissions for {description}",
                        current_value=f"Error: {e}",
                        expected_value="Secure permissions",
                        severity="medium"
                    ))
    
    def _check_database_security(self):
        """Check database security configuration"""
        category = "Database Security"
        
        # Check database URL for security
        db_url = os.environ.get('DATABASE_URL', '')
        if 'password' in db_url.lower() and '://' in db_url:
            # Check if password is in URL (less secure)
            self.checks.append(SecurityCheck(
                name="Database Credentials",
                category=category,
                status=SecurityStatus.WARN,
                description="Database credentials in connection string",
                current_value="Credentials in URL",
                expected_value="Separate credential management",
                recommendation="Use separate environment variables for database credentials",
                severity="medium"
            ))
        else:
            self.checks.append(SecurityCheck(
                name="Database Credentials",
                category=category,
                status=SecurityStatus.PASS,
                description="Database credential management",
                current_value="Secure configuration",
                expected_value="Separate credential management",
                severity="medium"
            ))
    
    def _check_network_security(self):
        """Check network security configuration"""
        category = "Network Security"
        
        # Check allowed origins
        allowed_origins = os.environ.get('ALLOWED_ORIGINS', '')
        if '*' in allowed_origins:
            self.checks.append(SecurityCheck(
                name="CORS Configuration",
                category=category,
                status=SecurityStatus.WARN,
                description="Cross-Origin Resource Sharing configuration",
                current_value="Wildcard (*) allowed",
                expected_value="Specific origins only",
                recommendation="Restrict ALLOWED_ORIGINS to specific domains",
                severity="medium"
            ))
        else:
            self.checks.append(SecurityCheck(
                name="CORS Configuration",
                category=category,
                status=SecurityStatus.PASS,
                description="Cross-Origin Resource Sharing configuration",
                current_value="Restricted origins",
                expected_value="Specific origins only",
                severity="medium"
            ))
    
    def _check_plugin_security(self):
        """Check plugin security configuration"""
        category = "Plugin Security"
        
        # Check if plugins are enabled
        enable_plugins = os.environ.get('ENABLE_PLUGINS', 'true').lower() == 'true'
        if enable_plugins:
            # Check plugin validation
            strict_validation = os.environ.get('PLUGIN_VALIDATION_STRICT', 'true').lower() == 'true'
            self.checks.append(SecurityCheck(
                name="Plugin Validation",
                category=category,
                status=SecurityStatus.PASS if strict_validation else SecurityStatus.WARN,
                description="Strict plugin validation",
                current_value="Enabled" if strict_validation else "Disabled",
                expected_value="Enabled",
                recommendation="Enable strict plugin validation" if not strict_validation else "",
                severity="medium"
            ))
        else:
            self.checks.append(SecurityCheck(
                name="Plugin System",
                category=category,
                status=SecurityStatus.PASS,
                description="Plugin system is disabled",
                current_value="Disabled",
                expected_value="Disabled or properly secured",
                severity="low"
            ))
    
    def _check_monitoring_config(self):
        """Check monitoring and alerting configuration"""
        category = "Monitoring & Alerting"
        
        # Check health monitoring
        enable_monitoring = os.environ.get('ENABLE_HEALTH_MONITORING', 'true').lower() == 'true'
        self.checks.append(SecurityCheck(
            name="Health Monitoring",
            category=category,
            status=SecurityStatus.PASS if enable_monitoring else SecurityStatus.WARN,
            description="System health monitoring",
            current_value="Enabled" if enable_monitoring else "Disabled",
            expected_value="Enabled",
            recommendation="Enable health monitoring for system oversight" if not enable_monitoring else "",
            severity="low"
        ))
    
    def _generate_report(self) -> SecurityReport:
        """Generate comprehensive security report"""
        # Calculate statistics
        total_checks = len(self.checks)
        passed_checks = len([c for c in self.checks if c.status == SecurityStatus.PASS])
        warning_checks = len([c for c in self.checks if c.status == SecurityStatus.WARN])
        failed_checks = len([c for c in self.checks if c.status == SecurityStatus.FAIL])
        
        # Calculate overall score
        if total_checks == 0:
            overall_score = 0.0
        else:
            # Weight: Pass=100%, Warn=50%, Fail=0%, Unknown=25%
            score = (passed_checks * 100 + warning_checks * 50 + 
                    len([c for c in self.checks if c.status == SecurityStatus.UNKNOWN]) * 25)
            overall_score = score / (total_checks * 100) * 100
        
        # Group checks by category
        categories = {}
        for check in self.checks:
            if check.category not in categories:
                categories[check.category] = []
            categories[check.category].append(check)
        
        # Generate recommendations
        recommendations = []
        for check in self.checks:
            if check.status in [SecurityStatus.FAIL, SecurityStatus.WARN] and check.recommendation:
                recommendations.append(check.recommendation)
        
        return SecurityReport(
            timestamp=datetime.utcnow(),
            overall_score=overall_score,
            total_checks=total_checks,
            passed_checks=passed_checks,
            warning_checks=warning_checks,
            failed_checks=failed_checks,
            categories=categories,
            recommendations=recommendations
        )
    
    def export_report_json(self, file_path: str = None) -> str:
        """Export security report as JSON"""
        if not self.last_report:
            self.run_security_verification()
        
        if file_path is None:
            file_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert report to JSON-serializable format
        report_data = asdict(self.last_report)
        
        # Convert datetime objects to ISO strings
        report_data['timestamp'] = self.last_report.timestamp.isoformat()
        
        for category, checks in report_data['categories'].items():
            for check in checks:
                check['last_checked'] = check['last_checked'][:19] if check['last_checked'] else None
                check['status'] = check['status']
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"Security report exported to {file_path}")
        return file_path
    
    def get_security_score(self) -> float:
        """Get current security score"""
        if not self.last_report:
            self.run_security_verification()
        
        return self.last_report.overall_score if self.last_report else 0.0
    
    def get_failed_checks(self) -> List[SecurityCheck]:
        """Get all failed security checks"""
        if not self.last_report:
            self.run_security_verification()
        
        return [check for check in self.checks if check.status == SecurityStatus.FAIL]
    
    def get_recommendations(self) -> List[str]:
        """Get security recommendations"""
        if not self.last_report:
            self.run_security_verification()
        
        return self.last_report.recommendations if self.last_report else []

# Global security dashboard instance
security_dashboard = SecurityVerificationDashboard()
