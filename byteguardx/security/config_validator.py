"""
Security Configuration Validator for ByteGuardX
Validates production secrets and enforces security policies
"""

import os
import sys
import logging
import re
from typing import Dict, List, Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityConfigValidator:
    """Validates security configuration and enforces production standards"""
    
    # Weak/default secrets that should not be used in production
    WEAK_SECRETS = [
        'dev-secret-key',
        'development',
        'test',
        'changeme',
        'password',
        'secret',
        'key',
        '123456',
        'admin',
        'default'
    ]
    
    # Required environment variables for production
    REQUIRED_PRODUCTION_VARS = [
        'SECRET_KEY',
        'JWT_SECRET',
        'BYTEGUARDX_MASTER_KEY',
        'DATABASE_URL'
    ]
    
    # Optional but recommended variables
    RECOMMENDED_VARS = [
        'REDIS_URL',
        'SMTP_SERVER',
        'SMTP_USERNAME',
        'SMTP_PASSWORD'
    ]
    
    def __init__(self):
        self.is_production = os.environ.get('ENV', '').lower() == 'production'
        self.flask_env = os.environ.get('FLASK_ENV', '').lower()
        self.errors = []
        self.warnings = []
    
    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate all security configurations
        Returns: (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        # Validate secrets
        self._validate_secrets()
        
        # Validate environment variables
        self._validate_environment_vars()
        
        # Validate file permissions
        self._validate_file_permissions()
        
        # Validate database configuration
        self._validate_database_config()
        
        # Production-specific validations
        if self.is_production:
            self._validate_production_config()
        
        return len(self.errors) == 0, self.errors, self.warnings
    
    def _validate_secrets(self):
        """Validate that secrets are not weak or default values"""
        secrets_to_check = {
            'SECRET_KEY': os.environ.get('SECRET_KEY', ''),
            'JWT_SECRET': os.environ.get('JWT_SECRET', ''),
            'BYTEGUARDX_MASTER_KEY': os.environ.get('BYTEGUARDX_MASTER_KEY', '')
        }
        
        for var_name, value in secrets_to_check.items():
            if not value:
                if self.is_production:
                    self.errors.append(f"❌ {var_name} is required in production")
                else:
                    self.warnings.append(f"⚠️  {var_name} not set, using default")
                continue
            
            # Check for weak secrets
            value_lower = value.lower()
            for weak_secret in self.WEAK_SECRETS:
                if weak_secret in value_lower:
                    if self.is_production:
                        self.errors.append(
                            f"❌ {var_name} contains weak/default value '{weak_secret}' - "
                            f"CRITICAL SECURITY RISK in production! Application will terminate."
                        )
                        # Log critical security event
                        logger.critical(f"SECURITY VIOLATION: Weak secret detected in production: {var_name}")
                    else:
                        self.warnings.append(
                            f"⚠️  {var_name} contains weak value '{weak_secret}'"
                        )
                    break

            # Check for development patterns in production
            dev_patterns = ['dev-', 'test-', 'development', 'localhost', '127.0.0.1']
            for pattern in dev_patterns:
                if pattern in value_lower and self.is_production:
                    self.errors.append(
                        f"❌ {var_name} contains development pattern '{pattern}' in production"
                    )
            
            # Check minimum length
            if len(value) < 32:
                if self.is_production:
                    self.errors.append(
                        f"❌ {var_name} must be at least 32 characters in production"
                    )
                else:
                    self.warnings.append(
                        f"⚠️  {var_name} should be at least 32 characters"
                    )
    
    def _validate_environment_vars(self):
        """Validate required environment variables"""
        for var in self.REQUIRED_PRODUCTION_VARS:
            value = os.environ.get(var)
            if not value and self.is_production:
                self.errors.append(f"❌ Required environment variable {var} not set")
        
        for var in self.RECOMMENDED_VARS:
            value = os.environ.get(var)
            if not value:
                self.warnings.append(f"⚠️  Recommended variable {var} not set")
    
    def _validate_file_permissions(self):
        """Validate file permissions for sensitive files"""
        sensitive_files = [
            '.env',
            '.env.production',
            'data/users.json',
            'data/audit_logs.json'
        ]
        
        for file_path in sensitive_files:
            path = Path(file_path)
            if path.exists():
                # Check if file is readable by others (Unix-like systems)
                if hasattr(os, 'stat'):
                    import stat
                    file_stat = path.stat()
                    if file_stat.st_mode & stat.S_IROTH:
                        self.warnings.append(
                            f"⚠️  {file_path} is readable by others - consider restricting permissions"
                        )
    
    def _validate_database_config(self):
        """Validate database configuration"""
        db_url = os.environ.get('DATABASE_URL', '')
        
        if not db_url and self.is_production:
            self.errors.append("❌ DATABASE_URL required in production")
        
        # Check for insecure database URLs
        if db_url and 'password' in db_url.lower():
            if 'localhost' in db_url or '127.0.0.1' in db_url:
                self.warnings.append("⚠️  Database appears to be local in production")
    
    def _validate_production_config(self):
        """Production-specific validations"""
        # Check Flask environment
        if self.flask_env != 'production':
            self.errors.append(
                f"❌ FLASK_ENV should be 'production', got '{self.flask_env}'"
            )
        
        # Check debug mode
        if os.environ.get('FLASK_DEBUG', '').lower() in ['1', 'true']:
            self.errors.append("❌ FLASK_DEBUG must be disabled in production")
        
        # Check HTTPS enforcement
        if not os.environ.get('FORCE_HTTPS'):
            self.warnings.append("⚠️  FORCE_HTTPS not enabled - consider enabling for production")
    
    def terminate_if_invalid(self):
        """Terminate application if critical security issues found"""
        is_valid, errors, warnings = self.validate_all()

        # Log warnings
        for warning in warnings:
            logger.warning(warning)

        # Log errors and terminate if in production
        if errors:
            for error in errors:
                logger.critical(error)

            if self.is_production:
                logger.critical("🚨 CRITICAL SECURITY ISSUES DETECTED - TERMINATING APPLICATION")
                sys.exit(1)
            else:
                logger.error("⚠️  Security issues detected in development mode")

        return is_valid

    # validate_all method already exists in the class

def validate_startup_security():
    """Validate security configuration at startup"""
    validator = SecurityConfigValidator()
    return validator.terminate_if_invalid()

# Global instance for validation
config_validator = SecurityConfigValidator()
