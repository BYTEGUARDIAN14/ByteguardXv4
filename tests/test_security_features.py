"""
Comprehensive test suite for ByteGuardX security features
Tests authentication, authorization, rate limiting, audit logging, and more
"""

import pytest
import tempfile
import os
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Import security modules
from byteguardx.security.two_factor_auth import TwoFactorAuth, TOTPManager
from byteguardx.security.password_policy import PasswordValidator, PasswordPolicy
from byteguardx.security.rate_limiter import RateLimiter, BruteForceProtection, RateLimitRule, RateLimitType
from byteguardx.security.audit_logger import AuditLogger, SecurityEvent, SecurityEventType, EventSeverity
from byteguardx.security.encryption import DataEncryption, SecureStorage
from byteguardx.security.input_sanitizer import InputSanitizer, SanitizationConfig
from byteguardx.security.log_redactor import LogRedactor
from byteguardx.scanners.intelligent_fallback import IntelligentFallbackSystem, FallbackReason

class TestTwoFactorAuth:
    """Test 2FA functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.two_fa = TwoFactorAuth(storage_path=self.temp_dir)
        self.user_id = "test_user_123"
        self.user_email = "test@example.com"
    
    def test_totp_setup(self):
        """Test TOTP setup process"""
        setup_data = self.two_fa.setup_totp(self.user_id, self.user_email)
        
        assert 'secret' in setup_data
        assert 'qr_code' in setup_data
        assert 'backup_codes' in setup_data
        assert len(setup_data['backup_codes']) == 10
        assert len(setup_data['secret']) == 32  # Base32 encoded
    
    def test_totp_enable_with_valid_token(self):
        """Test enabling TOTP with valid token"""
        # Setup TOTP
        setup_data = self.two_fa.setup_totp(self.user_id, self.user_email)
        secret = setup_data['secret']
        
        # Generate valid token
        totp_manager = TOTPManager()
        valid_token = totp_manager.get_current_token(secret)
        
        # Enable TOTP
        result = self.two_fa.enable_totp(self.user_id, valid_token)
        assert result is True
        
        # Verify 2FA is enabled
        assert self.two_fa.is_2fa_enabled(self.user_id) is True
    
    def test_totp_enable_with_invalid_token(self):
        """Test enabling TOTP with invalid token"""
        # Setup TOTP
        self.two_fa.setup_totp(self.user_id, self.user_email)
        
        # Try to enable with invalid token
        result = self.two_fa.enable_totp(self.user_id, "invalid_token")
        assert result is False
        
        # Verify 2FA is not enabled
        assert self.two_fa.is_2fa_enabled(self.user_id) is False
    
    def test_backup_code_usage(self):
        """Test backup code verification"""
        # Setup and enable TOTP
        setup_data = self.two_fa.setup_totp(self.user_id, self.user_email)
        totp_manager = TOTPManager()
        valid_token = totp_manager.get_current_token(setup_data['secret'])
        self.two_fa.enable_totp(self.user_id, valid_token)
        
        # Get backup codes
        backup_codes = self.two_fa.get_backup_codes(self.user_id)
        assert len(backup_codes) == 10
        
        # Use a backup code
        backup_code = backup_codes[0]
        result = self.two_fa.verify_2fa(self.user_id, backup_code)
        assert result is True
        
        # Verify backup code is removed
        remaining_codes = self.two_fa.get_backup_codes(self.user_id)
        assert len(remaining_codes) == 9
        assert backup_code not in remaining_codes

class TestPasswordPolicy:
    """Test password policy and validation"""
    
    def setup_method(self):
        """Setup test environment"""
        self.policy = PasswordPolicy()
        self.validator = PasswordValidator(self.policy)
    
    def test_strong_password_validation(self):
        """Test validation of strong password"""
        strong_password = "MyStr0ng!P@ssw0rd123"
        result = self.validator.validate_password(strong_password)
        
        assert result.is_valid is True
        assert result.strength.value in ['strong', 'very_strong']
        assert result.score >= 75
        assert len(result.errors) == 0
    
    def test_weak_password_validation(self):
        """Test validation of weak password"""
        weak_password = "123456"
        result = self.validator.validate_password(weak_password)
        
        assert result.is_valid is False
        assert result.strength.value == 'weak'
        assert result.score < 40
        assert len(result.errors) > 0
    
    def test_common_password_detection(self):
        """Test detection of common passwords"""
        common_password = "password123"
        result = self.validator.validate_password(common_password)
        
        assert result.is_valid is False
        assert any("common" in error.lower() for error in result.errors)
    
    def test_personal_info_detection(self):
        """Test detection of personal information in password"""
        user_info = {'email': 'john.doe@example.com', 'username': 'johndoe'}
        password_with_personal_info = "johndoe123!"
        
        result = self.validator.validate_password(password_with_personal_info, user_info)
        
        assert result.is_valid is False
        assert any("personal" in error.lower() for error in result.errors)
    
    def test_password_generation(self):
        """Test secure password generation"""
        generated_password = self.validator.generate_password(16)
        
        assert len(generated_password) == 16
        
        # Validate the generated password
        result = self.validator.validate_password(generated_password)
        assert result.is_valid is True
        assert result.strength.value in ['strong', 'very_strong']

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.rate_limiter = RateLimiter(storage_path=self.temp_dir)
        
        # Add test rule
        test_rule = RateLimitRule(
            name="test_rule",
            limit=3,
            window=60,
            block_duration=300,
            rule_type=RateLimitType.PER_IP,
            endpoints=["/test"]
        )
        self.rate_limiter.add_rule(test_rule)
    
    def test_rate_limit_within_limits(self):
        """Test requests within rate limits"""
        client_ip = "192.168.1.100"
        endpoint = "/test"
        
        # Make requests within limit
        for i in range(3):
            is_allowed, reason, retry_after = self.rate_limiter.check_rate_limit(
                identifier=client_ip,
                endpoint=endpoint
            )
            assert is_allowed is True
            assert reason is None
    
    def test_rate_limit_exceeded(self):
        """Test rate limit exceeded scenario"""
        client_ip = "192.168.1.101"
        endpoint = "/test"
        
        # Make requests up to limit
        for i in range(3):
            self.rate_limiter.check_rate_limit(
                identifier=client_ip,
                endpoint=endpoint
            )
        
        # Next request should be blocked
        is_allowed, reason, retry_after = self.rate_limiter.check_rate_limit(
            identifier=client_ip,
            endpoint=endpoint
        )
        
        assert is_allowed is False
        assert "rate limit exceeded" in reason.lower()
        assert retry_after > 0
    
    def test_brute_force_protection(self):
        """Test brute force protection"""
        brute_force = BruteForceProtection(self.rate_limiter)
        client_ip = "192.168.1.102"
        
        # Record failed attempts
        for i in range(5):
            brute_force.record_failed_attempt(client_ip)
        
        # Check if brute force is detected
        assert brute_force.is_brute_force_detected(client_ip) is True
        
        # Record successful attempt
        brute_force.record_successful_attempt(client_ip)
        
        # Brute force should be cleared
        assert brute_force.is_brute_force_detected(client_ip) is False

class TestAuditLogging:
    """Test audit logging functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.temp_dir)
    
    def test_login_success_logging(self):
        """Test logging successful login"""
        user_id = "user123"
        username = "testuser"
        ip_address = "192.168.1.100"
        
        self.audit_logger.log_login_success(
            user_id=user_id,
            username=username,
            ip_address=ip_address
        )
        
        # Force flush buffer
        self.audit_logger._flush_buffer()
        
        # Search for the event
        events = self.audit_logger.search_events(
            event_types=[SecurityEventType.LOGIN_SUCCESS],
            user_id=user_id,
            limit=10
        )
        
        assert len(events) == 1
        assert events[0].user_id == user_id
        assert events[0].username == username
        assert events[0].ip_address == ip_address
    
    def test_security_violation_logging(self):
        """Test logging security violations"""
        violation_type = "suspicious_activity"
        ip_address = "192.168.1.200"
        
        self.audit_logger.log_security_violation(
            violation_type=violation_type,
            ip_address=ip_address,
            details={"reason": "multiple_failed_attempts"}
        )
        
        # Force flush buffer
        self.audit_logger._flush_buffer()
        
        # Search for the event
        events = self.audit_logger.search_events(
            event_types=[SecurityEventType.SECURITY_VIOLATION],
            ip_address=ip_address,
            limit=10
        )
        
        assert len(events) == 1
        assert events[0].ip_address == ip_address
        assert events[0].details["violation_type"] == violation_type
    
    def test_event_statistics(self):
        """Test audit event statistics"""
        # Log multiple events
        for i in range(5):
            self.audit_logger.log_login_success(
                user_id=f"user{i}",
                username=f"testuser{i}",
                ip_address="192.168.1.100"
            )
        
        for i in range(3):
            self.audit_logger.log_login_failure(
                username=f"baduser{i}",
                ip_address="192.168.1.200",
                reason="invalid_credentials"
            )
        
        # Force flush buffer
        self.audit_logger._flush_buffer()
        
        # Get statistics
        stats = self.audit_logger.get_event_statistics()
        
        assert stats["total_events"] == 8
        assert stats["successful_logins"] == 5
        assert stats["failed_logins"] == 3

class TestDataEncryption:
    """Test data encryption functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.encryption = DataEncryption()
        self.test_data = "This is sensitive test data!"
    
    def test_data_encryption_decryption(self):
        """Test basic encryption and decryption"""
        # Encrypt data
        encrypted_data = self.encryption.encrypt_data(self.test_data)
        assert encrypted_data != self.test_data
        assert len(encrypted_data) > len(self.test_data)
        
        # Decrypt data
        decrypted_data = self.encryption.decrypt_to_string(encrypted_data)
        assert decrypted_data == self.test_data
    
    def test_json_encryption_decryption(self):
        """Test JSON encryption and decryption"""
        test_json = {
            "username": "testuser",
            "api_key": "secret_api_key_123",
            "settings": {"theme": "dark", "notifications": True}
        }
        
        # Encrypt JSON
        encrypted_json = self.encryption.encrypt_json(test_json)
        assert isinstance(encrypted_json, str)
        
        # Decrypt JSON
        decrypted_json = self.encryption.decrypt_json(encrypted_json)
        assert decrypted_json == test_json
    
    def test_password_based_encryption(self):
        """Test encryption with custom password"""
        password = "my_custom_password_123"
        
        # Encrypt with password
        encrypted_data = self.encryption.encrypt_data(self.test_data, password)
        
        # Decrypt with correct password
        decrypted_data = self.encryption.decrypt_to_string(encrypted_data, password)
        assert decrypted_data == self.test_data
        
        # Try to decrypt with wrong password
        with pytest.raises(Exception):
            self.encryption.decrypt_to_string(encrypted_data, "wrong_password")

class TestInputSanitization:
    """Test input sanitization functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.sanitizer = InputSanitizer()
        self.temp_dir = tempfile.mkdtemp()
    
    def test_safe_file_validation(self):
        """Test validation of safe files"""
        # Create a safe test file
        test_file = os.path.join(self.temp_dir, "safe_file.txt")
        with open(test_file, 'w') as f:
            f.write("This is a safe text file.")
        
        is_safe, threats = self.sanitizer.sanitize_file_upload(test_file, "safe_file.txt")
        
        assert is_safe is True
        assert len(threats) == 0
    
    def test_oversized_file_detection(self):
        """Test detection of oversized files"""
        # Create a large test file
        test_file = os.path.join(self.temp_dir, "large_file.txt")
        with open(test_file, 'w') as f:
            f.write("x" * (self.sanitizer.config.max_file_size + 1))
        
        is_safe, threats = self.sanitizer.sanitize_file_upload(test_file, "large_file.txt")
        
        assert is_safe is False
        assert any(threat.threat_type.value == "oversized_file" for threat in threats)
    
    def test_malicious_filename_detection(self):
        """Test detection of malicious filenames"""
        malicious_filenames = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "test.exe",
            "script.bat",
            "CON.txt"
        ]
        
        for filename in malicious_filenames:
            # Create a test file
            safe_filename = "test.txt"
            test_file = os.path.join(self.temp_dir, safe_filename)
            with open(test_file, 'w') as f:
                f.write("test content")
            
            is_safe, threats = self.sanitizer.sanitize_file_upload(test_file, filename)
            
            assert is_safe is False
            assert len(threats) > 0
    
    def test_filename_sanitization(self):
        """Test filename sanitization"""
        malicious_filename = "../../../malicious<>file|name?.exe"
        sanitized = self.sanitizer.sanitize_filename(malicious_filename)
        
        assert ".." not in sanitized
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "|" not in sanitized
        assert "?" not in sanitized
        assert not sanitized.endswith(".exe")

class TestLogRedaction:
    """Test log redaction functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.redactor = LogRedactor()
    
    def test_password_redaction(self):
        """Test redaction of passwords"""
        text_with_password = 'password="my_secret_password123"'
        redacted_text = self.redactor.redact_text(text_with_password)
        
        assert "my_secret_password123" not in redacted_text
        assert "[REDACTED]" in redacted_text
    
    def test_api_key_redaction(self):
        """Test redaction of API keys"""
        text_with_api_key = "api_key=AKIA1234567890ABCDEF"
        redacted_text = self.redactor.redact_text(text_with_api_key)
        
        assert "AKIA1234567890ABCDEF" not in redacted_text
        assert "[REDACTED" in redacted_text
    
    def test_jwt_token_redaction(self):
        """Test redaction of JWT tokens"""
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        redacted_text = self.redactor.redact_text(jwt_token)
        
        assert jwt_token not in redacted_text
        assert "[REDACTED_JWT]" in redacted_text
    
    def test_dict_redaction(self):
        """Test redaction of dictionary data"""
        sensitive_dict = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "sk_test_1234567890",
            "normal_field": "normal_value"
        }
        
        redacted_dict = self.redactor.redact_dict(sensitive_dict)
        
        assert redacted_dict["username"] == "testuser"  # Not sensitive
        assert redacted_dict["password"] == "[REDACTED]"
        assert redacted_dict["api_key"] == "[REDACTED]"
        assert redacted_dict["normal_field"] == "normal_value"

class TestIntelligentFallback:
    """Test intelligent fallback system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.fallback_system = IntelligentFallbackSystem()
    
    def test_secret_scanning_fallback(self):
        """Test fallback secret scanning"""
        test_content = '''
        api_key = "AKIA1234567890ABCDEF"
        password = "my_secret_password"
        normal_variable = "normal_value"
        '''
        
        result = self.fallback_system.scan_with_fallback(
            content=test_content,
            file_path="test.py",
            scan_type="secrets",
            fallback_reason=FallbackReason.ML_MODEL_UNAVAILABLE
        )
        
        assert result.success is True
        assert len(result.findings) >= 2  # Should find API key and password
        assert result.method_used == "rule_based_fallback"
        assert result.fallback_reason == FallbackReason.ML_MODEL_UNAVAILABLE
    
    def test_vulnerability_scanning_fallback(self):
        """Test fallback vulnerability scanning"""
        test_content = '''
        query = "SELECT * FROM users WHERE id = " + user_id
        eval(user_input)
        system("rm -rf " + directory)
        '''
        
        result = self.fallback_system.scan_with_fallback(
            content=test_content,
            file_path="test.py",
            scan_type="vulnerabilities",
            fallback_reason=FallbackReason.ML_MODEL_ERROR
        )
        
        assert result.success is True
        assert len(result.findings) >= 2  # Should find SQL injection and command injection
        assert "vulnerability_detection" in result.rules_applied
    
    def test_fallback_statistics(self):
        """Test fallback statistics tracking"""
        # Perform multiple fallback scans
        for i in range(3):
            self.fallback_system.scan_with_fallback(
                content="test content",
                fallback_reason=FallbackReason.ML_MODEL_TIMEOUT
            )
        
        stats = self.fallback_system.get_fallback_stats()
        
        assert stats["total_fallbacks"] == 3
        assert "ml_model_timeout" in stats["fallback_reasons"]
        assert stats["fallback_reasons"]["ml_model_timeout"]["count"] == 3
        assert stats["success_rate"] > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
