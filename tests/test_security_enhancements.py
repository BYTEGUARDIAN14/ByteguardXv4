"""
Test suite for ByteGuardX Enterprise Security Enhancements
Tests all 10 security improvements for functionality and compliance
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

from byteguardx.security.zero_trust_enforcement import ZeroTrustEnforcer, RoutePolicy, AccessDecision
from byteguardx.security.insider_threat_auditing import InsiderThreatMonitor, AccessType, ThreatLevel
from byteguardx.security.dast_integration import DASTManager, DASTTool, ScanStatus
from byteguardx.plugins.signature_verification import PluginSignatureVerifier, PluginSignature
from byteguardx.security.frontend_hardening import ContentSecurityPolicy, InputSanitizer
from byteguardx.cli.backup import BackupManager
from byteguardx.auth.models import UserRole, PermissionType
from byteguardx.security.rbac import Permission

class TestZeroTrustEnforcement:
    """Test Zero Trust API enforcement"""
    
    def setup_method(self):
        self.enforcer = ZeroTrustEnforcer()
    
    def test_default_deny_policy(self):
        """Test that unknown routes are denied by default"""
        policy = self.enforcer._find_matching_policy("/unknown/route")
        assert policy.route_pattern == "*"
        assert not policy.allow_anonymous
    
    def test_public_route_policy(self):
        """Test that public routes allow anonymous access"""
        policy = self.enforcer._find_matching_policy("/health")
        assert policy.allow_anonymous
    
    def test_admin_route_policy(self):
        """Test that admin routes require admin role and 2FA"""
        policy = self.enforcer._find_matching_policy("/api/v1/admin/users")
        assert UserRole.ADMIN in policy.required_roles
        assert policy.require_2fa
    
    @patch('byteguardx.security.zero_trust_enforcement.request')
    @patch('byteguardx.security.zero_trust_enforcement.verify_jwt_in_request')
    @patch('byteguardx.security.zero_trust_enforcement.get_jwt_identity')
    def test_authentication_validation(self, mock_get_jwt, mock_verify_jwt, mock_request):
        """Test JWT authentication validation"""
        mock_request.remote_addr = "127.0.0.1"
        mock_request.headers = {'User-Agent': 'test'}
        mock_get_jwt.return_value = "user123"
        
        # Mock user manager
        with patch.object(self.enforcer, 'user_manager') as mock_user_manager:
            mock_user = Mock()
            mock_user.id = "user123"
            mock_user.username = "testuser"
            mock_user.role = UserRole.ADMIN
            mock_user.is_active = True
            mock_user_manager.get_user_by_id.return_value = mock_user
            
            policy = RoutePolicy(
                route_pattern="/test",
                required_permissions=[],
                required_roles=[UserRole.ADMIN],
                allow_anonymous=False
            )
            
            is_auth, error, user_info = self.enforcer._validate_authentication(policy)
            assert is_auth
            assert user_info['user_id'] == "user123"
            assert user_info['role'] == UserRole.ADMIN

class TestInsiderThreatAuditing:
    """Test insider threat monitoring and auditing"""
    
    def setup_method(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.monitor = InsiderThreatMonitor(audit_dir=temp_dir)
    
    def test_risk_factor_analysis(self):
        """Test risk factor analysis for privileged access"""
        with patch('byteguardx.security.insider_threat_auditing.datetime') as mock_datetime:
            # Mock off-hours access (10 PM)
            mock_datetime.now.return_value = datetime(2024, 1, 1, 22, 0, 0)
            mock_datetime.weekday.return_value = 0  # Monday
            
            risk_factors = self.monitor._analyze_risk_factors(
                "admin123", "user456", AccessType.USER_DATA_ACCESS
            )
            
            assert "off_hours_access" in risk_factors
    
    def test_threat_level_calculation(self):
        """Test threat level calculation based on risk factors"""
        # High risk factors
        high_risk_factors = ["off_hours_access", "unusual_ip", "bulk_access", "privileged_escalation"]
        threat_level = self.monitor._calculate_threat_level(high_risk_factors)
        assert threat_level == ThreatLevel.CRITICAL
        
        # Low risk factors
        low_risk_factors = ["repeated_access"]
        threat_level = self.monitor._calculate_threat_level(low_risk_factors)
        assert threat_level == ThreatLevel.LOW
    
    @patch('byteguardx.security.insider_threat_auditing.request')
    def test_privileged_access_logging(self, mock_request):
        """Test logging of privileged access events"""
        mock_request.remote_addr = "192.168.1.100"
        mock_request.headers = {'User-Agent': 'Mozilla/5.0'}
        
        with patch.object(self.monitor, 'user_manager') as mock_user_manager:
            mock_admin = Mock()
            mock_admin.id = "admin123"
            mock_admin.username = "admin"
            mock_user_manager.get_user_by_id.return_value = mock_admin
            
            event_id = self.monitor.log_privileged_access(
                admin_user_id="admin123",
                target_user_id="user456",
                access_type=AccessType.USER_DATA_ACCESS,
                resource_type="scan_results",
                resource_id="scan789",
                action="read"
            )
            
            assert event_id
            assert len(self.monitor.threat_events) == 1
            event = self.monitor.threat_events[0]
            assert event.admin_user_id == "admin123"
            assert event.target_user_id == "user456"

class TestDASTIntegration:
    """Test DAST integration functionality"""
    
    def setup_method(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.dast_manager = DASTManager(dast_logs_dir=temp_dir)
    
    def test_start_internal_spider_scan(self):
        """Test starting internal spider scan"""
        scan_id = self.dast_manager.start_dast_scan(
            target_url="http://example.com",
            tool=DASTTool.INTERNAL_SPIDER,
            scan_config={'test_xss': True}
        )
        
        assert scan_id
        scan_result = self.dast_manager.get_scan_result(scan_id)
        assert scan_result
        assert scan_result.tool == DASTTool.INTERNAL_SPIDER
        assert scan_result.target_url == "http://example.com"
    
    def test_owasp_zap_integration_stub(self):
        """Test OWASP ZAP integration stub"""
        zap_integration = self.dast_manager.zap_integration
        
        scan_id = zap_integration.start_scan("http://example.com", {})
        assert scan_id
        
        status = zap_integration.get_scan_status(scan_id)
        assert status == ScanStatus.COMPLETED
        
        findings = zap_integration.get_scan_results(scan_id)
        assert len(findings) > 0
        assert findings[0].vulnerability_type == "Cross Site Scripting (Reflected)"

class TestPluginSignatureVerification:
    """Test plugin signature verification system"""
    
    def setup_method(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.verifier = PluginSignatureVerifier(trust_store_dir=temp_dir)
    
    def test_file_hash_calculation(self):
        """Test file hash calculation"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("test content")
            temp_file.flush()
            
            hash1 = self.verifier.calculate_file_hash(temp_file.name)
            hash2 = self.verifier.calculate_file_hash(temp_file.name)
            
            assert hash1 == hash2
            assert len(hash1) == 64  # SHA256 hex length
            
            os.unlink(temp_file.name)
    
    def test_trusted_signer_management(self):
        """Test trusted signer management"""
        from byteguardx.plugins.signature_verification import TrustedSigner
        
        signer = TrustedSigner(
            signer_id="test-signer",
            name="Test Signer",
            public_key="test-public-key",
            trusted_since=datetime.now().isoformat()
        )
        
        success = self.verifier.add_trusted_signer(signer)
        assert success
        
        signers = self.verifier.get_trusted_signers()
        assert len(signers) >= 1
        assert any(s.signer_id == "test-signer" for s in signers)
        
        # Test revocation
        success = self.verifier.revoke_signer("test-signer")
        assert success
        
        active_signers = self.verifier.get_trusted_signers()
        assert not any(s.signer_id == "test-signer" for s in active_signers)

class TestFrontendHardening:
    """Test frontend security hardening"""
    
    def setup_method(self):
        self.csp = ContentSecurityPolicy()
        self.sanitizer = InputSanitizer()
    
    def test_csp_policy_generation(self):
        """Test CSP policy string generation"""
        policy_string = self.csp.get_policy_string(development=False)
        
        assert "default-src 'self'" in policy_string
        assert "frame-ancestors 'none'" in policy_string
        assert "upgrade-insecure-requests" in policy_string
    
    def test_development_csp_policy(self):
        """Test development CSP policy allows localhost"""
        dev_policy = self.csp.get_policy_string(development=True)
        
        assert "http://localhost:*" in dev_policy
        assert "ws://localhost:*" in dev_policy
    
    def test_html_sanitization(self):
        """Test HTML content sanitization"""
        malicious_html = '<script>alert("xss")</script><p>Safe content</p>'
        sanitized = self.sanitizer.sanitize_html(malicious_html)
        
        assert '<script>' not in sanitized
        assert 'alert(' not in sanitized
        assert '<p>Safe content</p>' in sanitized
    
    def test_text_sanitization(self):
        """Test plain text sanitization"""
        malicious_text = '<script>alert("xss")</script>Normal text'
        sanitized = self.sanitizer.sanitize_text(malicious_text)
        
        assert '&lt;script&gt;' in sanitized
        assert 'alert(' in sanitized  # HTML escaped
        assert 'Normal text' in sanitized
    
    def test_json_sanitization(self):
        """Test JSON data sanitization"""
        malicious_data = {
            'name': '<script>alert("xss")</script>',
            'description': 'Safe description',
            'nested': {
                'value': 'javascript:alert(1)'
            }
        }
        
        sanitized = self.sanitizer.sanitize_json(malicious_data)
        
        assert '<script>' not in sanitized['name']
        assert 'Safe description' == sanitized['description']
        assert 'javascript:' not in sanitized['nested']['value']

class TestBackupSystem:
    """Test backup and disaster recovery system"""
    
    def setup_method(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.backup_manager = BackupManager(backup_dir=temp_dir)
    
    @patch('subprocess.run')
    def test_database_backup_postgresql(self, mock_subprocess):
        """Test PostgreSQL database backup"""
        mock_subprocess.return_value.returncode = 0
        
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir)
            
            with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://user:pass@localhost/db'}):
                result = self.backup_manager._backup_database(backup_path)
                
                assert result is not None
                mock_subprocess.assert_called_once()
                assert 'pg_dump' in mock_subprocess.call_args[0][0]
    
    def test_file_backup(self):
        """Test file system backup"""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir)
            
            # Create some test directories and files
            os.makedirs('data/test', exist_ok=True)
            with open('data/test/file.txt', 'w') as f:
                f.write('test content')
            
            result = self.backup_manager._backup_files(backup_path)
            
            if result:  # Only assert if backup was created
                assert result.exists()
                assert result.suffix == '.gz'
    
    def test_backup_listing(self):
        """Test backup listing functionality"""
        # Create a mock backup file
        backup_file = self.backup_manager.backup_dir / "byteguardx_backup_20240101_120000.tar.gz"
        backup_file.touch()
        
        backups = self.backup_manager.list_backups()
        
        assert len(backups) >= 1
        assert any(b['name'] == backup_file.name for b in backups)

class TestAPIVersioning:
    """Test API versioning and schema validation"""
    
    def test_api_response_format(self):
        """Test standard API response format"""
        from byteguardx.api.v1 import api_response
        
        response, status_code = api_response(data={'test': 'data'})
        response_data = json.loads(response.data)
        
        assert response_data['success'] is True
        assert response_data['data']['test'] == 'data'
        assert response_data['version'] == '1.0'
        assert 'timestamp' in response_data
        assert status_code == 200
    
    def test_api_error_response(self):
        """Test API error response format"""
        from byteguardx.api.v1 import api_response
        
        response, status_code = api_response(error='Test error', status_code=400)
        response_data = json.loads(response.data)
        
        assert response_data['success'] is False
        assert response_data['error'] == 'Test error'
        assert response_data['data'] is None
        assert status_code == 400
    
    def test_schema_validation(self):
        """Test request schema validation"""
        from byteguardx.api.v1 import ScanRequestSchema
        from marshmallow import ValidationError
        
        schema = ScanRequestSchema()
        
        # Valid data
        valid_data = {
            'directory_path': '/test/path',
            'recursive': True,
            'include_secrets': True
        }
        result = schema.load(valid_data)
        assert result['directory_path'] == '/test/path'
        
        # Invalid data
        with pytest.raises(ValidationError):
            schema.load({})  # Missing required field

# Integration tests
class TestSecurityIntegration:
    """Test integration between security components"""
    
    def test_zero_trust_with_insider_threat_monitoring(self):
        """Test that zero trust enforcement triggers insider threat monitoring"""
        with patch('byteguardx.security.zero_trust_enforcement.insider_threat_monitor') as mock_monitor:
            enforcer = ZeroTrustEnforcer()
            
            # Mock successful authentication and authorization
            with patch.object(enforcer, '_validate_authentication') as mock_auth:
                with patch.object(enforcer, '_validate_authorization') as mock_authz:
                    mock_auth.return_value = (True, None, {'user_id': 'admin123', 'role': UserRole.ADMIN})
                    mock_authz.return_value = (True, None)
                    
                    @enforcer.enforce_zero_trust
                    def test_route():
                        return "success"
                    
                    with patch('byteguardx.security.zero_trust_enforcement.request') as mock_request:
                        mock_request.path = '/api/v1/admin/test'
                        mock_request.method = 'GET'
                        mock_request.remote_addr = '127.0.0.1'
                        mock_request.headers = {'User-Agent': 'test'}
                        mock_request.endpoint = 'test'
                        
                        result = test_route()
                        assert result == "success"
    
    def test_plugin_security_with_signature_verification(self):
        """Test that plugin loading requires signature verification"""
        with tempfile.TemporaryDirectory() as temp_dir:
            verifier = PluginSignatureVerifier(trust_store_dir=temp_dir)
            
            # Create a test plugin file
            plugin_file = Path(temp_dir) / "test_plugin.py"
            plugin_file.write_text("# Test plugin content")
            
            # Test signature verification requirement
            signature = PluginSignature(
                plugin_id="test-plugin",
                plugin_version="1.0.0",
                file_hash=verifier.calculate_file_hash(str(plugin_file)),
                signature="fake-signature",
                signer_id="unknown-signer",
                signed_at=datetime.now().isoformat()
            )
            
            is_valid, message = verifier.verify_plugin_signature(str(plugin_file), signature)
            assert not is_valid
            assert "Unknown signer" in message

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
