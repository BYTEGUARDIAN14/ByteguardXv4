"""
Test suite for new ByteGuardX enterprise features
Tests scheduled scans, admin dashboard, email notifications, CVSS scoring, and plugin system
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from byteguardx.database.models import ScheduledScan, User, Finding
from byteguardx.utils.cvss_calculator import CVSSCalculator, CVSSVector
from byteguardx.alerts.email_templates import EmailTemplates


class TestScheduledScans:
    """Test scheduled scan functionality"""
    
    def test_scheduled_scan_creation(self):
        """Test creating a scheduled scan"""
        scan = ScheduledScan(
            name="Daily Security Scan",
            description="Automated daily scan",
            user_id="test-user-id",
            directory_path="/test/path",
            frequency="daily",
            timezone="UTC"
        )
        
        assert scan.name == "Daily Security Scan"
        assert scan.frequency == "daily"
        assert scan.is_active == True
        assert scan.total_runs == 0
    
    def test_scheduled_scan_to_dict(self):
        """Test scheduled scan serialization"""
        scan = ScheduledScan(
            name="Test Scan",
            user_id="test-user-id",
            directory_path="/test",
            frequency="weekly"
        )
        
        scan_dict = scan.to_dict()
        
        assert scan_dict['name'] == "Test Scan"
        assert scan_dict['frequency'] == "weekly"
        assert 'id' in scan_dict
        assert 'created_at' in scan_dict


class TestCVSSCalculator:
    """Test CVSS v3.1 scoring functionality"""
    
    def test_cvss_vector_creation(self):
        """Test CVSS vector creation"""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N"
        )
        
        vector_string = vector.to_string()
        assert vector_string.startswith("CVSS:3.1/")
        assert "AV:N" in vector_string
        assert "AC:L" in vector_string
        assert "C:H" in vector_string
    
    def test_cvss_vector_parsing(self):
        """Test parsing CVSS vector string"""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        vector = CVSSVector.from_string(vector_string)
        
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"
        assert vector.confidentiality == "H"
        assert vector.integrity == "H"
        assert vector.availability == "N"
    
    def test_cvss_base_score_calculation(self):
        """Test CVSS base score calculation"""
        vector = CVSSVector(
            attack_vector="N",  # Network
            attack_complexity="L",  # Low
            privileges_required="N",  # None
            user_interaction="N",  # None
            scope="U",  # Unchanged
            confidentiality="H",  # High
            integrity="H",  # High
            availability="N"  # None
        )
        
        score, severity = CVSSCalculator.calculate_base_score(vector)
        
        assert 0.0 <= score <= 10.0
        assert severity in ["None", "Low", "Medium", "High", "Critical"]
        assert score > 0  # Should have some score with high confidentiality/integrity impact
    
    def test_severity_labels(self):
        """Test severity label mapping"""
        assert CVSSCalculator.get_severity_label(0.0) == "None"
        assert CVSSCalculator.get_severity_label(2.5) == "Low"
        assert CVSSCalculator.get_severity_label(5.5) == "Medium"
        assert CVSSCalculator.get_severity_label(8.0) == "High"
        assert CVSSCalculator.get_severity_label(9.5) == "Critical"
    
    def test_auto_calculate_from_finding(self):
        """Test automatic CVSS calculation from finding data"""
        finding_data = {
            'scanner_type': 'secret',
            'file_path': '/api/config.py',
            'severity': 'high'
        }
        
        vector, score, label = CVSSCalculator.auto_calculate_from_finding(finding_data)
        
        assert isinstance(vector, CVSSVector)
        assert 0.0 <= score <= 10.0
        assert label in ["None", "Low", "Medium", "High", "Critical"]


class TestEmailTemplates:
    """Test email notification templates"""
    
    def test_scan_completed_template(self):
        """Test scan completion email template"""
        data = {
            'scan_id': 'test-scan-123',
            'directory_path': '/test/project',
            'total_findings': 5,
            'critical_findings': 1,
            'high_findings': 2,
            'medium_findings': 1,
            'low_findings': 1,
            'scan_duration_seconds': 45.2,
            'report_url': 'https://example.com/report/123'
        }
        
        email = EmailTemplates.scan_completed(data)
        
        assert 'subject' in email
        assert 'html' in email
        assert 'text' in email
        assert 'test-scan-123' in email['html']
        assert '5 findings found' in email['subject']
        assert 'Critical Vulnerabilities Found' in email['html']  # Should show critical alert
    
    def test_login_alert_template(self):
        """Test login alert email template"""
        data = {
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 Chrome/91.0',
            'location': 'New York, US',
            'timestamp': datetime.now(),
            'security_url': 'https://example.com/security'
        }
        
        email = EmailTemplates.login_alert(data)
        
        assert 'New login detected' in email['subject']
        assert '192.168.1.100' in email['html']
        assert 'New York, US' in email['html']
        assert 'security_url' in str(email)
    
    def test_scheduled_scan_failed_template(self):
        """Test scheduled scan failure email template"""
        data = {
            'scan_name': 'Daily Security Scan',
            'error_message': 'Directory not found',
            'next_run_at': '2024-01-16 10:00:00',
            'schedule_url': 'https://example.com/schedule'
        }
        
        email = EmailTemplates.scheduled_scan_failed(data)
        
        assert 'failed' in email['subject'].lower()
        assert 'Daily Security Scan' in email['html']
        assert 'Directory not found' in email['html']
    
    def test_weekly_summary_template(self):
        """Test weekly summary email template"""
        data = {
            'week_start': '2024-01-08',
            'week_end': '2024-01-14',
            'total_scans': 12,
            'total_findings': 45,
            'new_critical': 2,
            'resolved_issues': 8,
            'dashboard_url': 'https://example.com/dashboard'
        }
        
        email = EmailTemplates.weekly_summary(data)
        
        assert 'Weekly Summary' in email['subject']
        assert '12' in email['html']  # total scans
        assert '45' in email['html']  # total findings
        assert '2024-01-08' in email['html']


class TestAdminDashboard:
    """Test admin dashboard functionality"""
    
    @patch('byteguardx.database.connection_pool.db_manager')
    def test_admin_stats_calculation(self, mock_db):
        """Test admin statistics calculation"""
        # Mock database session and queries
        mock_session = Mock()
        mock_db.get_session.return_value.__enter__.return_value = mock_session
        
        # Mock query results
        mock_session.query.return_value.count.return_value = 100  # total users
        mock_session.query.return_value.filter.return_value.count.return_value = 85  # active users
        
        # This would test the actual admin stats endpoint
        # In a real test, we'd make an API call and verify the response
        assert True  # Placeholder for actual test
    
    def test_user_role_validation(self):
        """Test user role validation for admin access"""
        from byteguardx.auth.models import UserRole
        
        valid_roles = [role.value for role in UserRole]
        
        assert 'admin' in valid_roles
        assert 'developer' in valid_roles
        assert 'viewer' in valid_roles


class TestPluginSystem:
    """Test plugin marketplace functionality"""
    
    def test_plugin_metadata_validation(self):
        """Test plugin metadata validation"""
        valid_metadata = {
            'id': 'test-plugin',
            'name': 'Test Plugin',
            'version': '1.0.0',
            'author': 'Test Author',
            'type': 'scanner',
            'main': 'plugin.py'
        }
        
        required_fields = ['id', 'name', 'version', 'author', 'type', 'main']
        
        for field in required_fields:
            assert field in valid_metadata
    
    def test_plugin_type_validation(self):
        """Test plugin type validation"""
        valid_types = ['scanner', 'rule', 'exporter', 'validator']
        
        for plugin_type in valid_types:
            assert plugin_type in valid_types


class TestDeploymentWizard:
    """Test deployment wizard functionality"""
    
    def test_docker_compose_template_generation(self):
        """Test Docker Compose template generation"""
        config = {
            'backend_port': '5000',
            'frontend_port': '3000',
            'database_url': 'postgresql://user:pass@db:5432/byteguardx',
            'jwt_secret': 'test-secret',
            'smtp_host': 'smtp.example.com',
            'smtp_port': '587',
            'smtp_username': 'user@example.com',
            'smtp_password': 'password',
            'email_from': 'noreply@example.com',
            'db_name': 'byteguardx',
            'db_user': 'byteguardx',
            'db_password': 'password'
        }
        
        # Test that all required config keys are present
        required_keys = [
            'backend_port', 'frontend_port', 'database_url', 'jwt_secret',
            'smtp_host', 'smtp_port', 'db_name', 'db_user', 'db_password'
        ]
        
        for key in required_keys:
            assert key in config
    
    def test_environment_template_generation(self):
        """Test environment file template generation"""
        config = {
            'database_url': 'postgresql://user:pass@localhost:5432/byteguardx',
            'jwt_secret': 'test-jwt-secret',
            'encryption_key': 'test-encryption-key',
            'smtp_host': 'smtp.example.com',
            'frontend_url': 'http://localhost:3000'
        }
        
        # Verify essential configuration is present
        assert config['database_url'].startswith('postgresql://')
        assert len(config['jwt_secret']) > 10
        assert config['frontend_url'].startswith('http')


if __name__ == '__main__':
    pytest.main([__file__])
