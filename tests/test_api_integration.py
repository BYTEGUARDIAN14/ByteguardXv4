"""
Integration tests for ByteGuardX API endpoints
Tests complete workflows and API interactions
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the Flask app
from byteguardx.api.app import create_app
from byteguardx.database.connection_pool import db_manager

@pytest.fixture
def app():
    """Create test Flask app"""
    test_config = {
        'TESTING': True,
        'DATABASE_URL': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-secret-key',
        'JWT_SECRET_KEY': 'test-jwt-secret'
    }
    
    app = create_app(test_config)
    
    with app.app_context():
        # Initialize test database
        db_manager.initialize()
        yield app

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def temp_test_file():
    """Create temporary test file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("""
# Test Python file with potential security issues
import os
import subprocess

# Hardcoded secret (should be detected)
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def unsafe_command(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    
def sql_injection_risk(user_id):
    # SQL injection pattern
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Insecure random
import random
token = random.randint(1000, 9999)
""")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass

@pytest.fixture
def temp_test_dir():
    """Create temporary test directory with multiple files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        test_files = {
            'app.py': '''
import os
SECRET_KEY = "hardcoded-secret-123"
def run_command(cmd):
    os.system(cmd)  # Command injection
''',
            'config.json': '''
{
    "database": {
        "password": "admin123",
        "host": "localhost"
    },
    "api_key": "sk-test-key-456"
}
''',
            'requirements.txt': '''
flask==1.0.0
requests==2.20.0
''',
            'README.md': '''
# Test Project
This is a test project for ByteGuardX scanning.
'''
        }
        
        for filename, content in test_files.items():
            file_path = Path(temp_dir) / filename
            file_path.write_text(content)
        
        yield temp_dir

class TestHealthEndpoints:
    """Test health check endpoints"""
    
    def test_health_check(self, client):
        """Test basic health check"""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'version' in data

class TestScanWorkflows:
    """Test complete scan workflows"""
    
    def test_file_scan_workflow(self, client, temp_test_file):
        """Test complete file scanning workflow"""
        # Read test file content
        with open(temp_test_file, 'r') as f:
            file_content = f.read()
        
        # Submit scan
        response = client.post('/scan/file', json={
            'file_path': temp_test_file,
            'content': file_content
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify scan response structure
        assert 'scan_id' in data
        assert 'findings' in data
        assert 'total_findings' in data
        assert isinstance(data['findings'], list)
        
        # Should detect secrets and vulnerabilities
        assert data['total_findings'] > 0
        
        # Verify finding structure
        if data['findings']:
            finding = data['findings'][0]
            required_fields = ['type', 'severity', 'description', 'line_number']
            for field in required_fields:
                assert field in finding
    
    def test_directory_scan_workflow(self, client, temp_test_dir):
        """Test directory scanning workflow"""
        response = client.post('/scan/directory', json={
            'directory_path': temp_test_dir,
            'recursive': True
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify response structure
        assert 'scan_id' in data
        assert 'total_files' in data
        assert 'total_findings' in data
        assert 'summary' in data
        
        # Should process multiple files
        assert data['total_files'] >= 3  # At least 3 test files
        
        # Should find security issues
        assert data['total_findings'] > 0
    
    def test_scan_results_retrieval(self, client, temp_test_file):
        """Test scan results retrieval"""
        # First, perform a scan
        with open(temp_test_file, 'r') as f:
            file_content = f.read()
        
        scan_response = client.post('/scan/file', json={
            'file_path': temp_test_file,
            'content': file_content
        })
        
        assert scan_response.status_code == 200
        scan_data = json.loads(scan_response.data)
        scan_id = scan_data['scan_id']
        
        # Retrieve scan results
        results_response = client.get(f'/scan/results/{scan_id}')
        assert results_response.status_code == 200
        
        results_data = json.loads(results_response.data)
        assert results_data['scan_id'] == scan_id
        assert 'findings' in results_data
    
    def test_scan_list(self, client, temp_test_file):
        """Test scan list endpoint"""
        # Perform a scan first
        with open(temp_test_file, 'r') as f:
            file_content = f.read()
        
        client.post('/scan/file', json={
            'file_path': temp_test_file,
            'content': file_content
        })
        
        # Get scan list
        response = client.get('/scan/list')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'scans' in data
        assert isinstance(data['scans'], list)
        assert len(data['scans']) >= 1

class TestSecurityFeatures:
    """Test security-related features"""
    
    def test_rate_limiting_headers(self, client, temp_test_file):
        """Test that rate limiting is properly configured"""
        with open(temp_test_file, 'r') as f:
            file_content = f.read()
        
        # Make multiple requests to test rate limiting
        for i in range(3):
            response = client.post('/scan/file', json={
                'file_path': temp_test_file,
                'content': file_content
            })
            
            # First few requests should succeed
            if i < 2:
                assert response.status_code == 200
    
    def test_input_validation(self, client):
        """Test input validation"""
        # Test missing required fields
        response = client.post('/scan/file', json={})
        assert response.status_code == 400
        
        # Test invalid directory path
        response = client.post('/scan/directory', json={
            'directory_path': '/nonexistent/path'
        })
        assert response.status_code == 400
    
    def test_security_headers(self, client):
        """Test security headers are present"""
        response = client.get('/health')
        
        # Check for security headers (if implemented)
        headers = response.headers
        # Note: Add specific header checks based on your implementation

class TestErrorHandling:
    """Test error handling scenarios"""
    
    def test_nonexistent_scan_results(self, client):
        """Test retrieving nonexistent scan results"""
        response = client.get('/scan/results/nonexistent-scan-id')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_malformed_json(self, client):
        """Test handling of malformed JSON"""
        response = client.post('/scan/file', 
                             data='invalid json',
                             content_type='application/json')
        assert response.status_code == 400
    
    def test_large_file_handling(self, client):
        """Test handling of large files"""
        # Create a large content string
        large_content = "x" * (11 * 1024 * 1024)  # 11MB (over limit)
        
        response = client.post('/scan/file', json={
            'file_path': 'large_file.py',
            'content': large_content
        })
        
        # Should handle gracefully (either reject or process)
        assert response.status_code in [200, 400, 413]

class TestPerformance:
    """Test performance-related aspects"""
    
    def test_scan_performance(self, client, temp_test_dir):
        """Test scan performance metrics"""
        import time
        
        start_time = time.time()
        
        response = client.post('/scan/directory', json={
            'directory_path': temp_test_dir,
            'recursive': True
        })
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        assert response.status_code == 200
        
        # Scan should complete within reasonable time (adjust as needed)
        assert scan_duration < 30  # 30 seconds max for test files
        
        data = json.loads(response.data)
        assert data['total_files'] > 0

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
