"""
Pytest configuration and fixtures for ByteGuardX tests
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, patch

# Import ByteGuardX components
from byteguardx.core.file_processor import FileProcessor
from byteguardx.scanners.secret_scanner import SecretScanner
from byteguardx.scanners.dependency_scanner import DependencyScanner
from byteguardx.scanners.ai_pattern_scanner import AIPatternScanner
from byteguardx.ai_suggestions.fix_engine import FixEngine
from byteguardx.auth.models import UserManager, User, UserRole, SubscriptionTier
from byteguardx.analytics.dashboard import AnalyticsDashboard

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)

@pytest.fixture
def sample_files(temp_dir):
    """Create sample files for testing"""
    files = {}
    
    # Python file with secrets
    python_file = temp_dir / "app.py"
    python_content = '''
import os
import requests

# Hardcoded API key (should be detected)
API_KEY = "sk_live_abcdef123456789012345678"
DATABASE_URL = "postgresql://user:password@localhost/db"

def get_user_data(user_input):
    # Unsafe user input (AI pattern)
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def weak_password_check(password):
    # Weak authentication (AI pattern)
    if password == "admin":
        return True
    return False
'''
    python_file.write_text(python_content)
    files['python'] = python_file
    
    # JavaScript file with vulnerabilities
    js_file = temp_dir / "app.js"
    js_content = '''
const express = require('express');
const app = express();

// Hardcoded GitHub token
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// Vulnerable dependency
const lodash = require('lodash');

app.get('/user/:id', (req, res) => {
    // Direct user input usage (unsafe)
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    // SQL injection vulnerability
});
'''
    js_file.write_text(js_content)
    files['javascript'] = js_file
    
    # Package.json with vulnerable dependencies
    package_json = temp_dir / "package.json"
    package_content = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.20",  # Vulnerable version
            "express": "4.17.1",
            "axios": "0.21.1"     # Vulnerable version
        }
    }
    package_json.write_text(json.dumps(package_content, indent=2))
    files['package_json'] = package_json
    
    # Requirements.txt with vulnerable Python packages
    requirements_file = temp_dir / "requirements.txt"
    requirements_content = '''
django==3.2.0
requests==2.25.1
pillow==8.0.0
flask==1.1.4
'''
    requirements_file.write_text(requirements_content)
    files['requirements'] = requirements_file
    
    return files

@pytest.fixture
def file_processor():
    """Create FileProcessor instance"""
    return FileProcessor()

@pytest.fixture
def secret_scanner():
    """Create SecretScanner instance"""
    return SecretScanner()

@pytest.fixture
def dependency_scanner():
    """Create DependencyScanner instance"""
    return DependencyScanner()

@pytest.fixture
def ai_pattern_scanner():
    """Create AIPatternScanner instance"""
    return AIPatternScanner()

@pytest.fixture
def fix_engine():
    """Create FixEngine instance"""
    return FixEngine()

@pytest.fixture
def user_manager(temp_dir):
    """Create UserManager instance with temporary data directory"""
    return UserManager(str(temp_dir / "user_data"))

@pytest.fixture
def test_user(user_manager):
    """Create a test user"""
    return user_manager.create_user(
        email="test@example.com",
        username="testuser",
        password="testpass123",
        role=UserRole.DEVELOPER
    )

@pytest.fixture
def admin_user(user_manager):
    """Create an admin user"""
    return user_manager.create_user(
        email="admin@example.com",
        username="admin",
        password="adminpass123",
        role=UserRole.ADMIN
    )

@pytest.fixture
def analytics_dashboard(temp_dir):
    """Create AnalyticsDashboard instance"""
    return AnalyticsDashboard(str(temp_dir / "analytics_data"))

@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing"""
    return {
        'scan_id': 'test-scan-123',
        'user_id': 'user-123',
        'organization_id': 'org-123',
        'total_files': 10,
        'total_findings': 15,
        'findings_by_severity': {
            'critical': 2,
            'high': 5,
            'medium': 6,
            'low': 2
        },
        'findings_by_type': {
            'secret': 3,
            'vulnerability': 8,
            'ai_pattern': 4
        },
        'scan_duration': 45.2,
        'languages_detected': ['python', 'javascript'],
        'fix_suggestions': 12
    }

@pytest.fixture
def sample_findings():
    """Sample findings for testing"""
    return [
        {
            'type': 'secret',
            'subtype': 'api_keys.github_token',
            'severity': 'critical',
            'confidence': 0.95,
            'file_path': 'src/config.py',
            'line_number': 12,
            'description': 'GitHub Personal Access Token detected',
            'context': "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
            'recommendation': 'Move token to environment variable'
        },
        {
            'type': 'vulnerability',
            'subtype': 'dependency',
            'severity': 'high',
            'package_name': 'lodash',
            'current_version': '4.17.20',
            'fixed_version': '4.17.21',
            'cve_id': 'CVE-2021-23337',
            'file_path': 'package.json',
            'line_number': 15,
            'description': 'Lodash command injection vulnerability',
            'recommendation': 'Update lodash to version 4.17.21 or later'
        },
        {
            'type': 'ai_pattern',
            'subtype': 'input_validation.sql_injection',
            'severity': 'medium',
            'confidence': 0.82,
            'file_path': 'src/database.py',
            'line_number': 25,
            'description': 'Potential SQL injection vulnerability',
            'context': "query = f'SELECT * FROM users WHERE id = {user_id}'",
            'recommendation': 'Use parameterized queries'
        }
    ]

@pytest.fixture
def mock_flask_app():
    """Mock Flask app for API testing"""
    from byteguardx.api.app import create_app
    app = create_app({'TESTING': True})
    app.config['JWT_SECRET_KEY'] = 'test-secret'
    return app

@pytest.fixture
def api_client(mock_flask_app):
    """Flask test client"""
    return mock_flask_app.test_client()

@pytest.fixture
def auth_headers(api_client, test_user):
    """Authentication headers for API testing"""
    # Login to get token
    response = api_client.post('/auth/login', json={
        'email': test_user.email,
        'password': 'testpass123'
    })
    
    if response.status_code == 200:
        token = response.json['access_token']
        return {'Authorization': f'Bearer {token}'}
    
    return {}

# Mock external dependencies
@pytest.fixture(autouse=True)
def mock_external_apis():
    """Mock external API calls"""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
        
        # Mock successful responses
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'status': 'ok'}
        
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {'status': 'ok'}
        
        yield mock_get, mock_post

# Performance testing fixtures
@pytest.fixture
def large_codebase(temp_dir):
    """Create a large codebase for performance testing"""
    files = []
    
    for i in range(100):
        file_path = temp_dir / f"file_{i}.py"
        content = f'''
# File {i}
import os
import sys

API_KEY_{i} = "sk_test_{'x' * 24}"
SECRET_{i} = "{'a' * 32}"

def function_{i}(user_input):
    # Potential vulnerability {i}
    query = f"SELECT * FROM table_{i} WHERE id = {{user_input}}"
    return query

class Class_{i}:
    def __init__(self):
        self.password = "admin123"
        
    def authenticate(self, pwd):
        if pwd == "admin":
            return True
        return False
'''
        file_path.write_text(content)
        files.append(file_path)
    
    return files

# Database fixtures for integration tests
@pytest.fixture
def mock_database():
    """Mock database for testing"""
    db_data = {
        'users': [],
        'scans': [],
        'findings': [],
        'audit_logs': []
    }
    
    class MockDB:
        def __init__(self):
            self.data = db_data
        
        def insert(self, table, record):
            self.data[table].append(record)
            return len(self.data[table]) - 1
        
        def find(self, table, query=None):
            if query is None:
                return self.data[table]
            # Simple query implementation
            return [r for r in self.data[table] if all(r.get(k) == v for k, v in query.items())]
        
        def update(self, table, record_id, updates):
            if 0 <= record_id < len(self.data[table]):
                self.data[table][record_id].update(updates)
        
        def delete(self, table, record_id):
            if 0 <= record_id < len(self.data[table]):
                del self.data[table][record_id]
    
    return MockDB()

# Async testing fixtures
@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

# Security testing fixtures
@pytest.fixture
def malicious_files(temp_dir):
    """Create files with various malicious patterns"""
    files = {}
    
    # File with multiple secrets
    secrets_file = temp_dir / "secrets.py"
    secrets_content = '''
# Multiple secrets in one file
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
STRIPE_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxx"
DATABASE_URL = "postgresql://user:pass@host:5432/db"
'''
    secrets_file.write_text(secrets_content)
    files['secrets'] = secrets_file
    
    # File with AI-generated vulnerabilities
    ai_vulns_file = temp_dir / "ai_vulns.py"
    ai_vulns_content = '''
import subprocess
import os

def execute_command(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    subprocess.call(f"echo {user_input}", shell=True)

def file_operation(filename):
    # Path traversal vulnerability
    with open(f"/uploads/{filename}", "r") as f:
        return f.read()

def authenticate(username, password):
    # Hardcoded credentials
    if username == "admin" and password == "password123":
        return True
    return False

def get_user_data(user_id):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)
'''
    ai_vulns_file.write_text(ai_vulns_content)
    files['ai_vulns'] = ai_vulns_file
    
    return files
