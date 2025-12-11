"""
Test Secrets Replacement System
Replaces hardcoded secrets in test files with secure mock values
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
import json
import tempfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecretPattern:
    """Pattern for detecting and replacing secrets"""
    name: str
    pattern: str
    replacement: str
    description: str
    severity: str = "HIGH"

class TestSecretsReplacer:
    """Replaces hardcoded secrets in test files with mock values"""
    
    # Comprehensive secret patterns for replacement
    SECRET_PATTERNS = [
        # API Keys
        SecretPattern(
            name="aws_access_key",
            pattern=r'AKIA[0-9A-Z]{16}',
            replacement='AKIAIOSFODNN7EXAMPLE',
            description="AWS Access Key ID"
        ),
        SecretPattern(
            name="aws_secret_key",
            pattern=r'[A-Za-z0-9/+=]{40}',
            replacement='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            description="AWS Secret Access Key"
        ),
        SecretPattern(
            name="github_token",
            pattern=r'ghp_[A-Za-z0-9]{36}',
            replacement='ghp_MOCK_TOKEN_FOR_TESTING_ONLY_36CHARS',
            description="GitHub Personal Access Token"
        ),
        SecretPattern(
            name="github_token_old",
            pattern=r'[a-f0-9]{40}',
            replacement='1234567890abcdef1234567890abcdef12345678',
            description="GitHub Token (old format)"
        ),
        SecretPattern(
            name="stripe_key",
            pattern=r'sk_live_[A-Za-z0-9]{24}',
            replacement='sk_test_MOCK_STRIPE_KEY_FOR_TESTING',
            description="Stripe Live Secret Key"
        ),
        SecretPattern(
            name="stripe_publishable",
            pattern=r'pk_live_[A-Za-z0-9]{24}',
            replacement='pk_test_MOCK_STRIPE_PUBLISHABLE_KEY',
            description="Stripe Live Publishable Key"
        ),
        SecretPattern(
            name="openai_api_key",
            pattern=r'sk-[A-Za-z0-9]{48}',
            replacement='sk-MOCK_OPENAI_API_KEY_FOR_TESTING_ONLY_48CHARS',
            description="OpenAI API Key"
        ),
        SecretPattern(
            name="jwt_secret",
            pattern=r'["\']jwt[_-]?secret[_-]?key["\']:\s*["\'][^"\']+["\']',
            replacement='"jwt_secret_key": "mock_jwt_secret_for_testing_only"',
            description="JWT Secret Key"
        ),
        
        # Database URLs
        SecretPattern(
            name="postgres_url",
            pattern=r'postgresql://[^:]+:[^@]+@[^/]+/\w+',
            replacement='postgresql://testuser:testpass@localhost:5432/testdb',
            description="PostgreSQL Connection URL"
        ),
        SecretPattern(
            name="mysql_url",
            pattern=r'mysql://[^:]+:[^@]+@[^/]+/\w+',
            replacement='mysql://testuser:testpass@localhost:3306/testdb',
            description="MySQL Connection URL"
        ),
        SecretPattern(
            name="mongodb_url",
            pattern=r'mongodb://[^:]+:[^@]+@[^/]+/\w+',
            replacement='mongodb://testuser:testpass@localhost:27017/testdb',
            description="MongoDB Connection URL"
        ),
        
        # Generic passwords and secrets
        SecretPattern(
            name="password_field",
            pattern=r'["\']password["\']:\s*["\'][^"\']+["\']',
            replacement='"password": "mock_password_for_testing"',
            description="Password field in JSON/config"
        ),
        SecretPattern(
            name="api_key_field",
            pattern=r'["\']api[_-]?key["\']:\s*["\'][^"\']+["\']',
            replacement='"api_key": "mock_api_key_for_testing"',
            description="API key field in JSON/config"
        ),
        SecretPattern(
            name="secret_key_field",
            pattern=r'["\']secret[_-]?key["\']:\s*["\'][^"\']+["\']',
            replacement='"secret_key": "mock_secret_key_for_testing"',
            description="Secret key field in JSON/config"
        ),
        
        # Hardcoded credentials in code
        SecretPattern(
            name="hardcoded_api_key",
            pattern=r'API_KEY\s*=\s*["\'][^"\']+["\']',
            replacement='API_KEY = "mock_api_key_for_testing_only"',
            description="Hardcoded API key variable"
        ),
        SecretPattern(
            name="hardcoded_secret",
            pattern=r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
            replacement='SECRET_KEY = "mock_secret_key_for_testing_only"',
            description="Hardcoded secret key variable"
        ),
        SecretPattern(
            name="hardcoded_password",
            pattern=r'PASSWORD\s*=\s*["\'][^"\']+["\']',
            replacement='PASSWORD = "mock_password_for_testing_only"',
            description="Hardcoded password variable"
        ),
        SecretPattern(
            name="hardcoded_token",
            pattern=r'TOKEN\s*=\s*["\'][^"\']+["\']',
            replacement='TOKEN = "mock_token_for_testing_only"',
            description="Hardcoded token variable"
        ),
        
        # Common test patterns that should be mocked
        SecretPattern(
            name="test_admin_password",
            pattern=r'["\']admin["\'].*["\']password123["\']',
            replacement='"admin" and password == "mock_admin_password"',
            description="Test admin credentials"
        ),
        SecretPattern(
            name="test_database_password",
            pattern=r'DATABASE_PASSWORD\s*=\s*["\'][^"\']+["\']',
            replacement='DATABASE_PASSWORD = "mock_db_password_for_testing"',
            description="Database password variable"
        ),
    ]
    
    def __init__(self):
        self.mock_values = self._generate_mock_values()
        self.replacement_log = []
    
    def _generate_mock_values(self) -> Dict[str, str]:
        """Generate consistent mock values for testing"""
        return {
            'api_key': 'mock_api_key_' + 'a' * 20,
            'secret_key': 'mock_secret_key_' + 'b' * 16,
            'password': 'mock_password_' + 'c' * 12,
            'token': 'mock_token_' + 'd' * 24,
            'database_url': 'sqlite:///mock_test_database.db',
            'jwt_secret': 'mock_jwt_secret_' + 'e' * 16,
            'github_token': 'ghp_' + 'f' * 36,
            'aws_access_key': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'stripe_key': 'sk_test_' + 'g' * 24,
            'openai_key': 'sk-' + 'h' * 48
        }
    
    def scan_and_replace_secrets(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Scan file for hardcoded secrets and replace with mock values
        Returns: (was_modified, list_of_replacements)
        """
        if not file_path.exists():
            return False, ["File does not exist"]
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return False, [f"Failed to read file: {e}"]
        
        original_content = content
        replacements = []
        
        # Apply each secret pattern
        for pattern in self.SECRET_PATTERNS:
            matches = re.finditer(pattern.pattern, content, re.IGNORECASE)
            for match in matches:
                old_value = match.group(0)
                content = content.replace(old_value, pattern.replacement)
                replacements.append(f"Replaced {pattern.name}: {old_value[:20]}...")
                
                # Log replacement
                self.replacement_log.append({
                    'file': str(file_path),
                    'pattern': pattern.name,
                    'description': pattern.description,
                    'old_value': old_value,
                    'new_value': pattern.replacement
                })
        
        # Write back if modified
        if content != original_content:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True, replacements
            except Exception as e:
                return False, [f"Failed to write file: {e}"]
        
        return False, []
    
    def scan_directory(self, directory: Path, file_patterns: List[str] = None) -> Dict[str, Any]:
        """
        Scan entire directory for hardcoded secrets
        """
        if file_patterns is None:
            file_patterns = ['*.py', '*.js', '*.json', '*.yaml', '*.yml', '*.txt', '*.md']
        
        results = {
            'total_files_scanned': 0,
            'files_modified': 0,
            'total_replacements': 0,
            'files_with_secrets': [],
            'replacement_summary': {}
        }
        
        for pattern in file_patterns:
            for file_path in directory.rglob(pattern):
                if file_path.is_file() and not self._should_skip_file(file_path):
                    results['total_files_scanned'] += 1
                    
                    was_modified, replacements = self.scan_and_replace_secrets(file_path)
                    
                    if was_modified:
                        results['files_modified'] += 1
                        results['total_replacements'] += len(replacements)
                        results['files_with_secrets'].append({
                            'file': str(file_path),
                            'replacements': replacements
                        })
        
        # Generate summary
        for log_entry in self.replacement_log:
            pattern_name = log_entry['pattern']
            if pattern_name not in results['replacement_summary']:
                results['replacement_summary'][pattern_name] = 0
            results['replacement_summary'][pattern_name] += 1
        
        return results
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during scanning"""
        skip_patterns = [
            '.git/',
            '__pycache__/',
            '.pytest_cache/',
            'node_modules/',
            '.venv/',
            'venv/',
            '.env',
            'dist/',
            'build/',
            '*.pyc',
            '*.pyo',
            '*.egg-info/',
        ]
        
        file_str = str(file_path)
        for pattern in skip_patterns:
            if pattern in file_str:
                return True
        
        return False
    
    def generate_test_env_file(self, output_path: Path):
        """Generate .env.test file with mock values"""
        env_content = """# Test Environment Variables - Mock Values Only
# DO NOT USE IN PRODUCTION

# API Keys (Mock)
API_KEY=mock_api_key_for_testing_only
SECRET_KEY=mock_secret_key_for_testing_only
JWT_SECRET_KEY=mock_jwt_secret_for_testing_only

# Database (Test)
DATABASE_URL=sqlite:///test_database.db
TEST_DATABASE_URL=sqlite:///test_database.db

# External Services (Mock)
GITHUB_TOKEN=ghp_MOCK_TOKEN_FOR_TESTING_ONLY_36CHARS
OPENAI_API_KEY=sk-MOCK_OPENAI_API_KEY_FOR_TESTING_ONLY_48CHARS
STRIPE_SECRET_KEY=sk_test_MOCK_STRIPE_KEY_FOR_TESTING
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Testing Flags
TESTING=true
FLASK_ENV=testing
DEBUG=false

# Security (Test Mode)
ENABLE_2FA=false
ENABLE_RATE_LIMITING=false
ENABLE_AUDIT_LOGGING=true
"""
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(env_content)
            logger.info(f"Generated test environment file: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate test env file: {e}")
    
    def create_mock_fixtures(self, output_dir: Path):
        """Create mock fixture files for testing"""
        output_dir.mkdir(exist_ok=True)
        
        # Mock secrets fixture
        mock_secrets = {
            'api_keys': {
                'github': 'ghp_MOCK_TOKEN_FOR_TESTING_ONLY_36CHARS',
                'openai': 'sk-MOCK_OPENAI_API_KEY_FOR_TESTING_ONLY_48CHARS',
                'stripe': 'sk_test_MOCK_STRIPE_KEY_FOR_TESTING'
            },
            'database': {
                'url': 'sqlite:///mock_test_database.db',
                'username': 'testuser',
                'password': 'mock_password_for_testing'
            },
            'jwt': {
                'secret_key': 'mock_jwt_secret_for_testing_only',
                'algorithm': 'HS256'
            }
        }
        
        fixtures_file = output_dir / 'mock_secrets.json'
        with open(fixtures_file, 'w', encoding='utf-8') as f:
            json.dump(mock_secrets, f, indent=2)
        
        logger.info(f"Created mock fixtures: {fixtures_file}")
    
    def get_replacement_report(self) -> Dict[str, Any]:
        """Get detailed report of all replacements made"""
        return {
            'total_replacements': len(self.replacement_log),
            'replacements_by_type': self._group_replacements_by_type(),
            'files_affected': list(set(entry['file'] for entry in self.replacement_log)),
            'detailed_log': self.replacement_log
        }
    
    def _group_replacements_by_type(self) -> Dict[str, int]:
        """Group replacements by pattern type"""
        grouped = {}
        for entry in self.replacement_log:
            pattern = entry['pattern']
            grouped[pattern] = grouped.get(pattern, 0) + 1
        return grouped

# Global instance
test_secrets_replacer = TestSecretsReplacer()

# Utility functions for test files
def get_mock_secret(secret_type: str) -> str:
    """Get mock secret value for testing"""
    mock_values = {
        'api_key': 'mock_api_key_for_testing_only',
        'secret_key': 'mock_secret_key_for_testing_only',
        'password': 'mock_password_for_testing_only',
        'token': 'mock_token_for_testing_only',
        'github_token': 'ghp_MOCK_TOKEN_FOR_TESTING_ONLY_36CHARS',
        'openai_key': 'sk-MOCK_OPENAI_API_KEY_FOR_TESTING_ONLY_48CHARS',
        'jwt_secret': 'mock_jwt_secret_for_testing_only',
        'database_url': 'sqlite:///mock_test_database.db'
    }
    return mock_values.get(secret_type, f'mock_{secret_type}_for_testing')

def create_test_user_with_mock_credentials():
    """Create test user with mock credentials"""
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': get_mock_secret('password'),
        'api_key': get_mock_secret('api_key'),
        'role': 'developer'
    }

# Global instance
test_secrets_replacer = TestSecretsReplacer()

# Additional function for test environment generation
def generate_test_environment():
    """Generate secure test environment configuration"""
    return test_secrets_replacer.generate_test_environment()
