#!/usr/bin/env python3
"""
ByteGuardX Environment Validator
Validates environment configuration and dependencies before startup
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import re

class EnvironmentValidator:
    """Comprehensive environment validation for ByteGuardX"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.project_root = Path(__file__).parent
        self.errors = []
        self.warnings = []
        
        # Required Python packages
        self.required_python_packages = [
            'flask>=2.0.0',
            'flask-cors>=3.0.0',
            'flask-limiter>=2.0.0',
            'pyjwt>=2.0.0',
            'bcrypt>=3.2.0',
            'cryptography>=3.4.0',
            'requests>=2.25.0',
            'python-magic>=0.4.0',
            'docker>=5.0.0'
        ]
        
        # Required Node.js packages
        self.required_node_packages = [
            'react>=18.0.0',
            'react-dom>=18.0.0',
            'vite>=4.0.0',
            'typescript>=4.9.0'
        ]
        
        # Environment variables with validation rules
        self.env_vars = {
            'SECRET_KEY': {
                'required': True,
                'min_length': 32,
                'description': 'Flask application secret key'
            },
            'JWT_SECRET': {
                'required': True,
                'min_length': 32,
                'description': 'JWT token signing secret'
            },
            'BYTEGUARDX_MASTER_KEY': {
                'required_in_production': True,
                'min_length': 32,
                'description': 'Master encryption key for secrets'
            },
            'DATABASE_URL': {
                'required_in_production': True,
                'description': 'Database connection URL'
            },
            'REDIS_URL': {
                'required': False,
                'description': 'Redis connection URL for caching'
            },
            'SMTP_SERVER': {
                'required': False,
                'description': 'SMTP server for email notifications'
            },
            'ALLOWED_ORIGINS': {
                'required': False,
                'default': 'http://localhost:3000,http://localhost:3001',
                'description': 'Allowed CORS origins'
            }
        }
    
    def _setup_logging(self):
        """Setup logging for validator"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('EnvValidator')
    
    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Run all validations
        Returns: (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        self.logger.info("🔍 Starting environment validation...")
        
        # Validate Python environment
        self._validate_python_environment()
        
        # Validate Node.js environment
        self._validate_nodejs_environment()
        
        # Validate environment variables
        self._validate_environment_variables()
        
        # Validate file permissions
        self._validate_file_permissions()
        
        # Validate project structure
        self._validate_project_structure()
        
        # Validate dependencies
        self._validate_dependencies()
        
        # Summary
        is_valid = len(self.errors) == 0
        
        if is_valid:
            self.logger.info("✅ Environment validation passed")
        else:
            self.logger.error("❌ Environment validation failed")
        
        return is_valid, self.errors, self.warnings
    
    def _validate_python_environment(self):
        """Validate Python environment"""
        self.logger.info("🐍 Validating Python environment...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            self.errors.append(f"Python 3.8+ required, found {sys.version}")
        elif sys.version_info < (3, 9):
            self.warnings.append(f"Python 3.9+ recommended, found {sys.version}")
        
        # Check pip
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                         check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.errors.append("pip is not available")
        
        # Check virtual environment
        if not hasattr(sys, 'real_prefix') and not sys.base_prefix != sys.prefix:
            self.warnings.append("Not running in a virtual environment")
    
    def _validate_nodejs_environment(self):
        """Validate Node.js environment"""
        self.logger.info("📦 Validating Node.js environment...")
        
        # Check Node.js
        try:
            result = subprocess.run(['node', '--version'], 
                                  check=True, capture_output=True, text=True)
            version = result.stdout.strip()
            
            # Extract version number
            version_match = re.match(r'v(\d+)\.(\d+)\.(\d+)', version)
            if version_match:
                major = int(version_match.group(1))
                if major < 16:
                    self.errors.append(f"Node.js 16+ required, found {version}")
                elif major < 18:
                    self.warnings.append(f"Node.js 18+ recommended, found {version}")
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.errors.append("Node.js is not installed or not in PATH")
        
        # Check npm
        try:
            subprocess.run(['npm', '--version'], 
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.errors.append("npm is not installed or not in PATH")
    
    def _validate_environment_variables(self):
        """Validate environment variables"""
        self.logger.info("🔧 Validating environment variables...")
        
        is_production = os.environ.get('ENV', '').lower() == 'production'
        
        for var_name, config in self.env_vars.items():
            value = os.environ.get(var_name)
            
            # Check if required
            required = config.get('required', False)
            required_in_prod = config.get('required_in_production', False)
            
            if (required or (required_in_prod and is_production)) and not value:
                self.errors.append(f"Required environment variable {var_name} not set")
                continue
            
            if not value:
                # Set default if available
                default = config.get('default')
                if default:
                    os.environ[var_name] = default
                    self.warnings.append(f"{var_name} not set, using default: {default}")
                continue
            
            # Validate length
            min_length = config.get('min_length')
            if min_length and len(value) < min_length:
                if is_production:
                    self.errors.append(f"{var_name} must be at least {min_length} characters")
                else:
                    self.warnings.append(f"{var_name} should be at least {min_length} characters")
            
            # Check for weak values
            if self._is_weak_secret(value):
                if is_production:
                    self.errors.append(f"{var_name} appears to be a weak/default value")
                else:
                    self.warnings.append(f"{var_name} appears to be a weak/default value")
    
    def _validate_file_permissions(self):
        """Validate file permissions"""
        self.logger.info("🔒 Validating file permissions...")
        
        sensitive_files = [
            '.env',
            '.env.production',
            '.env.local',
            'data/users.json',
            'data/secrets.enc',
            'logs/'
        ]
        
        for file_path in sensitive_files:
            full_path = self.project_root / file_path
            
            if full_path.exists():
                # Check if file is readable by others (Unix-like systems)
                if hasattr(os, 'stat'):
                    import stat
                    file_stat = full_path.stat()
                    
                    if full_path.is_file() and (file_stat.st_mode & stat.S_IROTH):
                        self.warnings.append(f"{file_path} is readable by others")
                    
                    if full_path.is_file() and (file_stat.st_mode & stat.S_IWOTH):
                        self.errors.append(f"{file_path} is writable by others")
    
    def _validate_project_structure(self):
        """Validate project structure"""
        self.logger.info("📁 Validating project structure...")
        
        required_files = [
            'run_server.py',
            'requirements.txt',
            'package.json'
        ]
        
        required_dirs = [
            'byteguardx/',
            'src/',
            'data/'
        ]
        
        for file_path in required_files:
            if not (self.project_root / file_path).exists():
                self.errors.append(f"Required file missing: {file_path}")
        
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            if not full_path.exists():
                self.errors.append(f"Required directory missing: {dir_path}")
            elif not full_path.is_dir():
                self.errors.append(f"Path exists but is not a directory: {dir_path}")
        
        # Create missing directories
        for dir_name in ['logs', 'data', 'temp']:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                try:
                    dir_path.mkdir(exist_ok=True)
                    self.logger.info(f"Created directory: {dir_name}")
                except Exception as e:
                    self.warnings.append(f"Could not create directory {dir_name}: {e}")
    
    def _validate_dependencies(self):
        """Validate dependencies"""
        self.logger.info("📚 Validating dependencies...")
        
        # Check Python dependencies
        missing_python = []
        for package in self.required_python_packages:
            package_name = package.split('>=')[0].split('==')[0]
            try:
                __import__(package_name.replace('-', '_'))
            except ImportError:
                missing_python.append(package)

        # Check for security-critical packages
        security_packages = ['cryptography', 'bcrypt', 'pyjwt', 'flask-limiter']
        missing_security = []
        for package in security_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_security.append(package)

        if missing_security:
            self.errors.append(f"Missing critical security packages: {', '.join(missing_security)}")
        
        if missing_python:
            self.warnings.append(f"Missing Python packages: {', '.join(missing_python)}")
        
        # Check Node.js dependencies
        package_json = self.project_root / 'package.json'
        if package_json.exists():
            try:
                with open(package_json) as f:
                    package_data = json.load(f)
                
                dependencies = package_data.get('dependencies', {})
                dev_dependencies = package_data.get('devDependencies', {})
                all_deps = {**dependencies, **dev_dependencies}
                
                missing_node = []
                for package in self.required_node_packages:
                    package_name = package.split('>=')[0].split('==')[0]
                    if package_name not in all_deps:
                        missing_node.append(package)
                
                if missing_node:
                    self.warnings.append(f"Missing Node.js packages: {', '.join(missing_node)}")
                    
            except (json.JSONDecodeError, FileNotFoundError) as e:
                self.errors.append(f"Could not read package.json: {e}")
    
    def _is_weak_secret(self, value: str) -> bool:
        """Check if a secret value is weak"""
        weak_patterns = [
            'dev-', 'test-', 'demo-', 'example-',
            'changeme', 'password', 'secret', 'key',
            '123456', 'admin', 'default'
        ]
        
        value_lower = value.lower()
        return any(pattern in value_lower for pattern in weak_patterns)
    
    def print_report(self):
        """Print validation report"""
        print("\n" + "=" * 60)
        print("🔍 ByteGuardX Environment Validation Report")
        print("=" * 60)
        
        if self.errors:
            print("\n❌ ERRORS:")
            for error in self.errors:
                print(f"  • {error}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"  • {warning}")
        
        if not self.errors and not self.warnings:
            print("\n✅ All validations passed!")
        
        print("\n📋 Environment Summary:")
        print(f"  Python Version: {sys.version}")
        print(f"  Project Root: {self.project_root}")
        print(f"  Environment: {os.environ.get('ENV', 'development')}")
        
        print("\n🔧 Next Steps:")
        if self.errors:
            print("  1. Fix all errors listed above")
            print("  2. Re-run validation: python validate_environment.py")
        else:
            print("  1. Start the stack: python launch_stack.py")
            print("  2. Or start individual components:")
            print("     - Backend: python run_server.py")
            print("     - Frontend: npm run dev")
        
        print("=" * 60)

def main():
    """Main entry point"""
    validator = EnvironmentValidator()
    is_valid, errors, warnings = validator.validate_all()
    validator.print_report()
    
    # Exit with appropriate code
    sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()
