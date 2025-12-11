#!/usr/bin/env python3
"""
ByteGuardX Security Audit Script
Comprehensive security validation for production deployment
"""

import os
import sys
import json
import re
import subprocess
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAuditor:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.issues = []
        self.warnings = []
        self.passed_checks = []
        
    def log_issue(self, severity, category, message, file_path=None):
        """Log a security issue"""
        issue = {
            'severity': severity,
            'category': category,
            'message': message,
            'file_path': file_path,
            'timestamp': datetime.now().isoformat()
        }
        
        if severity == 'critical' or severity == 'high':
            self.issues.append(issue)
            logger.error(f"[{severity.upper()}] {category}: {message}")
        elif severity == 'medium' or severity == 'low':
            self.warnings.append(issue)
            logger.warning(f"[{severity.upper()}] {category}: {message}")
        else:
            self.passed_checks.append(issue)
            logger.info(f"[PASS] {category}: {message}")
    
    def check_environment_variables(self):
        """Check for secure environment variable configuration"""
        logger.info("Checking environment variables...")
        
        required_vars = [
            'SECRET_KEY',
            'JWT_SECRET_KEY',
            'DATABASE_URL'
        ]
        
        insecure_defaults = [
            'dev-secret-key-change-in-production',
            'jwt-secret-key-change-in-production',
            'your-secret-key',
            'your-jwt-secret'
        ]
        
        for var in required_vars:
            value = os.getenv(var)
            if not value:
                self.log_issue('high', 'Environment', f'Missing required environment variable: {var}')
            elif value in insecure_defaults:
                self.log_issue('critical', 'Environment', f'Using default/insecure value for {var}')
            else:
                self.log_issue('pass', 'Environment', f'{var} is properly configured')
    
    def check_file_permissions(self):
        """Check file permissions for sensitive files"""
        logger.info("Checking file permissions...")
        
        sensitive_files = [
            '.env',
            'config.py',
            'byteguardx_auth_api_server.py',
            'deploy.py'
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                # Check if file is readable by others (should not be)
                if stat_info.st_mode & 0o044:
                    self.log_issue('medium', 'File Permissions', 
                                 f'{file_path} has overly permissive permissions', file_path)
                else:
                    self.log_issue('pass', 'File Permissions', f'{file_path} has secure permissions')
    
    def check_hardcoded_secrets(self):
        """Check for hardcoded secrets in source code"""
        logger.info("Checking for hardcoded secrets...")
        
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{20,}["\']',
            r'secret_key\s*=\s*["\'][^"\']{20,}["\']',
            r'token\s*=\s*["\'][^"\']{20,}["\']',
            r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']',  # Base64 encoded secrets
        ]
        
        exclude_patterns = [
            r'example',
            r'test',
            r'demo',
            r'placeholder',
            r'your-.*-here'
        ]
        
        source_files = []
        for ext in ['.py', '.js', '.jsx', '.ts', '.tsx']:
            source_files.extend(self.project_root.rglob(f'*{ext}'))
        
        for file_path in source_files:
            if 'node_modules' in str(file_path) or '.git' in str(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                for pattern in secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Check if it's likely a placeholder/example
                        is_placeholder = any(re.search(exclude_pat, match.group(), re.IGNORECASE) 
                                           for exclude_pat in exclude_patterns)
                        
                        if not is_placeholder:
                            self.log_issue('high', 'Hardcoded Secrets', 
                                         f'Potential hardcoded secret found: {match.group()[:20]}...', 
                                         str(file_path))
            except Exception as e:
                logger.warning(f"Could not scan {file_path}: {e}")
    
    def check_dependency_vulnerabilities(self):
        """Check for known vulnerabilities in dependencies"""
        logger.info("Checking dependency vulnerabilities...")
        
        # Check Python dependencies
        if os.path.exists('requirements.txt'):
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'check'],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    self.log_issue('medium', 'Dependencies', 
                                 f'Python dependency issues found: {result.stdout}')
                else:
                    self.log_issue('pass', 'Dependencies', 'Python dependencies are consistent')
            except Exception as e:
                self.log_issue('low', 'Dependencies', f'Could not check Python dependencies: {e}')
        
        # Check Node.js dependencies
        if os.path.exists('package.json'):
            try:
                result = subprocess.run(['npm', 'audit', '--json'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    audit_data = json.loads(result.stdout)
                    if audit_data.get('metadata', {}).get('vulnerabilities', {}).get('total', 0) > 0:
                        high_vulns = audit_data['metadata']['vulnerabilities'].get('high', 0)
                        critical_vulns = audit_data['metadata']['vulnerabilities'].get('critical', 0)
                        
                        if critical_vulns > 0:
                            self.log_issue('critical', 'Dependencies', 
                                         f'{critical_vulns} critical vulnerabilities in npm packages')
                        elif high_vulns > 0:
                            self.log_issue('high', 'Dependencies', 
                                         f'{high_vulns} high severity vulnerabilities in npm packages')
                        else:
                            self.log_issue('medium', 'Dependencies', 
                                         'Some vulnerabilities found in npm packages')
                    else:
                        self.log_issue('pass', 'Dependencies', 'No known vulnerabilities in npm packages')
            except Exception as e:
                self.log_issue('low', 'Dependencies', f'Could not check npm dependencies: {e}')
    
    def check_security_headers(self):
        """Check if security headers are properly configured"""
        logger.info("Checking security headers configuration...")
        
        flask_file = 'byteguardx_auth_api_server.py'
        if os.path.exists(flask_file):
            with open(flask_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            security_features = [
                ('Flask-Talisman', 'Talisman'),
                ('CORS configuration', 'CORS'),
                ('Rate limiting', 'Limiter'),
                ('CSRF protection', 'csrf'),
                ('Input validation', 'validate_')
            ]
            
            for feature_name, pattern in security_features:
                if pattern in content:
                    self.log_issue('pass', 'Security Headers', f'{feature_name} is configured')
                else:
                    self.log_issue('medium', 'Security Headers', f'{feature_name} not found')
    
    def generate_report(self):
        """Generate security audit report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'critical_issues': len([i for i in self.issues if i['severity'] == 'critical']),
                'high_issues': len([i for i in self.issues if i['severity'] == 'high']),
                'medium_issues': len([i for i in self.warnings if i['severity'] == 'medium']),
                'low_issues': len([i for i in self.warnings if i['severity'] == 'low']),
                'passed_checks': len(self.passed_checks)
            },
            'issues': self.issues,
            'warnings': self.warnings,
            'passed_checks': self.passed_checks
        }
        
        # Save report to file
        with open('security_audit_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def run_audit(self):
        """Run complete security audit"""
        logger.info("Starting ByteGuardX security audit...")
        
        self.check_environment_variables()
        self.check_file_permissions()
        self.check_hardcoded_secrets()
        self.check_dependency_vulnerabilities()
        self.check_security_headers()
        
        report = self.generate_report()
        
        # Print summary
        print("\n" + "="*60)
        print("BYTEGUARDX SECURITY AUDIT SUMMARY")
        print("="*60)
        print(f"Critical Issues: {report['summary']['critical_issues']}")
        print(f"High Issues: {report['summary']['high_issues']}")
        print(f"Medium Issues: {report['summary']['medium_issues']}")
        print(f"Low Issues: {report['summary']['low_issues']}")
        print(f"Passed Checks: {report['summary']['passed_checks']}")
        print("="*60)
        
        if report['summary']['critical_issues'] > 0:
            print("❌ CRITICAL ISSUES FOUND - DO NOT DEPLOY TO PRODUCTION")
            return False
        elif report['summary']['high_issues'] > 0:
            print("⚠️  HIGH SEVERITY ISSUES FOUND - REVIEW BEFORE DEPLOYMENT")
            return False
        else:
            print("✅ SECURITY AUDIT PASSED - READY FOR DEPLOYMENT")
            return True

def main():
    auditor = SecurityAuditor()
    success = auditor.run_audit()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
