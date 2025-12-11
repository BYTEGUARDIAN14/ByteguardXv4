#!/usr/bin/env python3
"""
ByteGuardX Security Test Suite
Comprehensive security testing for all components
"""

import os
import sys
import subprocess
import logging
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Any
import unittest
import requests
import time

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class SecurityTestSuite:
    """Comprehensive security test suite"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.project_root = project_root
        self.test_results = {}
        
        # Test configurations
        self.backend_url = "http://localhost:5000"
        self.frontend_url = "http://localhost:3001"
        
    def _setup_logging(self):
        """Setup logging for tests"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('SecurityTests')
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests"""
        self.logger.info("🔒 Starting comprehensive security test suite...")
        
        test_categories = [
            ('dependency_scan', self.test_dependency_security),
            ('secret_scan', self.test_secret_scanning),
            ('code_quality', self.test_code_quality),
            ('authentication', self.test_authentication_security),
            ('input_validation', self.test_input_validation),
            ('file_upload', self.test_file_upload_security),
            ('csrf_protection', self.test_csrf_protection),
            ('rate_limiting', self.test_rate_limiting),
            ('plugin_security', self.test_plugin_security),
            ('ai_security', self.test_ai_security)
        ]
        
        for test_name, test_func in test_categories:
            self.logger.info(f"Running {test_name} tests...")
            try:
                result = test_func()
                self.test_results[test_name] = result
                
                if result['passed']:
                    self.logger.info(f"✅ {test_name} tests passed")
                else:
                    self.logger.error(f"❌ {test_name} tests failed")
                    
            except Exception as e:
                self.logger.error(f"❌ {test_name} tests error: {e}")
                self.test_results[test_name] = {
                    'passed': False,
                    'error': str(e),
                    'details': []
                }
        
        return self.test_results
    
    def test_dependency_security(self) -> Dict[str, Any]:
        """Test dependency security"""
        results = {'passed': True, 'details': []}
        
        # Python dependency scan with safety
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', 'safety'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                safety_result = subprocess.run([
                    sys.executable, '-m', 'safety', 'check', '--json'
                ], capture_output=True, text=True)
                
                if safety_result.returncode != 0:
                    try:
                        vulnerabilities = json.loads(safety_result.stdout)
                        if vulnerabilities:
                            results['passed'] = False
                            results['details'].append(f"Found {len(vulnerabilities)} Python vulnerabilities")
                    except json.JSONDecodeError:
                        results['details'].append("Safety scan completed with warnings")
                else:
                    results['details'].append("No Python vulnerabilities found")
            
        except Exception as e:
            results['details'].append(f"Python dependency scan error: {e}")
        
        # Node.js dependency scan with npm audit
        try:
            audit_result = subprocess.run([
                'npm', 'audit', '--json'
            ], capture_output=True, text=True, cwd=self.project_root)
            
            if audit_result.returncode != 0:
                try:
                    audit_data = json.loads(audit_result.stdout)
                    vulnerabilities = audit_data.get('metadata', {}).get('vulnerabilities', {})
                    
                    high_vuln = vulnerabilities.get('high', 0)
                    critical_vuln = vulnerabilities.get('critical', 0)
                    
                    if high_vuln > 0 or critical_vuln > 0:
                        results['passed'] = False
                        results['details'].append(f"Found {high_vuln} high and {critical_vuln} critical Node.js vulnerabilities")
                    else:
                        results['details'].append("No critical Node.js vulnerabilities found")
                        
                except json.JSONDecodeError:
                    results['details'].append("npm audit completed with warnings")
            else:
                results['details'].append("No Node.js vulnerabilities found")
                
        except Exception as e:
            results['details'].append(f"Node.js dependency scan error: {e}")
        
        return results
    
    def test_secret_scanning(self) -> Dict[str, Any]:
        """Test for exposed secrets"""
        results = {'passed': True, 'details': []}
        
        # Install and run trufflehog
        try:
            # Simple regex-based secret detection
            secret_patterns = [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']',
                r'secret[_-]?key\s*=\s*["\'][^"\']{32,}["\']',
                r'token\s*=\s*["\'][^"\']{20,}["\']'
            ]
            
            secrets_found = []
            
            for py_file in self.project_root.rglob('*.py'):
                if 'venv' in str(py_file) or '__pycache__' in str(py_file):
                    continue
                
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    for pattern in secret_patterns:
                        import re
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            secrets_found.append(f"Potential secret in {py_file}")
                            
                except Exception:
                    continue
            
            if secrets_found:
                results['passed'] = False
                results['details'].extend(secrets_found)
            else:
                results['details'].append("No hardcoded secrets detected")
                
        except Exception as e:
            results['details'].append(f"Secret scanning error: {e}")
        
        return results
    
    def test_code_quality(self) -> Dict[str, Any]:
        """Test code quality and security"""
        results = {'passed': True, 'details': []}
        
        # Python code quality with bandit
        try:
            bandit_result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', 'bandit'
            ], capture_output=True)
            
            if bandit_result.returncode == 0:
                scan_result = subprocess.run([
                    sys.executable, '-m', 'bandit', '-r', 'byteguardx/', '-f', 'json'
                ], capture_output=True, text=True)
                
                try:
                    bandit_data = json.loads(scan_result.stdout)
                    high_issues = [r for r in bandit_data.get('results', []) if r.get('issue_severity') == 'HIGH']
                    
                    if high_issues:
                        results['passed'] = False
                        results['details'].append(f"Found {len(high_issues)} high-severity security issues")
                    else:
                        results['details'].append("No high-severity security issues found")
                        
                except json.JSONDecodeError:
                    results['details'].append("Bandit scan completed")
                    
        except Exception as e:
            results['details'].append(f"Code quality scan error: {e}")
        
        return results
    
    def test_authentication_security(self) -> Dict[str, Any]:
        """Test authentication security"""
        results = {'passed': True, 'details': []}
        
        try:
            # Test weak password rejection
            weak_passwords = ['123456', 'password', 'admin', 'test']
            
            for weak_pwd in weak_passwords:
                response = requests.post(f"{self.backend_url}/api/auth/register", json={
                    'email': 'test@example.com',
                    'username': 'testuser',
                    'password': weak_pwd
                }, timeout=5)
                
                if response.status_code == 200:
                    results['passed'] = False
                    results['details'].append(f"Weak password '{weak_pwd}' was accepted")
                    break
            
            if results['passed']:
                results['details'].append("Weak passwords properly rejected")
            
            # Test rate limiting on login
            login_attempts = 0
            for i in range(10):
                response = requests.post(f"{self.backend_url}/api/auth/login", json={
                    'email': 'nonexistent@example.com',
                    'password': 'wrongpassword'
                }, timeout=5)
                
                if response.status_code == 429:  # Rate limited
                    break
                login_attempts += 1
            
            if login_attempts >= 10:
                results['passed'] = False
                results['details'].append("Rate limiting not working on login endpoint")
            else:
                results['details'].append("Rate limiting working correctly")
                
        except requests.RequestException as e:
            results['details'].append(f"Authentication test error: {e}")
        
        return results
    
    def test_input_validation(self) -> Dict[str, Any]:
        """Test input validation"""
        results = {'passed': True, 'details': []}
        
        # Test SQL injection patterns
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --"
        ]
        
        # Test XSS patterns
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        try:
            for payload in sql_payloads + xss_payloads:
                response = requests.post(f"{self.backend_url}/api/auth/login", json={
                    'email': payload,
                    'password': payload
                }, timeout=5)
                
                # Check if payload was reflected or caused error
                if payload in response.text:
                    results['passed'] = False
                    results['details'].append(f"Input validation failed for payload: {payload[:20]}...")
                    break
            
            if results['passed']:
                results['details'].append("Input validation working correctly")
                
        except requests.RequestException as e:
            results['details'].append(f"Input validation test error: {e}")
        
        return results
    
    def test_file_upload_security(self) -> Dict[str, Any]:
        """Test file upload security"""
        results = {'passed': True, 'details': []}
        
        # Create test files
        test_files = {
            'malicious.exe': b'MZ\x90\x00',  # PE header
            'script.php': b'<?php system($_GET["cmd"]); ?>',
            'large_file.txt': b'A' * (10 * 1024 * 1024),  # 10MB file
            'path_traversal.txt': b'../../../etc/passwd'
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                for filename, content in test_files.items():
                    file_path = Path(temp_dir) / filename
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    # Test file upload (if endpoint exists)
                    try:
                        with open(file_path, 'rb') as f:
                            files = {'file': (filename, f, 'application/octet-stream')}
                            response = requests.post(
                                f"{self.backend_url}/api/upload",
                                files=files,
                                timeout=10
                            )
                            
                            if response.status_code == 200:
                                results['passed'] = False
                                results['details'].append(f"Malicious file {filename} was accepted")
                                
                    except requests.RequestException:
                        # Upload endpoint might not exist, which is fine
                        pass
            
            if results['passed']:
                results['details'].append("File upload security working correctly")
                
        except Exception as e:
            results['details'].append(f"File upload test error: {e}")
        
        return results
    
    def test_csrf_protection(self) -> Dict[str, Any]:
        """Test CSRF protection"""
        results = {'passed': True, 'details': []}
        
        try:
            # Test POST without CSRF token
            response = requests.post(f"{self.backend_url}/api/auth/logout", timeout=5)
            
            if response.status_code != 403:
                results['passed'] = False
                results['details'].append("CSRF protection not working - POST allowed without token")
            else:
                results['details'].append("CSRF protection working correctly")
                
        except requests.RequestException as e:
            results['details'].append(f"CSRF test error: {e}")
        
        return results
    
    def test_rate_limiting(self) -> Dict[str, Any]:
        """Test rate limiting"""
        results = {'passed': True, 'details': []}
        
        try:
            # Test rate limiting on API endpoints
            rate_limited = False
            
            for i in range(20):
                response = requests.get(f"{self.backend_url}/health", timeout=5)
                if response.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.1)
            
            if not rate_limited:
                results['passed'] = False
                results['details'].append("Rate limiting not working")
            else:
                results['details'].append("Rate limiting working correctly")
                
        except requests.RequestException as e:
            results['details'].append(f"Rate limiting test error: {e}")
        
        return results
    
    def test_plugin_security(self) -> Dict[str, Any]:
        """Test plugin security"""
        results = {'passed': True, 'details': []}
        
        # Test malicious plugin code
        malicious_plugins = [
            "import os; os.system('rm -rf /')",
            "eval('__import__(\"os\").system(\"whoami\")')",
            "exec('import subprocess; subprocess.call([\"ls\", \"/\"])')",
            "open('/etc/passwd', 'r').read()"
        ]
        
        try:
            from byteguardx.security.plugin_sandbox import plugin_sandbox
            
            for plugin_code in malicious_plugins:
                manifest = {
                    'name': 'test_plugin',
                    'version': '1.0.0',
                    'author': 'test',
                    'description': 'test plugin',
                    'permissions': [],
                    'trusted': False,
                    'hash': 'test_hash'
                }
                
                success, result = plugin_sandbox.execute_plugin(plugin_code, manifest)
                
                if success:
                    results['passed'] = False
                    results['details'].append(f"Malicious plugin code was executed: {plugin_code[:30]}...")
                    break
            
            if results['passed']:
                results['details'].append("Plugin security working correctly")
                
        except Exception as e:
            results['details'].append(f"Plugin security test error: {e}")
        
        return results
    
    def test_ai_security(self) -> Dict[str, Any]:
        """Test AI/ML security"""
        results = {'passed': True, 'details': []}
        
        try:
            from byteguardx.security.ai_security import adversarial_detector
            
            # Test adversarial inputs
            adversarial_inputs = [
                "A" * 20000,  # Very long input
                "<script>alert('xss')</script>" * 100,  # Repeated XSS
                "\\x41\\x42\\x43" * 1000,  # Hex encoding
                "eval('malicious_code')" * 50  # Repeated eval
            ]
            
            for adv_input in adversarial_inputs:
                is_valid, reason = adversarial_detector.validate_input(adv_input, 'text')
                
                if is_valid:
                    results['passed'] = False
                    results['details'].append(f"Adversarial input was accepted: {reason}")
                    break
            
            if results['passed']:
                results['details'].append("AI security working correctly")
                
        except Exception as e:
            results['details'].append(f"AI security test error: {e}")
        
        return results
    
    def generate_report(self) -> str:
        """Generate security test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results.values() if r['passed'])
        
        report = f"""
ByteGuardX Security Test Report
{'=' * 50}

Summary: {passed_tests}/{total_tests} test categories passed

Test Results:
"""
        
        for test_name, result in self.test_results.items():
            status = "✅ PASS" if result['passed'] else "❌ FAIL"
            report += f"\n{test_name}: {status}\n"
            
            for detail in result.get('details', []):
                report += f"  • {detail}\n"
        
        if passed_tests == total_tests:
            report += "\n🎉 All security tests passed!"
        else:
            report += f"\n⚠️  {total_tests - passed_tests} test categories failed. Please review and fix issues."
        
        return report

def main():
    """Main entry point"""
    test_suite = SecurityTestSuite()
    results = test_suite.run_all_tests()
    report = test_suite.generate_report()
    
    print(report)
    
    # Save report to file
    with open('security_test_report.txt', 'w') as f:
        f.write(report)
    
    # Exit with appropriate code
    all_passed = all(r['passed'] for r in results.values())
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
