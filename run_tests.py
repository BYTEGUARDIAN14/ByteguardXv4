#!/usr/bin/env python3
"""
ByteGuardX Comprehensive Testing Script
Runs all tests and validates application functionality
"""

import os
import sys
import subprocess
import json
import time
import requests
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestRunner:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_results = {
            'frontend': {'passed': 0, 'failed': 0, 'errors': []},
            'backend': {'passed': 0, 'failed': 0, 'errors': []},
            'integration': {'passed': 0, 'failed': 0, 'errors': []},
            'security': {'passed': 0, 'failed': 0, 'errors': []}
        }
        
    def run_frontend_tests(self):
        """Run React frontend tests"""
        logger.info("Running frontend tests...")
        
        try:
            # Check if package.json exists
            if not (self.project_root / 'package.json').exists():
                self.test_results['frontend']['errors'].append('package.json not found')
                return False
            
            # Install dependencies if needed
            if not (self.project_root / 'node_modules').exists():
                logger.info("Installing npm dependencies...")
                result = subprocess.run(['npm', 'install'], 
                                      cwd=self.project_root, 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    self.test_results['frontend']['errors'].append(f'npm install failed: {result.stderr}')
                    return False
            
            # Run tests
            result = subprocess.run(['npm', 'test', '--', '--watchAll=false'], 
                                  cwd=self.project_root, 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.test_results['frontend']['passed'] += 1
                logger.info("Frontend tests passed")
                return True
            else:
                self.test_results['frontend']['failed'] += 1
                self.test_results['frontend']['errors'].append(result.stderr)
                logger.error(f"Frontend tests failed: {result.stderr}")
                return False
                
        except FileNotFoundError:
            self.test_results['frontend']['errors'].append('npm not found')
            logger.error("npm not found. Please install Node.js")
            return False
        except Exception as e:
            self.test_results['frontend']['errors'].append(str(e))
            logger.error(f"Frontend test error: {e}")
            return False
    
    def run_backend_tests(self):
        """Run Flask backend tests"""
        logger.info("Running backend tests...")
        
        try:
            # Check if tests directory exists
            tests_dir = self.project_root / 'tests'
            if not tests_dir.exists():
                logger.info("No tests directory found, creating basic test structure...")
                tests_dir.mkdir(exist_ok=True)
                
                # Create basic test file
                basic_test = tests_dir / 'test_basic.py'
                with open(basic_test, 'w') as f:
                    f.write("""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestBasic(unittest.TestCase):
    def test_imports(self):
        \"\"\"Test that main modules can be imported\"\"\"
        try:
            import byteguardx_auth_api_server
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import main module: {e}")
    
    def test_environment(self):
        \"\"\"Test environment setup\"\"\"
        self.assertTrue(os.path.exists('byteguardx_auth_api_server.py'))
        self.assertTrue(os.path.exists('requirements.txt'))

if __name__ == '__main__':
    unittest.main()
""")
            
            # Run pytest if available, otherwise unittest
            try:
                result = subprocess.run([sys.executable, '-m', 'pytest', str(tests_dir), '-v'], 
                                      capture_output=True, text=True)
            except FileNotFoundError:
                result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', str(tests_dir)], 
                                      capture_output=True, text=True)
            
            if result.returncode == 0:
                self.test_results['backend']['passed'] += 1
                logger.info("Backend tests passed")
                return True
            else:
                self.test_results['backend']['failed'] += 1
                self.test_results['backend']['errors'].append(result.stderr)
                logger.error(f"Backend tests failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.test_results['backend']['errors'].append(str(e))
            logger.error(f"Backend test error: {e}")
            return False
    
    def run_integration_tests(self):
        """Run integration tests"""
        logger.info("Running integration tests...")
        
        try:
            # Start Flask server in background
            server_process = subprocess.Popen(
                [sys.executable, 'byteguardx_auth_api_server.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for server to start
            time.sleep(3)
            
            # Test API endpoints
            base_url = 'http://localhost:5000'
            
            # Test health endpoint
            try:
                response = requests.get(f'{base_url}/api/health', timeout=5)
                if response.status_code == 200:
                    self.test_results['integration']['passed'] += 1
                    logger.info("Health endpoint test passed")
                else:
                    self.test_results['integration']['failed'] += 1
                    self.test_results['integration']['errors'].append(f'Health endpoint returned {response.status_code}')
            except requests.RequestException as e:
                self.test_results['integration']['failed'] += 1
                self.test_results['integration']['errors'].append(f'Health endpoint test failed: {e}')
            
            # Test CORS headers
            try:
                response = requests.options(f'{base_url}/api/auth/login', timeout=5)
                if 'Access-Control-Allow-Origin' in response.headers:
                    self.test_results['integration']['passed'] += 1
                    logger.info("CORS test passed")
                else:
                    self.test_results['integration']['failed'] += 1
                    self.test_results['integration']['errors'].append('CORS headers not found')
            except requests.RequestException as e:
                self.test_results['integration']['failed'] += 1
                self.test_results['integration']['errors'].append(f'CORS test failed: {e}')
            
            # Cleanup
            server_process.terminate()
            server_process.wait(timeout=5)
            
            return self.test_results['integration']['failed'] == 0
            
        except Exception as e:
            self.test_results['integration']['errors'].append(str(e))
            logger.error(f"Integration test error: {e}")
            return False
    
    def run_security_tests(self):
        """Run security validation tests"""
        logger.info("Running security tests...")
        
        try:
            # Run security audit script
            result = subprocess.run([sys.executable, 'security_audit.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                self.test_results['security']['passed'] += 1
                logger.info("Security audit passed")
                return True
            else:
                self.test_results['security']['failed'] += 1
                self.test_results['security']['errors'].append(result.stderr)
                logger.error(f"Security audit failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.test_results['security']['errors'].append(str(e))
            logger.error(f"Security test error: {e}")
            return False
    
    def generate_report(self):
        """Generate test report"""
        total_passed = sum(category['passed'] for category in self.test_results.values())
        total_failed = sum(category['failed'] for category in self.test_results.values())
        total_tests = total_passed + total_failed
        
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_tests': total_tests,
                'passed': total_passed,
                'failed': total_failed,
                'success_rate': (total_passed / total_tests * 100) if total_tests > 0 else 0
            },
            'details': self.test_results
        }
        
        # Save report
        with open('test_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def run_all_tests(self):
        """Run all test suites"""
        logger.info("Starting comprehensive test suite...")
        
        # Run all test categories
        frontend_ok = self.run_frontend_tests()
        backend_ok = self.run_backend_tests()
        integration_ok = self.run_integration_tests()
        security_ok = self.run_security_tests()
        
        # Generate report
        report = self.generate_report()
        
        # Print summary
        print("\n" + "="*60)
        print("BYTEGUARDX TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {report['summary']['total_tests']}")
        print(f"Passed: {report['summary']['passed']}")
        print(f"Failed: {report['summary']['failed']}")
        print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
        print("="*60)
        
        # Print category details
        for category, results in self.test_results.items():
            status = "✅" if results['failed'] == 0 else "❌"
            print(f"{status} {category.title()}: {results['passed']} passed, {results['failed']} failed")
            
            if results['errors']:
                for error in results['errors'][:3]:  # Show first 3 errors
                    print(f"   Error: {error[:100]}...")
        
        print("="*60)
        
        # Overall result
        all_passed = frontend_ok and backend_ok and integration_ok and security_ok
        if all_passed:
            print("🎉 ALL TESTS PASSED - READY FOR DEPLOYMENT")
        else:
            print("❌ SOME TESTS FAILED - REVIEW BEFORE DEPLOYMENT")
        
        return all_passed

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run ByteGuardX test suite')
    parser.add_argument('--frontend-only', action='store_true', help='Run only frontend tests')
    parser.add_argument('--backend-only', action='store_true', help='Run only backend tests')
    parser.add_argument('--integration-only', action='store_true', help='Run only integration tests')
    parser.add_argument('--security-only', action='store_true', help='Run only security tests')
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    if args.frontend_only:
        success = runner.run_frontend_tests()
    elif args.backend_only:
        success = runner.run_backend_tests()
    elif args.integration_only:
        success = runner.run_integration_tests()
    elif args.security_only:
        success = runner.run_security_tests()
    else:
        success = runner.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
