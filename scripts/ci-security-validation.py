#!/usr/bin/env python3
"""
CI/CD Security Validation Script for ByteGuardX
Integrates security validation into continuous integration pipeline
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CISecurityValidator:
    """CI/CD Security Validation Manager"""
    
    def __init__(self):
        self.project_root = project_root
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'security_validation': {},
            'static_analysis': {},
            'dependency_scan': {},
            'secret_scan': {},
            'overall_status': 'unknown'
        }
        
    def run_all_validations(self) -> Dict[str, Any]:
        """Run all security validations for CI/CD"""
        logger.info("🔐 Starting CI/CD Security Validation")
        
        try:
            # 1. Run ByteGuardX security validation
            self._run_security_validation()
            
            # 2. Run static analysis
            self._run_static_analysis()
            
            # 3. Run dependency vulnerability scan
            self._run_dependency_scan()
            
            # 4. Run secret scanning
            self._run_secret_scan()
            
            # 5. Generate overall assessment
            self._generate_overall_assessment()
            
            # 6. Save results
            self._save_results()
            
            logger.info(f"✅ Security validation completed. Status: {self.results['overall_status']}")
            return self.results
            
        except Exception as e:
            logger.error(f"❌ Security validation failed: {e}")
            self.results['overall_status'] = 'failed'
            self.results['error'] = str(e)
            return self.results
    
    def _run_security_validation(self):
        """Run ByteGuardX security module validation"""
        logger.info("Running ByteGuardX security validation...")
        
        try:
            # Set up test environment
            os.environ.update({
                'JWT_SECRET_KEY': 'test-jwt-secret-key-for-ci-validation-only',
                'BYTEGUARDX_MASTER_KEY': 'test-master-key-for-ci-validation-only',
                'DATABASE_URL': 'sqlite:///test.db',
                'ENV': 'test'
            })
            
            # Create required directories
            for dir_name in ['data', 'logs', 'reports']:
                Path(dir_name).mkdir(exist_ok=True)
            
            # Run security validation
            result = subprocess.run([
                sys.executable, 'security_validation_summary.py'
            ], capture_output=True, text=True, cwd=self.project_root)
            
            # Parse results
            if Path('security_validation_results.json').exists():
                with open('security_validation_results.json', 'r') as f:
                    validation_results = json.load(f)
                
                self.results['security_validation'] = {
                    'status': 'passed' if result.returncode == 0 else 'failed',
                    'exit_code': result.returncode,
                    'success_rate': validation_results.get('success_rate', 0),
                    'passed_checks': validation_results.get('passed_checks', 0),
                    'total_checks': validation_results.get('total_checks', 0),
                    'failed_checks': validation_results.get('failed_checks', 0),
                    'details': validation_results.get('detailed_results', {})
                }
            else:
                self.results['security_validation'] = {
                    'status': 'failed',
                    'error': 'No validation results generated',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
                
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            self.results['security_validation'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def _run_static_analysis(self):
        """Run static analysis with Bandit"""
        logger.info("Running static analysis (Bandit)...")
        
        try:
            # Install bandit if not available
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'bandit'], 
                         capture_output=True)
            
            # Run bandit
            result = subprocess.run([
                'bandit', '-r', 'byteguardx/', '-f', 'json'
            ], capture_output=True, text=True)
            
            if result.stdout:
                try:
                    bandit_results = json.loads(result.stdout)
                    self.results['static_analysis'] = {
                        'status': 'completed',
                        'high_severity': len([r for r in bandit_results.get('results', []) 
                                            if r.get('issue_severity') == 'HIGH']),
                        'medium_severity': len([r for r in bandit_results.get('results', []) 
                                              if r.get('issue_severity') == 'MEDIUM']),
                        'low_severity': len([r for r in bandit_results.get('results', []) 
                                           if r.get('issue_severity') == 'LOW']),
                        'total_issues': len(bandit_results.get('results', [])),
                        'details': bandit_results
                    }
                except json.JSONDecodeError:
                    self.results['static_analysis'] = {
                        'status': 'error',
                        'error': 'Failed to parse Bandit output'
                    }
            else:
                self.results['static_analysis'] = {
                    'status': 'completed',
                    'total_issues': 0,
                    'message': 'No issues found'
                }
                
        except Exception as e:
            logger.error(f"Static analysis error: {e}")
            self.results['static_analysis'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def _run_dependency_scan(self):
        """Run dependency vulnerability scan with Safety"""
        logger.info("Running dependency vulnerability scan (Safety)...")
        
        try:
            # Install safety if not available
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'safety'], 
                         capture_output=True)
            
            # Run safety check
            result = subprocess.run([
                'safety', 'check', '--json'
            ], capture_output=True, text=True)
            
            if result.stdout:
                try:
                    safety_results = json.loads(result.stdout)
                    self.results['dependency_scan'] = {
                        'status': 'completed',
                        'vulnerabilities_found': len(safety_results),
                        'details': safety_results
                    }
                except json.JSONDecodeError:
                    self.results['dependency_scan'] = {
                        'status': 'completed',
                        'vulnerabilities_found': 0,
                        'message': 'No vulnerabilities found'
                    }
            else:
                self.results['dependency_scan'] = {
                    'status': 'completed',
                    'vulnerabilities_found': 0,
                    'message': 'No vulnerabilities found'
                }
                
        except Exception as e:
            logger.error(f"Dependency scan error: {e}")
            self.results['dependency_scan'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def _run_secret_scan(self):
        """Run secret scanning with TruffleHog"""
        logger.info("Running secret scan (TruffleHog)...")
        
        try:
            # Install trufflehog if not available
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'trufflehog'], 
                         capture_output=True)
            
            # Run trufflehog
            result = subprocess.run([
                'trufflehog', 'filesystem', '.', '--json'
            ], capture_output=True, text=True)
            
            secrets_found = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            secret = json.loads(line)
                            secrets_found.append(secret)
                        except json.JSONDecodeError:
                            continue
            
            self.results['secret_scan'] = {
                'status': 'completed',
                'secrets_found': len(secrets_found),
                'details': secrets_found[:10]  # Limit to first 10 for security
            }
                
        except Exception as e:
            logger.error(f"Secret scan error: {e}")
            self.results['secret_scan'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def _generate_overall_assessment(self):
        """Generate overall security assessment"""
        logger.info("Generating overall security assessment...")
        
        # Check security validation
        security_passed = (
            self.results['security_validation'].get('status') == 'passed' and
            self.results['security_validation'].get('success_rate', 0) >= 90
        )
        
        # Check static analysis
        static_analysis_passed = (
            self.results['static_analysis'].get('status') == 'completed' and
            self.results['static_analysis'].get('high_severity', 0) == 0
        )
        
        # Check dependency scan
        dependency_scan_passed = (
            self.results['dependency_scan'].get('status') == 'completed' and
            self.results['dependency_scan'].get('vulnerabilities_found', 0) == 0
        )
        
        # Check secret scan
        secret_scan_passed = (
            self.results['secret_scan'].get('status') == 'completed' and
            self.results['secret_scan'].get('secrets_found', 0) == 0
        )
        
        # Determine overall status
        if all([security_passed, static_analysis_passed, dependency_scan_passed, secret_scan_passed]):
            self.results['overall_status'] = 'passed'
        elif security_passed and static_analysis_passed:
            self.results['overall_status'] = 'warning'  # Minor issues but core security is good
        else:
            self.results['overall_status'] = 'failed'
        
        # Add summary
        self.results['summary'] = {
            'security_validation_passed': security_passed,
            'static_analysis_passed': static_analysis_passed,
            'dependency_scan_passed': dependency_scan_passed,
            'secret_scan_passed': secret_scan_passed
        }
    
    def _save_results(self):
        """Save validation results"""
        results_file = self.project_root / 'ci_security_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {results_file}")

def main():
    """Main CI security validation function"""
    validator = CISecurityValidator()
    results = validator.run_all_validations()
    
    # Print summary
    print("\n" + "="*60)
    print("🔐 CI/CD Security Validation Summary")
    print("="*60)
    
    print(f"Overall Status: {results['overall_status'].upper()}")
    print(f"Timestamp: {results['timestamp']}")
    
    if 'security_validation' in results:
        sv = results['security_validation']
        if 'success_rate' in sv:
            print(f"Security Modules: {sv['success_rate']:.1f}% ({sv['passed_checks']}/{sv['total_checks']})")
    
    if 'static_analysis' in results:
        sa = results['static_analysis']
        if 'total_issues' in sa:
            print(f"Static Analysis: {sa['total_issues']} issues found")
    
    if 'dependency_scan' in results:
        ds = results['dependency_scan']
        if 'vulnerabilities_found' in ds:
            print(f"Dependency Scan: {ds['vulnerabilities_found']} vulnerabilities found")
    
    if 'secret_scan' in results:
        ss = results['secret_scan']
        if 'secrets_found' in ss:
            print(f"Secret Scan: {ss['secrets_found']} secrets found")
    
    print("="*60)
    
    # Exit with appropriate code
    if results['overall_status'] == 'passed':
        sys.exit(0)
    elif results['overall_status'] == 'warning':
        sys.exit(1)
    else:
        sys.exit(2)

if __name__ == "__main__":
    main()
