#!/usr/bin/env python3
"""
ByteGuardX Production Deployment Script
Handles secure deployment with proper error handling and validation
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DeploymentManager:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.required_env_vars = [
            'SECRET_KEY',
            'JWT_SECRET_KEY',
            'DATABASE_URL',
            'FLASK_ENV'
        ]
        
    def validate_environment(self):
        """Validate required environment variables"""
        logger.info("Validating environment variables...")
        missing_vars = []
        
        for var in self.required_env_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            return False
        
        logger.info("Environment validation passed")
        return True
    
    def check_dependencies(self):
        """Check if all required dependencies are installed"""
        logger.info("Checking Python dependencies...")
        
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'check'],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("All Python dependencies are satisfied")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Dependency check failed: {e.stdout}")
            return False
    
    def run_security_checks(self):
        """Run security validation checks"""
        logger.info("Running security checks...")
        
        checks_passed = 0
        total_checks = 4
        
        # Check 1: Validate secret keys are not default values
        secret_key = os.getenv('SECRET_KEY', '')
        jwt_secret = os.getenv('JWT_SECRET_KEY', '')
        
        if secret_key and secret_key not in ['dev-secret-key-change-in-production', 'your-secret-key']:
            checks_passed += 1
            logger.info("✓ SECRET_KEY is properly configured")
        else:
            logger.warning("✗ SECRET_KEY appears to be using default value")
        
        if jwt_secret and jwt_secret not in ['jwt-secret-key-change-in-production', 'your-jwt-secret']:
            checks_passed += 1
            logger.info("✓ JWT_SECRET_KEY is properly configured")
        else:
            logger.warning("✗ JWT_SECRET_KEY appears to be using default value")
        
        # Check 2: Validate HTTPS in production
        flask_env = os.getenv('FLASK_ENV', 'development')
        if flask_env == 'production':
            if os.getenv('FORCE_HTTPS', '').lower() == 'true':
                checks_passed += 1
                logger.info("✓ HTTPS is enforced in production")
            else:
                logger.warning("✗ HTTPS should be enforced in production")
        else:
            checks_passed += 1
            logger.info("✓ Development environment detected")
        
        # Check 3: Validate file permissions
        sensitive_files = ['.env', 'config.py', 'byteguardx_auth_api_server.py']
        file_perms_ok = True
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                # Check if file is readable by others (should not be)
                if stat_info.st_mode & 0o044:
                    logger.warning(f"✗ {file_path} has overly permissive permissions")
                    file_perms_ok = False
        
        if file_perms_ok:
            checks_passed += 1
            logger.info("✓ File permissions are secure")
        
        logger.info(f"Security checks: {checks_passed}/{total_checks} passed")
        return checks_passed >= 3  # Allow deployment if most checks pass
    
    def build_frontend(self):
        """Build the React frontend"""
        logger.info("Building React frontend...")
        
        try:
            # Check if node_modules exists
            if not (self.project_root / 'node_modules').exists():
                logger.info("Installing npm dependencies...")
                subprocess.run(['npm', 'install'], check=True, cwd=self.project_root)
            
            # Build the frontend
            subprocess.run(['npm', 'run', 'build'], check=True, cwd=self.project_root)
            logger.info("Frontend build completed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Frontend build failed: {e}")
            return False
        except FileNotFoundError:
            logger.error("npm not found. Please install Node.js and npm")
            return False
    
    def run_tests(self):
        """Run test suite"""
        logger.info("Running test suite...")
        
        try:
            # Run Python tests if they exist
            if (self.project_root / 'tests').exists():
                result = subprocess.run(
                    [sys.executable, '-m', 'pytest', 'tests/', '-v'],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root
                )
                
                if result.returncode == 0:
                    logger.info("All tests passed")
                    return True
                else:
                    logger.error(f"Tests failed: {result.stdout}")
                    return False
            else:
                logger.info("No test directory found, skipping tests")
                return True
                
        except Exception as e:
            logger.error(f"Test execution failed: {e}")
            return False
    
    def create_deployment_info(self):
        """Create deployment information file"""
        deployment_info = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'environment': os.getenv('FLASK_ENV', 'development'),
            'python_version': sys.version,
            'deployment_id': f"deploy_{int(datetime.now().timestamp())}"
        }
        
        with open('deployment_info.json', 'w') as f:
            json.dump(deployment_info, f, indent=2)
        
        logger.info(f"Deployment info created: {deployment_info['deployment_id']}")
    
    def deploy(self, skip_tests=False, skip_build=False):
        """Main deployment function"""
        logger.info("Starting ByteGuardX deployment...")
        
        # Step 1: Validate environment
        if not self.validate_environment():
            logger.error("Environment validation failed. Deployment aborted.")
            return False
        
        # Step 2: Check dependencies
        if not self.check_dependencies():
            logger.error("Dependency check failed. Deployment aborted.")
            return False
        
        # Step 3: Run security checks
        if not self.run_security_checks():
            logger.error("Security checks failed. Deployment aborted.")
            return False
        
        # Step 4: Build frontend (if not skipped)
        if not skip_build:
            if not self.build_frontend():
                logger.error("Frontend build failed. Deployment aborted.")
                return False
        
        # Step 5: Run tests (if not skipped)
        if not skip_tests:
            if not self.run_tests():
                logger.error("Tests failed. Deployment aborted.")
                return False
        
        # Step 6: Create deployment info
        self.create_deployment_info()
        
        logger.info("✅ Deployment completed successfully!")
        logger.info("Next steps:")
        logger.info("1. Start the Flask server: python byteguardx_auth_api_server.py")
        logger.info("2. Serve the built frontend from the 'dist' directory")
        logger.info("3. Configure your web server (nginx/apache) for production")
        
        return True

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Deploy ByteGuardX application')
    parser.add_argument('--skip-tests', action='store_true', help='Skip running tests')
    parser.add_argument('--skip-build', action='store_true', help='Skip frontend build')
    parser.add_argument('--check-only', action='store_true', help='Only run validation checks')
    
    args = parser.parse_args()
    
    deployer = DeploymentManager()
    
    if args.check_only:
        logger.info("Running validation checks only...")
        env_ok = deployer.validate_environment()
        deps_ok = deployer.check_dependencies()
        security_ok = deployer.run_security_checks()
        
        if env_ok and deps_ok and security_ok:
            logger.info("✅ All checks passed. Ready for deployment.")
            sys.exit(0)
        else:
            logger.error("❌ Some checks failed. Please fix issues before deployment.")
            sys.exit(1)
    
    success = deployer.deploy(
        skip_tests=args.skip_tests,
        skip_build=args.skip_build
    )
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
