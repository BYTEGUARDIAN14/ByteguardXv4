#!/usr/bin/env python3
"""
ByteGuardX Unified Stack Launcher
Validates environment, starts all components, and provides unified management
"""

import os
import sys
import subprocess
import time
import signal
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import threading
import queue

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

class StackLauncher:
    """Unified launcher for ByteGuardX stack"""
    
    def __init__(self):
        self.processes = {}
        self.process_queue = queue.Queue()
        self.running = False
        self.logger = self._setup_logging()
        
        # Component configurations
        self.components = {
            'backend': {
                'name': 'ByteGuardX Backend',
                'command': [sys.executable, 'run_server.py'],
                'cwd': str(project_root),
                'port': 5000,
                'health_endpoint': 'http://localhost:5000/health',
                'required': True
            },
            'frontend': {
                'name': 'ByteGuardX Frontend',
                'command': ['npm', 'run', 'dev'],
                'cwd': str(project_root),
                'port': 3001,
                'health_endpoint': 'http://localhost:3001',
                'required': True
            },
            'portal': {
                'name': 'ByteGuardX Portal',
                'command': ['npm', 'run', 'dev'],
                'cwd': str(project_root / 'byteguardx-portal'),
                'port': 3003,
                'health_endpoint': 'http://localhost:3003',
                'required': False
            }
        }
    
    def _setup_logging(self):
        """Setup logging for launcher"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('StackLauncher')
    
    def validate_environment(self) -> Tuple[bool, List[str]]:
        """Validate environment variables and dependencies"""
        issues = []
        
        self.logger.info("🔍 Validating environment...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            issues.append("Python 3.8+ required")
        
        # Check required environment variables
        required_vars = {
            'SECRET_KEY': 'Application secret key',
            'JWT_SECRET': 'JWT secret key',
        }
        
        for var, description in required_vars.items():
            value = os.environ.get(var)
            if not value:
                # Set development defaults
                if var == 'SECRET_KEY':
                    os.environ[var] = 'dev-secret-key-change-in-production'
                elif var == 'JWT_SECRET':
                    os.environ[var] = 'dev-jwt-secret-change-in-production'
                
                self.logger.warning(f"⚠️  {var} not set, using development default")
        
        # Check for weak secrets in production
        if os.environ.get('ENV', '').lower() == 'production':
            for var in ['SECRET_KEY', 'JWT_SECRET']:
                value = os.environ.get(var, '')
                if 'dev-' in value.lower() or len(value) < 32:
                    issues.append(f"{var} is weak or default in production")
        
        # Check Node.js and npm
        try:
            subprocess.run(['node', '--version'], check=True, capture_output=True)
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            issues.append("Node.js and npm are required")
        
        # Check if package.json exists
        if not (project_root / 'package.json').exists():
            issues.append("package.json not found in project root")
        
        # Check if portal package.json exists
        portal_package = project_root / 'byteguardx-portal' / 'package.json'
        if not portal_package.exists():
            self.logger.warning("⚠️  Portal package.json not found, portal will be skipped")
            self.components['portal']['required'] = False
        
        # Check Python dependencies
        try:
            import flask
            import jwt
            import bcrypt
        except ImportError as e:
            issues.append(f"Missing Python dependency: {e}")
        
        return len(issues) == 0, issues
    
    def install_dependencies(self):
        """Install missing dependencies"""
        self.logger.info("📦 Installing dependencies...")
        
        # Install Python dependencies
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], check=True, cwd=project_root)
            self.logger.info("✅ Python dependencies installed")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"❌ Failed to install Python dependencies: {e}")
            return False
        
        # Install frontend dependencies
        if (project_root / 'package.json').exists():
            try:
                subprocess.run(['npm', 'install'], check=True, cwd=project_root)
                self.logger.info("✅ Frontend dependencies installed")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"❌ Failed to install frontend dependencies: {e}")
                return False
        
        # Install portal dependencies
        portal_dir = project_root / 'byteguardx-portal'
        if (portal_dir / 'package.json').exists():
            try:
                subprocess.run(['npm', 'install'], check=True, cwd=portal_dir)
                self.logger.info("✅ Portal dependencies installed")
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"⚠️  Failed to install portal dependencies: {e}")
        
        return True
    
    def start_component(self, component_name: str) -> bool:
        """Start a single component"""
        config = self.components[component_name]
        
        self.logger.info(f"🚀 Starting {config['name']}...")
        
        try:
            process = subprocess.Popen(
                config['command'],
                cwd=config['cwd'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.processes[component_name] = {
                'process': process,
                'config': config,
                'started_at': time.time()
            }
            
            # Start output monitoring thread
            threading.Thread(
                target=self._monitor_process_output,
                args=(component_name, process),
                daemon=True
            ).start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start {config['name']}: {e}")
            return False
    
    def _monitor_process_output(self, component_name: str, process: subprocess.Popen):
        """Monitor process output"""
        config = self.components[component_name]['config']
        
        while process.poll() is None:
            try:
                line = process.stdout.readline()
                if line:
                    self.logger.info(f"[{config['name']}] {line.strip()}")
            except:
                break
    
    def wait_for_health_checks(self, timeout: int = 60) -> bool:
        """Wait for all components to be healthy"""
        self.logger.info("🏥 Waiting for health checks...")
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            all_healthy = True
            
            for component_name, component_info in self.processes.items():
                config = component_info['config']
                
                if not self._check_component_health(component_name):
                    all_healthy = False
                    break
            
            if all_healthy:
                self.logger.info("✅ All components are healthy")
                return True
            
            time.sleep(2)
        
        self.logger.error("❌ Health check timeout")
        return False
    
    def _check_component_health(self, component_name: str) -> bool:
        """Check if component is healthy"""
        try:
            import requests
            config = self.components[component_name]['config']
            
            response = requests.get(
                config['health_endpoint'],
                timeout=5
            )
            return response.status_code == 200
            
        except:
            return False
    
    def display_status(self):
        """Display status of all components"""
        print("\n" + "=" * 60)
        print("🎯 ByteGuardX Stack Status")
        print("=" * 60)
        
        for component_name, component_info in self.processes.items():
            config = component_info['config']
            process = component_info['process']
            
            if process.poll() is None:
                status = "🟢 RUNNING"
                uptime = int(time.time() - component_info['started_at'])
                uptime_str = f"(uptime: {uptime}s)"
            else:
                status = "🔴 STOPPED"
                uptime_str = ""
            
            print(f"  {config['name']:<25} {status} {uptime_str}")
            print(f"    URL: http://localhost:{config['port']}")
        
        print("\n📡 Available Endpoints:")
        print("  Backend API:     http://localhost:5000")
        print("  Frontend App:    http://localhost:3001")
        print("  Portal:          http://localhost:3003")
        print("  Health Check:    http://localhost:5000/health")
        
        print("\n🛠️  Development Commands:")
        print("  Test API:        python test_auth.py")
        print("  View Logs:       tail -f logs/*.log")
        print("  Stop Stack:      Ctrl+C")
        print("=" * 60)
    
    def start_stack(self):
        """Start the entire stack"""
        self.logger.info("🚀 Starting ByteGuardX Stack...")
        
        # Validate environment
        is_valid, issues = self.validate_environment()
        if not is_valid:
            self.logger.error("❌ Environment validation failed:")
            for issue in issues:
                self.logger.error(f"  - {issue}")
            
            # Try to install dependencies
            if not self.install_dependencies():
                return False
        
        # Start components
        for component_name, config in self.components.items():
            if config['required'] or (project_root / config['cwd']).exists():
                if not self.start_component(component_name):
                    if config['required']:
                        self.logger.error(f"❌ Failed to start required component: {config['name']}")
                        return False
        
        # Wait for health checks
        if not self.wait_for_health_checks():
            self.logger.warning("⚠️  Some components may not be fully ready")
        
        # Display status
        self.display_status()
        
        self.running = True
        return True
    
    def stop_stack(self):
        """Stop the entire stack"""
        self.logger.info("🛑 Stopping ByteGuardX Stack...")
        
        for component_name, component_info in self.processes.items():
            process = component_info['process']
            config = component_info['config']
            
            if process.poll() is None:
                self.logger.info(f"Stopping {config['name']}...")
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Force killing {config['name']}...")
                    process.kill()
        
        self.running = False
        self.logger.info("✅ Stack stopped")
    
    def run(self):
        """Run the stack with signal handling"""
        def signal_handler(signum, frame):
            self.stop_stack()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        if self.start_stack():
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop_stack()

def main():
    """Main entry point"""
    launcher = StackLauncher()
    launcher.run()

if __name__ == "__main__":
    main()
