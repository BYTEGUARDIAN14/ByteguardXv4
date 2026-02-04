#!/usr/bin/env python3
"""
ByteGuardX Local Development Runner
Comprehensive script to set up and run ByteGuardX locally with all dependencies
"""

import os
import sys
import subprocess
import time
import signal
import threading
import requests
from pathlib import Path
import json

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class ByteGuardXRunner:
    def __init__(self):
        self.backend_process = None
        self.frontend_process = None
        self.running = True
        
    def print_header(self):
        """Print application header"""
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}   ByteGuardX Enterprise Security Platform{Colors.ENDC}")
        print(f"{Colors.HEADER}   Enhanced Scanning System - Local Development{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
    
    def check_python_version(self):
        """Check Python version compatibility"""
        print(f"{Colors.OKBLUE}[1/7] Checking Python version...{Colors.ENDC}")
        
        if sys.version_info < (3, 8):
            print(f"{Colors.FAIL}❌ Python 3.8+ required. Current: {sys.version}{Colors.ENDC}")
            return False
        
        print(f"{Colors.OKGREEN}✅ Python {sys.version.split()[0]} - Compatible{Colors.ENDC}")
        return True
    
    def check_node_version(self):
        """Check Node.js version"""
        print(f"{Colors.OKBLUE}[2/7] Checking Node.js version...{Colors.ENDC}")
        
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"{Colors.OKGREEN}✅ Node.js {version} - Available{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.FAIL}❌ Node.js not found{Colors.ENDC}")
                return False
        except FileNotFoundError:
            print(f"{Colors.FAIL}❌ Node.js not installed{Colors.ENDC}")
            return False
    
    def install_python_dependencies(self):
        """Install Python dependencies"""
        print(f"{Colors.OKBLUE}[3/7] Installing Python dependencies...{Colors.ENDC}")
        
        try:
            # Install core requirements
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], check=True, capture_output=True)
            
            # Install additional ML dependencies for enhanced scanning
            ml_packages = [
                'numpy==1.24.3',
                'scikit-learn==1.3.0',
                'pandas==2.0.3'
            ]
            
            for package in ml_packages:
                try:
                    subprocess.run([
                        sys.executable, '-m', 'pip', 'install', package
                    ], check=True, capture_output=True)
                except subprocess.CalledProcessError:
                    print(f"{Colors.WARNING}⚠️  Optional package {package} failed to install{Colors.ENDC}")
            
            print(f"{Colors.OKGREEN}✅ Python dependencies installed{Colors.ENDC}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}❌ Failed to install Python dependencies: {e}{Colors.ENDC}")
            return False
    
    def install_node_dependencies(self):
        """Install Node.js dependencies"""
        print(f"{Colors.OKBLUE}[4/7] Installing Node.js dependencies...{Colors.ENDC}")
        
        npm_cmd = 'npm.cmd' if os.name == 'nt' else 'npm'
        
        try:
            print(f"   Executing: {npm_cmd} install")
            subprocess.run([npm_cmd, 'install'], check=True, capture_output=True)
            print(f"{Colors.OKGREEN}✅ Node.js dependencies installed{Colors.ENDC}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.FAIL}❌ Failed to install Node.js dependencies: {e}{Colors.ENDC}")
            if e.stderr:
                print(f"{Colors.FAIL}Error details: {e.stderr.decode()}{Colors.ENDC}")
            return False
        except FileNotFoundError:
             print(f"{Colors.FAIL}❌ Command not found: {npm_cmd}. Ensure npm is in your PATH.{Colors.ENDC}")
             return False
    
    def setup_environment(self):
        """Set up environment variables"""
        print(f"{Colors.OKBLUE}[5/7] Setting up environment...{Colors.ENDC}")
        
        # Set environment variables
        os.environ['FLASK_ENV'] = 'development'
        os.environ['NODE_ENV'] = 'development'
        os.environ['BYTEGUARDX_ENV'] = 'development'
        os.environ['PYTHONPATH'] = str(Path.cwd())
        
        # Create necessary directories
        directories = ['data', 'logs', 'reports', 'temp']
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
        
        print(f"{Colors.OKGREEN}✅ Environment configured{Colors.ENDC}")
        return True
    
    def start_backend(self):
        """Start the backend server"""
        print(f"{Colors.OKBLUE}[6/7] Starting Backend API Server...{Colors.ENDC}")
        
        try:
            # Start backend process
            self.backend_process = subprocess.Popen([
                sys.executable, '-m', 'byteguardx.api.app'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for backend to be ready
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    response = requests.get('http://localhost:5000/health', timeout=2)
                    if response.status_code == 200:
                        print(f"{Colors.OKGREEN}✅ Backend server ready at http://localhost:5000{Colors.ENDC}")
                        return True
                except requests.exceptions.RequestException:
                    pass
                
                if attempt < max_attempts - 1:
                    print(f"{Colors.OKCYAN}   Waiting for backend... ({attempt + 1}/{max_attempts}){Colors.ENDC}")
                    time.sleep(2)
            
            print(f"{Colors.FAIL}❌ Backend failed to start within timeout{Colors.ENDC}")
            # Print stderr to see why it failed
            if self.backend_process.poll() is not None:
                 stdout, stderr = self.backend_process.communicate()
                 print(f"Backend Output:\n{stdout}")
                 print(f"Backend Error:\n{stderr}")
            return False
            
        except Exception as e:
            print(f"{Colors.FAIL}❌ Failed to start backend: {e}{Colors.ENDC}")
            return False
    
    def start_frontend(self):
        """Start the frontend server"""
        print(f"{Colors.OKBLUE}[7/7] Starting Frontend Development Server...{Colors.ENDC}")
        
        npm_cmd = 'npm.cmd' if os.name == 'nt' else 'npm'
        
        try:
            # Start frontend process
            self.frontend_process = subprocess.Popen([
                npm_cmd, 'run', 'dev'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for frontend to be ready
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    response = requests.get('http://localhost:3000', timeout=2)
                    if response.status_code in [200, 404]:  # 404 is OK for Vite dev server
                        print(f"{Colors.OKGREEN}✅ Frontend server ready at http://localhost:3000{Colors.ENDC}")
                        return True
                except requests.exceptions.RequestException:
                    pass
                
                if attempt < max_attempts - 1:
                    print(f"{Colors.OKCYAN}   Waiting for frontend... ({attempt + 1}/{max_attempts}){Colors.ENDC}")
                    time.sleep(2)
            
            print(f"{Colors.WARNING}⚠️  Frontend may not be fully ready, but continuing...{Colors.ENDC}")
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}❌ Failed to start frontend: {e}{Colors.ENDC}")
            return False
    
    def display_success_info(self):
        """Display success information"""
        print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}   ByteGuardX is now running locally!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}🌐 Frontend Application: {Colors.BOLD}http://localhost:3000{Colors.ENDC}")
        print(f"{Colors.OKCYAN}🔧 Backend API:          {Colors.BOLD}http://localhost:5000{Colors.ENDC}")
        print(f"{Colors.OKCYAN}📊 Health Check:         {Colors.BOLD}http://localhost:5000/health{Colors.ENDC}")
        print(f"{Colors.OKCYAN}📚 API Documentation:    {Colors.BOLD}http://localhost:5000/api/docs{Colors.ENDC}")
        
        print(f"\n{Colors.HEADER}🧪 Enhanced Scanning Features:{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Unified Scanner:     {Colors.BOLD}/api/v2/scan/unified{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Result Verification: {Colors.BOLD}Enhanced accuracy & explainability{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Plugin Trust Scoring:{Colors.BOLD}Reliability assessment{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Cross-Validation:    {Colors.BOLD}Multi-scanner verification{Colors.ENDC}")
        
        print(f"\n{Colors.HEADER}🔧 Test Endpoints:{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Connection Test:     {Colors.BOLD}http://localhost:3000/test-connection.html{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Authentication Test: {Colors.BOLD}http://localhost:3000/test-signup.html{Colors.ENDC}")
        print(f"{Colors.OKCYAN}   • Complete Workflow:   {Colors.BOLD}http://localhost:3000/test-dashboard-complete.html{Colors.ENDC}")
        
        print(f"\n{Colors.WARNING}Press Ctrl+C to stop all servers...{Colors.ENDC}\n")
    
    def monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            try:
                # Check backend process
                if self.backend_process and self.backend_process.poll() is not None:
                    print(f"{Colors.FAIL}❌ Backend process died unexpectedly{Colors.ENDC}")
                    stdout, stderr = self.backend_process.communicate()
                    print(f"Back Output: {stdout}")
                    print(f"Back Error: {stderr}")
                    self.cleanup()
                    break
                
                # Check frontend process
                if self.frontend_process and self.frontend_process.poll() is not None:
                    print(f"{Colors.FAIL}❌ Frontend process died unexpectedly{Colors.ENDC}")
                    stdout, stderr = self.frontend_process.communicate()
                    print(f"Front Output: {stdout}")
                    try:
                         # Sometimes communicate() returns bytes causing issues if not handled
                         if isinstance(stderr, bytes):
                             print(f"Front Error: {stderr.decode()}")
                         else:
                             print(f"Front Error: {stderr}")
                    except:
                         print(f"Front Error: {stderr}")
                    self.cleanup()
                    break
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                break
    
    def cleanup(self):
        """Clean up processes"""
        print(f"\n{Colors.WARNING}Stopping ByteGuardX servers...{Colors.ENDC}")
        self.running = False
        
        if self.backend_process:
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=5)
                print(f"{Colors.OKGREEN}✅ Backend server stopped{Colors.ENDC}")
            except subprocess.TimeoutExpired:
                self.backend_process.kill()
                print(f"{Colors.WARNING}⚠️  Backend server force killed{Colors.ENDC}")
        
        if self.frontend_process:
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=5)
                print(f"{Colors.OKGREEN}✅ Frontend server stopped{Colors.ENDC}")
            except subprocess.TimeoutExpired:
                self.frontend_process.kill()
                print(f"{Colors.WARNING}⚠️  Frontend server force killed{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}ByteGuardX stopped successfully!{Colors.ENDC}")
    
    def run(self):
        """Main run method"""
        try:
            self.print_header()
            
            # Setup steps
            if not self.check_python_version():
                return False
            
            if not self.check_node_version():
                return False
            
            if not self.install_python_dependencies():
                return False
            
            if not self.install_node_dependencies():
                return False
            
            if not self.setup_environment():
                return False
            
            if not self.start_backend():
                return False
            
            if not self.start_frontend():
                return False
            
            self.display_success_info()
            
            # Start monitoring in a separate thread
            monitor_thread = threading.Thread(target=self.monitor_processes)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Keep main thread alive
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            
            return True
            
        except Exception as e:
            print(f"{Colors.FAIL}❌ Unexpected error: {e}{Colors.ENDC}")
            return False
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    runner = ByteGuardXRunner()
    
    # Handle signals
    def signal_handler(signum, frame):
        runner.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    success = runner.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
