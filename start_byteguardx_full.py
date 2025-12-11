#!/usr/bin/env python3
"""
ByteGuardX Full Stack Startup Script
Launches both backend API and frontend development server
"""

import subprocess
import sys
import os
import time
import threading
import signal
from pathlib import Path

def print_banner():
    """Print ByteGuardX startup banner"""
    print("🛡️  " + "=" * 60)
    print("🛡️  ByteGuardX Enterprise Security Platform")
    print("🛡️  Full Stack Startup - Backend + Frontend")
    print("🛡️  " + "=" * 60)
    print()

def check_dependencies():
    """Check if required dependencies are available"""
    print("🔍 Checking dependencies...")
    
    # Check Python dependencies
    try:
        import flask
        import requests
        print("✅ Python dependencies: OK")
    except ImportError as e:
        print(f"❌ Missing Python dependency: {e}")
        return False
    
    # Check if Node.js is available
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Node.js: {result.stdout.strip()}")
        else:
            print("❌ Node.js not found")
            return False
    except FileNotFoundError:
        print("❌ Node.js not found")
        return False
    
    # Check if npm is available
    try:
        result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npm: {result.stdout.strip()}")
        else:
            print("❌ npm not found")
            return False
    except FileNotFoundError:
        print("❌ npm not found")
        return False
    
    return True

def start_backend():
    """Start the Flask backend server"""
    print("🚀 Starting ByteGuardX Backend API...")
    
    try:
        # Set environment variables
        env = os.environ.copy()
        env['FLASK_APP'] = 'byteguardx.api.app'
        env['FLASK_ENV'] = 'development'
        env['PYTHONPATH'] = os.getcwd()
        
        # Start Flask server
        process = subprocess.Popen([
            sys.executable, '-m', 'byteguardx.api.app'
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Wait for server to start
        print("⏳ Waiting for backend to start...")
        time.sleep(5)
        
        # Check if server is running
        try:
            import requests
            response = requests.get('http://localhost:5000/api/health', timeout=5)
            if response.status_code == 200:
                print("✅ Backend API started successfully on http://localhost:5000")
                return process
            else:
                print("❌ Backend API health check failed")
                return None
        except Exception as e:
            print(f"❌ Backend API connection failed: {e}")
            return None
            
    except Exception as e:
        print(f"❌ Failed to start backend: {e}")
        return None

def start_frontend():
    """Start the React frontend development server"""
    print("🚀 Starting ByteGuardX Frontend...")
    
    try:
        # Check if node_modules exists
        if not os.path.exists('node_modules'):
            print("📦 Installing frontend dependencies...")
            result = subprocess.run(['npm', 'install'], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ npm install failed: {result.stderr}")
                return None
        
        # Start development server
        process = subprocess.Popen([
            'npm', 'run', 'dev'
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Wait for server to start
        print("⏳ Waiting for frontend to start...")
        time.sleep(10)
        
        print("✅ Frontend started successfully on http://localhost:3000")
        return process
        
    except Exception as e:
        print(f"❌ Failed to start frontend: {e}")
        return None

def monitor_processes(backend_process, frontend_process):
    """Monitor both processes and restart if needed"""
    print("👀 Monitoring processes...")
    
    while True:
        try:
            # Check backend
            if backend_process and backend_process.poll() is not None:
                print("⚠️  Backend process stopped, restarting...")
                backend_process = start_backend()
            
            # Check frontend
            if frontend_process and frontend_process.poll() is not None:
                print("⚠️  Frontend process stopped, restarting...")
                frontend_process = start_frontend()
            
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n🛑 Shutting down ByteGuardX...")
            break
    
    # Cleanup
    if backend_process:
        backend_process.terminate()
    if frontend_process:
        frontend_process.terminate()

def display_startup_info():
    """Display startup information and URLs"""
    print("\n🎉 ByteGuardX is now running!")
    print("=" * 50)
    print("🌐 Frontend (React):     http://localhost:3000")
    print("🔧 Backend API (Flask):  http://localhost:5000")
    print("📊 API Documentation:    http://localhost:5000/api/docs")
    print("🔌 Plugin Marketplace:   http://localhost:3000/plugins")
    print("🛡️  Security Dashboard:  http://localhost:3000/dashboard")
    print("🔍 Advanced Scanner:     http://localhost:3000/scan")
    print("=" * 50)
    print("\n📋 AVAILABLE FEATURES:")
    print("✅ 22+ Production-Grade Security Plugins")
    print("✅ Real-time Plugin Execution Monitoring")
    print("✅ Advanced Security Analytics Dashboard")
    print("✅ Plugin Marketplace & Configuration")
    print("✅ Enhanced Scan Interface with Plugin Selection")
    print("✅ Plugin Testing & Development Tools")
    print("✅ Security Metrics & Vulnerability Tracking")
    print("✅ Enterprise-grade UI with Glassmorphism Design")
    print("\n💡 Press Ctrl+C to stop all services")
    print("-" * 50)

def main():
    """Main startup function"""
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Dependency check failed. Please install missing dependencies.")
        sys.exit(1)
    
    print("✅ All dependencies available\n")
    
    # Start backend
    backend_process = start_backend()
    if not backend_process:
        print("❌ Failed to start backend. Exiting.")
        sys.exit(1)
    
    # Start frontend
    frontend_process = start_frontend()
    if not frontend_process:
        print("❌ Failed to start frontend. Stopping backend.")
        backend_process.terminate()
        sys.exit(1)
    
    # Display startup info
    display_startup_info()
    
    # Set up signal handlers
    def signal_handler(sig, frame):
        print("\n🛑 Received shutdown signal...")
        if backend_process:
            backend_process.terminate()
        if frontend_process:
            frontend_process.terminate()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Monitor processes
    try:
        monitor_processes(backend_process, frontend_process)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down ByteGuardX...")
        if backend_process:
            backend_process.terminate()
        if frontend_process:
            frontend_process.terminate()

if __name__ == "__main__":
    main()
