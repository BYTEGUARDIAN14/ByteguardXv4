#!/usr/bin/env python3
"""
ByteGuardX Quick Start Script
Run both backend API and frontend development server
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path

def run_backend():
    """Run the Flask backend API"""
    print("🚀 Starting ByteGuardX Backend API...")
    try:
        os.chdir(Path(__file__).parent)
        subprocess.run([
            sys.executable, "-m", "byteguardx.api.app"
        ], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Backend stopped")
    except Exception as e:
        print(f"❌ Backend error: {e}")

def run_frontend():
    """Run the React frontend development server"""
    print("🎨 Starting ByteGuardX Frontend...")
    try:
        # Wait a moment for backend to start
        time.sleep(3)
        subprocess.run(["npm", "run", "dev"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Frontend stopped")
    except Exception as e:
        print(f"❌ Frontend error: {e}")

def main():
    """Main function to run both services"""
    print("🔐 ByteGuardX - AI-Powered Vulnerability Scanner")
    print("=" * 50)
    
    # Check if npm is available
    try:
        subprocess.run(["npm", "--version"], 
                      capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ npm not found. Please install Node.js and npm first.")
        sys.exit(1)
    
    # Install frontend dependencies if needed
    if not Path("node_modules").exists():
        print("📦 Installing frontend dependencies...")
        subprocess.run(["npm", "install"], check=True)
    
    # Start both services
    backend_thread = threading.Thread(target=run_backend, daemon=True)
    frontend_thread = threading.Thread(target=run_frontend, daemon=True)
    
    try:
        backend_thread.start()
        frontend_thread.start()
        
        print("\n✅ ByteGuardX is running!")
        print("🌐 Frontend: http://localhost:3000")
        print("🔧 Backend API: http://localhost:5000")
        print("📚 API Docs: http://localhost:5000/health")
        print("\nPress Ctrl+C to stop all services")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Shutting down ByteGuardX...")
        sys.exit(0)

if __name__ == "__main__":
    main()
