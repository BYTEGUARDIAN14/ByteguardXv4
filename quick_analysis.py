#!/usr/bin/env python3
"""
Quick ByteGuardX Analysis without problematic imports
"""

import os
import json
from pathlib import Path

def analyze_byteguardx():
    """Quick analysis of ByteGuardX issues"""
    print("🔍 ByteGuardX Quick Analysis")
    print("=" * 40)
    
    issues = []
    
    # Check .env configuration
    print("1. Checking environment configuration...")
    env_file = Path('.env')
    if env_file.exists():
        with open(env_file, 'r') as f:
            env_content = f.read()
        
        if 'MAIL_USERNAME=your-gmail@gmail.com' in env_content:
            issues.append("❌ Gmail not configured - still has placeholder")
        else:
            print("   ✅ Gmail configuration appears to be set")
        
        if 'SECRET_KEY=your-super-secret-key' in env_content:
            issues.append("❌ Secret key not configured - still has placeholder")
        else:
            print("   ✅ Secret key appears to be set")
    else:
        issues.append("❌ .env file missing")
    
    # Check database
    print("2. Checking database...")
    db_file = Path('byteguardx.db')
    if db_file.exists():
        print("   ✅ Database file exists")
    else:
        issues.append("❌ Database file missing")
    
    # Check frontend
    print("3. Checking frontend...")
    package_json = Path('package.json')
    if package_json.exists():
        print("   ✅ package.json exists")
    else:
        issues.append("❌ package.json missing")
    
    node_modules = Path('node_modules')
    if node_modules.exists():
        print("   ✅ node_modules exists")
    else:
        issues.append("❌ node_modules missing - run 'npm install'")
    
    # Check backend files
    print("4. Checking backend...")
    auth_server = Path('byteguardx_auth_api_server.py')
    if auth_server.exists():
        print("   ✅ Auth API server exists")
    else:
        issues.append("❌ Auth API server missing")
    
    # Summary
    print("\n📊 ANALYSIS SUMMARY:")
    print(f"   Issues found: {len(issues)}")
    
    if issues:
        print("\n🔧 ISSUES TO FIX:")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
    else:
        print("   ✅ No major issues found!")
    
    print("\n🎯 RECOMMENDED ACTIONS:")
    print("1. Run: python setup_complete_byteguardx.py")
    print("2. Configure your Gmail credentials when prompted")
    print("3. Install frontend dependencies: npm install")
    print("4. Start backend: python byteguardx_auth_api_server.py")
    print("5. Start frontend: npm run dev")
    
    return issues

if __name__ == "__main__":
    analyze_byteguardx()
