#!/usr/bin/env python3
"""
Simple test script to verify ByteGuardX API endpoints
"""

import requests
import json

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get('http://127.0.0.1:5000/health')
        print(f"Health endpoint: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Health test failed: {e}")
        return False

def test_login():
    """Test login endpoint with enhanced security"""
    try:
        # First get CSRF token
        csrf_response = requests.get('http://127.0.0.1:5000/api/auth/csrf-token')
        csrf_token = None
        if csrf_response.status_code == 200:
            csrf_token = csrf_response.json().get('csrf_token')
            print(f"CSRF token obtained: {csrf_token[:20]}...")

        data = {
            "email": "demo@byteguardx.com",
            "password": "demo123"
        }

        headers = {}
        if csrf_token:
            headers['X-CSRF-Token'] = csrf_token

        response = requests.post('http://127.0.0.1:5000/api/auth/login', json=data, headers=headers)
        print(f"Login endpoint: {response.status_code}")
        print(f"Response: {response.json()}")

        # Check for security headers
        security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
        print("Security headers present:")
        for header in security_headers:
            if header in response.headers:
                print(f"  ✅ {header}: {response.headers[header]}")
            else:
                print(f"  ❌ {header}: Missing")

        return response.status_code == 200
    except Exception as e:
        print(f"Login test failed: {e}")
        return False

def test_verify():
    """Test auth verify endpoint"""
    try:
        headers = {
            'Authorization': 'Bearer demo_token_123'
        }
        response = requests.get('http://127.0.0.1:5000/api/auth/verify', headers=headers)
        print(f"Verify endpoint: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Verify test failed: {e}")
        return False

if __name__ == '__main__':
    print("Testing ByteGuardX API endpoints...")
    print("=" * 50)
    
    print("\n1. Testing Health Endpoint:")
    health_ok = test_health()
    
    print("\n2. Testing Login Endpoint:")
    login_ok = test_login()
    
    print("\n3. Testing Auth Verify Endpoint:")
    verify_ok = test_verify()
    
    print("\n" + "=" * 50)
    print(f"Results: Health={health_ok}, Login={login_ok}, Verify={verify_ok}")
    
    if all([health_ok, login_ok, verify_ok]):
        print("✅ All tests passed! API is working correctly.")
    else:
        print("❌ Some tests failed. Check the output above.")
