#!/usr/bin/env python3
"""
Test CORS fix for ByteGuardX authentication endpoints
"""

import requests
import json

def test_cors_auth_verify():
    """Test the /api/auth/verify endpoint with CORS"""
    print("🧪 Testing CORS fix for /api/auth/verify endpoint")
    print("=" * 50)
    
    url = "http://localhost:5000/api/auth/verify"
    headers = {
        'Origin': 'http://localhost:3000',
        'Content-Type': 'application/json'
    }
    
    try:
        # Test without credentials first
        print("1. Testing without credentials...")
        response = requests.get(url, headers=headers)
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.json()}")
        print(f"   CORS Headers:")
        for header, value in response.headers.items():
            if 'access-control' in header.lower() or 'cors' in header.lower():
                print(f"     {header}: {value}")
        
        # Check if Access-Control-Allow-Credentials is present and set to 'true'
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        print(f"   Access-Control-Allow-Credentials: {cors_credentials}")
        
        if cors_credentials == 'true':
            print("   ✅ CORS credentials header is correctly set!")
        else:
            print("   ❌ CORS credentials header is missing or incorrect!")
        
        print("\n2. Testing with credentials (cookies)...")
        # Test with credentials
        session = requests.Session()
        response = session.get(url, headers=headers)
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        print(f"   Access-Control-Allow-Credentials: {cors_credentials}")
        
        print("\n3. Testing login endpoint...")
        login_url = "http://localhost:5000/api/auth/login"
        login_data = {
            'email': 'demo@byteguardx.com',
            'password': 'demo123'
        }
        
        login_response = session.post(login_url, json=login_data, headers=headers)
        print(f"   Login Status Code: {login_response.status_code}")
        print(f"   Login Response: {login_response.json()}")
        
        cors_credentials = login_response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        print(f"   Login CORS credentials: {cors_credentials}")
        
        print("\n4. Testing auth verify after login...")
        verify_response = session.get(url, headers=headers)
        print(f"   Verify Status Code: {verify_response.status_code}")
        print(f"   Verify Response: {verify_response.json()}")
        
        cors_credentials = verify_response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        print(f"   Verify CORS credentials: {cors_credentials}")
        
        print("\n🎯 CORS Test Summary:")
        if cors_credentials == 'true':
            print("   ✅ CORS credentials are properly configured!")
            print("   ✅ Frontend should be able to make authenticated requests!")
        else:
            print("   ❌ CORS credentials are not properly configured!")
            print("   ❌ Frontend will encounter CORS errors!")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the API server.")
        print("   Make sure the ByteGuardX API server is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")

def test_preflight_request():
    """Test CORS preflight (OPTIONS) request"""
    print("\n🧪 Testing CORS preflight request")
    print("=" * 50)
    
    url = "http://localhost:5000/api/auth/verify"
    headers = {
        'Origin': 'http://localhost:3000',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Content-Type,Authorization'
    }
    
    try:
        response = requests.options(url, headers=headers)
        print(f"   Preflight Status Code: {response.status_code}")
        print(f"   Preflight CORS Headers:")
        for header, value in response.headers.items():
            if 'access-control' in header.lower():
                print(f"     {header}: {value}")
                
        # Check key CORS headers
        allow_origin = response.headers.get('Access-Control-Allow-Origin', 'NOT_SET')
        allow_credentials = response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        allow_methods = response.headers.get('Access-Control-Allow-Methods', 'NOT_SET')
        allow_headers = response.headers.get('Access-Control-Allow-Headers', 'NOT_SET')
        
        print(f"\n   Key CORS Headers:")
        print(f"     Allow-Origin: {allow_origin}")
        print(f"     Allow-Credentials: {allow_credentials}")
        print(f"     Allow-Methods: {allow_methods}")
        print(f"     Allow-Headers: {allow_headers}")
        
        if allow_credentials == 'true' and allow_origin == 'http://localhost:3000':
            print("   ✅ Preflight CORS configuration looks good!")
        else:
            print("   ❌ Preflight CORS configuration has issues!")
            
    except Exception as e:
        print(f"❌ Preflight test failed with error: {e}")

if __name__ == "__main__":
    test_cors_auth_verify()
    test_preflight_request()
    
    print("\n🔧 If CORS is still not working:")
    print("   1. Check that the frontend is running on http://localhost:3000")
    print("   2. Ensure the API server is running on http://localhost:5000")
    print("   3. Check browser developer tools for specific CORS error messages")
    print("   4. Try clearing browser cache and cookies")
