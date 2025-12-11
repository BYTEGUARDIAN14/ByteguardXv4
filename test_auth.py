#!/usr/bin/env python3
"""
Test script for ByteGuardX authentication system
Tests signup, login, logout, and token refresh functionality
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000"
TEST_USER = {
    "email": "test@byteguardx.com",
    "username": "testuser",
    "password": "TestPassword123!"
}

def test_signup():
    """Test user registration"""
    print("🔐 Testing user registration...")
    
    url = f"{BASE_URL}/api/auth/register"
    response = requests.post(url, json=TEST_USER)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 201:
        print("✅ Registration successful!")
        return True
    elif response.status_code == 409:
        print("⚠️  User already exists, continuing with login test...")
        return True
    else:
        print("❌ Registration failed!")
        return False

def test_login():
    """Test user login"""
    print("\n🔑 Testing user login...")
    
    url = f"{BASE_URL}/api/auth/login"
    login_data = {
        "email": TEST_USER["email"],
        "password": TEST_USER["password"]
    }
    
    response = requests.post(url, json=login_data)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ Login successful!")
        
        # Extract cookies for subsequent requests
        cookies = response.cookies
        return cookies
    else:
        print("❌ Login failed!")
        return None

def test_verify_token(cookies):
    """Test token verification"""
    print("\n🔍 Testing token verification...")
    
    url = f"{BASE_URL}/api/auth/verify"
    response = requests.get(url, cookies=cookies)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200 and response.json().get('valid'):
        print("✅ Token verification successful!")
        return True
    else:
        print("❌ Token verification failed!")
        return False

def test_refresh_token(cookies):
    """Test token refresh"""
    print("\n🔄 Testing token refresh...")
    
    url = f"{BASE_URL}/api/auth/refresh"
    response = requests.post(url, cookies=cookies)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ Token refresh successful!")
        return response.cookies
    else:
        print("❌ Token refresh failed!")
        return cookies

def test_logout(cookies):
    """Test user logout"""
    print("\n🚪 Testing user logout...")
    
    url = f"{BASE_URL}/api/auth/logout"
    response = requests.post(url, cookies=cookies)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        print("✅ Logout successful!")
        return True
    else:
        print("❌ Logout failed!")
        return False

def test_protected_route_after_logout(cookies):
    """Test that protected routes are inaccessible after logout"""
    print("\n🛡️  Testing protected route access after logout...")
    
    url = f"{BASE_URL}/api/auth/verify"
    response = requests.get(url, cookies=cookies)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 401 or not response.json().get('valid', True):
        print("✅ Protected route correctly blocked after logout!")
        return True
    else:
        print("❌ Protected route still accessible after logout!")
        return False

def test_invalid_credentials():
    """Test login with invalid credentials"""
    print("\n🚫 Testing login with invalid credentials...")
    
    url = f"{BASE_URL}/api/auth/login"
    invalid_data = {
        "email": TEST_USER["email"],
        "password": "WrongPassword123!"
    }
    
    response = requests.post(url, json=invalid_data)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 401:
        print("✅ Invalid credentials correctly rejected!")
        return True
    else:
        print("❌ Invalid credentials not properly handled!")
        return False

def main():
    """Run all authentication tests"""
    print("🧪 ByteGuardX Authentication System Test Suite")
    print("=" * 50)
    print(f"Testing against: {BASE_URL}")
    print(f"Test user: {TEST_USER['email']}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 50)
    
    results = []
    
    try:
        # Test 1: User Registration
        results.append(("Registration", test_signup()))
        
        # Test 2: User Login
        cookies = test_login()
        results.append(("Login", cookies is not None))
        
        if cookies:
            # Test 3: Token Verification
            results.append(("Token Verification", test_verify_token(cookies)))
            
            # Test 4: Token Refresh
            new_cookies = test_refresh_token(cookies)
            results.append(("Token Refresh", new_cookies is not None))
            
            # Test 5: User Logout
            results.append(("Logout", test_logout(new_cookies or cookies)))
            
            # Test 6: Protected Route After Logout
            results.append(("Protected Route Block", test_protected_route_after_logout(new_cookies or cookies)))
        
        # Test 7: Invalid Credentials
        results.append(("Invalid Credentials", test_invalid_credentials()))
        
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Make sure the ByteGuardX server is running on", BASE_URL)
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    
    # Print Results Summary
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<25} {status}")
        if result:
            passed += 1
    
    print("-" * 50)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 All tests passed! Authentication system is working correctly.")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
