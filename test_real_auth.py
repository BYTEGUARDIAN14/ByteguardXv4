#!/usr/bin/env python3
"""
Test Real Authentication with User Credentials
"""

import requests
import json

def test_authentication():
    """Test authentication with real credentials"""
    print("🧪 Testing Real Authentication")
    print("=" * 40)
    
    base_url = "http://localhost:5000"
    
    # Test credentials
    credentials = {
        "email": "jmmunnerahmed@gmail.com",
        "password": "Aduu1410@8190022160"
    }
    
    print(f"📧 Testing login for: {credentials['email']}")
    
    # Test login
    try:
        response = requests.post(
            f"{base_url}/api/auth/login",
            json=credentials,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"🔐 Login Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Login Successful!")
            print(f"   User: {data['user']['username']}")
            print(f"   Email: {data['user']['email']}")
            print(f"   Role: {data['user']['role']}")
            print(f"   Token: {data['access_token'][:20]}...")
            
            # Test token verification
            token = data['access_token']
            verify_response = requests.get(
                f"{base_url}/api/auth/verify",
                headers={'Authorization': f'Bearer {token}'}
            )
            
            print(f"\n🔍 Token Verification: {verify_response.status_code}")
            if verify_response.status_code == 200:
                verify_data = verify_response.json()
                print("✅ Token Valid!")
                print(f"   Valid: {verify_data['valid']}")
                print(f"   User: {verify_data['user']['username']}")
            else:
                print("❌ Token verification failed")
                print(f"   Error: {verify_response.json()}")
            
        else:
            print("❌ Login Failed!")
            print(f"   Error: {response.json()}")
    
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend server")
        print("   Make sure the server is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Test failed: {e}")

def test_health():
    """Test health endpoint"""
    print("\n🏥 Testing Health Endpoint")
    print("-" * 30)
    
    try:
        response = requests.get("http://localhost:5000/api/health")
        if response.status_code == 200:
            data = response.json()
            print("✅ Backend Health Check Passed")
            print(f"   Service: {data['service']}")
            print(f"   Version: {data['version']}")
            print(f"   Database: {data['database']}")
            print(f"   Email: {data['email']}")
        else:
            print("❌ Health check failed")
    except Exception as e:
        print(f"❌ Health check error: {e}")

if __name__ == "__main__":
    test_health()
    test_authentication()
    
    print("\n🎯 Summary:")
    print("If login was successful, you can now:")
    print("1. Start frontend: npm run dev")
    print("2. Go to http://localhost:3000")
    print("3. Login with your credentials")
    print("4. Access the full ByteGuardX platform!")
