#!/usr/bin/env python3
"""
Test frontend status and connectivity
"""

import requests
import time

def test_frontend_and_backend():
    """Test both frontend and backend connectivity"""
    print("🧪 Testing ByteGuardX Frontend and Backend Status")
    print("=" * 50)
    
    # Test backend API
    print("1. Testing Backend API (http://localhost:5000)...")
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Backend API is running")
            print(f"   📊 Service: {data.get('service', 'Unknown')}")
            print(f"   🔧 Version: {data.get('version', 'Unknown')}")
            print(f"   🌐 CORS: {data.get('cors_enabled', 'Unknown')}")
        else:
            print(f"   ❌ Backend API returned status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("   ❌ Backend API is not running or not accessible")
    except Exception as e:
        print(f"   ❌ Backend API test failed: {e}")
    
    # Test frontend dev server
    print("\n2. Testing Frontend Dev Server (http://localhost:3000)...")
    try:
        response = requests.get('http://localhost:3000', timeout=5)
        if response.status_code == 200:
            print(f"   ✅ Frontend dev server is running")
            print(f"   📄 Content length: {len(response.text)} bytes")
            
            # Check if it's actually serving the React app
            if 'ByteGuardX' in response.text or 'react' in response.text.lower():
                print("   ✅ React app appears to be loaded")
            else:
                print("   ⚠️  Frontend may not be serving the React app properly")
        else:
            print(f"   ❌ Frontend dev server returned status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("   ❌ Frontend dev server is not running or not accessible")
    except Exception as e:
        print(f"   ❌ Frontend dev server test failed: {e}")
    
    # Test CORS between frontend and backend
    print("\n3. Testing CORS between Frontend and Backend...")
    try:
        headers = {
            'Origin': 'http://localhost:3000',
            'Content-Type': 'application/json'
        }
        response = requests.get('http://localhost:5000/api/auth/verify', headers=headers, timeout=5)
        
        cors_origin = response.headers.get('Access-Control-Allow-Origin', 'NOT_SET')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials', 'NOT_SET')
        
        print(f"   📡 CORS Origin: {cors_origin}")
        print(f"   🔐 CORS Credentials: {cors_credentials}")
        
        if cors_origin == 'http://localhost:3000' and cors_credentials == 'true':
            print("   ✅ CORS is properly configured")
        else:
            print("   ❌ CORS configuration has issues")
            
    except Exception as e:
        print(f"   ❌ CORS test failed: {e}")
    
    print("\n🎯 Summary:")
    print("   If both servers are running and CORS is working,")
    print("   your ByteGuardX application should be accessible at:")
    print("   🌐 Frontend: http://localhost:3000")
    print("   🔧 Backend:  http://localhost:5000")
    
    print("\n💡 If you're still seeing a black screen:")
    print("   1. Clear your browser cache (Ctrl+Shift+R)")
    print("   2. Check browser developer tools for JavaScript errors")
    print("   3. Ensure both servers are running")
    print("   4. Try opening http://localhost:3000 in an incognito window")

if __name__ == "__main__":
    test_frontend_and_backend()
