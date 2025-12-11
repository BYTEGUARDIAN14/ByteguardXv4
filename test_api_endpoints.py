#!/usr/bin/env python3
"""
Test ByteGuardX API Endpoints
Quick test to verify API endpoints are working
"""

import requests
import json
import time

def test_api_endpoints():
    """Test all the API endpoints that frontend is trying to access"""
    
    base_url = "http://localhost:5000"
    
    print("🔧 Testing ByteGuardX API Endpoints")
    print("=" * 50)
    
    endpoints = [
        ('GET', '/api/health', 'Health Check'),
        ('GET', '/api/v2/plugins', 'Plugin List'),
        ('GET', '/api/v2/plugins/stats', 'Plugin Stats'),
        ('GET', '/api/v2/plugins/categories', 'Plugin Categories'),
        ('GET', '/api/v2/plugins/featured', 'Featured Plugins'),
        ('GET', '/api/dashboard/stats', 'Dashboard Stats'),
        ('POST', '/api/scan/file', 'File Scan')
    ]
    
    results = []
    
    for method, endpoint, description in endpoints:
        try:
            print(f"🔍 Testing {description} ({method} {endpoint})...")
            
            if method == 'GET':
                response = requests.get(f"{base_url}{endpoint}", timeout=10)
            elif method == 'POST' and endpoint == '/api/scan/file':
                # Test with JSON data
                test_data = {
                    'content': 'print("Hello World")',
                    'file_path': 'test.py',
                    'scan_mode': 'comprehensive'
                }
                response = requests.post(
                    f"{base_url}{endpoint}", 
                    json=test_data, 
                    timeout=15
                )
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Success: {response.status_code}")
                if 'status' in data:
                    print(f"   📊 Status: {data['status']}")
                results.append((description, True, response.status_code, None))
            else:
                print(f"   ❌ Failed: {response.status_code}")
                print(f"   📄 Response: {response.text[:200]}...")
                results.append((description, False, response.status_code, response.text[:200]))
                
        except requests.exceptions.ConnectionError:
            print(f"   ❌ Connection Error: Server not running")
            results.append((description, False, 0, "Connection refused"))
        except Exception as e:
            print(f"   ❌ Error: {e}")
            results.append((description, False, 0, str(e)))
        
        time.sleep(0.5)  # Small delay between requests
    
    # Summary
    print("\n📊 TEST RESULTS SUMMARY")
    print("-" * 30)
    
    passed = sum(1 for _, success, _, _ in results if success)
    total = len(results)
    
    for desc, success, status_code, error in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {desc} ({status_code})")
        if not success and error:
            print(f"     Error: {error}")
    
    print(f"\n🎯 Overall: {passed}/{total} endpoints working")
    
    if passed == total:
        print("🎉 All API endpoints are working!")
        return True
    else:
        print("⚠️  Some endpoints need attention")
        if passed == 0:
            print("\n💡 To start the backend server:")
            print("python -m byteguardx.api.app")
        return False

if __name__ == "__main__":
    success = test_api_endpoints()
    exit(0 if success else 1)
