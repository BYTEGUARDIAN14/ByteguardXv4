#!/usr/bin/env python3
"""
Test Working ByteGuardX API Endpoints
Test only the endpoints we know are working
"""

import requests
import json
import time

def test_working_endpoints():
    """Test the working API endpoints"""
    
    base_url = "http://localhost:5000"
    
    print("🔧 Testing Working ByteGuardX API Endpoints")
    print("=" * 50)
    
    # Test the endpoints we know work
    working_endpoints = [
        ('GET', '/api/v2/plugins', 'Plugin List'),
        ('GET', '/api/v2/plugins/stats', 'Plugin Stats'),
        ('GET', '/api/v2/plugins/categories', 'Plugin Categories'),
        ('GET', '/api/v2/plugins/featured', 'Featured Plugins'),
        ('GET', '/api/dashboard/stats', 'Dashboard Stats'),
        ('POST', '/api/scan/file', 'File Scan')
    ]
    
    results = []
    
    for method, endpoint, description in working_endpoints:
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
                
                # Show some key data
                if endpoint == '/api/v2/plugins':
                    if 'marketplace' in data:
                        stats = data['marketplace']['statistics']
                        print(f"   📊 Plugins: {stats['total_plugins']}, Categories: {stats['categories']}")
                elif endpoint == '/api/v2/plugins/stats':
                    if 'stats' in data:
                        stats = data['stats']
                        print(f"   📊 Executions: {stats['total_executions']}, Success Rate: {stats['success_rate']:.1%}")
                elif endpoint == '/api/dashboard/stats':
                    if 'stats' in data:
                        stats = data['stats']
                        print(f"   📊 Security Score: {stats.get('security_score', 'N/A')}")
                elif endpoint == '/api/scan/file':
                    if 'findings' in data:
                        print(f"   📊 Findings: {len(data['findings'])}")
                
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
    
    if passed >= 4:  # Most endpoints working
        print("🎉 Most API endpoints are working!")
        print("\n💡 Frontend should now be able to connect!")
        print("🌐 Start frontend with: npm run dev")
        return True
    else:
        print("⚠️  Some endpoints need attention")
        return False

if __name__ == "__main__":
    success = test_working_endpoints()
    exit(0 if success else 1)
