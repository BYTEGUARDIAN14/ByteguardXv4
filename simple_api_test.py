#!/usr/bin/env python3
"""
Simple API Test
Test the Flask app directly
"""

import sys
import os

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_flask_app():
    """Test Flask app creation and endpoints"""
    
    print("🔧 Testing Flask App Creation")
    print("=" * 40)
    
    try:
        from byteguardx.api.app import create_app
        
        print("✅ create_app imported successfully")
        
        # Create the app
        app = create_app()
        print("✅ Flask app created successfully")
        
        # Test client
        with app.test_client() as client:
            print("\n🔍 Testing Endpoints")
            print("-" * 20)
            
            # Test health endpoint
            try:
                response = client.get('/api/health')
                print(f"✅ Health endpoint: {response.status_code}")
                if response.status_code == 200:
                    data = response.get_json()
                    print(f"   Status: {data.get('status')}")
            except Exception as e:
                print(f"❌ Health endpoint: {e}")
            
            # Test plugin endpoints
            endpoints = [
                '/api/v2/plugins',
                '/api/v2/plugins/stats',
                '/api/v2/plugins/categories',
                '/api/v2/plugins/featured',
                '/api/dashboard/stats'
            ]
            
            for endpoint in endpoints:
                try:
                    response = client.get(endpoint)
                    print(f"✅ {endpoint}: {response.status_code}")
                    if response.status_code == 200:
                        data = response.get_json()
                        if 'status' in data:
                            print(f"   Status: {data['status']}")
                except Exception as e:
                    print(f"❌ {endpoint}: {e}")
            
            # Test scan endpoint
            try:
                test_data = {
                    'content': 'print("Hello World")',
                    'file_path': 'test.py',
                    'scan_mode': 'comprehensive'
                }
                response = client.post('/api/scan/file', json=test_data)
                print(f"✅ /api/scan/file: {response.status_code}")
                if response.status_code == 200:
                    data = response.get_json()
                    print(f"   Status: {data.get('status')}")
                    print(f"   Findings: {len(data.get('findings', []))}")
            except Exception as e:
                print(f"❌ /api/scan/file: {e}")
        
        print("\n🎉 Flask app test completed!")
        return True
        
    except Exception as e:
        print(f"❌ Flask app test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_flask_app()
    exit(0 if success else 1)
