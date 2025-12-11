#!/usr/bin/env python3
"""
Debug ByteGuardX Server Startup
Check what happens when the server starts
"""

import sys
import os

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def debug_server_startup():
    """Debug server startup process"""
    
    print("🔧 Debugging ByteGuardX Server Startup")
    print("=" * 50)
    
    try:
        print("1. Testing imports...")
        from byteguardx.api.app import create_app
        print("   ✅ create_app imported")
        
        print("2. Creating Flask app...")
        app = create_app()
        print("   ✅ Flask app created")
        
        print("3. Checking registered routes...")
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'rule': str(rule)
            })
        
        # Filter for our API routes
        api_routes = [r for r in routes if r['rule'].startswith('/api')]
        
        print(f"   ✅ Found {len(api_routes)} API routes:")
        for route in sorted(api_routes, key=lambda x: x['rule']):
            methods = [m for m in route['methods'] if m not in ['HEAD', 'OPTIONS']]
            print(f"      {route['rule']} [{', '.join(methods)}]")
        
        print("4. Testing plugin-specific routes...")
        plugin_routes = [r for r in api_routes if 'plugin' in r['rule']]
        print(f"   ✅ Found {len(plugin_routes)} plugin routes:")
        for route in plugin_routes:
            methods = [m for m in route['methods'] if m not in ['HEAD', 'OPTIONS']]
            print(f"      {route['rule']} [{', '.join(methods)}]")
        
        print("5. Testing plugin registry import within app context...")
        with app.app_context():
            try:
                from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
                result = get_plugin_marketplace_data()
                print(f"   ✅ Plugin registry working: {result['statistics']['total_plugins']} plugins")
            except Exception as e:
                print(f"   ❌ Plugin registry error: {e}")
        
        print("6. Testing endpoints with test client...")
        with app.test_client() as client:
            test_endpoints = [
                '/api/health',
                '/api/v2/plugins',
                '/api/v2/plugins/stats',
                '/api/dashboard/stats'
            ]
            
            for endpoint in test_endpoints:
                try:
                    response = client.get(endpoint)
                    print(f"   {endpoint}: {response.status_code}")
                except Exception as e:
                    print(f"   {endpoint}: ERROR - {e}")
        
        print("\n🎉 Server startup debug completed!")
        return True
        
    except Exception as e:
        print(f"❌ Server startup debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_server_startup()
    exit(0 if success else 1)
