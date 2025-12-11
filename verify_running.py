#!/usr/bin/env python3
import requests
import time

print("🛡️  ByteGuardX Local Instance Verification")
print("=" * 50)

# Test all key endpoints
endpoints = [
    ('Backend Health', 'http://localhost:5000/api/health'),
    ('Plugin System', 'http://localhost:5000/api/v2/plugins'),
    ('Dashboard Stats', 'http://localhost:5000/api/dashboard/stats'),
    ('Frontend App', 'http://localhost:3001')
]

all_working = True

for name, url in endpoints:
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"✅ {name}: Working ({response.status_code})")
            
            if 'api/v2/plugins' in url:
                data = response.json()
                plugins = data['marketplace']['statistics']['total_plugins']
                print(f"   📊 {plugins} security plugins loaded")
            elif 'dashboard/stats' in url:
                data = response.json()
                score = data['stats']['security_score']
                print(f"   📊 Security Score: {score}/100")
        else:
            print(f"❌ {name}: Error ({response.status_code})")
            all_working = False
    except Exception as e:
        print(f"❌ {name}: Not accessible")
        all_working = False

if all_working:
    print(f"\n🎉 SUCCESS: ByteGuardX is fully operational!")
    print("=" * 50)
    print("🌐 Main Application: http://localhost:3001")
    print("📊 Security Dashboard: http://localhost:3001/dashboard")
    print("🔌 Plugin Marketplace: http://localhost:3001/plugins")
    print("🔍 Advanced Scanner: http://localhost:3001/scan")
    print("🔧 API Documentation: http://localhost:5000/api/health")
    print("\n💡 Open http://localhost:3001 in your browser to get started!")
else:
    print(f"\n⚠️  Some components may need attention")

print(f"\n🔧 Backend API Server: PID 38 (http://localhost:5000)")
print(f"🌐 Frontend Dev Server: PID 39 (http://localhost:3001)")
print(f"\n💡 To stop: Press Ctrl+C in both terminal windows")
