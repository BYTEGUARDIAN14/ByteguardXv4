#!/usr/bin/env python3
import requests
import time
import json

time.sleep(3)  # Wait for server to start

endpoints = [
    ('GET', 'http://localhost:5002/api/health', None),
    ('GET', 'http://localhost:5002/api/v2/plugins', None),
    ('GET', 'http://localhost:5002/api/v2/plugins/stats', None),
    ('POST', 'http://localhost:5002/api/scan/file', {
        'content': 'print("Hello World")',
        'file_path': 'test.py',
        'scan_mode': 'comprehensive'
    })
]

for method, endpoint, data in endpoints:
    try:
        if method == 'GET':
            response = requests.get(endpoint, timeout=5)
        else:
            response = requests.post(endpoint, json=data, timeout=5)
            
        print(f"{method} {endpoint}: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"  Success: {result.get('status')}")
            if 'marketplace' in result:
                stats = result['marketplace']['statistics']
                print(f"    Plugins: {stats['total_plugins']}, Categories: {stats['categories']}")
            elif 'stats' in result:
                stats = result['stats']
                print(f"    Executions: {stats['total_executions']}, Success Rate: {stats['success_rate']:.1%}")
            elif 'findings' in result:
                print(f"    Findings: {len(result['findings'])}")
        else:
            print(f"  Error: {response.text}")
    except Exception as e:
        print(f"{method} {endpoint}: Exception - {e}")
