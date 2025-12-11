#!/usr/bin/env python3
import requests
import time

time.sleep(3)  # Wait for server to start

endpoints = [
    'http://localhost:5001/api/health',
    'http://localhost:5001/api/v2/plugins',
    'http://localhost:5001/api/v2/plugins/stats'
]

for endpoint in endpoints:
    try:
        response = requests.get(endpoint, timeout=5)
        print(f"{endpoint}: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Success: {data.get('status')}")
        else:
            print(f"  Error: {response.text[:100]}")
    except Exception as e:
        print(f"{endpoint}: Exception - {e}")
