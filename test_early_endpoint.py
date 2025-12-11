#!/usr/bin/env python3
import requests
import time

time.sleep(2)

endpoints = [
    'http://localhost:5000/api/v2/early-test',
    'http://localhost:5000/api/v2/test',
    'http://localhost:5000/api/v2/plugins'
]

for endpoint in endpoints:
    try:
        response = requests.get(endpoint, timeout=5)
        print(f"{endpoint}: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Success: {data}")
        else:
            print(f"  Error: {response.text}")
    except Exception as e:
        print(f"{endpoint}: Exception - {e}")
