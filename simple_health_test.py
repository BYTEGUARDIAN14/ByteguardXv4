#!/usr/bin/env python3
import requests
import time

time.sleep(1)

try:
    response = requests.get('http://localhost:5000/api/health', timeout=5)
    print(f"Health endpoint: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response: {data}")
    else:
        print(f"Error: {response.text}")
except Exception as e:
    print(f"Exception: {e}")

# Test plugin endpoint
try:
    response = requests.get('http://localhost:5000/api/v2/plugins', timeout=5)
    print(f"Plugin endpoint: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response: {data.get('status')}")
    else:
        print(f"Error: {response.text}")
except Exception as e:
    print(f"Exception: {e}")
