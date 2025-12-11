#!/usr/bin/env python3
import requests
import time

time.sleep(2)  # Wait for server to start

try:
    response = requests.get('http://localhost:5000/api/v2/plugins', timeout=5)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Success: {data.get('status')}")
    else:
        print(f"Error: {response.text}")
except Exception as e:
    print(f"Exception: {e}")
