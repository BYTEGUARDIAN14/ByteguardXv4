#!/usr/bin/env python3
"""
Test file with real vulnerabilities for ByteGuardX scanning
This file contains intentional security vulnerabilities for testing purposes
"""

import os
import sqlite3
import subprocess
import hashlib
import pickle
import yaml
import requests
from flask import Flask, request, render_template_string

# ============================================================================
# SECRETS AND HARDCODED CREDENTIALS (Critical Vulnerabilities)
# ============================================================================

# AWS Credentials (Critical)
AWS_ACCESS_KEY = "FAKE_AWS_KEY_NOT_REAL_12345"
AWS_SECRET_KEY = "FAKE_AWS_SECRET_KEY_NOT_REAL_1234567890"

# Database credentials (High)
DATABASE_URL = "postgresql://admin:super_secret_password@localhost:5432/mydb"
MYSQL_CONNECTION = "mysql://root:password123@localhost/production_db"

# API Keys (High)
STRIPE_SECRET_KEY = "FAKE_STRIPE_KEY_FOR_TESTING_NOT_REAL_12345"
GITHUB_TOKEN = "FAKE_GITHUB_TOKEN_NOT_REAL_12345678901234567890"
SLACK_BOT_TOKEN = "FAKE_SLACK_TOKEN_NOT_REAL_123456789"

# Private Keys (Critical)
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btNjc
IuuJaFHHHb0C5GdrWtVMzSBFKsHGiVVd4VYvQdwsYinVlv/hM3reFRNRjbXqvzTb
vvjHVs0yOzM2u9yQjgfyeNtYkSsPmM2QdgQw8YHSrPYOHBODnslHZqpD6/Aj7MnD
x1/sC2ce4pjzNgxqmmbHnQtXPmw5wnHunFwlk1gXinB3OhYqh5BVXuiUk1wy9nqz
VtVzMlkoTuK/TpXzlHCwRXa6JVXtghB2ZzllIdHFTlJBjwgmFvuiAHXlIqmzjbI
x1YAyUBTEO6pm5GTNjKiIBrx2EZXyqg1lL4ORoQIDAQABAoIBAQDYFCS6dJKjQ4J
-----END RSA PRIVATE KEY-----"""

# ============================================================================
# SQL INJECTION VULNERABILITIES (Critical)
# ============================================================================

def vulnerable_login(username, password):
    """SQL Injection vulnerability - user input directly in query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result

def another_sql_injection(user_id):
    """Another SQL injection example"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting
    query = "SELECT * FROM products WHERE user_id = %s" % user_id
    cursor.execute(query)
    
    return cursor.fetchall()

def search_products(search_term):
    """SQL injection in search functionality"""
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # VULNERABLE: f-string with user input
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    return cursor.fetchall()

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (Critical)
# ============================================================================

def vulnerable_ping(host):
    """Command injection vulnerability"""
    # VULNERABLE: Direct execution of user input
    command = f"ping -c 4 {host}"
    result = os.system(command)
    return result

def backup_file(filename):
    """Command injection in file operations"""
    # VULNERABLE: subprocess with shell=True and user input
    subprocess.call(f"cp {filename} /backup/", shell=True)

def process_log_file(log_file):
    """Command injection in log processing"""
    # VULNERABLE: Direct command execution
    subprocess.run(f"grep ERROR {log_file} | wc -l", shell=True, capture_output=True)

# ============================================================================
# CROSS-SITE SCRIPTING (XSS) VULNERABILITIES (High)
# ============================================================================

app = Flask(__name__)

@app.route('/profile')
def user_profile():
    """Reflected XSS vulnerability"""
    username = request.args.get('username', '')
    
    # VULNERABLE: Direct output without escaping
    return f"<h1>Welcome {username}!</h1>"

@app.route('/comment')
def show_comment():
    """Stored XSS vulnerability"""
    comment = request.args.get('comment', '')
    
    # VULNERABLE: render_template_string with user input
    template = f"<div class='comment'>{comment}</div>"
    return render_template_string(template)

@app.route('/search')
def search_results():
    """DOM-based XSS vulnerability"""
    query = request.args.get('q', '')
    
    # VULNERABLE: JavaScript with user input
    return f"""
    <script>
        var searchQuery = "{query}";
        document.getElementById('results').innerHTML = "Results for: " + searchQuery;
    </script>
    """

# ============================================================================
# INSECURE DESERIALIZATION (Critical)
# ============================================================================

def load_user_data(serialized_data):
    """Unsafe deserialization vulnerability"""
    # VULNERABLE: pickle.loads with untrusted data
    user_data = pickle.loads(serialized_data)
    return user_data

def load_config(yaml_content):
    """Unsafe YAML loading"""
    # VULNERABLE: yaml.load without safe loader
    config = yaml.load(yaml_content)
    return config

# ============================================================================
# WEAK CRYPTOGRAPHY (Medium)
# ============================================================================

def weak_hash_password(password):
    """Weak hashing algorithm"""
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def weak_encryption_key():
    """Hardcoded encryption key"""
    # VULNERABLE: Hardcoded key
    encryption_key = "1234567890123456"  # 16 bytes for AES
    return encryption_key

def insecure_random():
    """Insecure random number generation"""
    import random
    
    # VULNERABLE: Not cryptographically secure
    session_token = str(random.random())
    return session_token

# ============================================================================
# PATH TRAVERSAL VULNERABILITIES (High)
# ============================================================================

def read_file(filename):
    """Path traversal vulnerability"""
    # VULNERABLE: No path validation
    file_path = f"/var/www/uploads/{filename}"
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

def download_file(file_id):
    """Another path traversal example"""
    # VULNERABLE: Direct file access
    base_path = "/app/files/"
    file_path = base_path + file_id
    
    with open(file_path, 'rb') as f:
        return f.read()

# ============================================================================
# AUTHENTICATION AND AUTHORIZATION ISSUES (High)
# ============================================================================

def weak_password_check(password):
    """Weak password policy"""
    # VULNERABLE: Very weak password requirements
    if len(password) >= 4:
        return True
    return False

@app.route('/admin')
def admin_panel():
    """Missing authentication check"""
    # VULNERABLE: No authentication required for admin panel
    return "Admin Panel - Sensitive Information"

@app.route('/user/<user_id>/profile')
def get_user_profile(user_id):
    """Missing authorization check"""
    # VULNERABLE: No check if current user can access this profile
    return f"Profile data for user {user_id}"

# ============================================================================
# INFORMATION DISCLOSURE (Medium)
# ============================================================================

def debug_info():
    """Information disclosure in debug output"""
    # VULNERABLE: Exposing sensitive system information
    return {
        'database_password': 'super_secret_db_pass',
        'api_keys': ['key1', 'key2', 'key3'],
        'internal_paths': ['/etc/passwd', '/var/log/auth.log'],
        'system_info': os.uname()
    }

def error_with_stack_trace():
    """Information disclosure through error messages"""
    try:
        # This will cause an error
        result = 1 / 0
    except Exception as e:
        # VULNERABLE: Exposing full stack trace to user
        import traceback
        return traceback.format_exc()

# ============================================================================
# LOGGING VULNERABILITIES (Low)
# ============================================================================

import logging

logger = logging.getLogger(__name__)

def log_user_action(username, action):
    """Log injection vulnerability"""
    # VULNERABLE: User input directly in log message
    logger.info(f"User {username} performed action: {action}")

def log_sensitive_data(user_data):
    """Sensitive data in logs"""
    # VULNERABLE: Logging sensitive information
    logger.debug(f"User login: {user_data['username']} with password: {user_data['password']}")

# ============================================================================
# RACE CONDITIONS AND CONCURRENCY ISSUES (Medium)
# ============================================================================

import threading
import time

balance = 1000
balance_lock = threading.Lock()

def withdraw_money(amount):
    """Race condition in financial transaction"""
    global balance
    
    # VULNERABLE: No proper locking
    if balance >= amount:
        time.sleep(0.1)  # Simulate processing time
        balance -= amount
        return True
    return False

# ============================================================================
# MAIN FUNCTION FOR TESTING
# ============================================================================

if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing ByteGuardX")
    print("DO NOT USE THIS CODE IN PRODUCTION!")
    
    # Test some functions (safely)
    print(f"Weak password check: {weak_password_check('123')}")
    print(f"Debug info keys: {list(debug_info().keys())}")
    
    # Run Flask app for XSS testing
    app.run(debug=True, host='0.0.0.0', port=5001)
