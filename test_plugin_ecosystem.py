#!/usr/bin/env python3
"""
ByteGuardX Plugin Ecosystem Test
Demonstrates all 20+ advanced scanning plugins
"""

import sys
import os
import json
import time
from pathlib import Path

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_plugin_ecosystem():
    """Test the complete plugin ecosystem"""
    
    print("🔌 ByteGuardX Advanced Plugin Ecosystem Test")
    print("=" * 60)
    
    try:
        # Initialize plugin system
        from byteguardx.plugins.plugin_registry import plugin_registry, initialize_plugin_system
        
        print("🚀 Initializing Plugin System...")
        plugin_info = initialize_plugin_system()
        
        print(f"✅ Plugin system initialized!")
        print(f"📊 Total plugins: {plugin_info['total_plugins']}")
        print(f"📂 Categories: {len(plugin_info['by_category'])}")
        print()
        
        # Display plugin categories
        print("📋 PLUGIN CATEGORIES")
        print("-" * 40)
        for category, count in plugin_info['by_category'].items():
            print(f"🔍 {category.replace('_', ' ').title()}: {count} plugins")
        print()
        
        # Test each plugin category
        test_cloud_security_plugins()
        test_web_security_plugins()
        test_binary_analysis_plugins()
        test_infrastructure_plugins()
        test_source_code_plugins()
        test_network_security_plugins()
        test_compliance_plugins()
        
        # Display plugin marketplace
        display_plugin_marketplace()
        
        # Test unified scanning with plugins
        test_unified_scanning_with_plugins()
        
        print("🎉 Plugin ecosystem test completed successfully!")
        
    except Exception as e:
        print(f"❌ Plugin ecosystem test failed: {e}")
        import traceback
        traceback.print_exc()

def test_cloud_security_plugins():
    """Test cloud security plugins"""
    print("☁️  TESTING CLOUD SECURITY PLUGINS")
    print("-" * 40)
    
    # Test AWS S3 Scanner
    test_content = '''
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    '''
    
    test_plugin("aws_s3_exposure_scanner", test_content, "bucket-policy.json")
    
    # Test GCP IAM Scanner
    gcp_content = '''
    bindings:
    - members:
      - allUsers
      role: roles/owner
    '''
    
    test_plugin("gcp_iam_weakness_detector", gcp_content, "iam-policy.yaml")
    
    # Test Azure KeyVault Scanner
    azure_content = '''
    {
        "properties": {
            "publicNetworkAccess": "Enabled",
            "enableRbacAuthorization": false
        }
    }
    '''
    
    test_plugin("azure_keyvault_scanner", azure_content, "keyvault.json")
    print()

def test_web_security_plugins():
    """Test web security plugins"""
    print("🌐 TESTING WEB SECURITY PLUGINS")
    print("-" * 40)
    
    # Test SSRF Detector
    ssrf_content = '''
    import requests
    
    def fetch_url(url):
        # Vulnerable: user input directly in request
        response = requests.get(request.args.get('url'))
        return response.text
    '''
    
    test_plugin("ssrf_detector", ssrf_content, "app.py")
    
    # Test Open Redirect Detector
    redirect_content = '''
    def redirect_user():
        redirect_url = request.args.get('next')
        return redirect(redirect_url)  # Vulnerable
    '''
    
    test_plugin("open_redirect_detector", redirect_content, "auth.py")
    
    # Test JWT Security Validator
    jwt_content = '''
    JWT_SECRET = "weak123"
    token = jwt.encode(payload, JWT_SECRET, algorithm="none")
    '''
    
    test_plugin("jwt_security_validator", jwt_content, "auth.py")
    
    # Test GraphQL Scanner
    graphql_content = '''
    schema = buildSchema(introspection=true, debug=true)
    '''
    
    test_plugin("graphql_introspection_scanner", graphql_content, "schema.py")
    
    # Test Broken Access Control
    access_content = '''
    @app.route('/admin')
    def admin_panel():
        # Missing authorization check
        return render_template('admin.html')
    '''
    
    test_plugin("broken_access_control_detector", access_content, "admin.py")
    print()

def test_binary_analysis_plugins():
    """Test binary analysis plugins"""
    print("🔍 TESTING BINARY ANALYSIS PLUGINS")
    print("-" * 40)
    
    # Test ELF/PE Malware Scanner
    binary_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    test_plugin("elf_pe_malware_scanner", binary_content.decode('latin-1'), "suspicious.exe")
    
    # Test PDF Exploit Detector
    pdf_content = b"%PDF-1.4\n/JavaScript (eval(unescape('malicious')))"
    test_plugin("pdf_exploit_detector", pdf_content.decode('latin-1'), "document.pdf")
    
    # Test Archive Scanner
    zip_content = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    test_plugin("archive_exploit_scanner", zip_content.decode('latin-1'), "archive.zip")
    print()

def test_infrastructure_plugins():
    """Test infrastructure plugins"""
    print("🏗️  TESTING INFRASTRUCTURE PLUGINS")
    print("-" * 40)
    
    # Test Terraform Scanner
    terraform_content = '''
    resource "aws_s3_bucket" "example" {
        bucket = "my-bucket"
        acl    = "public-read"
        
        server_side_encryption_configuration = []
    }
    '''
    
    test_plugin("terraform_security_scanner", terraform_content, "main.tf")
    
    # Test Dockerfile Scanner
    dockerfile_content = '''
    FROM ubuntu:latest
    USER root
    RUN apt-get update && apt-get install -y sudo
    ENV PASSWORD=secret123
    '''
    
    test_plugin("dockerfile_security_analyzer", dockerfile_content, "Dockerfile")
    
    # Test Kubernetes RBAC Scanner
    k8s_content = '''
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: admin-binding
    roleRef:
      name: cluster-admin
    subjects:
    - kind: User
      name: user1
    '''
    
    test_plugin("kubernetes_rbac_scanner", k8s_content, "rbac.yaml")
    print()

def test_source_code_plugins():
    """Test source code analysis plugins"""
    print("💻 TESTING SOURCE CODE PLUGINS")
    print("-" * 40)
    
    # Test ReDoS Detector
    redos_content = '''
    import re
    pattern = r"(a+)+"
    regex = re.compile(pattern)
    '''
    
    test_plugin("redos_detector", redos_content, "regex.py")
    
    # Test Unsafe Function Scanner
    unsafe_content = '''
    import os
    user_input = request.args.get('cmd')
    os.system(user_input)  # Dangerous
    eval(user_code)  # Very dangerous
    '''
    
    test_plugin("unsafe_function_scanner", unsafe_content, "dangerous.py")
    
    # Test Crypto Weakness Detector
    crypto_content = '''
    import hashlib
    password_hash = hashlib.md5(password.encode()).hexdigest()
    secret_key = "hardcoded_key_12345"
    '''
    
    test_plugin("crypto_weakness_detector", crypto_content, "crypto.py")
    
    # Test Race Condition Analyzer
    race_content = '''
    import threading
    global_counter = 0
    
    def increment():
        global global_counter
        global_counter += 1  # Race condition
    '''
    
    test_plugin("race_condition_analyzer", race_content, "concurrent.py")
    print()

def test_network_security_plugins():
    """Test network security plugins"""
    print("🌐 TESTING NETWORK SECURITY PLUGINS")
    print("-" * 40)
    
    # Test TLS/SSL Scanner
    tls_content = '''
    ssl_protocols TLSv1.0 TLSv1.1 TLSv1.2;
    ssl_ciphers RC4:DES:MD5;
    '''
    
    test_plugin("tls_ssl_scanner", tls_content, "nginx.conf")
    
    # Test Insecure Headers Scanner
    headers_content = '''
    response.headers['X-Frame-Options'] = 'DENY'
    # Missing Content-Security-Policy
    '''
    
    test_plugin("insecure_headers_scanner", headers_content, "security.py")
    
    # Test Subdomain Takeover Detector
    dns_content = '''
    subdomain.example.com CNAME old-app.herokuapp.com
    api.example.com CNAME deleted-bucket.s3.amazonaws.com
    '''
    
    test_plugin("subdomain_takeover_detector", dns_content, "dns.zone")
    print()

def test_compliance_plugins():
    """Test compliance plugins"""
    print("📋 TESTING COMPLIANCE PLUGINS")
    print("-" * 40)
    
    # Test GDPR Compliance Checker
    gdpr_content = '''
    def collect_user_data():
        email = request.form.get('email')
        phone = request.form.get('phone')
        # Missing consent mechanism
        save_personal_data(email, phone)
    '''
    
    test_plugin("gdpr_compliance_checker", gdpr_content, "data_collection.py")
    print()

def test_plugin(plugin_name, content, file_path):
    """Test a specific plugin"""
    try:
        from byteguardx.plugins.plugin_registry import plugin_registry
        
        print(f"🔍 Testing {plugin_name}...")
        
        start_time = time.time()
        result = plugin_registry.execute_plugin(plugin_name, content, file_path)
        execution_time = time.time() - start_time
        
        if result.status.value == "completed":
            print(f"   ✅ Success: {len(result.findings)} findings in {execution_time:.2f}s")
            
            # Show top finding
            if result.findings:
                top_finding = result.findings[0]
                print(f"   🎯 Top finding: {top_finding.get('title', 'Unknown')}")
                print(f"   🚨 Severity: {top_finding.get('severity', 'unknown')}")
        else:
            print(f"   ❌ Failed: {result.error_message}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")

def display_plugin_marketplace():
    """Display plugin marketplace information"""
    print("🏪 PLUGIN MARKETPLACE")
    print("-" * 40)
    
    try:
        from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
        
        marketplace = get_plugin_marketplace_data()
        
        print(f"📊 Statistics:")
        stats = marketplace['statistics']
        print(f"   • Total Plugins: {stats['total_plugins']}")
        print(f"   • Categories: {stats['categories']}")
        print(f"   • Active Plugins: {stats['active_plugins']}")
        print()
        
        print(f"🌟 Featured Plugins:")
        for plugin in marketplace['featured_plugins'][:3]:
            manifest = plugin['manifest']
            print(f"   • {manifest['name']} v{manifest['version']}")
            print(f"     {manifest['description']}")
        print()
        
    except Exception as e:
        print(f"❌ Marketplace error: {e}")

def test_unified_scanning_with_plugins():
    """Test unified scanning with plugin integration"""
    print("🔄 TESTING UNIFIED SCANNING WITH PLUGINS")
    print("-" * 40)
    
    try:
        from byteguardx.core.unified_scanner import unified_scanner, ScanContext, ScanMode
        
        # Create test content with multiple vulnerability types
        test_content = '''
        import requests
        import os
        
        # SSRF vulnerability
        def fetch_data(url):
            return requests.get(request.args.get('url'))
        
        # Command injection
        def run_command(cmd):
            os.system(request.form.get('command'))
        
        # Hardcoded secret
        API_KEY = "FAKE_TEST_KEY_FOR_SECURITY_SCANNING_DEMO_12345"
        '''
        
        context = ScanContext(
            file_path="vulnerable_app.py",
            content=test_content,
            language="python",
            file_size=len(test_content),
            scan_mode=ScanMode.COMPREHENSIVE,
            confidence_threshold=0.6,
            enable_ml=True,
            enable_plugins=True
        )
        
        print("🔍 Running unified scan with plugins...")
        start_time = time.time()
        
        findings = unified_scanner.scan_content(context)
        
        scan_time = time.time() - start_time
        
        print(f"✅ Unified scan completed in {scan_time:.2f}s")
        print(f"📊 Total findings: {len(findings)}")
        
        # Group findings by scanner
        by_scanner = {}
        for finding in findings:
            scanner = finding.scanner_source
            if scanner not in by_scanner:
                by_scanner[scanner] = 0
            by_scanner[scanner] += 1
        
        print(f"🔍 Findings by scanner:")
        for scanner, count in by_scanner.items():
            print(f"   • {scanner}: {count}")
        
        print()
        
    except Exception as e:
        print(f"❌ Unified scanning error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_plugin_ecosystem()
