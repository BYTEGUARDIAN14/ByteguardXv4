#!/usr/bin/env python3
"""
Test script to demonstrate ByteGuardX enhanced scanning capabilities
This script shows real vulnerability detection and reporting
"""

import json
import requests
import time
from pathlib import Path

def test_enhanced_scanning():
    """Test the enhanced scanning system with real vulnerabilities"""
    
    print("🛡️  ByteGuardX Enhanced Scanning Test")
    print("=" * 50)
    
    # Read the vulnerable test file
    test_file_path = "test_vulnerable_code.py"
    
    if not Path(test_file_path).exists():
        print(f"❌ Test file {test_file_path} not found!")
        return
    
    with open(test_file_path, 'r', encoding='utf-8') as f:
        test_content = f.read()
    
    print(f"📁 Scanning file: {test_file_path}")
    print(f"📊 File size: {len(test_content)} characters")
    print(f"📝 Lines of code: {len(test_content.splitlines())}")
    print()
    
    # Test the enhanced unified scanning API
    scan_payload = {
        "content": test_content,
        "file_path": test_file_path,
        "scan_mode": "comprehensive",
        "enable_verification": True,
        "enable_explanations": True,
        "confidence_threshold": 0.6,
        "enable_ml": True,
        "enable_plugins": True,
        "enable_cross_validation": True,
        "enable_false_positive_filtering": True
    }
    
    try:
        print("🔍 Starting enhanced vulnerability scan...")
        start_time = time.time()
        
        # Call the enhanced scanning API
        response = requests.post(
            'http://localhost:5000/api/v2/scan/unified',
            json=scan_payload,
            headers={'Content-Type': 'application/json'},
            timeout=60
        )
        
        scan_time = time.time() - start_time
        
        if response.status_code == 200:
            scan_results = response.json()
            print(f"✅ Scan completed in {scan_time:.2f} seconds")
            print()
            
            # Display scan summary
            display_scan_summary(scan_results)
            
            # Display findings
            display_findings(scan_results.get('findings', []))
            
            # Display verification results
            display_verification_results(scan_results.get('verification_reports', []))
            
            # Generate security report
            generate_security_report(scan_results)
            
        else:
            print(f"❌ Scan failed with status {response.status_code}")
            print(f"Error: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        print("Make sure ByteGuardX is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def display_scan_summary(scan_results):
    """Display scan summary information"""
    summary = scan_results.get('summary', {})
    metadata = scan_results.get('scan_metadata', {})
    
    print("📊 SCAN SUMMARY")
    print("-" * 30)
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    print(f"Scan Mode: {metadata.get('scan_mode', 'unknown')}")
    print(f"Processing Time: {metadata.get('processing_time', 0):.2f}s")
    print(f"Scanners Used: {', '.join(metadata.get('scanners_used', []))}")
    print()
    
    # Display by severity
    by_severity = summary.get('by_severity', {})
    if by_severity:
        print("🚨 FINDINGS BY SEVERITY")
        print("-" * 30)
        for severity in ['critical', 'high', 'medium', 'low']:
            count = by_severity.get(severity, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                print(f"{emoji.get(severity, '⚪')} {severity.upper()}: {count}")
        print()
    
    # Display by type
    by_type = summary.get('by_type', {})
    if by_type:
        print("🔍 FINDINGS BY TYPE")
        print("-" * 30)
        for vuln_type, count in by_type.items():
            print(f"• {vuln_type}: {count}")
        print()

def display_findings(findings):
    """Display detailed findings"""
    if not findings:
        print("✅ No vulnerabilities found!")
        return
    
    print(f"🔍 DETAILED FINDINGS ({len(findings)} total)")
    print("=" * 50)
    
    # Group findings by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get('severity', 'low')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    # Display in severity order
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in by_severity:
            print(f"\n🚨 {severity.upper()} SEVERITY ({len(by_severity[severity])} findings)")
            print("-" * 40)
            
            for i, finding in enumerate(by_severity[severity][:5], 1):  # Show top 5 per severity
                print(f"\n{i}. {finding.get('description', 'Unknown vulnerability')}")
                print(f"   📁 File: {finding.get('file_path', 'unknown')}")
                print(f"   📍 Line: {finding.get('line_number', 0)}")
                print(f"   🎯 Type: {finding.get('type', 'unknown')} → {finding.get('subtype', 'unknown')}")
                print(f"   🔒 Scanner: {finding.get('scanner_source', 'unknown')}")
                print(f"   ✅ Confidence: {finding.get('confidence', 0):.1%}")
                print(f"   🔍 Verification: {finding.get('verification_status', 'pending')}")
                
                # Show CWE and OWASP if available
                if finding.get('cwe_id'):
                    print(f"   🏷️  CWE: {finding.get('cwe_id')}")
                if finding.get('owasp_category'):
                    print(f"   🏷️  OWASP: {finding.get('owasp_category')}")
                
                # Show remediation
                if finding.get('recommendation'):
                    print(f"   💡 Fix: {finding.get('recommendation')}")
            
            if len(by_severity[severity]) > 5:
                print(f"\n   ... and {len(by_severity[severity]) - 5} more {severity} findings")

def display_verification_results(verification_reports):
    """Display verification results"""
    if not verification_reports:
        return
    
    print(f"\n🔍 VERIFICATION RESULTS ({len(verification_reports)} findings verified)")
    print("=" * 50)
    
    # Count verification results
    result_counts = {}
    for report in verification_reports:
        result = report.get('verification_result', 'unknown')
        result_counts[result] = result_counts.get(result, 0) + 1
    
    for result, count in result_counts.items():
        emoji = {
            'verified': '✅',
            'rejected': '❌',
            'uncertain': '❓',
            'requires_manual_review': '👁️'
        }
        print(f"{emoji.get(result, '⚪')} {result.replace('_', ' ').title()}: {count}")
    
    # Show verification methods used
    methods_used = set()
    for report in verification_reports:
        methods_used.update(report.get('verification_methods', []))
    
    if methods_used:
        print(f"\n🔧 Verification Methods Used:")
        for method in methods_used:
            print(f"   • {method.replace('_', ' ').title()}")

def generate_security_report(scan_results):
    """Generate and display security report"""
    print(f"\n📋 GENERATING SECURITY REPORT")
    print("=" * 50)
    
    try:
        # Call the security report API
        report_response = requests.post(
            'http://localhost:5000/api/v2/reports/security',
            json={'scan_results': scan_results},
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if report_response.status_code == 200:
            security_report = report_response.json()
            
            # Display executive summary
            exec_summary = security_report.get('executive_summary', {})
            print(f"🎯 Security Posture: {exec_summary.get('security_posture', 'Unknown')}")
            print(f"📊 Overall Risk Score: {exec_summary.get('overall_risk_score', 0)}/10")
            print(f"🎯 Average CVSS Score: {exec_summary.get('average_cvss_score', 0)}")
            print(f"📈 False Positive Rate: {exec_summary.get('false_positive_rate', 0)}%")
            
            # Display key recommendations
            recommendations = exec_summary.get('key_recommendations', [])
            if recommendations:
                print(f"\n💡 KEY RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations, 1):
                    print(f"   {i}. {rec}")
            
            # Display compliance status
            compliance = security_report.get('compliance_status', {})
            if compliance:
                print(f"\n📋 COMPLIANCE STATUS:")
                owasp = compliance.get('owasp_top_10', {})
                if owasp:
                    print(f"   🔒 OWASP Top 10 Score: {owasp.get('compliance_score', 0)}/100")
                    violations = owasp.get('violations', [])
                    if violations:
                        print(f"   ⚠️  Violations: {', '.join(violations)}")
            
            print(f"\n✅ Security report generated successfully!")
            print(f"📄 Report ID: {security_report.get('report_id', 'unknown')}")
            
        else:
            print(f"❌ Report generation failed: {report_response.status_code}")
            
    except Exception as e:
        print(f"❌ Report generation error: {e}")

def test_individual_scanners():
    """Test individual scanner components"""
    print(f"\n🧪 TESTING INDIVIDUAL SCANNERS")
    print("=" * 50)
    
    # Test secret scanner
    print("🔐 Testing Secret Scanner...")
    secret_test_content = '''
    AWS_ACCESS_KEY = "FAKE_AWS_KEY_NOT_REAL_12345"
    STRIPE_KEY = "FAKE_STRIPE_KEY_FOR_TESTING_NOT_REAL_12345"
    DATABASE_URL = "postgresql://admin:password123@localhost:5432/db"
    '''
    
    # Test vulnerability scanner
    print("🐛 Testing Vulnerability Scanner...")
    vuln_test_content = '''
    def sql_injection(user_input):
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        cursor.execute(query)
    
    def command_injection(filename):
        os.system(f"cat {filename}")
    '''
    
    print("✅ Individual scanner tests would run here")

if __name__ == "__main__":
    print("🚀 Starting ByteGuardX Enhanced Scanning Tests")
    print()
    
    # Test the main enhanced scanning
    test_enhanced_scanning()
    
    # Test individual scanners
    test_individual_scanners()
    
    print(f"\n🎉 Testing completed!")
    print("📚 Check the generated reports for detailed analysis")
    print("🔧 Tune confidence thresholds and filters as needed")
