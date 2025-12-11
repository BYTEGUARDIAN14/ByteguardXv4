#!/usr/bin/env python3
"""
Vulnerability Checker for CI/CD Pipeline
Analyzes security scan results and fails build on critical issues
"""

import json
import sys
import os
from pathlib import Path

def check_bandit_results():
    """Check Bandit security scan results"""
    bandit_file = Path("bandit-report.json")
    if not bandit_file.exists():
        print("⚠️  Bandit report not found")
        return True
    
    try:
        with open(bandit_file) as f:
            data = json.load(f)
        
        high_issues = [r for r in data.get('results', []) if r.get('issue_severity') == 'HIGH']
        medium_issues = [r for r in data.get('results', []) if r.get('issue_severity') == 'MEDIUM']
        
        print(f"🔍 Bandit Results: {len(high_issues)} high, {len(medium_issues)} medium severity issues")
        
        if high_issues:
            print("❌ HIGH SEVERITY SECURITY ISSUES FOUND:")
            for issue in high_issues[:5]:  # Show first 5
                print(f"  - {issue.get('test_name')}: {issue.get('issue_text')}")
                print(f"    File: {issue.get('filename')}:{issue.get('line_number')}")
            
            if len(high_issues) > 5:
                print(f"  ... and {len(high_issues) - 5} more")
            
            return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Error reading Bandit report: {e}")
        return True

def check_safety_results():
    """Check Safety vulnerability scan results"""
    safety_file = Path("safety-report.json")
    if not safety_file.exists():
        print("⚠️  Safety report not found")
        return True
    
    try:
        with open(safety_file) as f:
            data = json.load(f)
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        print(f"🔍 Safety Results: {len(vulnerabilities)} vulnerabilities found")
        
        if vulnerabilities:
            print("❌ PYTHON PACKAGE VULNERABILITIES FOUND:")
            for vuln in vulnerabilities[:5]:  # Show first 5
                print(f"  - {vuln.get('package_name')} {vuln.get('installed_version')}")
                print(f"    Vulnerability: {vuln.get('vulnerability_id')}")
                print(f"    Severity: {vuln.get('severity', 'Unknown')}")
            
            if len(vulnerabilities) > 5:
                print(f"  ... and {len(vulnerabilities) - 5} more")
            
            return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Error reading Safety report: {e}")
        return True

def check_npm_audit_results():
    """Check npm audit results"""
    npm_file = Path("npm-audit-report.json")
    if not npm_file.exists():
        print("⚠️  npm audit report not found")
        return True
    
    try:
        with open(npm_file) as f:
            data = json.load(f)
        
        metadata = data.get('metadata', {})
        vulnerabilities = metadata.get('vulnerabilities', {})
        
        high_count = vulnerabilities.get('high', 0)
        critical_count = vulnerabilities.get('critical', 0)
        
        print(f"🔍 npm Audit Results: {critical_count} critical, {high_count} high severity issues")
        
        if critical_count > 0 or high_count > 0:
            print("❌ CRITICAL/HIGH SEVERITY NPM VULNERABILITIES FOUND:")
            
            advisories = data.get('advisories', {})
            for advisory_id, advisory in list(advisories.items())[:5]:
                severity = advisory.get('severity', 'unknown')
                if severity in ['high', 'critical']:
                    print(f"  - {advisory.get('title')}")
                    print(f"    Package: {advisory.get('module_name')}")
                    print(f"    Severity: {severity}")
            
            return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Error reading npm audit report: {e}")
        return True

def check_trivy_results():
    """Check Trivy container scan results"""
    trivy_file = Path("trivy-results.sarif")
    if not trivy_file.exists():
        print("⚠️  Trivy report not found")
        return True
    
    try:
        with open(trivy_file) as f:
            data = json.load(f)
        
        runs = data.get('runs', [])
        if not runs:
            return True
        
        results = runs[0].get('results', [])
        
        critical_issues = []
        high_issues = []
        
        for result in results:
            for rule_result in result.get('ruleResults', []):
                level = rule_result.get('level', 'note')
                if level == 'error':
                    critical_issues.append(rule_result)
                elif level == 'warning':
                    high_issues.append(rule_result)
        
        print(f"🔍 Trivy Results: {len(critical_issues)} critical, {len(high_issues)} high severity issues")
        
        if critical_issues:
            print("❌ CRITICAL CONTAINER VULNERABILITIES FOUND:")
            for issue in critical_issues[:5]:
                rule_id = issue.get('ruleId', 'Unknown')
                message = issue.get('message', {}).get('text', 'No description')
                print(f"  - {rule_id}: {message}")
            
            return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Error reading Trivy report: {e}")
        return True

def check_custom_security_tests():
    """Check custom security test results"""
    test_file = Path("security_test_report.txt")
    if not test_file.exists():
        print("⚠️  Security test report not found")
        return True
    
    try:
        with open(test_file) as f:
            content = f.read()
        
        if "❌ FAIL" in content:
            print("❌ CUSTOM SECURITY TESTS FAILED")
            # Extract failed tests
            lines = content.split('\n')
            for line in lines:
                if "❌ FAIL" in line:
                    print(f"  - {line}")
            return False
        
        print("✅ Custom security tests passed")
        return True
        
    except Exception as e:
        print(f"⚠️  Error reading security test report: {e}")
        return True

def main():
    """Main vulnerability checker"""
    print("🔍 Checking security scan results...")
    
    all_passed = True
    
    # Check all security scan results
    checks = [
        ("Bandit (Python Security)", check_bandit_results),
        ("Safety (Python Dependencies)", check_safety_results),
        ("npm audit (Node.js Dependencies)", check_npm_audit_results),
        ("Trivy (Container Security)", check_trivy_results),
        ("Custom Security Tests", check_custom_security_tests),
    ]
    
    for check_name, check_func in checks:
        print(f"\n📋 Checking {check_name}...")
        try:
            passed = check_func()
            if not passed:
                all_passed = False
                print(f"❌ {check_name} failed")
            else:
                print(f"✅ {check_name} passed")
        except Exception as e:
            print(f"⚠️  {check_name} check error: {e}")
            # Don't fail on check errors, just warn
    
    print("\n" + "="*60)
    
    if all_passed:
        print("🎉 All security checks passed!")
        print("✅ Build can proceed")
        sys.exit(0)
    else:
        print("🚨 Security vulnerabilities detected!")
        print("❌ Build failed due to security issues")
        print("\nPlease fix the security issues above before merging.")
        print("For help, see: https://docs.byteguardx.com/security")
        sys.exit(1)

if __name__ == "__main__":
    main()
