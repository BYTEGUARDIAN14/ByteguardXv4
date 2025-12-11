#!/usr/bin/env python3
"""
Direct demonstration of ByteGuardX real scanning capabilities
This bypasses API authentication to show the enhanced scanning system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from byteguardx.core.unified_scanner import UnifiedScanner, ScanContext, ScanMode
from byteguardx.validation.verify_scan_results import ResultVerifier
from byteguardx.validation.plugin_result_trust_score import PluginTrustScorer
from byteguardx.reports.real_security_report import RealSecurityReportGenerator
from pathlib import Path
import json

def demonstrate_real_scanning():
    """Demonstrate the real scanning capabilities"""
    
    print("🛡️  ByteGuardX Real Scanning Demonstration")
    print("=" * 60)
    
    # Read the vulnerable test file
    test_file = "test_vulnerable_code.py"
    if not Path(test_file).exists():
        print(f"❌ Test file {test_file} not found!")
        return
    
    with open(test_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print(f"📁 Analyzing: {test_file}")
    print(f"📊 Size: {len(content):,} characters")
    print(f"📝 Lines: {len(content.splitlines()):,}")
    print()
    
    # Initialize the enhanced scanning system
    print("🔧 Initializing Enhanced Scanning System...")
    scanner = UnifiedScanner()
    verifier = ResultVerifier()
    trust_scorer = PluginTrustScorer()
    report_generator = RealSecurityReportGenerator()
    
    # Create scan context
    context = ScanContext(
        file_path=test_file,
        content=content,
        language="python",
        file_size=len(content),
        scan_mode=ScanMode.COMPREHENSIVE,
        confidence_threshold=0.6,
        enable_ml=True,
        enable_plugins=True,
        enable_cross_validation=True,
        enable_false_positive_filtering=True
    )
    
    print("🔍 Starting Comprehensive Scan...")
    print("-" * 40)
    
    # Perform the scan
    findings = scanner.scan_content(context)
    
    print(f"✅ Scan completed! Found {len(findings)} potential issues")
    print()
    
    # Display findings by category
    display_findings_by_category(findings)
    
    # Verify findings
    print("🔍 VERIFICATION RESULTS")
    print("-" * 40)
    
    verification_reports = []
    for finding in findings:
        finding_dict = {
            'type': finding.type,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'description': finding.description,
            'severity': finding.severity,
            'confidence': finding.confidence
        }
        
        verification_report = verifier.verify_finding(finding_dict)
        verification_reports.append(verification_report)
    
    # Display verification summary
    verified_count = len([r for r in verification_reports if r.verification_result.value == 'verified'])
    rejected_count = len([r for r in verification_reports if r.verification_result.value == 'rejected'])
    uncertain_count = len([r for r in verification_reports if r.verification_result.value == 'uncertain'])
    
    print(f"✅ Verified: {verified_count}")
    print(f"❌ Rejected: {rejected_count}")
    print(f"❓ Uncertain: {uncertain_count}")
    print()
    
    # Generate comprehensive security report
    print("📋 GENERATING SECURITY REPORT")
    print("-" * 40)
    
    # Convert findings to dict format for report
    findings_dict = []
    for finding in findings:
        findings_dict.append({
            'type': finding.type,
            'subtype': finding.subtype,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'description': finding.description,
            'verification_status': finding.verification_status.value,
            'cwe_id': getattr(finding, 'cwe_id', ''),
            'owasp_category': getattr(finding, 'owasp_category', ''),
            'cvss_score': getattr(finding, 'cvss_score', 0.0),
            'recommendation': getattr(finding, 'recommendation', ''),
            'scanner_source': finding.scanner_source
        })
    
    scan_results = {
        'findings': findings_dict,
        'scan_metadata': {
            'scan_mode': 'comprehensive',
            'file_path': test_file,
            'processing_time': 2.5,
            'scanners_used': ['SecretScanner', 'VulnerabilityScanner', 'DependencyScanner']
        },
        'verification_stats': {
            'total_verifications': len(verification_reports),
            'verification_rate': verified_count / len(verification_reports) if verification_reports else 0,
            'false_positive_rate': rejected_count / len(verification_reports) if verification_reports else 0
        }
    }
    
    # Generate the report
    security_report = report_generator.generate_comprehensive_report(scan_results)
    
    # Display key report sections
    display_security_report_summary(security_report)
    
    # Save detailed report
    with open('security_report.json', 'w') as f:
        json.dump(security_report, f, indent=2, default=str)
    
    print(f"📄 Detailed report saved to: security_report.json")
    print()
    
    # Display scanner statistics
    display_scanner_statistics(scanner, verifier, trust_scorer)

def display_findings_by_category(findings):
    """Display findings organized by category and severity"""
    
    # Group by type and severity
    by_type = {}
    by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    for finding in findings:
        # By type
        if finding.type not in by_type:
            by_type[finding.type] = []
        by_type[finding.type].append(finding)
        
        # By severity
        severity = finding.severity.lower()
        if severity in by_severity:
            by_severity[severity].append(finding)
    
    print("📊 FINDINGS BY TYPE")
    print("-" * 30)
    for vuln_type, type_findings in by_type.items():
        print(f"🔍 {vuln_type.upper()}: {len(type_findings)} findings")
        
        # Show top 3 examples
        for i, finding in enumerate(type_findings[:3], 1):
            print(f"   {i}. {finding.description}")
            print(f"      📍 Line {finding.line_number} | {finding.severity.upper()} | {finding.confidence:.1%}")
        
        if len(type_findings) > 3:
            print(f"   ... and {len(type_findings) - 3} more")
        print()
    
    print("🚨 FINDINGS BY SEVERITY")
    print("-" * 30)
    for severity in ['critical', 'high', 'medium', 'low']:
        count = len(by_severity[severity])
        if count > 0:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
            print(f"{emoji[severity]} {severity.upper()}: {count} findings")
            
            # Show examples
            for finding in by_severity[severity][:2]:
                print(f"   • {finding.description} (Line {finding.line_number})")
    print()

def display_security_report_summary(report):
    """Display key sections of the security report"""
    
    exec_summary = report.get('executive_summary', {})
    risk_assessment = report.get('risk_assessment', {})
    compliance = report.get('compliance_status', {})
    
    print("🎯 EXECUTIVE SUMMARY")
    print("-" * 30)
    print(f"Security Posture: {exec_summary.get('security_posture', 'Unknown')}")
    print(f"Overall Risk Score: {exec_summary.get('overall_risk_score', 0)}/10")
    print(f"Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
    print(f"Critical Issues: {exec_summary.get('critical_issues', 0)}")
    print(f"High Priority: {exec_summary.get('high_priority_issues', 0)}")
    print(f"Average CVSS: {exec_summary.get('average_cvss_score', 0)}")
    print()
    
    print("⚠️  RISK ASSESSMENT")
    print("-" * 30)
    print(f"Risk Level: {risk_assessment.get('overall_risk_level', 'Unknown')}")
    print(f"Business Impact: {risk_assessment.get('business_impact', 'Unknown')}")
    print(f"Exploitation Likelihood: {risk_assessment.get('exploitation_likelihood', 'Unknown')}")
    print(f"Time to Remediation: {risk_assessment.get('time_to_remediation_days', 0)} days")
    print()
    
    print("📋 COMPLIANCE STATUS")
    print("-" * 30)
    owasp = compliance.get('owasp_top_10', {})
    print(f"OWASP Top 10 Score: {owasp.get('compliance_score', 0)}/100")
    print(f"PCI DSS: {compliance.get('pci_dss', {}).get('compliance_status', 'Unknown')}")
    print()
    
    # Show top recommendations
    recommendations = exec_summary.get('key_recommendations', [])
    if recommendations:
        print("💡 KEY RECOMMENDATIONS")
        print("-" * 30)
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        print()

def display_scanner_statistics(scanner, verifier, trust_scorer):
    """Display statistics from all scanner components"""
    
    scan_stats = scanner.get_scan_statistics()
    verification_stats = verifier.get_verification_statistics()
    trust_stats = trust_scorer.get_trust_statistics()
    
    print("📈 SCANNER PERFORMANCE")
    print("-" * 30)
    print(f"Total Scans: {scan_stats.get('total_scans', 0)}")
    print(f"Average Processing Time: {scan_stats.get('avg_processing_time', 0):.2f}s")
    print(f"Cache Hit Rate: {scan_stats.get('cache_hits', 0)}/{scan_stats.get('total_scans', 1)}")
    print(f"False Positive Rate: {scan_stats.get('false_positive_rate', 0):.1%}")
    print()
    
    print("✅ VERIFICATION METRICS")
    print("-" * 30)
    print(f"Total Verifications: {verification_stats.get('total_verifications', 0)}")
    print(f"Verification Rate: {verification_stats.get('verification_rate', 0):.1%}")
    print(f"Average Confidence: {verification_stats.get('average_confidence', 0):.1%}")
    print()
    
    print("🔧 PLUGIN TRUST SCORES")
    print("-" * 30)
    print(f"Total Plugins: {trust_stats.get('total_plugins', 0)}")
    print(f"High Trust Plugins: {trust_stats.get('high_trust_plugins', 0)}")
    print(f"Risky Plugins: {trust_stats.get('risky_plugins', 0)}")
    print(f"Average Trust Score: {trust_stats.get('average_trust_score', 0):.1%}")

if __name__ == "__main__":
    print("🚀 Starting ByteGuardX Real Scanning Demo")
    print()
    
    try:
        demonstrate_real_scanning()
        print("🎉 Demo completed successfully!")
        print("📚 Check security_report.json for detailed analysis")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
