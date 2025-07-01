"""
Compliance reporting for ByteGuardX
Provides automated compliance reports for various security frameworks
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    NIST = "nist"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    CIS = "cis"

@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    requirement: str
    status: str  # "compliant", "non_compliant", "partial", "not_applicable"
    evidence: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    last_assessed: Optional[datetime] = None

@dataclass
class ComplianceReport:
    """Compliance assessment report"""
    report_id: str
    framework: ComplianceFramework
    organization: str
    assessment_period_start: datetime
    assessment_period_end: datetime
    generated_at: datetime
    controls: List[ComplianceControl] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def compliance_score(self) -> float:
        """Calculate overall compliance score"""
        if not self.controls:
            return 0.0
        
        compliant_count = sum(1 for c in self.controls if c.status == "compliant")
        return (compliant_count / len(self.controls)) * 100

class ComplianceReporter:
    """
    Automated compliance reporting system
    Generates compliance reports for various security frameworks
    """
    
    def __init__(self, reports_dir: str = "data/compliance"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize framework controls
        self.framework_controls = self._initialize_framework_controls()
    
    def generate_report(self, framework: ComplianceFramework, 
                       organization: str = "ByteGuardX Organization",
                       assessment_period_days: int = 30) -> ComplianceReport:
        """Generate compliance report for specified framework"""
        try:
            import uuid
            
            # Calculate assessment period
            end_date = datetime.now()
            start_date = end_date - timedelta(days=assessment_period_days)
            
            # Create report
            report = ComplianceReport(
                report_id=str(uuid.uuid4()),
                framework=framework,
                organization=organization,
                assessment_period_start=start_date,
                assessment_period_end=end_date,
                generated_at=datetime.now()
            )
            
            # Assess controls for the framework
            controls = self.framework_controls.get(framework, [])
            for control_template in controls:
                assessed_control = self._assess_control(control_template, start_date, end_date)
                report.controls.append(assessed_control)
            
            # Generate summary
            report.summary = self._generate_summary(report)
            
            # Generate recommendations
            report.recommendations = self._generate_recommendations(report)
            
            # Save report
            self._save_report(report)
            
            logger.info(f"Generated {framework.value} compliance report: {report.report_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    def _assess_control(self, control_template: Dict[str, Any], 
                       start_date: datetime, end_date: datetime) -> ComplianceControl:
        """Assess individual compliance control"""
        try:
            # This is a simplified assessment - in production would integrate with actual security data
            control = ComplianceControl(
                control_id=control_template['id'],
                framework=ComplianceFramework(control_template['framework']),
                title=control_template['title'],
                description=control_template['description'],
                requirement=control_template['requirement'],
                status="compliant",  # Default to compliant for demo
                last_assessed=datetime.now()
            )
            
            # Simulate assessment based on control type
            if "access_control" in control_template.get('category', ''):
                control.evidence.append("RBAC system implemented with fine-grained permissions")
                control.evidence.append("User access reviews conducted monthly")
                control.status = "compliant"
            
            elif "vulnerability_management" in control_template.get('category', ''):
                control.evidence.append("Automated vulnerability scanning implemented")
                control.evidence.append("Critical vulnerabilities remediated within 24 hours")
                control.status = "compliant"
            
            elif "audit_logging" in control_template.get('category', ''):
                control.evidence.append("Comprehensive audit trail implemented")
                control.evidence.append("Log retention policy of 1 year enforced")
                control.status = "compliant"
            
            elif "data_protection" in control_template.get('category', ''):
                control.evidence.append("Data encryption at rest and in transit")
                control.evidence.append("Data classification and handling procedures")
                control.status = "compliant"
            
            else:
                control.status = "partial"
                control.findings.append("Manual assessment required")
                control.remediation.append("Implement automated controls")
            
            return control
            
        except Exception as e:
            logger.error(f"Failed to assess control {control_template.get('id', 'unknown')}: {e}")
            # Return a default control in case of error
            return ComplianceControl(
                control_id=control_template.get('id', 'unknown'),
                framework=ComplianceFramework(control_template.get('framework', 'soc2')),
                title=control_template.get('title', 'Unknown Control'),
                description=control_template.get('description', ''),
                requirement=control_template.get('requirement', ''),
                status="not_applicable",
                last_assessed=datetime.now()
            )
    
    def _generate_summary(self, report: ComplianceReport) -> Dict[str, Any]:
        """Generate report summary"""
        total_controls = len(report.controls)
        compliant_controls = sum(1 for c in report.controls if c.status == "compliant")
        non_compliant_controls = sum(1 for c in report.controls if c.status == "non_compliant")
        partial_controls = sum(1 for c in report.controls if c.status == "partial")
        
        return {
            "total_controls": total_controls,
            "compliant_controls": compliant_controls,
            "non_compliant_controls": non_compliant_controls,
            "partial_controls": partial_controls,
            "compliance_score": report.compliance_score,
            "assessment_period_days": (report.assessment_period_end - report.assessment_period_start).days,
            "risk_level": "low" if report.compliance_score >= 90 else "medium" if report.compliance_score >= 70 else "high"
        }
    
    def _generate_recommendations(self, report: ComplianceReport) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        # Analyze non-compliant controls
        non_compliant = [c for c in report.controls if c.status == "non_compliant"]
        if non_compliant:
            recommendations.append(f"Address {len(non_compliant)} non-compliant controls immediately")
        
        # Analyze partial controls
        partial = [c for c in report.controls if c.status == "partial"]
        if partial:
            recommendations.append(f"Complete implementation of {len(partial)} partially compliant controls")
        
        # Score-based recommendations
        if report.compliance_score < 70:
            recommendations.append("Implement comprehensive security program to improve compliance posture")
        elif report.compliance_score < 90:
            recommendations.append("Focus on automation and continuous monitoring to achieve full compliance")
        
        # Framework-specific recommendations
        if report.framework == ComplianceFramework.SOC2:
            recommendations.append("Conduct annual SOC 2 Type II audit")
            recommendations.append("Implement continuous monitoring for security controls")
        
        elif report.framework == ComplianceFramework.ISO27001:
            recommendations.append("Establish Information Security Management System (ISMS)")
            recommendations.append("Conduct regular risk assessments and management reviews")
        
        elif report.framework == ComplianceFramework.PCI_DSS:
            recommendations.append("Implement network segmentation for cardholder data environment")
            recommendations.append("Conduct quarterly vulnerability scans")
        
        return recommendations
    
    def _save_report(self, report: ComplianceReport):
        """Save compliance report to storage"""
        try:
            report_file = self.reports_dir / f"{report.framework.value}_{report.report_id}.json"
            
            # Convert to serializable format
            report_data = {
                "report_id": report.report_id,
                "framework": report.framework.value,
                "organization": report.organization,
                "assessment_period_start": report.assessment_period_start.isoformat(),
                "assessment_period_end": report.assessment_period_end.isoformat(),
                "generated_at": report.generated_at.isoformat(),
                "controls": [
                    {
                        "control_id": c.control_id,
                        "framework": c.framework.value,
                        "title": c.title,
                        "description": c.description,
                        "requirement": c.requirement,
                        "status": c.status,
                        "evidence": c.evidence,
                        "findings": c.findings,
                        "remediation": c.remediation,
                        "last_assessed": c.last_assessed.isoformat() if c.last_assessed else None
                    }
                    for c in report.controls
                ],
                "summary": report.summary,
                "recommendations": report.recommendations
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Saved compliance report to {report_file}")
            
        except Exception as e:
            logger.error(f"Failed to save compliance report: {e}")
    
    def _initialize_framework_controls(self) -> Dict[ComplianceFramework, List[Dict[str, Any]]]:
        """Initialize compliance framework controls"""
        return {
            ComplianceFramework.SOC2: [
                {
                    "id": "CC6.1",
                    "framework": "soc2",
                    "title": "Logical and Physical Access Controls",
                    "description": "The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.",
                    "requirement": "Implement access controls to restrict access to system resources",
                    "category": "access_control"
                },
                {
                    "id": "CC7.1",
                    "framework": "soc2",
                    "title": "System Monitoring",
                    "description": "The entity monitors system components and the operation of controls to detect anomalies.",
                    "requirement": "Implement monitoring and alerting for security events",
                    "category": "monitoring"
                },
                {
                    "id": "CC8.1",
                    "framework": "soc2",
                    "title": "Change Management",
                    "description": "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to system components.",
                    "requirement": "Implement formal change management process",
                    "category": "change_management"
                }
            ],
            ComplianceFramework.ISO27001: [
                {
                    "id": "A.9.1.1",
                    "framework": "iso27001",
                    "title": "Access Control Policy",
                    "description": "An access control policy shall be established, documented and reviewed based on business and information security requirements.",
                    "requirement": "Establish and maintain access control policy",
                    "category": "access_control"
                },
                {
                    "id": "A.12.6.1",
                    "framework": "iso27001",
                    "title": "Management of Technical Vulnerabilities",
                    "description": "Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion.",
                    "requirement": "Implement vulnerability management process",
                    "category": "vulnerability_management"
                },
                {
                    "id": "A.12.4.1",
                    "framework": "iso27001",
                    "title": "Event Logging",
                    "description": "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
                    "requirement": "Implement comprehensive audit logging",
                    "category": "audit_logging"
                }
            ],
            ComplianceFramework.PCI_DSS: [
                {
                    "id": "1.1",
                    "framework": "pci_dss",
                    "title": "Firewall Configuration Standards",
                    "description": "Establish and implement firewall and router configuration standards.",
                    "requirement": "Implement and maintain firewall configuration",
                    "category": "network_security"
                },
                {
                    "id": "6.1",
                    "framework": "pci_dss",
                    "title": "Security Vulnerability Management",
                    "description": "Establish a process to identify security vulnerabilities and assign a risk ranking to newly discovered security vulnerabilities.",
                    "requirement": "Implement vulnerability management program",
                    "category": "vulnerability_management"
                },
                {
                    "id": "10.1",
                    "framework": "pci_dss",
                    "title": "Audit Trail Implementation",
                    "description": "Implement audit trails to link all access to system components to each individual user.",
                    "requirement": "Implement comprehensive audit trails",
                    "category": "audit_logging"
                }
            ]
        }

# Global compliance reporter
compliance_reporter = ComplianceReporter()
