"""
PDF Report Generator - Generate professional security reports
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from jinja2 import Template, Environment, FileSystemLoader
import weasyprint

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """
    Professional PDF report generator for security scan results
    """
    
    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir or self._get_default_template_dir()
        self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        
    def _get_default_template_dir(self) -> str:
        """Get default template directory"""
        current_dir = Path(__file__).parent
        template_dir = current_dir / "templates"
        template_dir.mkdir(exist_ok=True)
        return str(template_dir)
    
    def _create_default_template(self) -> str:
        """Create default HTML template for reports"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ByteGuardX Security Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .logo {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e40af;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #6b7280;
            font-size: 1.1em;
        }
        
        .summary {
            background: #f8fafc;
            border-left: 4px solid #2563eb;
            padding: 20px;
            margin: 20px 0;
        }
        
        .summary h2 {
            margin-top: 0;
            color: #1e40af;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #6b7280;
            font-size: 0.9em;
        }
        
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #d97706; }
        .low { color: #65a30d; }
        
        .findings-section {
            margin: 30px 0;
        }
        
        .finding {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
        }
        
        .finding-header {
            padding: 15px;
            background: #f9fafb;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .finding-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .finding-meta {
            font-size: 0.9em;
            color: #6b7280;
        }
        
        .finding-body {
            padding: 15px;
        }
        
        .code-block {
            background: #1f2937;
            color: #f9fafb;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .recommendation {
            background: #ecfdf5;
            border: 1px solid #10b981;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .recommendation-title {
            font-weight: bold;
            color: #047857;
            margin-bottom: 5px;
        }
        
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            font-size: 0.9em;
        }
        
        @media print {
            body { margin: 0; padding: 15px; }
            .finding { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">ByteGuardX</div>
        <div class="subtitle">AI-Powered Security Vulnerability Report</div>
        <div style="margin-top: 15px; color: #6b7280;">
            Generated on {{ report_date }} | Scan ID: {{ scan_id }}
        </div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report contains the results of a comprehensive security scan performed on your codebase. 
        ByteGuardX analyzed {{ total_files }} files and identified {{ total_findings }} potential security issues.</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">{{ severity_counts.critical or 0 }}</div>
                <div class="stat-label">Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{{ severity_counts.high or 0 }}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{{ severity_counts.medium or 0 }}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{{ severity_counts.low or 0 }}</div>
                <div class="stat-label">Low Risk</div>
            </div>
        </div>
    </div>

    {% if findings %}
    <div class="findings-section">
        <h2>Detailed Findings</h2>
        
        {% for finding in findings %}
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="{{ finding.severity }}">{{ finding.severity.upper() }}</span> - 
                    {{ finding.description or finding.type }}
                </div>
                <div class="finding-meta">
                    File: {{ finding.file_path }} | Line: {{ finding.line_number }}
                    {% if finding.confidence %}| Confidence: {{ "%.0f"|format(finding.confidence * 100) }}%{% endif %}
                </div>
            </div>
            
            <div class="finding-body">
                {% if finding.context %}
                <div>
                    <strong>Code Context:</strong>
                    <div class="code-block">{{ finding.context }}</div>
                </div>
                {% endif %}
                
                {% if finding.recommendation %}
                <div class="recommendation">
                    <div class="recommendation-title">Recommendation:</div>
                    {{ finding.recommendation }}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
    {% endif %}

    {% if fixes %}
    <div class="findings-section">
        <h2>Suggested Fixes</h2>
        
        {% for fix in fixes %}
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">Fix for {{ fix.vulnerability_type }}</div>
                <div class="finding-meta">
                    File: {{ fix.file_path }} | Line: {{ fix.line_number }}
                    | Confidence: {{ "%.0f"|format(fix.confidence * 100) }}%
                </div>
            </div>
            
            <div class="finding-body">
                <div>
                    <strong>Original Code:</strong>
                    <div class="code-block">{{ fix.original_code }}</div>
                </div>
                
                <div>
                    <strong>Suggested Fix:</strong>
                    <div class="code-block">{{ fix.fixed_code }}</div>
                </div>
                
                <div class="recommendation">
                    <div class="recommendation-title">Explanation:</div>
                    {{ fix.explanation }}
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <div class="footer">
        <p>This report was generated by ByteGuardX - AI-Powered Vulnerability Scanner</p>
        <p>For more information, visit: https://github.com/byteguardx/byteguardx</p>
    </div>
</body>
</html>
        """
    
    def _ensure_template_exists(self):
        """Ensure the default template file exists"""
        template_path = Path(self.template_dir) / "report_template.html"
        if not template_path.exists():
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(self._create_default_template())
            # Set secure permissions (owner read/write only)
            template_path.chmod(0o600)
    
    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity level"""
        grouped = {"critical": [], "high": [], "medium": [], "low": []}
        
        for finding in findings:
            severity = finding.get("severity", "low").lower()
            if severity in grouped:
                grouped[severity].append(finding)
            else:
                grouped["low"].append(finding)
        
        return grouped
    
    def _calculate_severity_counts(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate count of findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for finding in findings:
            severity = finding.get("severity", "low").lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["low"] += 1
        
        return counts
    
    def generate_report(self, 
                       findings: List[Dict], 
                       fixes: List[Dict] = None,
                       scan_metadata: Dict = None,
                       output_path: str = None) -> str:
        """
        Generate PDF report from scan results
        """
        try:
            self._ensure_template_exists()
            
            # Prepare report data
            report_data = {
                "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_id": scan_metadata.get("scan_id", "N/A") if scan_metadata else "N/A",
                "total_files": scan_metadata.get("total_files", 0) if scan_metadata else 0,
                "total_findings": len(findings),
                "findings": sorted(findings, key=lambda x: {
                    "critical": 0, "high": 1, "medium": 2, "low": 3
                }.get(x.get("severity", "low").lower(), 3)),
                "fixes": fixes or [],
                "severity_counts": self._calculate_severity_counts(findings),
                "grouped_findings": self._group_findings_by_severity(findings)
            }
            
            # Load and render template
            template = self.jinja_env.get_template("report_template.html")
            html_content = template.render(**report_data)
            
            # Generate PDF
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"byteguardx_report_{timestamp}.pdf"
            
            # Ensure output directory exists
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate PDF using WeasyPrint
            weasyprint.HTML(string=html_content).write_pdf(output_path)

            # Set secure permissions on generated PDF
            Path(output_path).chmod(0o600)

            logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def generate_html_report(self, 
                            findings: List[Dict], 
                            fixes: List[Dict] = None,
                            scan_metadata: Dict = None,
                            output_path: str = None) -> str:
        """
        Generate HTML report from scan results
        """
        try:
            self._ensure_template_exists()
            
            # Prepare report data (same as PDF)
            report_data = {
                "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_id": scan_metadata.get("scan_id", "N/A") if scan_metadata else "N/A",
                "total_files": scan_metadata.get("total_files", 0) if scan_metadata else 0,
                "total_findings": len(findings),
                "findings": sorted(findings, key=lambda x: {
                    "critical": 0, "high": 1, "medium": 2, "low": 3
                }.get(x.get("severity", "low").lower(), 3)),
                "fixes": fixes or [],
                "severity_counts": self._calculate_severity_counts(findings),
                "grouped_findings": self._group_findings_by_severity(findings)
            }
            
            # Load and render template
            template = self.jinja_env.get_template("report_template.html")
            html_content = template.render(**report_data)
            
            # Save HTML file
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"byteguardx_report_{timestamp}.html"
            
            # Ensure output directory exists
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            # Set secure permissions on generated HTML
            Path(output_path).chmod(0o600)

            logger.info(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
