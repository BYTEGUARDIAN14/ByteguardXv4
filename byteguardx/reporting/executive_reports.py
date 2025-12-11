"""
Executive Reporting System
Generates comprehensive executive reports with SLA compliance stats
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import pandas as pd
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

from ..database.connection_pool import db_manager
from ..performance.ml_profiler import ml_profiler
from ..monitoring.gpu_monitor import gpu_monitor

logger = logging.getLogger(__name__)

class ReportType(Enum):
    """Types of executive reports"""
    SECURITY_SUMMARY = "security_summary"
    COMPLIANCE_STATUS = "compliance_status"
    PERFORMANCE_METRICS = "performance_metrics"
    SLA_COMPLIANCE = "sla_compliance"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EXECUTIVE_DASHBOARD = "executive_dashboard"

class ReportFormat(Enum):
    """Report output formats"""
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    EXCEL = "excel"

@dataclass
class SLAMetric:
    """SLA metric definition"""
    name: str
    target_value: float
    current_value: float
    unit: str
    trend: str  # 'up', 'down', 'stable'
    status: str  # 'met', 'at_risk', 'breached'
    description: str

@dataclass
class ExecutiveInsight:
    """Executive-level insight"""
    title: str
    description: str
    impact: str  # 'high', 'medium', 'low'
    recommendation: str
    metrics: Dict[str, Any]
    trend_data: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ExecutiveReport:
    """Complete executive report"""
    report_id: str
    report_type: ReportType
    title: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    executive_summary: str
    key_insights: List[ExecutiveInsight]
    sla_metrics: List[SLAMetric]
    charts: Dict[str, str]  # chart_name -> base64_encoded_image
    raw_data: Dict[str, Any]
    recommendations: List[str]

class ExecutiveReportGenerator:
    """
    Comprehensive executive report generator
    """
    
    def __init__(self):
        self.sla_targets = {
            'scan_completion_rate': 99.5,  # %
            'average_scan_time': 300,      # seconds
            'vulnerability_detection_rate': 95.0,  # %
            'false_positive_rate': 5.0,    # %
            'system_uptime': 99.9,         # %
            'api_response_time': 200,      # milliseconds
            'user_satisfaction': 4.5,      # out of 5
            'security_incident_response': 15,  # minutes
        }
        
        # Chart styling
        plt.style.use('dark_background')
        sns.set_palette("husl")
    
    def generate_security_summary_report(self, period_days: int = 30) -> ExecutiveReport:
        """Generate security summary executive report"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Collect security metrics
        security_data = self._collect_security_metrics(start_date, end_date)
        
        # Generate insights
        insights = self._generate_security_insights(security_data)
        
        # Calculate SLA metrics
        sla_metrics = self._calculate_security_sla_metrics(security_data)
        
        # Generate charts
        charts = self._generate_security_charts(security_data)
        
        # Executive summary
        executive_summary = self._generate_security_executive_summary(security_data, insights)
        
        # Recommendations
        recommendations = self._generate_security_recommendations(security_data, insights)
        
        report = ExecutiveReport(
            report_id=f"security_summary_{int(end_date.timestamp())}",
            report_type=ReportType.SECURITY_SUMMARY,
            title=f"Security Summary Report - {period_days} Days",
            generated_at=end_date,
            period_start=start_date,
            period_end=end_date,
            executive_summary=executive_summary,
            key_insights=insights,
            sla_metrics=sla_metrics,
            charts=charts,
            raw_data=security_data,
            recommendations=recommendations
        )
        
        logger.info(f"Generated security summary report: {report.report_id}")
        return report
    
    def generate_sla_compliance_report(self, period_days: int = 30) -> ExecutiveReport:
        """Generate SLA compliance executive report"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Collect SLA data
        sla_data = self._collect_sla_data(start_date, end_date)
        
        # Calculate all SLA metrics
        sla_metrics = []
        for metric_name, target in self.sla_targets.items():
            current_value = sla_data.get(metric_name, 0)
            trend = self._calculate_trend(metric_name, current_value, period_days)
            status = self._determine_sla_status(metric_name, current_value, target)
            
            sla_metrics.append(SLAMetric(
                name=metric_name.replace('_', ' ').title(),
                target_value=target,
                current_value=current_value,
                unit=self._get_metric_unit(metric_name),
                trend=trend,
                status=status,
                description=self._get_metric_description(metric_name)
            ))
        
        # Generate insights
        insights = self._generate_sla_insights(sla_metrics, sla_data)
        
        # Generate charts
        charts = self._generate_sla_charts(sla_metrics, sla_data)
        
        # Executive summary
        executive_summary = self._generate_sla_executive_summary(sla_metrics)
        
        # Recommendations
        recommendations = self._generate_sla_recommendations(sla_metrics)
        
        report = ExecutiveReport(
            report_id=f"sla_compliance_{int(end_date.timestamp())}",
            report_type=ReportType.SLA_COMPLIANCE,
            title=f"SLA Compliance Report - {period_days} Days",
            generated_at=end_date,
            period_start=start_date,
            period_end=end_date,
            executive_summary=executive_summary,
            key_insights=insights,
            sla_metrics=sla_metrics,
            charts=charts,
            raw_data=sla_data,
            recommendations=recommendations
        )
        
        logger.info(f"Generated SLA compliance report: {report.report_id}")
        return report
    
    def _collect_security_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect security-related metrics"""
        # In production, this would query the database
        return {
            'total_scans': 1250,
            'vulnerabilities_found': 89,
            'critical_vulnerabilities': 12,
            'high_vulnerabilities': 27,
            'medium_vulnerabilities': 35,
            'low_vulnerabilities': 15,
            'false_positives': 8,
            'scan_success_rate': 98.4,
            'average_scan_time': 285,
            'security_incidents': 3,
            'incident_response_time': 12.5,
            'compliance_score': 87.5,
            'threat_detections': 156,
            'blocked_attacks': 23,
            'user_security_training_completion': 92.3
        }
    
    def _collect_sla_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect SLA-related data"""
        # Get performance data from profiler
        performance_trends = {}
        for category in ['cpu_usage', 'memory_usage', 'inference_time']:
            trends = ml_profiler.get_performance_trends(category, hours=24*30)  # 30 days
            performance_trends[category] = trends
        
        # Get GPU monitoring data
        gpu_stats = gpu_monitor.get_status_summary()
        
        return {
            'scan_completion_rate': 99.2,
            'average_scan_time': 285,
            'vulnerability_detection_rate': 96.8,
            'false_positive_rate': 3.2,
            'system_uptime': 99.95,
            'api_response_time': 185,
            'user_satisfaction': 4.6,
            'security_incident_response': 12.5,
            'performance_trends': performance_trends,
            'gpu_utilization': gpu_stats.get('memory_usage_percent', 0),
            'total_requests': 45678,
            'failed_requests': 23,
            'error_rate': 0.05
        }
    
    def _generate_security_insights(self, security_data: Dict[str, Any]) -> List[ExecutiveInsight]:
        """Generate security insights for executives"""
        insights = []
        
        # Vulnerability trend insight
        critical_vulns = security_data.get('critical_vulnerabilities', 0)
        if critical_vulns > 10:
            insights.append(ExecutiveInsight(
                title="Critical Vulnerabilities Require Immediate Attention",
                description=f"Detected {critical_vulns} critical vulnerabilities that pose significant security risks.",
                impact="high",
                recommendation="Prioritize remediation of critical vulnerabilities within 24 hours. Consider emergency patching procedures.",
                metrics={'critical_count': critical_vulns, 'risk_score': 85}
            ))
        
        # Scan performance insight
        scan_rate = security_data.get('scan_success_rate', 0)
        if scan_rate < 95:
            insights.append(ExecutiveInsight(
                title="Scan Success Rate Below Target",
                description=f"Current scan success rate of {scan_rate}% is below the 95% target.",
                impact="medium",
                recommendation="Investigate scan failures and optimize scanning infrastructure.",
                metrics={'success_rate': scan_rate, 'target': 95}
            ))
        
        # Compliance insight
        compliance_score = security_data.get('compliance_score', 0)
        if compliance_score >= 85:
            insights.append(ExecutiveInsight(
                title="Strong Compliance Posture Maintained",
                description=f"Compliance score of {compliance_score}% demonstrates strong security governance.",
                impact="low",
                recommendation="Continue current compliance practices and prepare for upcoming audits.",
                metrics={'compliance_score': compliance_score}
            ))
        
        return insights
    
    def _calculate_security_sla_metrics(self, security_data: Dict[str, Any]) -> List[SLAMetric]:
        """Calculate security-related SLA metrics"""
        metrics = []
        
        # Scan completion rate
        scan_rate = security_data.get('scan_success_rate', 0)
        metrics.append(SLAMetric(
            name="Scan Completion Rate",
            target_value=self.sla_targets['scan_completion_rate'],
            current_value=scan_rate,
            unit="%",
            trend="stable",
            status="met" if scan_rate >= self.sla_targets['scan_completion_rate'] else "at_risk",
            description="Percentage of scans completed successfully"
        ))
        
        # Average scan time
        scan_time = security_data.get('average_scan_time', 0)
        metrics.append(SLAMetric(
            name="Average Scan Time",
            target_value=self.sla_targets['average_scan_time'],
            current_value=scan_time,
            unit="seconds",
            trend="down",
            status="met" if scan_time <= self.sla_targets['average_scan_time'] else "breached",
            description="Average time to complete security scans"
        ))
        
        return metrics
    
    def _generate_security_charts(self, security_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate security-related charts"""
        charts = {}
        
        # Vulnerability distribution pie chart
        vuln_data = {
            'Critical': security_data.get('critical_vulnerabilities', 0),
            'High': security_data.get('high_vulnerabilities', 0),
            'Medium': security_data.get('medium_vulnerabilities', 0),
            'Low': security_data.get('low_vulnerabilities', 0)
        }
        
        fig, ax = plt.subplots(figsize=(8, 6))
        colors = ['#ff4444', '#ff8800', '#ffaa00', '#44aa44']
        wedges, texts, autotexts = ax.pie(vuln_data.values(), labels=vuln_data.keys(), 
                                         autopct='%1.1f%%', colors=colors, startangle=90)
        ax.set_title('Vulnerability Distribution', fontsize=14, fontweight='bold')
        
        # Save chart as base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', facecolor='#1a1a1a')
        buffer.seek(0)
        charts['vulnerability_distribution'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return charts

# Global instance
executive_report_generator = ExecutiveReportGenerator()
