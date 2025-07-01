"""
Analytics Dashboard - Executive insights and metrics
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SecurityMetrics:
    """Security metrics data structure"""
    total_scans: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    fixed_issues: int = 0
    false_positives: int = 0
    scan_frequency: float = 0.0
    avg_resolution_time: float = 0.0
    security_score: float = 0.0

@dataclass
class TrendData:
    """Trend analysis data"""
    period: str
    value: float
    change_percent: float
    previous_value: float

class AnalyticsDashboard:
    """
    Executive analytics dashboard for security insights
    """
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.scans_file = self.data_dir / "scan_history.json"
        self.metrics_file = self.data_dir / "metrics.json"
        
        # Initialize files if they don't exist
        for file_path in [self.scans_file, self.metrics_file]:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump([], f)
    
    def record_scan(self, scan_data: Dict):
        """Record a completed scan for analytics"""
        try:
            # Load existing scans
            scans = self._load_scan_history()
            
            # Add timestamp and normalize data
            scan_record = {
                'scan_id': scan_data.get('scan_id'),
                'timestamp': datetime.now().isoformat(),
                'user_id': scan_data.get('user_id'),
                'organization_id': scan_data.get('organization_id'),
                'total_files': scan_data.get('total_files', 0),
                'total_findings': scan_data.get('total_findings', 0),
                'findings_by_severity': scan_data.get('findings_by_severity', {}),
                'findings_by_type': scan_data.get('findings_by_type', {}),
                'scan_duration': scan_data.get('scan_duration', 0),
                'languages_detected': scan_data.get('languages_detected', []),
                'fix_suggestions': scan_data.get('fix_suggestions', 0)
            }
            
            scans.append(scan_record)
            
            # Keep only last 1000 scans to prevent file from growing too large
            if len(scans) > 1000:
                scans = scans[-1000:]
            
            self._save_scan_history(scans)
            
            # Update metrics
            self._update_metrics()
            
        except Exception as e:
            logger.error(f"Failed to record scan: {e}")
    
    def get_executive_summary(self, days: int = 30, organization_id: str = None) -> Dict:
        """Get executive summary for the dashboard"""
        try:
            scans = self._load_scan_history()
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Filter scans by date and organization
            filtered_scans = []
            for scan in scans:
                scan_date = datetime.fromisoformat(scan['timestamp'])
                if scan_date >= cutoff_date:
                    if organization_id is None or scan.get('organization_id') == organization_id:
                        filtered_scans.append(scan)
            
            if not filtered_scans:
                return self._empty_summary()
            
            # Calculate metrics
            total_scans = len(filtered_scans)
            total_findings = sum(scan['total_findings'] for scan in filtered_scans)
            total_files = sum(scan['total_files'] for scan in filtered_scans)
            
            # Severity breakdown
            severity_counts = defaultdict(int)
            for scan in filtered_scans:
                for severity, count in scan.get('findings_by_severity', {}).items():
                    severity_counts[severity] += count
            
            # Type breakdown
            type_counts = defaultdict(int)
            for scan in filtered_scans:
                for finding_type, count in scan.get('findings_by_type', {}).items():
                    type_counts[finding_type] += count
            
            # Calculate security score (0-100, higher is better)
            security_score = self._calculate_security_score(filtered_scans)
            
            # Trend analysis
            trends = self._calculate_trends(filtered_scans, days)
            
            # Top vulnerabilities
            top_vulnerabilities = self._get_top_vulnerabilities(filtered_scans)
            
            # Language analysis
            language_stats = self._analyze_languages(filtered_scans)
            
            return {
                'period': f"Last {days} days",
                'summary': {
                    'total_scans': total_scans,
                    'total_findings': total_findings,
                    'total_files_scanned': total_files,
                    'security_score': security_score,
                    'avg_findings_per_scan': round(total_findings / total_scans, 2) if total_scans > 0 else 0,
                    'scan_frequency': round(total_scans / days, 2)
                },
                'severity_breakdown': dict(severity_counts),
                'type_breakdown': dict(type_counts),
                'trends': trends,
                'top_vulnerabilities': top_vulnerabilities,
                'language_stats': language_stats,
                'recommendations': self._generate_recommendations(filtered_scans, security_score)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return self._empty_summary()
    
    def get_compliance_report(self, framework: str = "owasp", organization_id: str = None) -> Dict:
        """Generate compliance report for specific framework"""
        try:
            scans = self._load_scan_history()
            
            # Filter by organization if specified
            if organization_id:
                scans = [s for s in scans if s.get('organization_id') == organization_id]
            
            if framework.lower() == "owasp":
                return self._generate_owasp_report(scans)
            elif framework.lower() == "pci":
                return self._generate_pci_report(scans)
            elif framework.lower() == "sox":
                return self._generate_sox_report(scans)
            else:
                return {'error': f'Unsupported compliance framework: {framework}'}
                
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {'error': 'Failed to generate compliance report'}
    
    def get_user_analytics(self, user_id: str, days: int = 30) -> Dict:
        """Get analytics for specific user"""
        try:
            scans = self._load_scan_history()
            cutoff_date = datetime.now() - timedelta(days=days)
            
            user_scans = []
            for scan in scans:
                scan_date = datetime.fromisoformat(scan['timestamp'])
                if scan_date >= cutoff_date and scan.get('user_id') == user_id:
                    user_scans.append(scan)
            
            if not user_scans:
                return {'user_id': user_id, 'scans': 0, 'findings': 0}
            
            total_scans = len(user_scans)
            total_findings = sum(scan['total_findings'] for scan in user_scans)
            
            # Most active days
            scan_dates = [datetime.fromisoformat(scan['timestamp']).date() for scan in user_scans]
            daily_activity = Counter(scan_dates)
            
            return {
                'user_id': user_id,
                'period': f"Last {days} days",
                'total_scans': total_scans,
                'total_findings': total_findings,
                'avg_findings_per_scan': round(total_findings / total_scans, 2),
                'most_active_day': str(daily_activity.most_common(1)[0][0]) if daily_activity else None,
                'daily_activity': {str(date): count for date, count in daily_activity.items()}
            }
            
        except Exception as e:
            logger.error(f"Failed to get user analytics: {e}")
            return {'error': 'Failed to get user analytics'}
    
    def _calculate_security_score(self, scans: List[Dict]) -> float:
        """Calculate overall security score (0-100)"""
        if not scans:
            return 100.0
        
        total_findings = sum(scan['total_findings'] for scan in scans)
        total_files = sum(scan['total_files'] for scan in scans)
        
        if total_files == 0:
            return 100.0
        
        # Calculate findings per file ratio
        findings_per_file = total_findings / total_files
        
        # Score calculation (lower findings = higher score)
        # Assume 0 findings per file = 100, 1 finding per file = 50, 2+ = 0
        score = max(0, 100 - (findings_per_file * 50))
        
        return round(score, 1)
    
    def _calculate_trends(self, scans: List[Dict], days: int) -> Dict:
        """Calculate trend data"""
        if len(scans) < 2:
            return {}
        
        # Split scans into two periods
        mid_point = len(scans) // 2
        recent_scans = scans[mid_point:]
        older_scans = scans[:mid_point]
        
        recent_avg = sum(scan['total_findings'] for scan in recent_scans) / len(recent_scans)
        older_avg = sum(scan['total_findings'] for scan in older_scans) / len(older_scans)
        
        change_percent = ((recent_avg - older_avg) / older_avg * 100) if older_avg > 0 else 0
        
        return {
            'findings_trend': {
                'current_avg': round(recent_avg, 2),
                'previous_avg': round(older_avg, 2),
                'change_percent': round(change_percent, 2),
                'direction': 'up' if change_percent > 0 else 'down' if change_percent < 0 else 'stable'
            }
        }
    
    def _get_top_vulnerabilities(self, scans: List[Dict], limit: int = 10) -> List[Dict]:
        """Get most common vulnerability types"""
        type_counts = defaultdict(int)
        
        for scan in scans:
            for vuln_type, count in scan.get('findings_by_type', {}).items():
                type_counts[vuln_type] += count
        
        # Sort by count and return top N
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'type': vuln_type, 'count': count, 'percentage': round(count / sum(type_counts.values()) * 100, 1)}
            for vuln_type, count in sorted_types[:limit]
        ]
    
    def _analyze_languages(self, scans: List[Dict]) -> Dict:
        """Analyze programming languages in scans"""
        language_counts = defaultdict(int)
        language_findings = defaultdict(int)
        
        for scan in scans:
            languages = scan.get('languages_detected', [])
            findings = scan.get('total_findings', 0)
            
            for lang in languages:
                language_counts[lang] += 1
                language_findings[lang] += findings
        
        # Calculate average findings per language
        language_stats = {}
        for lang in language_counts:
            language_stats[lang] = {
                'scans': language_counts[lang],
                'total_findings': language_findings[lang],
                'avg_findings': round(language_findings[lang] / language_counts[lang], 2)
            }
        
        return language_stats
    
    def _generate_recommendations(self, scans: List[Dict], security_score: float) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if security_score < 50:
            recommendations.append("Critical: Immediate security review required")
            recommendations.append("Implement mandatory security scanning in CI/CD pipeline")
        elif security_score < 70:
            recommendations.append("Increase scan frequency to catch issues earlier")
            recommendations.append("Provide security training for development team")
        else:
            recommendations.append("Maintain current security practices")
            recommendations.append("Consider implementing advanced security policies")
        
        # Analyze scan frequency
        if len(scans) < 10:
            recommendations.append("Increase scanning frequency for better coverage")
        
        return recommendations
    
    def _generate_owasp_report(self, scans: List[Dict]) -> Dict:
        """Generate OWASP Top 10 compliance report"""
        # Map finding types to OWASP categories
        owasp_mapping = {
            'injection': ['sql_injection', 'command_injection', 'ldap_injection'],
            'broken_auth': ['weak_password', 'session_fixation', 'credential_stuffing'],
            'sensitive_data': ['hardcoded_secrets', 'data_exposure', 'weak_crypto'],
            'xxe': ['xml_external_entity'],
            'broken_access': ['path_traversal', 'privilege_escalation'],
            'security_misconfig': ['default_passwords', 'debug_enabled'],
            'xss': ['cross_site_scripting', 'dom_xss'],
            'insecure_deserialization': ['unsafe_deserialization'],
            'vulnerable_components': ['outdated_dependencies', 'known_vulnerabilities'],
            'insufficient_logging': ['missing_logs', 'inadequate_monitoring']
        }
        
        # Count findings by OWASP category
        owasp_findings = defaultdict(int)
        total_findings = 0
        
        for scan in scans:
            for finding_type, count in scan.get('findings_by_type', {}).items():
                total_findings += count
                for owasp_cat, types in owasp_mapping.items():
                    if any(t in finding_type.lower() for t in types):
                        owasp_findings[owasp_cat] += count
                        break
        
        # Calculate compliance score
        compliance_score = max(0, 100 - (total_findings / len(scans) * 10)) if scans else 100
        
        return {
            'framework': 'OWASP Top 10',
            'compliance_score': round(compliance_score, 1),
            'total_findings': total_findings,
            'categories': dict(owasp_findings),
            'recommendations': [
                'Address injection vulnerabilities first',
                'Implement proper authentication mechanisms',
                'Encrypt sensitive data at rest and in transit'
            ]
        }
    
    def _generate_pci_report(self, scans: List[Dict]) -> Dict:
        """Generate PCI DSS compliance report"""
        # Simplified PCI compliance check
        pci_issues = 0
        for scan in scans:
            pci_issues += scan.get('findings_by_type', {}).get('payment_data', 0)
            pci_issues += scan.get('findings_by_type', {}).get('encryption', 0)
        
        compliance_score = max(0, 100 - pci_issues * 5)
        
        return {
            'framework': 'PCI DSS',
            'compliance_score': round(compliance_score, 1),
            'critical_issues': pci_issues,
            'recommendations': [
                'Encrypt all payment data',
                'Implement strong access controls',
                'Regular security testing required'
            ]
        }
    
    def _generate_sox_report(self, scans: List[Dict]) -> Dict:
        """Generate SOX compliance report"""
        # Simplified SOX compliance check
        sox_issues = 0
        for scan in scans:
            sox_issues += scan.get('findings_by_type', {}).get('access_control', 0)
            sox_issues += scan.get('findings_by_type', {}).get('audit_trail', 0)
        
        compliance_score = max(0, 100 - sox_issues * 3)
        
        return {
            'framework': 'SOX',
            'compliance_score': round(compliance_score, 1),
            'control_deficiencies': sox_issues,
            'recommendations': [
                'Implement proper access controls',
                'Maintain comprehensive audit trails',
                'Regular compliance assessments'
            ]
        }
    
    def _empty_summary(self) -> Dict:
        """Return empty summary structure"""
        return {
            'period': 'No data',
            'summary': {
                'total_scans': 0,
                'total_findings': 0,
                'total_files_scanned': 0,
                'security_score': 100.0,
                'avg_findings_per_scan': 0,
                'scan_frequency': 0
            },
            'severity_breakdown': {},
            'type_breakdown': {},
            'trends': {},
            'top_vulnerabilities': [],
            'language_stats': {},
            'recommendations': ['Start scanning to generate insights']
        }
    
    def _load_scan_history(self) -> List[Dict]:
        """Load scan history from file"""
        try:
            with open(self.scans_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    def _save_scan_history(self, scans: List[Dict]):
        """Save scan history to file"""
        try:
            with open(self.scans_file, 'w') as f:
                json.dump(scans, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scan history: {e}")
    
    def _update_metrics(self):
        """Update cached metrics"""
        try:
            scans = self._load_scan_history()
            if not scans:
                return
            
            # Calculate and cache key metrics
            metrics = {
                'last_updated': datetime.now().isoformat(),
                'total_scans': len(scans),
                'total_findings': sum(scan['total_findings'] for scan in scans),
                'avg_security_score': self._calculate_security_score(scans)
            }
            
            with open(self.metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")
