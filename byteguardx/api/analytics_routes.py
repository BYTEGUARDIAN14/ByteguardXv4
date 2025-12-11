"""
Analytics and Reporting Routes for ByteGuardX
Real-time visualizations and comprehensive reporting with export capabilities
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from flask import Blueprint, request, jsonify, send_file, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
import io
import csv
from sqlalchemy import func, desc, and_

from ..database.connection_pool import db_manager
from ..database.models import ScanResult, Finding, User, AuditLog, PluginExecution
from ..security.auth_middleware import admin_required_enhanced
from ..reports.pdf_report import PDFReportGenerator

logger = logging.getLogger(__name__)

analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/v1/analytics')

@analytics_bp.route('/dashboard-metrics', methods=['GET'])
@jwt_required()
def get_dashboard_metrics():
    """Get real-time dashboard metrics"""
    try:
        user_id = get_jwt_identity()
        time_range = request.args.get('range', '7d')  # 1d, 7d, 30d, 90d
        
        # Calculate date range
        if time_range == '1d':
            start_date = datetime.now() - timedelta(days=1)
        elif time_range == '7d':
            start_date = datetime.now() - timedelta(days=7)
        elif time_range == '30d':
            start_date = datetime.now() - timedelta(days=30)
        elif time_range == '90d':
            start_date = datetime.now() - timedelta(days=90)
        else:
            start_date = datetime.now() - timedelta(days=7)
        
        with db_manager.get_session() as session:
            # Basic metrics
            total_scans = session.query(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).count()
            
            completed_scans = session.query(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.status == 'completed',
                ScanResult.created_at >= start_date
            ).count()
            
            total_findings = session.query(Finding).join(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).count()
            
            # Severity breakdown
            severity_counts = session.query(
                Finding.severity,
                func.count(Finding.id).label('count')
            ).join(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).group_by(Finding.severity).all()
            
            severity_breakdown = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            for severity, count in severity_counts:
                if severity.lower() in severity_breakdown:
                    severity_breakdown[severity.lower()] = count
            
            # Scan success rate
            success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
            
            # Recent activity
            recent_scans = session.query(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).order_by(desc(ScanResult.created_at)).limit(10).all()
            
            recent_activity = []
            for scan in recent_scans:
                recent_activity.append({
                    'id': scan.id,
                    'scan_type': scan.scan_type,
                    'status': scan.status,
                    'total_findings': scan.total_findings or 0,
                    'created_at': scan.created_at.isoformat(),
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'time_range': time_range,
                    'metrics': {
                        'total_scans': total_scans,
                        'completed_scans': completed_scans,
                        'total_findings': total_findings,
                        'success_rate': round(success_rate, 1)
                    },
                    'severity_breakdown': severity_breakdown,
                    'recent_activity': recent_activity
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting dashboard metrics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@analytics_bp.route('/vulnerability-trends', methods=['GET'])
@jwt_required()
def get_vulnerability_trends():
    """Get vulnerability trends over time"""
    try:
        user_id = get_jwt_identity()
        days = int(request.args.get('days', 30))
        
        start_date = datetime.now() - timedelta(days=days)
        
        with db_manager.get_session() as session:
            # Daily vulnerability counts
            daily_trends = session.query(
                func.date(ScanResult.created_at).label('date'),
                func.count(Finding.id).label('total_findings'),
                func.sum(func.case([(Finding.severity == 'critical', 1)], else_=0)).label('critical'),
                func.sum(func.case([(Finding.severity == 'high', 1)], else_=0)).label('high'),
                func.sum(func.case([(Finding.severity == 'medium', 1)], else_=0)).label('medium'),
                func.sum(func.case([(Finding.severity == 'low', 1)], else_=0)).label('low')
            ).join(Finding).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).group_by(func.date(ScanResult.created_at)).order_by('date').all()
            
            trends_data = []
            for trend in daily_trends:
                trends_data.append({
                    'date': trend.date.isoformat(),
                    'total_findings': trend.total_findings or 0,
                    'critical': trend.critical or 0,
                    'high': trend.high or 0,
                    'medium': trend.medium or 0,
                    'low': trend.low or 0
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'trends': trends_data,
                    'period_days': days
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting vulnerability trends: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@analytics_bp.route('/scan-performance', methods=['GET'])
@jwt_required()
def get_scan_performance():
    """Get scan performance metrics"""
    try:
        user_id = get_jwt_identity()
        days = int(request.args.get('days', 30))
        
        start_date = datetime.now() - timedelta(days=days)
        
        with db_manager.get_session() as session:
            # Scan performance data
            performance_data = session.query(
                ScanResult.scan_type,
                func.count(ScanResult.id).label('total_scans'),
                func.avg(
                    func.extract('epoch', ScanResult.completed_at - ScanResult.created_at)
                ).label('avg_duration'),
                func.sum(func.case([(ScanResult.status == 'completed', 1)], else_=0)).label('successful'),
                func.sum(func.case([(ScanResult.status == 'failed', 1)], else_=0)).label('failed')
            ).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).group_by(ScanResult.scan_type).all()
            
            performance_metrics = []
            for perf in performance_data:
                success_rate = (perf.successful / perf.total_scans * 100) if perf.total_scans > 0 else 0
                performance_metrics.append({
                    'scan_type': perf.scan_type,
                    'total_scans': perf.total_scans,
                    'avg_duration_seconds': round(perf.avg_duration or 0, 2),
                    'success_rate': round(success_rate, 1),
                    'successful_scans': perf.successful or 0,
                    'failed_scans': perf.failed or 0
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'performance_metrics': performance_metrics,
                    'period_days': days
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting scan performance: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@analytics_bp.route('/plugin-usage', methods=['GET'])
@jwt_required()
def get_plugin_usage():
    """Get plugin usage statistics"""
    try:
        user_id = get_jwt_identity()
        days = int(request.args.get('days', 30))
        
        start_date = datetime.now() - timedelta(days=days)
        
        with db_manager.get_session() as session:
            # Plugin usage data
            plugin_usage = session.query(
                PluginExecution.plugin_id,
                func.count(PluginExecution.id).label('execution_count'),
                func.avg(PluginExecution.execution_time).label('avg_execution_time'),
                func.sum(func.case([(PluginExecution.status == 'completed', 1)], else_=0)).label('successful'),
                func.sum(func.case([(PluginExecution.status == 'failed', 1)], else_=0)).label('failed')
            ).filter(
                PluginExecution.user_id == user_id,
                PluginExecution.created_at >= start_date
            ).group_by(PluginExecution.plugin_id).order_by(desc('execution_count')).all()
            
            usage_data = []
            for usage in plugin_usage:
                success_rate = (usage.successful / usage.execution_count * 100) if usage.execution_count > 0 else 0
                usage_data.append({
                    'plugin_id': usage.plugin_id,
                    'execution_count': usage.execution_count,
                    'avg_execution_time': round(usage.avg_execution_time or 0, 2),
                    'success_rate': round(success_rate, 1),
                    'successful_executions': usage.successful or 0,
                    'failed_executions': usage.failed or 0
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'plugin_usage': usage_data,
                    'period_days': days
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting plugin usage: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@analytics_bp.route('/export-report', methods=['POST'])
@jwt_required()
def export_report():
    """Export comprehensive analytics report"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        export_format = data.get('format', 'pdf')  # pdf, csv, json
        date_range = data.get('date_range', '30d')
        include_sections = data.get('sections', ['summary', 'vulnerabilities', 'performance'])
        
        # Calculate date range
        if date_range == '7d':
            start_date = datetime.now() - timedelta(days=7)
        elif date_range == '30d':
            start_date = datetime.now() - timedelta(days=30)
        elif date_range == '90d':
            start_date = datetime.now() - timedelta(days=90)
        else:
            start_date = datetime.now() - timedelta(days=30)
        
        # Collect report data
        report_data = _collect_report_data(user_id, start_date, include_sections)
        
        if export_format == 'pdf':
            return _export_pdf_report(report_data, user_id)
        elif export_format == 'csv':
            return _export_csv_report(report_data, user_id)
        elif export_format == 'json':
            return _export_json_report(report_data, user_id)
        else:
            return jsonify({'success': False, 'error': 'Invalid export format'}), 400
            
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@analytics_bp.route('/compliance-summary', methods=['GET'])
@jwt_required()
def get_compliance_summary():
    """Get compliance summary with PCI, HIPAA, OWASP Top 10 mapping"""
    try:
        user_id = get_jwt_identity()
        days = int(request.args.get('days', 30))
        
        start_date = datetime.now() - timedelta(days=days)
        
        with db_manager.get_session() as session:
            # Get findings with compliance mapping
            findings = session.query(Finding).join(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).all()
            
            # Compliance mappings
            compliance_summary = {
                'owasp_top_10': _map_owasp_compliance(findings),
                'pci_dss': _map_pci_compliance(findings),
                'hipaa': _map_hipaa_compliance(findings),
                'total_findings': len(findings),
                'compliance_score': _calculate_compliance_score(findings)
            }
            
            return jsonify({
                'success': True,
                'data': compliance_summary
            })
            
    except Exception as e:
        logger.error(f"Error getting compliance summary: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def _collect_report_data(user_id: str, start_date: datetime, sections: List[str]) -> Dict[str, Any]:
    """Collect comprehensive report data"""
    report_data = {
        'user_id': user_id,
        'generated_at': datetime.now().isoformat(),
        'period_start': start_date.isoformat(),
        'period_end': datetime.now().isoformat()
    }
    
    with db_manager.get_session() as session:
        if 'summary' in sections:
            # Summary metrics
            total_scans = session.query(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).count()
            
            total_findings = session.query(Finding).join(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).count()
            
            report_data['summary'] = {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'period_days': (datetime.now() - start_date).days
            }
        
        if 'vulnerabilities' in sections:
            # Vulnerability details
            findings = session.query(Finding).join(ScanResult).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).all()
            
            report_data['vulnerabilities'] = [
                {
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'severity': f.severity,
                    'finding_type': f.finding_type,
                    'description': f.description,
                    'scanner_type': f.scanner_type
                }
                for f in findings
            ]
        
        if 'performance' in sections:
            # Performance metrics
            performance_data = session.query(
                ScanResult.scan_type,
                func.count(ScanResult.id).label('count'),
                func.avg(
                    func.extract('epoch', ScanResult.completed_at - ScanResult.created_at)
                ).label('avg_duration')
            ).filter(
                ScanResult.user_id == user_id,
                ScanResult.created_at >= start_date
            ).group_by(ScanResult.scan_type).all()
            
            report_data['performance'] = [
                {
                    'scan_type': p.scan_type,
                    'total_scans': p.count,
                    'avg_duration_seconds': round(p.avg_duration or 0, 2)
                }
                for p in performance_data
            ]
    
    return report_data

def _export_pdf_report(report_data: Dict[str, Any], user_id: str) -> Any:
    """Export report as PDF"""
    try:
        pdf_generator = PDFReportGenerator()
        
        # Convert report data to PDF format
        findings_data = report_data.get('vulnerabilities', [])
        
        pdf_path = pdf_generator.generate_report(
            findings=findings_data,
            scan_metadata={
                'user_id': user_id,
                'generated_at': report_data['generated_at'],
                'period_start': report_data['period_start'],
                'period_end': report_data['period_end'],
                'summary': report_data.get('summary', {})
            }
        )
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f'byteguardx_report_{user_id}_{datetime.now().strftime("%Y%m%d")}.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        logger.error(f"PDF export failed: {e}")
        return jsonify({'success': False, 'error': 'PDF export failed'}), 500

def _export_csv_report(report_data: Dict[str, Any], user_id: str) -> Any:
    """Export report as CSV"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write vulnerabilities data
        if 'vulnerabilities' in report_data:
            writer.writerow(['File Path', 'Line Number', 'Severity', 'Type', 'Description', 'Scanner'])
            
            for vuln in report_data['vulnerabilities']:
                writer.writerow([
                    vuln['file_path'],
                    vuln['line_number'],
                    vuln['severity'],
                    vuln['finding_type'],
                    vuln['description'],
                    vuln['scanner_type']
                ])
        
        csv_content = output.getvalue()
        output.close()
        
        response = make_response(csv_content)
        response.headers['Content-Disposition'] = f'attachment; filename=byteguardx_report_{user_id}_{datetime.now().strftime("%Y%m%d")}.csv'
        response.headers['Content-Type'] = 'text/csv'
        
        return response
        
    except Exception as e:
        logger.error(f"CSV export failed: {e}")
        return jsonify({'success': False, 'error': 'CSV export failed'}), 500

def _export_json_report(report_data: Dict[str, Any], user_id: str) -> Any:
    """Export report as JSON"""
    try:
        response = make_response(json.dumps(report_data, indent=2))
        response.headers['Content-Disposition'] = f'attachment; filename=byteguardx_report_{user_id}_{datetime.now().strftime("%Y%m%d")}.json'
        response.headers['Content-Type'] = 'application/json'
        
        return response
        
    except Exception as e:
        logger.error(f"JSON export failed: {e}")
        return jsonify({'success': False, 'error': 'JSON export failed'}), 500

def _map_owasp_compliance(findings: List) -> Dict[str, Any]:
    """Map findings to OWASP Top 10"""
    owasp_mapping = {
        'A01_Broken_Access_Control': 0,
        'A02_Cryptographic_Failures': 0,
        'A03_Injection': 0,
        'A04_Insecure_Design': 0,
        'A05_Security_Misconfiguration': 0,
        'A06_Vulnerable_Components': 0,
        'A07_Authentication_Failures': 0,
        'A08_Software_Integrity_Failures': 0,
        'A09_Logging_Failures': 0,
        'A10_Server_Side_Request_Forgery': 0
    }
    
    # Simple mapping based on finding types
    for finding in findings:
        finding_type = finding.finding_type.lower()
        
        if 'injection' in finding_type or 'sql' in finding_type:
            owasp_mapping['A03_Injection'] += 1
        elif 'crypto' in finding_type or 'encryption' in finding_type:
            owasp_mapping['A02_Cryptographic_Failures'] += 1
        elif 'auth' in finding_type or 'session' in finding_type:
            owasp_mapping['A07_Authentication_Failures'] += 1
        elif 'access' in finding_type or 'permission' in finding_type:
            owasp_mapping['A01_Broken_Access_Control'] += 1
        elif 'config' in finding_type:
            owasp_mapping['A05_Security_Misconfiguration'] += 1
        elif 'dependency' in finding_type or 'component' in finding_type:
            owasp_mapping['A06_Vulnerable_Components'] += 1
    
    return owasp_mapping

def _map_pci_compliance(findings: List) -> Dict[str, Any]:
    """Map findings to PCI DSS requirements"""
    # Simplified PCI mapping
    return {
        'requirement_3_cardholder_data': len([f for f in findings if 'card' in f.description.lower()]),
        'requirement_4_encryption': len([f for f in findings if 'encrypt' in f.description.lower()]),
        'requirement_6_secure_systems': len([f for f in findings if f.severity in ['critical', 'high']]),
        'total_violations': len(findings)
    }

def _map_hipaa_compliance(findings: List) -> Dict[str, Any]:
    """Map findings to HIPAA requirements"""
    # Simplified HIPAA mapping
    return {
        'access_control': len([f for f in findings if 'access' in f.finding_type.lower()]),
        'audit_controls': len([f for f in findings if 'audit' in f.finding_type.lower()]),
        'integrity': len([f for f in findings if 'integrity' in f.description.lower()]),
        'transmission_security': len([f for f in findings if 'transmission' in f.description.lower()]),
        'total_violations': len(findings)
    }

def _calculate_compliance_score(findings: List) -> float:
    """Calculate overall compliance score"""
    if not findings:
        return 100.0
    
    # Simple scoring based on severity
    critical_weight = 10
    high_weight = 5
    medium_weight = 2
    low_weight = 1
    
    total_score = 0
    for finding in findings:
        if finding.severity == 'critical':
            total_score += critical_weight
        elif finding.severity == 'high':
            total_score += high_weight
        elif finding.severity == 'medium':
            total_score += medium_weight
        else:
            total_score += low_weight
    
    # Calculate score out of 100
    max_possible_score = len(findings) * critical_weight
    compliance_score = max(0, 100 - (total_score / max_possible_score * 100)) if max_possible_score > 0 else 100
    
    return round(compliance_score, 1)
