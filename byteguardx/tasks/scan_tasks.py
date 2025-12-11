"""
Distributed Scan Tasks for ByteGuardX
Background processing for security scans and analysis
"""

import os
import logging
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import current_task
from pathlib import Path

from .celery_app import celery_app
from ..core.file_processor import FileProcessor
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner
from ..database.connection_pool import db_manager
from ..database.models import ScanResult, Finding, User
from ..reports.pdf_report import PDFReportGenerator

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name='byteguardx.tasks.scan_tasks.run_scheduled_scan')
def run_scheduled_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a scheduled security scan
    
    Args:
        scan_config: Configuration for the scan including:
            - user_id: User ID requesting the scan
            - scan_type: Type of scan (full, quick, custom)
            - target_path: Path to scan
            - options: Additional scan options
    
    Returns:
        Dict containing scan results and metadata
    """
    try:
        # Update task state
        self.update_state(state='PROGRESS', meta={'status': 'Initializing scan...'})
        
        user_id = scan_config['user_id']
        scan_type = scan_config.get('scan_type', 'full')
        target_path = scan_config['target_path']
        options = scan_config.get('options', {})
        
        logger.info(f"Starting scheduled scan for user {user_id}, type: {scan_type}")
        
        # Create scan record
        with db_manager.get_session() as session:
            scan_result = ScanResult(
                user_id=user_id,
                scan_type=scan_type,
                status='running',
                created_at=datetime.now(),
                scan_metadata={
                    'task_id': self.request.id,
                    'target_path': target_path,
                    'options': options
                }
            )
            session.add(scan_result)
            session.commit()
            scan_id = scan_result.id
        
        # Initialize scanners
        file_processor = FileProcessor()
        secret_scanner = SecretScanner()
        dependency_scanner = DependencyScanner()
        ai_pattern_scanner = AIPatternScanner()
        
        # Process files
        self.update_state(state='PROGRESS', meta={'status': 'Processing files...'})
        
        if target_path.startswith('http'):
            # Handle repository URLs
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository (simplified)
                import subprocess
                subprocess.run(['git', 'clone', target_path, temp_dir], check=True)
                files = file_processor.process_directory(temp_dir)
        else:
            # Handle local paths
            files = file_processor.process_directory(target_path)
        
        total_files = len(files)
        findings = []
        
        # Scan files
        for i, file_info in enumerate(files):
            progress = int((i / total_files) * 100)
            self.update_state(
                state='PROGRESS', 
                meta={
                    'status': f'Scanning file {i+1}/{total_files}',
                    'progress': progress,
                    'current_file': file_info['path']
                }
            )
            
            file_path = file_info['path']
            file_content = file_info.get('content', '')
            
            # Secret scanning
            if scan_type in ['full', 'secrets']:
                secret_findings = secret_scanner.scan_content(file_content, file_path)
                findings.extend(secret_findings)
            
            # Dependency scanning
            if scan_type in ['full', 'dependencies'] and file_info.get('is_dependency_file'):
                dep_findings = dependency_scanner.scan_file(file_path)
                findings.extend(dep_findings)
            
            # AI pattern scanning
            if scan_type in ['full', 'ai_patterns']:
                ai_findings = ai_pattern_scanner.scan_content(file_content, file_path)
                findings.extend(ai_findings)
        
        # Store findings
        self.update_state(state='PROGRESS', meta={'status': 'Storing results...'})
        
        with db_manager.get_session() as session:
            scan_result = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
            
            for finding_data in findings:
                finding = Finding(
                    scan_id=scan_id,
                    file_path=finding_data['file_path'],
                    line_number=finding_data.get('line_number', 0),
                    severity=finding_data['severity'],
                    finding_type=finding_data['type'],
                    description=finding_data['description'],
                    scanner_type=finding_data.get('scanner', 'unknown'),
                    scan_metadata=finding_data.get('metadata', {})
                )
                session.add(finding)
            
            # Update scan result
            scan_result.status = 'completed'
            scan_result.completed_at = datetime.now()
            scan_result.total_files = total_files
            scan_result.total_findings = len(findings)
            scan_result.scan_metadata.update({
                'findings_by_severity': _count_findings_by_severity(findings),
                'scan_duration': (datetime.now() - scan_result.created_at).total_seconds()
            })
            
            session.commit()
        
        # Send notification
        from .notification_tasks import send_scan_notification
        send_scan_notification.delay(scan_id, user_id)
        
        logger.info(f"Completed scan {scan_id} with {len(findings)} findings")
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'total_files': total_files,
            'total_findings': len(findings),
            'findings_by_severity': _count_findings_by_severity(findings)
        }
        
    except Exception as e:
        logger.error(f"Scan task failed: {e}")
        
        # Update scan status to failed
        if 'scan_id' in locals():
            with db_manager.get_session() as session:
                scan_result = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
                if scan_result:
                    scan_result.status = 'failed'
                    scan_result.error_message = str(e)
                    session.commit()
        
        raise

@celery_app.task(bind=True, name='byteguardx.tasks.scan_tasks.run_ai_inference')
def run_ai_inference(self, model_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run AI/ML inference for vulnerability detection
    
    Args:
        model_input: Input data for ML model
    
    Returns:
        Dict containing inference results
    """
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Loading model...'})
        
        # Import ML components
        from ..ml.vulnerability_predictor import VulnerabilityPredictor
        from ..security.ai_audit_system import ai_audit_system
        
        predictor = VulnerabilityPredictor()
        
        self.update_state(state='PROGRESS', meta={'status': 'Running inference...'})
        
        # Run prediction
        prediction = predictor.predict(model_input['code_snippet'])
        
        # Log prediction for audit
        ai_audit_system.log_prediction(
            model_name='vulnerability_predictor',
            model_version='1.0.0',
            input_data=model_input,
            prediction=prediction,
            metadata={'task_id': self.request.id}
        )
        
        return {
            'prediction': prediction,
            'confidence': prediction.get('confidence', 0.0),
            'explanation': prediction.get('explanation', ''),
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"AI inference task failed: {e}")
        raise

@celery_app.task(bind=True, name='byteguardx.tasks.scan_tasks.generate_report_task')
def generate_report_task(self, scan_id: str, report_format: str = 'pdf') -> Dict[str, Any]:
    """
    Generate scan report in background
    
    Args:
        scan_id: ID of the scan to generate report for
        report_format: Format of report (pdf, json, csv)
    
    Returns:
        Dict containing report generation results
    """
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Fetching scan data...'})
        
        with db_manager.get_session() as session:
            scan_result = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
            if not scan_result:
                raise ValueError(f"Scan {scan_id} not found")
            
            findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
        
        self.update_state(state='PROGRESS', meta={'status': 'Generating report...'})
        
        if report_format == 'pdf':
            pdf_generator = PDFReportGenerator()
            
            findings_data = [
                {
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'severity': f.severity,
                    'type': f.finding_type,
                    'description': f.description
                }
                for f in findings
            ]
            
            report_path = pdf_generator.generate_report(
                findings=findings_data,
                scan_metadata={
                    'scan_id': scan_id,
                    'scan_type': scan_result.scan_type,
                    'total_files': scan_result.total_files,
                    'created_at': scan_result.created_at.isoformat()
                }
            )
            
            return {
                'status': 'completed',
                'report_path': report_path,
                'format': report_format
            }
        
        # Add other format handlers here
        
    except Exception as e:
        logger.error(f"Report generation task failed: {e}")
        raise

@celery_app.task(name='byteguardx.tasks.scan_tasks.cleanup_old_scans')
def cleanup_old_scans():
    """Clean up old scan results and files"""
    try:
        cutoff_date = datetime.now() - timedelta(days=90)  # Keep 90 days
        
        with db_manager.get_session() as session:
            # Delete old scan results
            old_scans = session.query(ScanResult).filter(
                ScanResult.created_at < cutoff_date
            ).all()
            
            for scan in old_scans:
                # Delete associated findings
                session.query(Finding).filter(Finding.scan_id == scan.id).delete()
                session.delete(scan)
            
            session.commit()
            
            logger.info(f"Cleaned up {len(old_scans)} old scans")
            
        return {'cleaned_scans': len(old_scans)}
        
    except Exception as e:
        logger.error(f"Cleanup task failed: {e}")
        raise

def _count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level"""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        if severity in counts:
            counts[severity] += 1
    
    return counts
