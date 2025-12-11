"""
Scheduled Scan API Routes
Provides endpoints for managing scheduled scans
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Blueprint, request, jsonify, current_app
from croniter import croniter

from ..database.connection_pool import db_manager
from ..database.models import ScheduledScan, User, ScanResult
from ..security.enhanced_auth_middleware import enhanced_auth_required, audit_logged
from ..background.job_scheduler import JobScheduler
from ..core.file_processor import FileProcessor
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner

logger = logging.getLogger(__name__)

# Create blueprint
scheduler_bp = Blueprint('scheduler', __name__, url_prefix='/api/scans')

# Initialize components
job_scheduler = JobScheduler()
file_processor = FileProcessor()
secret_scanner = SecretScanner()
dependency_scanner = DependencyScanner()
ai_pattern_scanner = AIPatternScanner()


@scheduler_bp.route('/schedule', methods=['POST'])
@enhanced_auth_required
@audit_logged
def create_scheduled_scan():
    """Create a new scheduled scan"""
    try:
        data = request.get_json()
        user_id = request.current_user.id
        
        # Validate required fields
        required_fields = ['name', 'directory_path', 'frequency']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate frequency
        frequency = data['frequency']
        valid_frequencies = ['daily', 'weekly', 'monthly', 'custom']
        if frequency not in valid_frequencies:
            return jsonify({'error': 'Invalid frequency'}), 400
        
        # Validate cron expression for custom frequency
        cron_expression = None
        if frequency == 'custom':
            cron_expression = data.get('cron_expression')
            if not cron_expression:
                return jsonify({'error': 'Cron expression required for custom frequency'}), 400
            
            try:
                croniter(cron_expression)
            except Exception:
                return jsonify({'error': 'Invalid cron expression'}), 400
        
        # Calculate next run time
        next_run_at = calculate_next_run_time(frequency, cron_expression)
        
        with db_manager.get_session() as session:
            # Create scheduled scan
            scheduled_scan = ScheduledScan(
                name=data['name'],
                description=data.get('description', ''),
                user_id=user_id,
                organization_id=request.current_user.organization_id,
                directory_path=data['directory_path'],
                scan_config=data.get('scan_config', {}),
                frequency=frequency,
                cron_expression=cron_expression,
                timezone=data.get('timezone', 'UTC'),
                next_run_at=next_run_at
            )
            
            session.add(scheduled_scan)
            session.commit()
            
            # Schedule the job
            job_id = job_scheduler.schedule_job(
                name=f"scheduled_scan_{scheduled_scan.id}",
                function_name="execute_scheduled_scan",
                args=[str(scheduled_scan.id)],
                scheduled_at=next_run_at
            )
            
            logger.info(f"Created scheduled scan {scheduled_scan.id} for user {user_id}")
            
            return jsonify({
                'message': 'Scheduled scan created successfully',
                'scheduled_scan': scheduled_scan.to_dict(),
                'job_id': job_id
            }), 201
            
    except Exception as e:
        logger.error(f"Error creating scheduled scan: {e}")
        return jsonify({'error': 'Failed to create scheduled scan'}), 500


@scheduler_bp.route('/scheduled', methods=['GET'])
@enhanced_auth_required
def get_scheduled_scans():
    """Get user's scheduled scans"""
    try:
        user_id = request.current_user.id
        
        with db_manager.get_session() as session:
            scheduled_scans = session.query(ScheduledScan).filter(
                ScheduledScan.user_id == user_id
            ).order_by(ScheduledScan.created_at.desc()).all()
            
            return jsonify({
                'scheduled_scans': [scan.to_dict() for scan in scheduled_scans]
            })
            
    except Exception as e:
        logger.error(f"Error fetching scheduled scans: {e}")
        return jsonify({'error': 'Failed to fetch scheduled scans'}), 500


@scheduler_bp.route('/scheduled/<scan_id>', methods=['GET'])
@enhanced_auth_required
def get_scheduled_scan(scan_id):
    """Get specific scheduled scan"""
    try:
        user_id = request.current_user.id
        
        with db_manager.get_session() as session:
            scheduled_scan = session.query(ScheduledScan).filter(
                ScheduledScan.id == scan_id,
                ScheduledScan.user_id == user_id
            ).first()
            
            if not scheduled_scan:
                return jsonify({'error': 'Scheduled scan not found'}), 404
            
            return jsonify({
                'scheduled_scan': scheduled_scan.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Error fetching scheduled scan: {e}")
        return jsonify({'error': 'Failed to fetch scheduled scan'}), 500


@scheduler_bp.route('/scheduled/<scan_id>', methods=['PUT'])
@enhanced_auth_required
@audit_logged
def update_scheduled_scan(scan_id):
    """Update scheduled scan"""
    try:
        data = request.get_json()
        user_id = request.current_user.id
        
        with db_manager.get_session() as session:
            scheduled_scan = session.query(ScheduledScan).filter(
                ScheduledScan.id == scan_id,
                ScheduledScan.user_id == user_id
            ).first()
            
            if not scheduled_scan:
                return jsonify({'error': 'Scheduled scan not found'}), 404
            
            # Update fields
            if 'name' in data:
                scheduled_scan.name = data['name']
            if 'description' in data:
                scheduled_scan.description = data['description']
            if 'directory_path' in data:
                scheduled_scan.directory_path = data['directory_path']
            if 'scan_config' in data:
                scheduled_scan.scan_config = data['scan_config']
            if 'is_active' in data:
                scheduled_scan.is_active = data['is_active']
            
            # Update frequency if provided
            if 'frequency' in data:
                frequency = data['frequency']
                cron_expression = data.get('cron_expression')
                
                if frequency == 'custom' and not cron_expression:
                    return jsonify({'error': 'Cron expression required for custom frequency'}), 400
                
                scheduled_scan.frequency = frequency
                scheduled_scan.cron_expression = cron_expression
                scheduled_scan.next_run_at = calculate_next_run_time(frequency, cron_expression)
            
            scheduled_scan.updated_at = datetime.now()
            session.commit()
            
            logger.info(f"Updated scheduled scan {scan_id}")
            
            return jsonify({
                'message': 'Scheduled scan updated successfully',
                'scheduled_scan': scheduled_scan.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Error updating scheduled scan: {e}")
        return jsonify({'error': 'Failed to update scheduled scan'}), 500


@scheduler_bp.route('/scheduled/<scan_id>', methods=['DELETE'])
@enhanced_auth_required
@audit_logged
def delete_scheduled_scan(scan_id):
    """Delete scheduled scan"""
    try:
        user_id = request.current_user.id
        
        with db_manager.get_session() as session:
            scheduled_scan = session.query(ScheduledScan).filter(
                ScheduledScan.id == scan_id,
                ScheduledScan.user_id == user_id
            ).first()
            
            if not scheduled_scan:
                return jsonify({'error': 'Scheduled scan not found'}), 404
            
            session.delete(scheduled_scan)
            session.commit()
            
            logger.info(f"Deleted scheduled scan {scan_id}")
            
            return jsonify({
                'message': 'Scheduled scan deleted successfully'
            })
            
    except Exception as e:
        logger.error(f"Error deleting scheduled scan: {e}")
        return jsonify({'error': 'Failed to delete scheduled scan'}), 500


@scheduler_bp.route('/scheduled/<scan_id>/run', methods=['POST'])
@enhanced_auth_required
@audit_logged
def run_scheduled_scan_now(scan_id):
    """Run scheduled scan immediately"""
    try:
        user_id = request.current_user.id
        
        with db_manager.get_session() as session:
            scheduled_scan = session.query(ScheduledScan).filter(
                ScheduledScan.id == scan_id,
                ScheduledScan.user_id == user_id
            ).first()
            
            if not scheduled_scan:
                return jsonify({'error': 'Scheduled scan not found'}), 404
            
            # Schedule immediate execution
            job_id = job_scheduler.schedule_job(
                name=f"manual_scheduled_scan_{scheduled_scan.id}",
                function_name="execute_scheduled_scan",
                args=[str(scheduled_scan.id)]
            )
            
            logger.info(f"Manually triggered scheduled scan {scan_id}")
            
            return jsonify({
                'message': 'Scheduled scan triggered successfully',
                'job_id': job_id
            })
            
    except Exception as e:
        logger.error(f"Error running scheduled scan: {e}")
        return jsonify({'error': 'Failed to run scheduled scan'}), 500


def calculate_next_run_time(frequency: str, cron_expression: Optional[str] = None) -> datetime:
    """Calculate next run time based on frequency"""
    now = datetime.now()
    
    if frequency == 'daily':
        return now + timedelta(days=1)
    elif frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif frequency == 'monthly':
        return now + timedelta(days=30)
    elif frequency == 'custom' and cron_expression:
        cron = croniter(cron_expression, now)
        return cron.get_next(datetime)
    else:
        return now + timedelta(hours=1)  # Default fallback


def execute_scheduled_scan(scheduled_scan_id: str):
    """Execute a scheduled scan (called by job scheduler)"""
    try:
        with db_manager.get_session() as session:
            scheduled_scan = session.query(ScheduledScan).filter(
                ScheduledScan.id == scheduled_scan_id
            ).first()
            
            if not scheduled_scan or not scheduled_scan.is_active:
                logger.warning(f"Scheduled scan {scheduled_scan_id} not found or inactive")
                return
            
            # Update run statistics
            scheduled_scan.total_runs += 1
            scheduled_scan.last_run_at = datetime.now()
            
            try:
                # Execute the scan
                scan_result = perform_scan(
                    directory_path=scheduled_scan.directory_path,
                    user_id=scheduled_scan.user_id,
                    scan_config=scheduled_scan.scan_config
                )
                
                scheduled_scan.successful_runs += 1
                
                # Send notification if enabled
                send_scan_completion_notification(scheduled_scan, scan_result, success=True)
                
                logger.info(f"Successfully executed scheduled scan {scheduled_scan_id}")
                
            except Exception as scan_error:
                scheduled_scan.failed_runs += 1
                
                # Send failure notification
                send_scan_completion_notification(scheduled_scan, None, success=False, error=str(scan_error))
                
                logger.error(f"Failed to execute scheduled scan {scheduled_scan_id}: {scan_error}")
                raise
            
            finally:
                # Calculate next run time
                scheduled_scan.next_run_at = calculate_next_run_time(
                    scheduled_scan.frequency, 
                    scheduled_scan.cron_expression
                )
                session.commit()
                
                # Schedule next run
                job_scheduler.schedule_job(
                    name=f"scheduled_scan_{scheduled_scan.id}",
                    function_name="execute_scheduled_scan",
                    args=[str(scheduled_scan.id)],
                    scheduled_at=scheduled_scan.next_run_at
                )
                
    except Exception as e:
        logger.error(f"Error in execute_scheduled_scan: {e}")
        raise


def perform_scan(directory_path: str, user_id: str, scan_config: Dict) -> Dict:
    """Perform the actual scan"""
    # This would integrate with the existing scan infrastructure
    # For now, return a mock result
    return {
        'scan_id': f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        'status': 'completed',
        'findings_count': 0
    }


def send_scan_completion_notification(scheduled_scan: ScheduledScan, scan_result: Optional[Dict], 
                                    success: bool, error: Optional[str] = None):
    """Send notification about scan completion"""
    # This would integrate with the alert engine
    # Implementation would be added when integrating with email system
    pass


# Register the job function with the scheduler
job_scheduler.register_function('execute_scheduled_scan', execute_scheduled_scan)
