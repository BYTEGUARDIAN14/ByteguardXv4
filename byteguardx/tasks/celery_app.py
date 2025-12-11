"""
Celery Application Configuration for ByteGuardX
Distributed task processing with Redis backend
"""

import os
import logging
from celery import Celery
from celery.schedules import crontab
from kombu import Queue

logger = logging.getLogger(__name__)

# Redis configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)

# Create Celery app
celery_app = Celery('byteguardx')

# Configuration
celery_app.conf.update(
    # Broker settings
    broker_url=CELERY_BROKER_URL,
    result_backend=CELERY_RESULT_BACKEND,
    
    # Task settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    
    # Result settings
    result_expires=3600,  # 1 hour
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    
    # Queue routing
    task_routes={
        'byteguardx.tasks.scan_tasks.*': {'queue': 'scans'},
        'byteguardx.tasks.ml_tasks.*': {'queue': 'ml_inference'},
        'byteguardx.tasks.notification_tasks.*': {'queue': 'notifications'},
        'byteguardx.tasks.report_tasks.*': {'queue': 'reports'},
    },
    
    # Queue definitions
    task_default_queue='default',
    task_queues=(
        Queue('default', routing_key='default'),
        Queue('scans', routing_key='scans'),
        Queue('ml_inference', routing_key='ml_inference'),
        Queue('notifications', routing_key='notifications'),
        Queue('reports', routing_key='reports'),
        Queue('priority', routing_key='priority'),
    ),
    
    # Beat schedule for periodic tasks
    beat_schedule={
        'cleanup-old-scans': {
            'task': 'byteguardx.tasks.scan_tasks.cleanup_old_scans',
            'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        },
        'security-health-check': {
            'task': 'byteguardx.tasks.monitoring_tasks.security_health_check',
            'schedule': crontab(minute='*/15'),  # Every 15 minutes
        },
        'model-drift-detection': {
            'task': 'byteguardx.tasks.ml_tasks.detect_model_drift',
            'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
        },
        'compliance-report-generation': {
            'task': 'byteguardx.tasks.compliance_tasks.generate_daily_compliance_report',
            'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
        },
        'key-rotation-check': {
            'task': 'byteguardx.tasks.security_tasks.check_key_rotation',
            'schedule': crontab(hour=0, minute=0),  # Daily at midnight
        }
    },
    
    # Error handling
    task_reject_on_worker_lost=True,
    task_ignore_result=False,
    
    # Security
    worker_hijack_root_logger=False,
    worker_log_color=False,
)

# Task discovery
celery_app.autodiscover_tasks([
    'byteguardx.tasks.scan_tasks',
    'byteguardx.tasks.ml_tasks', 
    'byteguardx.tasks.notification_tasks',
    'byteguardx.tasks.report_tasks',
    'byteguardx.tasks.monitoring_tasks',
    'byteguardx.tasks.compliance_tasks',
    'byteguardx.tasks.security_tasks'
])

# Health check task
@celery_app.task(bind=True)
def health_check(self):
    """Health check task for monitoring"""
    try:
        # Test Redis connection
        from celery import current_app
        current_app.backend.get('health_check')
        
        return {
            'status': 'healthy',
            'worker_id': self.request.id,
            'timestamp': self.request.utc,
            'queue': self.request.delivery_info.get('routing_key', 'unknown')
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': self.request.utc
        }

# Task failure handler
@celery_app.task(bind=True)
def task_failure_handler(self, task_id, error, traceback):
    """Handle task failures"""
    logger.error(f"Task {task_id} failed: {error}")
    
    # Send alert for critical task failures
    from byteguardx.alerts.alert_engine import alert_engine, AlertType, AlertSeverity
    
    alert_engine.create_alert(
        alert_type=AlertType.SYSTEM_ERROR,
        severity=AlertSeverity.HIGH,
        title=f"Task Failure: {task_id}",
        message=f"Celery task failed with error: {error}",
        metadata={
            'task_id': task_id,
            'error': str(error),
            'traceback': traceback
        }
    )

# Configure logging
if not celery_app.conf.worker_hijack_root_logger:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

logger.info("Celery app configured successfully")
