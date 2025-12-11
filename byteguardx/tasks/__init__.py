"""
Distributed Task Management for ByteGuardX
Implements Celery with Redis for background job processing
"""

from .celery_app import celery_app
from .scan_tasks import (
    run_scheduled_scan,
    run_ai_inference,
    generate_report_task,
    cleanup_old_scans
)
from .ml_tasks import (
    train_model_task,
    update_model_weights,
    run_adversarial_testing
)
from .notification_tasks import (
    send_scan_notification,
    send_security_alert,
    send_compliance_report
)

__all__ = [
    'celery_app',
    'run_scheduled_scan',
    'run_ai_inference', 
    'generate_report_task',
    'cleanup_old_scans',
    'train_model_task',
    'update_model_weights',
    'run_adversarial_testing',
    'send_scan_notification',
    'send_security_alert',
    'send_compliance_report'
]
