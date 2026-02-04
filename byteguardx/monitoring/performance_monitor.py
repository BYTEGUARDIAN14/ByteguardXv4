#!/usr/bin/env python3
"""
Advanced Performance Monitoring for ByteGuardX
Real-time performance metrics, alerting, and optimization recommendations
"""

import logging
import time
import psutil
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import deque, defaultdict
import statistics
import json

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Performance metric data point"""
    timestamp: datetime
    metric_name: str
    value: float
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""

@dataclass
class PerformanceAlert:
    """Performance alert"""
    alert_id: str
    metric_name: str
    threshold_type: str  # 'above', 'below', 'change'
    threshold_value: float
    current_value: float
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    message: str
    triggered_at: datetime
    resolved_at: Optional[datetime] = None

class PerformanceMonitor:
    """
    Advanced performance monitoring system
    """
    
    def __init__(self, collection_interval: int = 10):
        self.collection_interval = collection_interval
        self.metrics_buffer: deque = deque(maxlen=10000)  # Keep last 10k metrics
        self.alerts: List[PerformanceAlert] = []
        self.alert_thresholds: Dict[str, Dict[str, Any]] = {}
        
        # Performance counters
        self.counters = defaultdict(int)
        self.timers = defaultdict(list)
        self.gauges = defaultdict(float)
        
        # System monitoring
        self.system_metrics = {}
        self.process = psutil.Process()
        
        # Monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        self.lock = threading.RLock()
        
        # Initialize default thresholds
        self._setup_default_thresholds()

        # Advanced alerting system
        self.alert_handlers = {}
        self.alert_history = deque(maxlen=1000)
        self.alert_suppression = {}  # Prevent alert spam
        self.alert_escalation_rules = {}

        # Performance baselines for anomaly detection
        self.performance_baselines = {}
        self.baseline_window = 1000  # samples for baseline calculation

        # Real-time streaming metrics
        self.metrics_stream = deque(maxlen=10000)
        self.streaming_enabled = True

        # Initialize alert handlers
        self._setup_alert_handlers()

        logger.info("Advanced performance monitor initialized with real-time alerting")

    def _setup_alert_handlers(self):
        """Setup alert handlers for different notification channels"""
        # Email alert handler
        self.alert_handlers['email'] = self._send_email_alert

        # Webhook alert handler
        self.alert_handlers['webhook'] = self._send_webhook_alert

        # Log alert handler (always available)
        self.alert_handlers['log'] = self._log_alert

        # Slack alert handler (if configured)
        if os.environ.get('SLACK_WEBHOOK_URL'):
            self.alert_handlers['slack'] = self._send_slack_alert

        # Setup escalation rules
        self.alert_escalation_rules = {
            'CRITICAL': {
                'immediate': ['log', 'email', 'slack'],
                'after_5min': ['webhook'],
                'after_15min': ['email']  # Re-send
            },
            'HIGH': {
                'immediate': ['log', 'slack'],
                'after_10min': ['email']
            },
            'MEDIUM': {
                'immediate': ['log'],
                'after_30min': ['email']
            },
            'LOW': {
                'immediate': ['log']
            }
        }

    def _send_email_alert(self, alert: PerformanceAlert):
        """Send email alert"""
        try:
            # This would integrate with email service
            logger.info(f"EMAIL ALERT: {alert.severity} - {alert.message}")
            # Implementation would use SMTP or email service API
        except Exception as e:
            logger.error(f"Email alert failed: {e}")

    def _send_webhook_alert(self, alert: PerformanceAlert):
        """Send webhook alert"""
        try:
            import requests
            webhook_url = os.environ.get('ALERT_WEBHOOK_URL')
            if webhook_url:
                payload = {
                    'alert_id': alert.alert_id,
                    'severity': alert.severity,
                    'message': alert.message,
                    'metric_name': alert.metric_name,
                    'current_value': alert.current_value,
                    'threshold_value': alert.threshold_value,
                    'triggered_at': alert.triggered_at.isoformat()
                }
                requests.post(webhook_url, json=payload, timeout=10)
                logger.info(f"Webhook alert sent: {alert.alert_id}")
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")

    def _send_slack_alert(self, alert: PerformanceAlert):
        """Send Slack alert"""
        try:
            import requests
            slack_url = os.environ.get('SLACK_WEBHOOK_URL')
            if slack_url:
                color = {
                    'CRITICAL': '#FF0000',
                    'HIGH': '#FF8C00',
                    'MEDIUM': '#FFD700',
                    'LOW': '#32CD32'
                }.get(alert.severity, '#808080')

                payload = {
                    'attachments': [{
                        'color': color,
                        'title': f'🚨 {alert.severity} Performance Alert',
                        'text': alert.message,
                        'fields': [
                            {'title': 'Metric', 'value': alert.metric_name, 'short': True},
                            {'title': 'Current Value', 'value': str(alert.current_value), 'short': True},
                            {'title': 'Threshold', 'value': str(alert.threshold_value), 'short': True},
                            {'title': 'Time', 'value': alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S'), 'short': True}
                        ]
                    }]
                }
                requests.post(slack_url, json=payload, timeout=10)
                logger.info(f"Slack alert sent: {alert.alert_id}")
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")

    def _log_alert(self, alert: PerformanceAlert):
        """Log alert to system logs"""
        log_level = {
            'CRITICAL': logging.CRITICAL,
            'HIGH': logging.ERROR,
            'MEDIUM': logging.WARNING,
            'LOW': logging.INFO
        }.get(alert.severity, logging.INFO)

        logger.log(log_level, f"PERFORMANCE ALERT [{alert.severity}]: {alert.message} "
                             f"(metric: {alert.metric_name}, value: {alert.current_value}, "
                             f"threshold: {alert.threshold_value})")
    
    def _setup_default_thresholds(self):
        """Setup default performance alert thresholds"""
        self.alert_thresholds = {
            'cpu_usage': {
                'type': 'above',
                'threshold': 80.0,
                'severity': 'HIGH',
                'message': 'High CPU usage detected'
            },
            'memory_usage': {
                'type': 'above',
                'threshold': 85.0,
                'severity': 'HIGH',
                'message': 'High memory usage detected'
            },
            'response_time': {
                'type': 'above',
                'threshold': 5000.0,  # 5 seconds
                'severity': 'MEDIUM',
                'message': 'Slow response time detected'
            },
            'error_rate': {
                'type': 'above',
                'threshold': 5.0,  # 5%
                'severity': 'CRITICAL',
                'message': 'High error rate detected'
            },
            'disk_usage': {
                'type': 'above',
                'threshold': 90.0,
                'severity': 'HIGH',
                'message': 'High disk usage detected'
            },
            'active_connections': {
                'type': 'above',
                'threshold': 1000,
                'severity': 'MEDIUM',
                'message': 'High number of active connections'
            }
        }
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._collect_system_metrics()
                self._check_alert_thresholds()
                time.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.collection_interval)
    
    def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            current_time = datetime.now()
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            self._record_metric('cpu_usage', cpu_percent, {'unit': 'percent'})
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self._record_metric('memory_usage', memory.percent, {'unit': 'percent'})
            self._record_metric('memory_available', memory.available / 1024 / 1024, {'unit': 'MB'})
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self._record_metric('disk_usage', disk_percent, {'unit': 'percent'})
            self._record_metric('disk_free', disk.free / 1024 / 1024 / 1024, {'unit': 'GB'})
            
            # Process-specific metrics
            process_memory = self.process.memory_info()
            self._record_metric('process_memory_rss', process_memory.rss / 1024 / 1024, {'unit': 'MB'})
            self._record_metric('process_memory_vms', process_memory.vms / 1024 / 1024, {'unit': 'MB'})
            
            # Network metrics (if available)
            try:
                network = psutil.net_io_counters()
                self._record_metric('network_bytes_sent', network.bytes_sent, {'unit': 'bytes'})
                self._record_metric('network_bytes_recv', network.bytes_recv, {'unit': 'bytes'})
            except:
                pass
            
            # Application-specific metrics
            self._collect_application_metrics()
            
        except Exception as e:
            logger.error(f"System metrics collection failed: {e}")
    
    def _collect_application_metrics(self):
        """Collect application-specific metrics"""
        try:
            # Database connection pool metrics
            from ..database.connection_pool import db_manager
            if hasattr(db_manager, 'get_pool_status'):
                pool_status = db_manager.get_pool_status()
                self._record_metric('db_pool_size', pool_status.get('pool_size', 0))
                self._record_metric('db_checked_out', pool_status.get('checked_out', 0))
            
            # Cache metrics
            from ..performance.cache_manager import cache_manager
            if hasattr(cache_manager, 'get_stats'):
                cache_stats = cache_manager.get_stats()
                self._record_metric('cache_hit_rate', cache_stats.get('hit_rate', 0) * 100, {'unit': 'percent'})
                self._record_metric('cache_size', cache_stats.get('memory_entries', 0))
            
            # Security metrics
            from ..security.threat_detection import threat_detector
            if hasattr(threat_detector, 'get_stats'):
                threat_stats = threat_detector.get_stats()
                self._record_metric('threats_detected', threat_stats.get('total_threats', 0))
                self._record_metric('threat_detection_rate', threat_stats.get('detection_rate', 0))
            
        except Exception as e:
            logger.error(f"Application metrics collection failed: {e}")
    
    def _record_metric(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record a performance metric"""
        with self.lock:
            metric = PerformanceMetric(
                timestamp=datetime.now(),
                metric_name=name,
                value=value,
                tags=tags or {},
                unit=tags.get('unit', '') if tags else ''
            )
            
            self.metrics_buffer.append(metric)
            self.gauges[name] = value
    
    def _check_alert_thresholds(self):
        """Check metrics against alert thresholds"""
        try:
            current_time = datetime.now()
            
            for metric_name, threshold_config in self.alert_thresholds.items():
                if metric_name in self.gauges:
                    current_value = self.gauges[metric_name]
                    threshold_value = threshold_config['threshold']
                    threshold_type = threshold_config['type']
                    
                    should_alert = False
                    
                    if threshold_type == 'above' and current_value > threshold_value:
                        should_alert = True
                    elif threshold_type == 'below' and current_value < threshold_value:
                        should_alert = True
                    
                    if should_alert:
                        # Check if alert already exists
                        existing_alert = None
                        for alert in self.alerts:
                            if (alert.metric_name == metric_name and 
                                alert.resolved_at is None):
                                existing_alert = alert
                                break
                        
                        if not existing_alert:
                            # Create new alert
                            alert = PerformanceAlert(
                                alert_id=f"{metric_name}_{int(current_time.timestamp())}",
                                metric_name=metric_name,
                                threshold_type=threshold_type,
                                threshold_value=threshold_value,
                                current_value=current_value,
                                severity=threshold_config['severity'],
                                message=threshold_config['message'],
                                triggered_at=current_time
                            )
                            
                            self.alerts.append(alert)
                            logger.warning(f"Performance alert: {alert.message} "
                                         f"(current: {current_value}, threshold: {threshold_value})")
                    
                    else:
                        # Resolve existing alerts
                        for alert in self.alerts:
                            if (alert.metric_name == metric_name and 
                                alert.resolved_at is None):
                                alert.resolved_at = current_time
                                logger.info(f"Performance alert resolved: {alert.message}")
        
        except Exception as e:
            logger.error(f"Alert threshold checking failed: {e}")
    
    def record_timer(self, name: str, duration: float, tags: Dict[str, str] = None):
        """Record a timing metric"""
        with self.lock:
            self.timers[name].append(duration)
            # Keep only recent timings
            if len(self.timers[name]) > 1000:
                self.timers[name] = self.timers[name][-1000:]
            
            # Record as metric
            self._record_metric(f"{name}_duration", duration, tags)
    
    def increment_counter(self, name: str, value: int = 1, tags: Dict[str, str] = None):
        """Increment a counter metric"""
        with self.lock:
            self.counters[name] += value
            self._record_metric(f"{name}_count", self.counters[name], tags)
    
    def set_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Set a gauge metric"""
        with self.lock:
            self.gauges[name] = value
            self._record_metric(name, value, tags)
    
    def get_metrics_summary(self, time_window: timedelta = None) -> Dict[str, Any]:
        """Get performance metrics summary"""
        time_window = time_window or timedelta(minutes=10)
        cutoff_time = datetime.now() - time_window
        
        with self.lock:
            # Filter recent metrics
            recent_metrics = [
                m for m in self.metrics_buffer 
                if m.timestamp > cutoff_time
            ]
            
            # Group by metric name
            grouped_metrics = defaultdict(list)
            for metric in recent_metrics:
                grouped_metrics[metric.metric_name].append(metric.value)
            
            # Calculate statistics
            summary = {}
            for name, values in grouped_metrics.items():
                if values:
                    summary[name] = {
                        'count': len(values),
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'current': values[-1] if values else 0
                    }
                    
                    if len(values) > 1:
                        summary[name]['std'] = statistics.stdev(values)
            
            return {
                'time_window_minutes': time_window.total_seconds() / 60,
                'metrics': summary,
                'active_alerts': len([a for a in self.alerts if a.resolved_at is None]),
                'total_metrics_collected': len(recent_metrics)
            }
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active performance alerts"""
        with self.lock:
            active_alerts = [
                {
                    'alert_id': alert.alert_id,
                    'metric_name': alert.metric_name,
                    'severity': alert.severity,
                    'message': alert.message,
                    'current_value': alert.current_value,
                    'threshold_value': alert.threshold_value,
                    'triggered_at': alert.triggered_at.isoformat(),
                    'duration_minutes': (datetime.now() - alert.triggered_at).total_seconds() / 60
                }
                for alert in self.alerts
                if alert.resolved_at is None
            ]
            
            return sorted(active_alerts, key=lambda x: x['triggered_at'], reverse=True)
    
    def get_performance_recommendations(self) -> List[Dict[str, Any]]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        with self.lock:
            # CPU recommendations
            if 'cpu_usage' in self.gauges and self.gauges['cpu_usage'] > 70:
                recommendations.append({
                    'category': 'CPU',
                    'priority': 'HIGH',
                    'issue': 'High CPU usage detected',
                    'recommendation': 'Consider scaling horizontally or optimizing CPU-intensive operations',
                    'current_value': self.gauges['cpu_usage']
                })
            
            # Memory recommendations
            if 'memory_usage' in self.gauges and self.gauges['memory_usage'] > 80:
                recommendations.append({
                    'category': 'Memory',
                    'priority': 'HIGH',
                    'issue': 'High memory usage detected',
                    'recommendation': 'Review memory usage patterns and implement memory optimization',
                    'current_value': self.gauges['memory_usage']
                })
            
            # Cache recommendations
            if 'cache_hit_rate' in self.gauges and self.gauges['cache_hit_rate'] < 70:
                recommendations.append({
                    'category': 'Cache',
                    'priority': 'MEDIUM',
                    'issue': 'Low cache hit rate',
                    'recommendation': 'Review caching strategy and increase cache size if needed',
                    'current_value': self.gauges['cache_hit_rate']
                })
            
            # Response time recommendations
            response_times = self.timers.get('api_response_time', [])
            if response_times and statistics.mean(response_times[-100:]) > 2000:  # 2 seconds
                recommendations.append({
                    'category': 'Performance',
                    'priority': 'MEDIUM',
                    'issue': 'Slow API response times',
                    'recommendation': 'Optimize database queries and implement response caching',
                    'current_value': statistics.mean(response_times[-100:])
                })
        
        return recommendations
    
    def export_metrics(self, format: str = 'json') -> str:
        """Export metrics in specified format"""
        summary = self.get_metrics_summary()
        
        if format.lower() == 'json':
            return json.dumps(summary, indent=2, default=str)
        elif format.lower() == 'prometheus':
            # Basic Prometheus format
            lines = []
            for name, stats in summary['metrics'].items():
                lines.append(f"# HELP {name} Performance metric")
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name} {stats['current']}")
            return '\n'.join(lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")

# Performance monitoring decorator
def monitor_performance(metric_name: str = None):
    """Decorator to monitor function performance"""
    def decorator(func):
        name = metric_name or f"{func.__module__}.{func.__name__}"
        
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                performance_monitor.increment_counter(f"{name}_success")
                return result
            except Exception as e:
                performance_monitor.increment_counter(f"{name}_error")
                raise
            finally:
                duration = (time.time() - start_time) * 1000  # milliseconds
                performance_monitor.record_timer(name, duration)
        
        return wrapper
    return decorator

# Global performance monitor
performance_monitor = PerformanceMonitor()

# Auto-start monitoring
performance_monitor.start_monitoring()
