"""
Enhanced Health Monitoring System for ByteGuardX
Monitors system resources, database health, and service availability
"""

import os
import psutil
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import json
from pathlib import Path

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    DOWN = "down"

class ComponentType(Enum):
    """Types of components to monitor"""
    SYSTEM = "system"
    DATABASE = "database"
    CACHE = "cache"
    STORAGE = "storage"
    NETWORK = "network"
    APPLICATION = "application"

@dataclass
class HealthMetric:
    """Individual health metric"""
    name: str
    value: float
    unit: str
    status: HealthStatus
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class ComponentHealth:
    """Health status of a component"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    metrics: List[HealthMetric]
    last_check: datetime
    uptime: Optional[float] = None
    message: Optional[str] = None

class EnhancedHealthChecker:
    """Comprehensive health monitoring system"""
    
    def __init__(self, check_interval: int = 60, history_retention_hours: int = 24):
        self.check_interval = check_interval
        self.history_retention_hours = history_retention_hours
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Health data storage
        self.current_health = {}
        self.health_history = []
        self.lock = threading.RLock()
        
        # Thresholds
        self.thresholds = self._get_default_thresholds()
        
        # Storage for health data
        self.storage_dir = Path("data/health")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_default_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Get default health check thresholds"""
        return {
            "cpu_percent": {"warning": 70.0, "critical": 90.0},
            "memory_percent": {"warning": 80.0, "critical": 95.0},
            "disk_percent": {"warning": 85.0, "critical": 95.0},
            "disk_io_wait": {"warning": 20.0, "critical": 50.0},
            "network_errors": {"warning": 10.0, "critical": 50.0},
            "response_time": {"warning": 1000.0, "critical": 5000.0},  # milliseconds
            "database_connections": {"warning": 80.0, "critical": 95.0},  # percent of max
            "cache_hit_rate": {"warning": 80.0, "critical": 60.0},  # lower is worse
        }
    
    def start_monitoring(self):
        """Start background health monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Health monitoring started")
    
    def stop_monitoring(self):
        """Stop background health monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Health monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                self.perform_health_check()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(self.check_interval)
    
    def perform_health_check(self) -> Dict[str, ComponentHealth]:
        """Perform comprehensive health check"""
        with self.lock:
            health_results = {}
            
            # System health
            health_results["system"] = self._check_system_health()
            
            # Database health
            health_results["database"] = self._check_database_health()
            
            # Storage health
            health_results["storage"] = self._check_storage_health()
            
            # Application health
            health_results["application"] = self._check_application_health()
            
            # Network health
            health_results["network"] = self._check_network_health()
            
            # Update current health
            self.current_health = health_results
            
            # Add to history
            self._add_to_history(health_results)
            
            # Cleanup old history
            self._cleanup_history()
            
            # Save to storage
            self._save_health_data()
            
            return health_results
    
    def _check_system_health(self) -> ComponentHealth:
        """Check system resource health"""
        metrics = []
        overall_status = HealthStatus.HEALTHY
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_status = self._get_status_from_thresholds("cpu_percent", cpu_percent)
            metrics.append(HealthMetric(
                name="cpu_usage",
                value=cpu_percent,
                unit="percent",
                status=cpu_status,
                threshold_warning=self.thresholds["cpu_percent"]["warning"],
                threshold_critical=self.thresholds["cpu_percent"]["critical"]
            ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_status = self._get_status_from_thresholds("memory_percent", memory.percent)
            metrics.append(HealthMetric(
                name="memory_usage",
                value=memory.percent,
                unit="percent",
                status=memory_status,
                threshold_warning=self.thresholds["memory_percent"]["warning"],
                threshold_critical=self.thresholds["memory_percent"]["critical"]
            ))
            
            # Memory available
            metrics.append(HealthMetric(
                name="memory_available",
                value=memory.available / (1024**3),  # GB
                unit="GB",
                status=HealthStatus.HEALTHY
            ))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            disk_status = self._get_status_from_thresholds("disk_percent", disk_percent)
            metrics.append(HealthMetric(
                name="disk_usage",
                value=disk_percent,
                unit="percent",
                status=disk_status,
                threshold_warning=self.thresholds["disk_percent"]["warning"],
                threshold_critical=self.thresholds["disk_percent"]["critical"]
            ))
            
            # Disk free space
            metrics.append(HealthMetric(
                name="disk_free",
                value=disk.free / (1024**3),  # GB
                unit="GB",
                status=HealthStatus.HEALTHY
            ))
            
            # Load average (Unix-like systems)
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()[0]  # 1-minute load average
                cpu_count = psutil.cpu_count()
                load_percent = (load_avg / cpu_count) * 100
                load_status = self._get_status_from_thresholds("cpu_percent", load_percent)
                metrics.append(HealthMetric(
                    name="load_average",
                    value=load_avg,
                    unit="",
                    status=load_status
                ))
            
            # Process count
            process_count = len(psutil.pids())
            metrics.append(HealthMetric(
                name="process_count",
                value=process_count,
                unit="processes",
                status=HealthStatus.HEALTHY
            ))
            
            # Boot time / uptime
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_hours = uptime_seconds / 3600
            
            # Determine overall status
            statuses = [m.status for m in metrics]
            if HealthStatus.CRITICAL in statuses:
                overall_status = HealthStatus.CRITICAL
            elif HealthStatus.WARNING in statuses:
                overall_status = HealthStatus.WARNING
            
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            overall_status = HealthStatus.CRITICAL
            metrics.append(HealthMetric(
                name="system_check_error",
                value=1,
                unit="error",
                status=HealthStatus.CRITICAL,
                message=str(e)
            ))
        
        return ComponentHealth(
            component="system",
            component_type=ComponentType.SYSTEM,
            status=overall_status,
            metrics=metrics,
            last_check=datetime.now(),
            uptime=uptime_hours if 'uptime_hours' in locals() else None
        )
    
    def _check_database_health(self) -> ComponentHealth:
        """Check database health"""
        metrics = []
        overall_status = HealthStatus.HEALTHY
        
        try:
            from sqlalchemy import text
            from ..database.connection_pool import db_manager
            
            # Test database connection
            start_time = time.time()
            with db_manager.get_session() as session:
                # Simple query to test connection
                session.execute(text("SELECT 1"))
                connection_time = (time.time() - start_time) * 1000  # milliseconds
            
            # Connection response time
            response_status = self._get_status_from_thresholds("response_time", connection_time)
            metrics.append(HealthMetric(
                name="db_response_time",
                value=connection_time,
                unit="ms",
                status=response_status,
                threshold_warning=self.thresholds["response_time"]["warning"],
                threshold_critical=self.thresholds["response_time"]["critical"]
            ))
            
            # Connection pool status
            pool_info = db_manager.get_pool_status()
            if pool_info:
                pool_usage = (pool_info.get('active_connections', 0) / pool_info.get('pool_size', 1)) * 100
                pool_status = self._get_status_from_thresholds("database_connections", pool_usage)
                metrics.append(HealthMetric(
                    name="db_connection_pool",
                    value=pool_usage,
                    unit="percent",
                    status=pool_status,
                    threshold_warning=self.thresholds["database_connections"]["warning"],
                    threshold_critical=self.thresholds["database_connections"]["critical"]
                ))
            
            overall_status = max([m.status for m in metrics], key=lambda x: list(HealthStatus).index(x))
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            overall_status = HealthStatus.CRITICAL
            metrics.append(HealthMetric(
                name="db_connection_error",
                value=1,
                unit="error",
                status=HealthStatus.CRITICAL,
                message=str(e)
            ))
        
        return ComponentHealth(
            component="database",
            component_type=ComponentType.DATABASE,
            status=overall_status,
            metrics=metrics,
            last_check=datetime.now()
        )
    
    def _check_storage_health(self) -> ComponentHealth:
        """Check storage health"""
        metrics = []
        overall_status = HealthStatus.HEALTHY
        
        try:
            # Check critical directories
            critical_dirs = ["data", "data/audit_logs", "data/secure", "data/rate_limits"]
            
            for dir_path in critical_dirs:
                if os.path.exists(dir_path):
                    # Check if directory is writable
                    test_file = os.path.join(dir_path, ".health_check")
                    try:
                        with open(test_file, 'w') as f:
                            f.write("health_check")
                        os.remove(test_file)
                        
                        metrics.append(HealthMetric(
                            name=f"storage_{dir_path.replace('/', '_')}_writable",
                            value=1,
                            unit="boolean",
                            status=HealthStatus.HEALTHY,
                            message=f"Directory {dir_path} is writable"
                        ))
                    except Exception as e:
                        metrics.append(HealthMetric(
                            name=f"storage_{dir_path.replace('/', '_')}_writable",
                            value=0,
                            unit="boolean",
                            status=HealthStatus.CRITICAL,
                            message=f"Directory {dir_path} is not writable: {str(e)}"
                        ))
                        overall_status = HealthStatus.CRITICAL
                else:
                    metrics.append(HealthMetric(
                        name=f"storage_{dir_path.replace('/', '_')}_exists",
                        value=0,
                        unit="boolean",
                        status=HealthStatus.WARNING,
                        message=f"Directory {dir_path} does not exist"
                    ))
                    if overall_status == HealthStatus.HEALTHY:
                        overall_status = HealthStatus.WARNING
            
        except Exception as e:
            logger.error(f"Storage health check failed: {e}")
            overall_status = HealthStatus.CRITICAL
            metrics.append(HealthMetric(
                name="storage_check_error",
                value=1,
                unit="error",
                status=HealthStatus.CRITICAL,
                message=str(e)
            ))
        
        return ComponentHealth(
            component="storage",
            component_type=ComponentType.STORAGE,
            status=overall_status,
            metrics=metrics,
            last_check=datetime.now()
        )
    
    def _check_application_health(self) -> ComponentHealth:
        """Check application-specific health"""
        metrics = []
        overall_status = HealthStatus.HEALTHY
        
        try:
            # Check if critical services are available
            services = {
                "file_processor": "byteguardx.core.file_processor.FileProcessor",
                "secret_scanner": "byteguardx.scanners.secret_scanner.SecretScanner",
                "dependency_scanner": "byteguardx.scanners.dependency_scanner.DependencyScanner"
            }
            
            for service_name, service_class in services.items():
                try:
                    # Try to import and instantiate the service
                    module_path, class_name = service_class.rsplit('.', 1)
                    module = __import__(module_path, fromlist=[class_name])
                    service_cls = getattr(module, class_name)
                    service_instance = service_cls()
                    
                    metrics.append(HealthMetric(
                        name=f"service_{service_name}",
                        value=1,
                        unit="available",
                        status=HealthStatus.HEALTHY,
                        message=f"Service {service_name} is available"
                    ))
                except Exception as e:
                    metrics.append(HealthMetric(
                        name=f"service_{service_name}",
                        value=0,
                        unit="available",
                        status=HealthStatus.CRITICAL,
                        message=f"Service {service_name} failed: {str(e)}"
                    ))
                    overall_status = HealthStatus.CRITICAL
            
        except Exception as e:
            logger.error(f"Application health check failed: {e}")
            overall_status = HealthStatus.CRITICAL
            metrics.append(HealthMetric(
                name="app_check_error",
                value=1,
                unit="error",
                status=HealthStatus.CRITICAL,
                message=str(e)
            ))
        
        return ComponentHealth(
            component="application",
            component_type=ComponentType.APPLICATION,
            status=overall_status,
            metrics=metrics,
            last_check=datetime.now()
        )
    
    def _check_network_health(self) -> ComponentHealth:
        """Check network health"""
        metrics = []
        overall_status = HealthStatus.HEALTHY
        
        try:
            # Network interface statistics
            net_io = psutil.net_io_counters()
            
            if net_io:
                # Calculate error rate (if we have previous data)
                error_rate = 0
                if hasattr(self, '_prev_net_io'):
                    prev_errors = self._prev_net_io.errin + self._prev_net_io.errout
                    current_errors = net_io.errin + net_io.errout
                    error_rate = current_errors - prev_errors
                
                self._prev_net_io = net_io
                
                error_status = self._get_status_from_thresholds("network_errors", error_rate)
                metrics.append(HealthMetric(
                    name="network_errors",
                    value=error_rate,
                    unit="errors/check",
                    status=error_status,
                    threshold_warning=self.thresholds["network_errors"]["warning"],
                    threshold_critical=self.thresholds["network_errors"]["critical"]
                ))
                
                # Bytes sent/received
                metrics.append(HealthMetric(
                    name="network_bytes_sent",
                    value=net_io.bytes_sent / (1024**2),  # MB
                    unit="MB",
                    status=HealthStatus.HEALTHY
                ))
                
                metrics.append(HealthMetric(
                    name="network_bytes_recv",
                    value=net_io.bytes_recv / (1024**2),  # MB
                    unit="MB",
                    status=HealthStatus.HEALTHY
                ))
            
            overall_status = max([m.status for m in metrics], key=lambda x: list(HealthStatus).index(x)) if metrics else HealthStatus.HEALTHY
            
        except Exception as e:
            logger.error(f"Network health check failed: {e}")
            overall_status = HealthStatus.WARNING
            metrics.append(HealthMetric(
                name="network_check_error",
                value=1,
                unit="error",
                status=HealthStatus.WARNING,
                message=str(e)
            ))
        
        return ComponentHealth(
            component="network",
            component_type=ComponentType.NETWORK,
            status=overall_status,
            metrics=metrics,
            last_check=datetime.now()
        )
    
    def _get_status_from_thresholds(self, metric_name: str, value: float) -> HealthStatus:
        """Determine health status based on thresholds"""
        if metric_name not in self.thresholds:
            return HealthStatus.HEALTHY
        
        thresholds = self.thresholds[metric_name]
        
        # Special case for metrics where lower is worse (like cache hit rate)
        if metric_name == "cache_hit_rate":
            if value <= thresholds["critical"]:
                return HealthStatus.CRITICAL
            elif value <= thresholds["warning"]:
                return HealthStatus.WARNING
            else:
                return HealthStatus.HEALTHY
        else:
            # Normal case where higher is worse
            if value >= thresholds["critical"]:
                return HealthStatus.CRITICAL
            elif value >= thresholds["warning"]:
                return HealthStatus.WARNING
            else:
                return HealthStatus.HEALTHY
    
    def _add_to_history(self, health_results: Dict[str, ComponentHealth]):
        """Add health results to history"""
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": self._get_overall_status(health_results).value,
            "components": {k: asdict(v) for k, v in health_results.items()}
        }
        
        self.health_history.append(history_entry)
    
    def _cleanup_history(self):
        """Remove old history entries"""
        cutoff_time = datetime.now() - timedelta(hours=self.history_retention_hours)
        
        self.health_history = [
            entry for entry in self.health_history
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
        ]
    
    def _save_health_data(self):
        """Save current health data to storage"""
        try:
            health_file = self.storage_dir / "current_health.json"
            
            # Convert to serializable format
            health_data = {
                "timestamp": datetime.now().isoformat(),
                "components": {}
            }
            
            for component_name, component_health in self.current_health.items():
                health_data["components"][component_name] = {
                    "component": component_health.component,
                    "component_type": component_health.component_type.value,
                    "status": component_health.status.value,
                    "last_check": component_health.last_check.isoformat(),
                    "uptime": component_health.uptime,
                    "message": component_health.message,
                    "metrics": [
                        {
                            "name": m.name,
                            "value": m.value,
                            "unit": m.unit,
                            "status": m.status.value,
                            "threshold_warning": m.threshold_warning,
                            "threshold_critical": m.threshold_critical,
                            "message": m.message,
                            "timestamp": m.timestamp.isoformat()
                        }
                        for m in component_health.metrics
                    ]
                }
            
            with open(health_file, 'w') as f:
                json.dump(health_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save health data: {e}")
    
    def get_current_health(self) -> Dict[str, Any]:
        """Get current health status in JSON-serializable format"""
        with self.lock:
            if not self.current_health:
                # Perform health check if no current data
                self.perform_health_check()
            
            health_data = {
                "timestamp": datetime.now().isoformat(),
                "overall_status": self._get_overall_status(self.current_health).value,
                "components": {}
            }
            
            for component_name, component_health in self.current_health.items():
                health_data["components"][component_name] = {
                    "component": component_health.component,
                    "component_type": component_health.component_type.value,
                    "status": component_health.status.value,
                    "last_check": component_health.last_check.isoformat(),
                    "uptime": component_health.uptime,
                    "message": component_health.message,
                    "metrics": [
                        {
                            "name": m.name,
                            "value": m.value,
                            "unit": m.unit,
                            "status": m.status.value,
                            "threshold_warning": m.threshold_warning,
                            "threshold_critical": m.threshold_critical,
                            "message": m.message,
                            "timestamp": m.timestamp.isoformat() if m.timestamp else None
                        }
                        for m in component_health.metrics
                    ]
                }
            
            return health_data
    
    def _get_overall_status(self, health_results: Dict[str, ComponentHealth]) -> HealthStatus:
        """Determine overall system health status"""
        if not health_results:
            return HealthStatus.DOWN
        
        statuses = [component.status for component in health_results.values()]
        
        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        elif HealthStatus.WARNING in statuses:
            return HealthStatus.WARNING
        elif HealthStatus.DOWN in statuses:
            return HealthStatus.DOWN
        else:
            return HealthStatus.HEALTHY
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of health status"""
        current_health = self.get_current_health()
        
        summary = {
            "status": current_health["overall_status"],
            "timestamp": current_health["timestamp"],
            "components_count": len(current_health["components"]),
            "healthy_components": 0,
            "warning_components": 0,
            "critical_components": 0,
            "down_components": 0
        }
        
        for component in current_health["components"].values():
            status = component["status"]
            if status == "healthy":
                summary["healthy_components"] += 1
            elif status == "warning":
                summary["warning_components"] += 1
            elif status == "critical":
                summary["critical_components"] += 1
            elif status == "down":
                summary["down_components"] += 1
        
        return summary

# Global instance
enhanced_health_checker = EnhancedHealthChecker()
