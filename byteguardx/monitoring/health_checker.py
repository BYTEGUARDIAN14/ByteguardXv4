"""
Comprehensive health checker for ByteGuardX components
Monitors system health, dependencies, and performance metrics
"""

import logging
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, asdict
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

@dataclass
class ComponentHealth:
    """Health information for a component"""
    name: str
    status: HealthStatus
    message: str
    last_check: datetime
    response_time_ms: float = 0.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'status': self.status.value,
            'message': self.message,
            'last_check': self.last_check.isoformat(),
            'response_time_ms': self.response_time_ms,
            'metadata': self.metadata
        }

class HealthChecker:
    """
    Comprehensive health checker for all ByteGuardX components
    Monitors database, scanners, file system, memory, and external dependencies
    """
    
    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self.component_healths: Dict[str, ComponentHealth] = {}
        self.health_checks: Dict[str, Callable] = {}
        self._lock = threading.RLock()
        self._running = False
        self._background_thread = None
        
        # Performance thresholds
        self.thresholds = {
            'memory_usage_percent': 85.0,
            'disk_usage_percent': 90.0,
            'cpu_usage_percent': 80.0,
            'response_time_ms': 5000.0,
            'database_connection_time_ms': 1000.0
        }
        
        # Register default health checks
        self._register_default_checks()
    
    def register_health_check(self, name: str, check_func: Callable[[], ComponentHealth]):
        """Register a custom health check"""
        with self._lock:
            self.health_checks[name] = check_func
            logger.info(f"Registered health check: {name}")
    
    def start_background_monitoring(self):
        """Start background health monitoring"""
        if self._running:
            return
        
        self._running = True
        self._background_thread = threading.Thread(
            target=self._background_monitor,
            daemon=True,
            name="HealthChecker"
        )
        self._background_thread.start()
        logger.info("Started background health monitoring")
    
    def stop_background_monitoring(self):
        """Stop background health monitoring"""
        self._running = False
        if self._background_thread:
            self._background_thread.join(timeout=5)
        logger.info("Stopped background health monitoring")
    
    def check_all_components(self) -> Dict[str, ComponentHealth]:
        """Run all registered health checks"""
        results = {}
        
        with self._lock:
            for name, check_func in self.health_checks.items():
                try:
                    start_time = time.time()
                    health = check_func()
                    health.response_time_ms = (time.time() - start_time) * 1000
                    health.last_check = datetime.now()
                    
                    results[name] = health
                    self.component_healths[name] = health
                    
                except Exception as e:
                    logger.error(f"Health check failed for {name}: {e}")
                    results[name] = ComponentHealth(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Health check failed: {str(e)}",
                        last_check=datetime.now()
                    )
        
        return results
    
    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        component_healths = self.check_all_components()
        
        # Determine overall status
        statuses = [health.status for health in component_healths.values()]
        
        if HealthStatus.UNHEALTHY in statuses:
            overall_status = HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Count components by status
        status_counts = {}
        for status in HealthStatus:
            status_counts[status.value] = sum(
                1 for h in component_healths.values() if h.status == status
            )
        
        return {
            'overall_status': overall_status.value,
            'timestamp': datetime.now().isoformat(),
            'components': {name: health.to_dict() for name, health in component_healths.items()},
            'summary': {
                'total_components': len(component_healths),
                'status_breakdown': status_counts,
                'unhealthy_components': [
                    name for name, health in component_healths.items()
                    if health.status == HealthStatus.UNHEALTHY
                ]
            }
        }
    
    def get_component_health(self, component_name: str) -> Optional[ComponentHealth]:
        """Get health status for a specific component"""
        with self._lock:
            return self.component_healths.get(component_name)
    
    def _background_monitor(self):
        """Background monitoring loop"""
        while self._running:
            try:
                self.check_all_components()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in background health monitoring: {e}")
                time.sleep(min(self.check_interval, 30))  # Fallback interval
    
    def _register_default_checks(self):
        """Register default health checks"""
        
        def check_database():
            """Check database connectivity and performance"""
            try:
                from ..database.connection_pool import db_manager
                
                start_time = time.time()
                health_info = db_manager.health_check()
                response_time = (time.time() - start_time) * 1000
                
                if health_info['healthy']:
                    status = HealthStatus.HEALTHY
                    message = "Database connection healthy"
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f"Database unhealthy: {health_info.get('status', 'unknown')}"
                
                # Check response time
                if response_time > self.thresholds['database_connection_time_ms']:
                    status = HealthStatus.DEGRADED
                    message += f" (slow response: {response_time:.1f}ms)"
                
                return ComponentHealth(
                    name="database",
                    status=status,
                    message=message,
                    last_check=datetime.now(),
                    response_time_ms=response_time,
                    metadata=health_info
                )
                
            except Exception as e:
                return ComponentHealth(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Database check failed: {str(e)}",
                    last_check=datetime.now()
                )
        
        def check_system_resources():
            """Check system resource usage"""
            try:
                # Memory usage
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                
                # Disk usage
                disk = psutil.disk_usage('/')
                disk_percent = (disk.used / disk.total) * 100
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Determine status
                status = HealthStatus.HEALTHY
                issues = []
                
                if memory_percent > self.thresholds['memory_usage_percent']:
                    status = HealthStatus.DEGRADED
                    issues.append(f"High memory usage: {memory_percent:.1f}%")
                
                if disk_percent > self.thresholds['disk_usage_percent']:
                    status = HealthStatus.DEGRADED
                    issues.append(f"High disk usage: {disk_percent:.1f}%")
                
                if cpu_percent > self.thresholds['cpu_usage_percent']:
                    status = HealthStatus.DEGRADED
                    issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                
                message = "System resources healthy"
                if issues:
                    message = "; ".join(issues)
                
                return ComponentHealth(
                    name="system_resources",
                    status=status,
                    message=message,
                    last_check=datetime.now(),
                    metadata={
                        'memory_percent': memory_percent,
                        'disk_percent': disk_percent,
                        'cpu_percent': cpu_percent,
                        'memory_available_gb': memory.available / (1024**3),
                        'disk_free_gb': disk.free / (1024**3)
                    }
                )
                
            except Exception as e:
                return ComponentHealth(
                    name="system_resources",
                    status=HealthStatus.UNHEALTHY,
                    message=f"System resource check failed: {str(e)}",
                    last_check=datetime.now()
                )
        
        def check_scanners():
            """Check scanner components"""
            try:
                from ..scanners.secret_scanner import SecretScanner
                from ..scanners.dependency_scanner import DependencyScanner
                from ..scanners.ai_pattern_scanner import AIPatternScanner
                
                scanners = {
                    'secret': SecretScanner(),
                    'dependency': DependencyScanner(),
                    'ai_pattern': AIPatternScanner()
                }
                
                scanner_status = {}
                overall_status = HealthStatus.HEALTHY
                
                for name, scanner in scanners.items():
                    try:
                        # Test scanner with minimal data
                        test_file = {
                            'file_path': 'test.py',
                            'content': 'print("hello world")',
                            'size': 20,
                            'lines': 1,
                            'extension': '.py',
                            'name': 'test.py'
                        }
                        
                        start_time = time.time()
                        scanner.scan_file(test_file)
                        response_time = (time.time() - start_time) * 1000
                        
                        scanner_status[name] = {
                            'status': 'healthy',
                            'response_time_ms': response_time
                        }
                        
                    except Exception as e:
                        scanner_status[name] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        overall_status = HealthStatus.DEGRADED
                
                message = "All scanners healthy"
                if overall_status != HealthStatus.HEALTHY:
                    unhealthy = [name for name, status in scanner_status.items() 
                               if status['status'] != 'healthy']
                    message = f"Scanner issues: {', '.join(unhealthy)}"
                
                return ComponentHealth(
                    name="scanners",
                    status=overall_status,
                    message=message,
                    last_check=datetime.now(),
                    metadata=scanner_status
                )
                
            except Exception as e:
                return ComponentHealth(
                    name="scanners",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Scanner check failed: {str(e)}",
                    last_check=datetime.now()
                )
        
        def check_file_system():
            """Check file system access and permissions"""
            try:
                import tempfile
                import os
                
                # Test write access to data directory
                data_dir = "data"
                os.makedirs(data_dir, exist_ok=True)
                
                # Test file operations
                test_file = str(Path(data_dir) / "health_check_test.tmp")
                
                start_time = time.time()
                
                # Write test
                with open(test_file, 'w') as f:
                    f.write("health check test")
                
                # Read test
                with open(test_file, 'r') as f:
                    content = f.read()
                
                # Delete test
                os.remove(test_file)
                
                response_time = (time.time() - start_time) * 1000
                
                if content != "health check test":
                    raise Exception("File content mismatch")
                
                return ComponentHealth(
                    name="file_system",
                    status=HealthStatus.HEALTHY,
                    message="File system access healthy",
                    last_check=datetime.now(),
                    response_time_ms=response_time,
                    metadata={
                        'data_directory': data_dir,
                        'write_access': True,
                        'read_access': True
                    }
                )
                
            except Exception as e:
                return ComponentHealth(
                    name="file_system",
                    status=HealthStatus.UNHEALTHY,
                    message=f"File system check failed: {str(e)}",
                    last_check=datetime.now()
                )
        
        # Register all default checks
        self.register_health_check("database", check_database)
        self.register_health_check("system_resources", check_system_resources)
        self.register_health_check("scanners", check_scanners)
        self.register_health_check("file_system", check_file_system)

# Global health checker instance
health_checker = HealthChecker()
