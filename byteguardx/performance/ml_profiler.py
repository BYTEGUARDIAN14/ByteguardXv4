"""
Performance Profiler for Heavy ML Inference and Bulk Scans
Provides detailed performance analysis and optimization recommendations
"""

import logging
import time
import threading
import psutil
import tracemalloc
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json
import statistics
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class ProfilerLevel(Enum):
    """Profiling detail levels"""
    BASIC = "basic"
    DETAILED = "detailed"
    COMPREHENSIVE = "comprehensive"

class PerformanceCategory(Enum):
    """Performance measurement categories"""
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    GPU_USAGE = "gpu_usage"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    INFERENCE_TIME = "inference_time"
    PREPROCESSING_TIME = "preprocessing_time"
    POSTPROCESSING_TIME = "postprocessing_time"

@dataclass
class PerformanceMetric:
    """Individual performance metric"""
    category: PerformanceCategory
    name: str
    value: float
    unit: str
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ProfileSession:
    """Performance profiling session"""
    session_id: str
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    level: ProfilerLevel = ProfilerLevel.BASIC
    metrics: List[PerformanceMetric] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

@dataclass
class PerformanceReport:
    """Performance analysis report"""
    session_id: str
    session_name: str
    duration: float
    summary: Dict[str, Any]
    bottlenecks: List[Dict[str, Any]]
    recommendations: List[str]
    metrics_by_category: Dict[str, List[PerformanceMetric]]
    generated_at: datetime

class MLPerformanceProfiler:
    """
    Comprehensive performance profiler for ML inference and bulk operations
    """
    
    def __init__(self):
        self.active_sessions: Dict[str, ProfileSession] = {}
        self.completed_sessions: List[ProfileSession] = []
        self.global_metrics: List[PerformanceMetric] = []
        self._lock = threading.RLock()
        self._session_counter = 0
        
        # Performance thresholds
        self.thresholds = {
            'cpu_usage_warning': 80.0,
            'cpu_usage_critical': 95.0,
            'memory_usage_warning': 80.0,
            'memory_usage_critical': 95.0,
            'inference_time_warning': 5.0,  # seconds
            'inference_time_critical': 10.0,  # seconds
            'gpu_memory_warning': 80.0,
            'gpu_memory_critical': 95.0,
        }
    
    def start_session(self, name: str, level: ProfilerLevel = ProfilerLevel.BASIC,
                     context: Dict[str, Any] = None) -> str:
        """Start a new profiling session"""
        with self._lock:
            self._session_counter += 1
            session_id = f"profile_{self._session_counter}_{int(time.time())}"
            
            session = ProfileSession(
                session_id=session_id,
                name=name,
                start_time=datetime.now(),
                level=level,
                context=context or {}
            )
            
            self.active_sessions[session_id] = session
            
            # Start memory tracing for detailed profiling
            if level in [ProfilerLevel.DETAILED, ProfilerLevel.COMPREHENSIVE]:
                tracemalloc.start()
            
            logger.info(f"Started profiling session: {session_id} ({name})")
            return session_id
    
    def end_session(self, session_id: str) -> Optional[ProfileSession]:
        """End a profiling session"""
        with self._lock:
            session = self.active_sessions.pop(session_id, None)
            if not session:
                logger.warning(f"Session {session_id} not found")
                return None
            
            session.end_time = datetime.now()
            
            # Stop memory tracing
            if session.level in [ProfilerLevel.DETAILED, ProfilerLevel.COMPREHENSIVE]:
                try:
                    tracemalloc.stop()
                except:
                    pass
            
            self.completed_sessions.append(session)
            
            # Keep only last 100 completed sessions
            if len(self.completed_sessions) > 100:
                self.completed_sessions = self.completed_sessions[-100:]
            
            logger.info(f"Ended profiling session: {session_id} (duration: {session.duration:.2f}s)")
            return session
    
    @contextmanager
    def profile_context(self, name: str, level: ProfilerLevel = ProfilerLevel.BASIC,
                       context: Dict[str, Any] = None):
        """Context manager for profiling"""
        session_id = self.start_session(name, level, context)
        try:
            yield session_id
        finally:
            self.end_session(session_id)
    
    def record_metric(self, session_id: str, category: PerformanceCategory,
                     name: str, value: float, unit: str,
                     context: Dict[str, Any] = None):
        """Record a performance metric"""
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                logger.warning(f"Session {session_id} not found for metric recording")
                return
            
            metric = PerformanceMetric(
                category=category,
                name=name,
                value=value,
                unit=unit,
                timestamp=datetime.now(),
                context=context or {}
            )
            
            session.metrics.append(metric)
            self.global_metrics.append(metric)
            
            # Keep global metrics limited
            if len(self.global_metrics) > 10000:
                self.global_metrics = self.global_metrics[-5000:]
    
    def record_system_metrics(self, session_id: str):
        """Record current system performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.record_metric(session_id, PerformanceCategory.CPU_USAGE,
                             "cpu_percent", cpu_percent, "percent")
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.record_metric(session_id, PerformanceCategory.MEMORY_USAGE,
                             "memory_percent", memory.percent, "percent")
            self.record_metric(session_id, PerformanceCategory.MEMORY_USAGE,
                             "memory_used_mb", memory.used / (1024**2), "MB")
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.record_metric(session_id, PerformanceCategory.DISK_IO,
                                 "disk_read_mb", disk_io.read_bytes / (1024**2), "MB")
                self.record_metric(session_id, PerformanceCategory.DISK_IO,
                                 "disk_write_mb", disk_io.write_bytes / (1024**2), "MB")
            
            # Network I/O
            net_io = psutil.net_io_counters()
            if net_io:
                self.record_metric(session_id, PerformanceCategory.NETWORK_IO,
                                 "network_sent_mb", net_io.bytes_sent / (1024**2), "MB")
                self.record_metric(session_id, PerformanceCategory.NETWORK_IO,
                                 "network_recv_mb", net_io.bytes_recv / (1024**2), "MB")
            
        except Exception as e:
            logger.error(f"Error recording system metrics: {e}")
    
    def profile_function(self, session_id: str, func: Callable, *args, **kwargs) -> Any:
        """Profile a function execution"""
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            # Record pre-execution metrics
            self.record_system_metrics(session_id)
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Record post-execution metrics
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            execution_time = end_time - start_time
            memory_delta = (end_memory - start_memory) / (1024**2)  # MB
            
            self.record_metric(session_id, PerformanceCategory.INFERENCE_TIME,
                             f"{func.__name__}_execution_time", execution_time, "seconds")
            self.record_metric(session_id, PerformanceCategory.MEMORY_USAGE,
                             f"{func.__name__}_memory_delta", memory_delta, "MB")
            
            self.record_system_metrics(session_id)
            
            return result
            
        except Exception as e:
            logger.error(f"Error profiling function {func.__name__}: {e}")
            raise
    
    def generate_report(self, session_id: str) -> Optional[PerformanceReport]:
        """Generate performance analysis report"""
        with self._lock:
            # Find session in active or completed
            session = self.active_sessions.get(session_id)
            if not session:
                session = next((s for s in self.completed_sessions if s.session_id == session_id), None)
            
            if not session:
                logger.warning(f"Session {session_id} not found for report generation")
                return None
            
            # Group metrics by category
            metrics_by_category = {}
            for metric in session.metrics:
                category = metric.category.value
                if category not in metrics_by_category:
                    metrics_by_category[category] = []
                metrics_by_category[category].append(metric)
            
            # Generate summary
            summary = self._generate_summary(session, metrics_by_category)
            
            # Identify bottlenecks
            bottlenecks = self._identify_bottlenecks(session, metrics_by_category)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(session, metrics_by_category, bottlenecks)
            
            report = PerformanceReport(
                session_id=session_id,
                session_name=session.name,
                duration=session.duration or 0,
                summary=summary,
                bottlenecks=bottlenecks,
                recommendations=recommendations,
                metrics_by_category=metrics_by_category,
                generated_at=datetime.now()
            )
            
            return report
    
    def _generate_summary(self, session: ProfileSession, 
                         metrics_by_category: Dict[str, List[PerformanceMetric]]) -> Dict[str, Any]:
        """Generate performance summary"""
        summary = {
            'session_duration': session.duration or 0,
            'total_metrics': len(session.metrics),
            'categories': list(metrics_by_category.keys())
        }
        
        # Calculate averages for each category
        for category, metrics in metrics_by_category.items():
            if not metrics:
                continue
            
            values = [m.value for m in metrics]
            summary[f'{category}_avg'] = statistics.mean(values)
            summary[f'{category}_max'] = max(values)
            summary[f'{category}_min'] = min(values)
            
            if len(values) > 1:
                summary[f'{category}_std'] = statistics.stdev(values)
        
        return summary

    def _identify_bottlenecks(self, session: ProfileSession,
                            metrics_by_category: Dict[str, List[PerformanceMetric]]) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        bottlenecks = []

        for category, metrics in metrics_by_category.items():
            if not metrics:
                continue

            values = [m.value for m in metrics]
            avg_value = statistics.mean(values)
            max_value = max(values)

            # Check against thresholds
            if category == 'cpu_usage':
                if avg_value > self.thresholds['cpu_usage_warning']:
                    severity = 'critical' if avg_value > self.thresholds['cpu_usage_critical'] else 'warning'
                    bottlenecks.append({
                        'category': category,
                        'severity': severity,
                        'description': f'High CPU usage: {avg_value:.1f}% average',
                        'impact': 'May slow down inference and other operations',
                        'metric_count': len(metrics)
                    })

            elif category == 'memory_usage':
                if avg_value > self.thresholds['memory_usage_warning']:
                    severity = 'critical' if avg_value > self.thresholds['memory_usage_critical'] else 'warning'
                    bottlenecks.append({
                        'category': category,
                        'severity': severity,
                        'description': f'High memory usage: {avg_value:.1f}% average',
                        'impact': 'Risk of out-of-memory errors and system instability',
                        'metric_count': len(metrics)
                    })

            elif category == 'inference_time':
                inference_metrics = [m for m in metrics if 'execution_time' in m.name]
                if inference_metrics:
                    avg_inference_time = statistics.mean([m.value for m in inference_metrics])
                    if avg_inference_time > self.thresholds['inference_time_warning']:
                        severity = 'critical' if avg_inference_time > self.thresholds['inference_time_critical'] else 'warning'
                        bottlenecks.append({
                            'category': category,
                            'severity': severity,
                            'description': f'Slow inference: {avg_inference_time:.2f}s average',
                            'impact': 'Reduced throughput and user experience',
                            'metric_count': len(inference_metrics)
                        })

        return sorted(bottlenecks, key=lambda x: {'critical': 0, 'warning': 1}[x['severity']])

    def _generate_recommendations(self, session: ProfileSession,
                                metrics_by_category: Dict[str, List[PerformanceMetric]],
                                bottlenecks: List[Dict[str, Any]]) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []

        # General recommendations based on session duration
        if session.duration and session.duration > 30:
            recommendations.append("Consider breaking down long-running operations into smaller chunks")

        # Recommendations based on bottlenecks
        for bottleneck in bottlenecks:
            category = bottleneck['category']
            severity = bottleneck['severity']

            if category == 'cpu_usage':
                if severity == 'critical':
                    recommendations.extend([
                        "Reduce CPU-intensive operations or distribute across multiple workers",
                        "Consider using GPU acceleration for ML inference",
                        "Implement caching for repeated computations"
                    ])
                else:
                    recommendations.extend([
                        "Monitor CPU usage trends and consider scaling up if persistent",
                        "Optimize algorithms for better CPU efficiency"
                    ])

            elif category == 'memory_usage':
                if severity == 'critical':
                    recommendations.extend([
                        "Implement memory-efficient data processing (streaming, batching)",
                        "Clear unused variables and implement garbage collection",
                        "Consider using memory-mapped files for large datasets"
                    ])
                else:
                    recommendations.extend([
                        "Monitor memory usage patterns",
                        "Implement memory pooling for frequent allocations"
                    ])

            elif category == 'inference_time':
                if severity == 'critical':
                    recommendations.extend([
                        "Optimize model architecture or use model quantization",
                        "Implement batch processing for multiple inputs",
                        "Consider using faster hardware (GPU/TPU)",
                        "Cache frequent inference results"
                    ])
                else:
                    recommendations.extend([
                        "Profile individual inference steps to identify slow components",
                        "Consider model optimization techniques"
                    ])

        # GPU-specific recommendations
        gpu_metrics = metrics_by_category.get('gpu_usage', [])
        if gpu_metrics:
            gpu_usage = statistics.mean([m.value for m in gpu_metrics])
            if gpu_usage < 50:
                recommendations.append("GPU utilization is low - consider optimizing GPU workload distribution")
            elif gpu_usage > 95:
                recommendations.append("GPU is at capacity - consider scaling to multiple GPUs")

        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)

        return unique_recommendations

    def get_session_metrics(self, session_id: str) -> List[PerformanceMetric]:
        """Get all metrics for a session"""
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                session = next((s for s in self.completed_sessions if s.session_id == session_id), None)

            return session.metrics if session else []

    def get_global_metrics(self, category: PerformanceCategory = None,
                          hours: int = 24) -> List[PerformanceMetric]:
        """Get global metrics with optional filtering"""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        with self._lock:
            filtered_metrics = [
                m for m in self.global_metrics
                if m.timestamp >= cutoff_time
                and (category is None or m.category == category)
            ]

            return sorted(filtered_metrics, key=lambda x: x.timestamp)

    def get_performance_trends(self, category: PerformanceCategory,
                             hours: int = 24) -> Dict[str, Any]:
        """Get performance trends for a category"""
        metrics = self.get_global_metrics(category, hours)

        if not metrics:
            return {'trend': 'no_data', 'metrics_count': 0}

        values = [m.value for m in metrics]
        timestamps = [m.timestamp for m in metrics]

        # Calculate trend
        if len(values) < 2:
            trend = 'insufficient_data'
        else:
            # Simple linear trend calculation
            x_values = [(t - timestamps[0]).total_seconds() for t in timestamps]
            n = len(values)
            sum_x = sum(x_values)
            sum_y = sum(values)
            sum_xy = sum(x * y for x, y in zip(x_values, values))
            sum_x2 = sum(x * x for x in x_values)

            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x) if (n * sum_x2 - sum_x * sum_x) != 0 else 0

            if abs(slope) < 0.001:
                trend = 'stable'
            elif slope > 0:
                trend = 'increasing'
            else:
                trend = 'decreasing'

        return {
            'trend': trend,
            'metrics_count': len(metrics),
            'average': statistics.mean(values),
            'min': min(values),
            'max': max(values),
            'latest': values[-1] if values else None,
            'time_range_hours': hours
        }

    def export_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Export session data for external analysis"""
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                session = next((s for s in self.completed_sessions if s.session_id == session_id), None)

            if not session:
                return None

            return {
                'session_id': session.session_id,
                'name': session.name,
                'start_time': session.start_time.isoformat(),
                'end_time': session.end_time.isoformat() if session.end_time else None,
                'duration': session.duration,
                'level': session.level.value,
                'context': session.context,
                'metrics': [
                    {
                        'category': m.category.value,
                        'name': m.name,
                        'value': m.value,
                        'unit': m.unit,
                        'timestamp': m.timestamp.isoformat(),
                        'context': m.context
                    }
                    for m in session.metrics
                ]
            }

# Global instance
ml_profiler = MLPerformanceProfiler()
