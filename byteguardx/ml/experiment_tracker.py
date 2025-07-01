"""
Experiment tracking and ML pipeline management for ByteGuardX
Provides comprehensive experiment logging, metrics tracking, and model comparison
"""

import logging
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import pickle

from .model_registry import model_registry, ModelType, ModelMetrics, Experiment

logger = logging.getLogger(__name__)

@dataclass
class MetricPoint:
    """Single metric measurement point"""
    timestamp: float
    step: int
    value: float
    epoch: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExperimentRun:
    """Individual experiment run tracking"""
    run_id: str
    experiment_id: str
    name: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, stopped
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    
    # Metrics tracking
    metrics: Dict[str, List[MetricPoint]] = field(default_factory=dict)
    final_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Artifacts and logs
    artifacts: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    
    # System metrics
    system_metrics: Dict[str, List[MetricPoint]] = field(default_factory=dict)
    
    # Tags and notes
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['started_at'] = self.started_at.isoformat()
        if self.ended_at:
            data['ended_at'] = self.ended_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExperimentRun':
        """Create from dictionary"""
        data['started_at'] = datetime.fromisoformat(data['started_at'])
        if data.get('ended_at'):
            data['ended_at'] = datetime.fromisoformat(data['ended_at'])
        
        # Convert metric points
        for metric_name, points in data.get('metrics', {}).items():
            data['metrics'][metric_name] = [
                MetricPoint(**point) if isinstance(point, dict) else point
                for point in points
            ]
        
        for metric_name, points in data.get('system_metrics', {}).items():
            data['system_metrics'][metric_name] = [
                MetricPoint(**point) if isinstance(point, dict) else point
                for point in points
            ]
        
        return cls(**data)

class ExperimentTracker:
    """
    Comprehensive experiment tracking system for ML experiments
    Provides real-time metrics logging, visualization, and comparison
    """
    
    def __init__(self, tracking_dir: str = "data/experiments"):
        self.tracking_dir = Path(tracking_dir)
        self.tracking_dir.mkdir(parents=True, exist_ok=True)
        
        # Active runs
        self.active_runs: Dict[str, ExperimentRun] = {}
        self.completed_runs: Dict[str, ExperimentRun] = {}
        
        # Callbacks for real-time updates
        self.metric_callbacks: List[Callable] = []
        self.run_callbacks: List[Callable] = []
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Auto-save settings
        self.auto_save_interval = 60  # seconds
        self._auto_save_thread = None
        self._stop_auto_save = threading.Event()
        
        # Load existing runs
        self._load_runs()
        
        # Start auto-save
        self._start_auto_save()
    
    def start_run(self, experiment_id: str, run_name: str, 
                  config: Dict[str, Any] = None,
                  hyperparameters: Dict[str, Any] = None,
                  tags: List[str] = None) -> str:
        """Start new experiment run"""
        try:
            run_id = self._generate_run_id(experiment_id, run_name)
            
            run = ExperimentRun(
                run_id=run_id,
                experiment_id=experiment_id,
                name=run_name,
                started_at=datetime.now(),
                config=config or {},
                hyperparameters=hyperparameters or {},
                tags=tags or []
            )
            
            with self._lock:
                self.active_runs[run_id] = run
            
            # Save run
            self._save_run(run)
            
            # Notify callbacks
            self._notify_run_callbacks('started', run)
            
            logger.info(f"Started experiment run {run_id}")
            return run_id
            
        except Exception as e:
            logger.error(f"Failed to start experiment run: {e}")
            raise
    
    def log_metric(self, run_id: str, metric_name: str, value: float, 
                   step: int = None, epoch: int = None, 
                   metadata: Dict[str, Any] = None):
        """Log metric value for run"""
        try:
            with self._lock:
                if run_id not in self.active_runs:
                    logger.warning(f"Run {run_id} not found or not active")
                    return
                
                run = self.active_runs[run_id]
                
                if metric_name not in run.metrics:
                    run.metrics[metric_name] = []
                
                # Auto-increment step if not provided
                if step is None:
                    step = len(run.metrics[metric_name])
                
                metric_point = MetricPoint(
                    timestamp=time.time(),
                    step=step,
                    value=value,
                    epoch=epoch,
                    metadata=metadata or {}
                )
                
                run.metrics[metric_name].append(metric_point)
                
                # Update final metrics
                run.final_metrics[metric_name] = value
            
            # Notify callbacks
            self._notify_metric_callbacks(run_id, metric_name, value, step)
            
            logger.debug(f"Logged metric {metric_name}={value} for run {run_id}")
            
        except Exception as e:
            logger.error(f"Failed to log metric: {e}")
    
    def log_metrics(self, run_id: str, metrics: Dict[str, float], 
                    step: int = None, epoch: int = None):
        """Log multiple metrics at once"""
        for metric_name, value in metrics.items():
            self.log_metric(run_id, metric_name, value, step, epoch)
    
    def log_hyperparameter(self, run_id: str, param_name: str, value: Any):
        """Log hyperparameter for run"""
        with self._lock:
            if run_id in self.active_runs:
                self.active_runs[run_id].hyperparameters[param_name] = value
    
    def log_artifact(self, run_id: str, artifact_path: str, 
                     artifact_type: str = "file"):
        """Log artifact for run"""
        try:
            with self._lock:
                if run_id not in self.active_runs:
                    return
                
                run = self.active_runs[run_id]
                
                # Copy artifact to run directory
                run_dir = self.tracking_dir / run_id
                run_dir.mkdir(exist_ok=True)
                
                artifact_name = Path(artifact_path).name
                dest_path = run_dir / artifact_name
                
                if artifact_type == "file":
                    import shutil
                    shutil.copy2(artifact_path, dest_path)
                elif artifact_type == "model":
                    # Save model using pickle
                    with open(dest_path, 'wb') as f:
                        pickle.dump(artifact_path, f)
                
                run.artifacts.append(str(dest_path))
            
            logger.info(f"Logged artifact {artifact_path} for run {run_id}")
            
        except Exception as e:
            logger.error(f"Failed to log artifact: {e}")
    
    def log_text(self, run_id: str, text: str, timestamp: datetime = None):
        """Log text message for run"""
        with self._lock:
            if run_id in self.active_runs:
                timestamp = timestamp or datetime.now()
                log_entry = f"[{timestamp.isoformat()}] {text}"
                self.active_runs[run_id].logs.append(log_entry)
    
    def log_system_metrics(self, run_id: str):
        """Log system performance metrics"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            timestamp = time.time()
            step = int(timestamp)
            
            system_metrics = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024**3),
                'disk_percent': (disk.used / disk.total) * 100,
                'disk_free_gb': disk.free / (1024**3)
            }
            
            with self._lock:
                if run_id in self.active_runs:
                    run = self.active_runs[run_id]
                    
                    for metric_name, value in system_metrics.items():
                        if metric_name not in run.system_metrics:
                            run.system_metrics[metric_name] = []
                        
                        metric_point = MetricPoint(
                            timestamp=timestamp,
                            step=step,
                            value=value
                        )
                        
                        run.system_metrics[metric_name].append(metric_point)
            
        except Exception as e:
            logger.error(f"Failed to log system metrics: {e}")
    
    def end_run(self, run_id: str, status: str = "completed", 
                final_metrics: Dict[str, float] = None):
        """End experiment run"""
        try:
            with self._lock:
                if run_id not in self.active_runs:
                    logger.warning(f"Run {run_id} not found or not active")
                    return
                
                run = self.active_runs.pop(run_id)
                run.ended_at = datetime.now()
                run.status = status
                
                if final_metrics:
                    run.final_metrics.update(final_metrics)
                
                self.completed_runs[run_id] = run
            
            # Save run
            self._save_run(run)
            
            # Notify callbacks
            self._notify_run_callbacks('ended', run)
            
            logger.info(f"Ended experiment run {run_id} with status {status}")
            
        except Exception as e:
            logger.error(f"Failed to end experiment run: {e}")
    
    def get_run(self, run_id: str) -> Optional[ExperimentRun]:
        """Get experiment run by ID"""
        with self._lock:
            return (self.active_runs.get(run_id) or 
                   self.completed_runs.get(run_id))
    
    def list_runs(self, experiment_id: str = None, 
                  status: str = None) -> List[ExperimentRun]:
        """List experiment runs with optional filtering"""
        with self._lock:
            all_runs = list(self.active_runs.values()) + list(self.completed_runs.values())
            
            if experiment_id:
                all_runs = [r for r in all_runs if r.experiment_id == experiment_id]
            
            if status:
                all_runs = [r for r in all_runs if r.status == status]
            
            # Sort by start time (newest first)
            all_runs.sort(key=lambda r: r.started_at, reverse=True)
            return all_runs
    
    def compare_runs(self, run_ids: List[str], 
                     metrics: List[str] = None) -> Dict[str, Any]:
        """Compare multiple experiment runs"""
        comparison = {
            'runs': {},
            'metrics_comparison': {},
            'best_runs': {}
        }
        
        runs = []
        for run_id in run_ids:
            run = self.get_run(run_id)
            if run:
                runs.append(run)
                comparison['runs'][run_id] = {
                    'name': run.name,
                    'status': run.status,
                    'started_at': run.started_at.isoformat(),
                    'final_metrics': run.final_metrics,
                    'hyperparameters': run.hyperparameters
                }
        
        if not runs:
            return comparison
        
        # Get all metrics if not specified
        if metrics is None:
            all_metrics = set()
            for run in runs:
                all_metrics.update(run.final_metrics.keys())
            metrics = list(all_metrics)
        
        # Compare metrics
        for metric in metrics:
            metric_values = {}
            for run in runs:
                if metric in run.final_metrics:
                    metric_values[run.run_id] = run.final_metrics[metric]
            
            if metric_values:
                comparison['metrics_comparison'][metric] = metric_values
                
                # Find best run for this metric
                best_run_id = max(metric_values.keys(), 
                                key=lambda rid: metric_values[rid])
                comparison['best_runs'][metric] = {
                    'run_id': best_run_id,
                    'value': metric_values[best_run_id]
                }
        
        return comparison
    
    def plot_metrics(self, run_ids: List[str], metrics: List[str], 
                     save_path: str = None) -> str:
        """Plot metrics for multiple runs"""
        try:
            fig, axes = plt.subplots(len(metrics), 1, 
                                   figsize=(12, 4 * len(metrics)))
            if len(metrics) == 1:
                axes = [axes]
            
            for i, metric in enumerate(metrics):
                ax = axes[i]
                
                for run_id in run_ids:
                    run = self.get_run(run_id)
                    if run and metric in run.metrics:
                        points = run.metrics[metric]
                        steps = [p.step for p in points]
                        values = [p.value for p in points]
                        ax.plot(steps, values, label=f"{run.name} ({run_id[:8]})")
                
                ax.set_title(f"Metric: {metric}")
                ax.set_xlabel("Step")
                ax.set_ylabel(metric)
                ax.legend()
                ax.grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                plot_path = save_path
            else:
                plot_path = self.tracking_dir / f"metrics_plot_{int(time.time())}.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
            
            plt.close()
            
            logger.info(f"Saved metrics plot to {plot_path}")
            return str(plot_path)
            
        except Exception as e:
            logger.error(f"Failed to plot metrics: {e}")
            return ""
    
    def export_run_data(self, run_id: str, format: str = "json") -> str:
        """Export run data to file"""
        try:
            run = self.get_run(run_id)
            if not run:
                raise ValueError(f"Run {run_id} not found")
            
            export_dir = self.tracking_dir / "exports"
            export_dir.mkdir(exist_ok=True)
            
            if format == "json":
                export_path = export_dir / f"{run_id}.json"
                with open(export_path, 'w') as f:
                    json.dump(run.to_dict(), f, indent=2)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            logger.info(f"Exported run {run_id} to {export_path}")
            return str(export_path)
            
        except Exception as e:
            logger.error(f"Failed to export run data: {e}")
            raise
    
    def add_metric_callback(self, callback: Callable):
        """Add callback for metric updates"""
        self.metric_callbacks.append(callback)
    
    def add_run_callback(self, callback: Callable):
        """Add callback for run events"""
        self.run_callbacks.append(callback)
    
    def _notify_metric_callbacks(self, run_id: str, metric_name: str, 
                                value: float, step: int):
        """Notify metric callbacks"""
        for callback in self.metric_callbacks:
            try:
                callback(run_id, metric_name, value, step)
            except Exception as e:
                logger.error(f"Error in metric callback: {e}")
    
    def _notify_run_callbacks(self, event: str, run: ExperimentRun):
        """Notify run callbacks"""
        for callback in self.run_callbacks:
            try:
                callback(event, run)
            except Exception as e:
                logger.error(f"Error in run callback: {e}")
    
    def _generate_run_id(self, experiment_id: str, run_name: str) -> str:
        """Generate unique run ID"""
        timestamp = int(time.time())
        return f"{experiment_id}_{run_name}_{timestamp}"
    
    def _save_run(self, run: ExperimentRun):
        """Save run to disk"""
        try:
            run_file = self.tracking_dir / f"{run.run_id}.json"
            with open(run_file, 'w') as f:
                json.dump(run.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save run {run.run_id}: {e}")
    
    def _load_runs(self):
        """Load existing runs from disk"""
        try:
            for run_file in self.tracking_dir.glob("*.json"):
                if run_file.name.startswith("exp_"):
                    continue  # Skip experiment files
                
                try:
                    with open(run_file, 'r') as f:
                        data = json.load(f)
                    
                    run = ExperimentRun.from_dict(data)
                    
                    if run.status == "running":
                        # Mark as failed if process was interrupted
                        run.status = "failed"
                        run.ended_at = datetime.now()
                        self.completed_runs[run.run_id] = run
                    else:
                        self.completed_runs[run.run_id] = run
                        
                except Exception as e:
                    logger.error(f"Failed to load run {run_file}: {e}")
            
            logger.info(f"Loaded {len(self.completed_runs)} experiment runs")
            
        except Exception as e:
            logger.error(f"Failed to load runs: {e}")
    
    def _start_auto_save(self):
        """Start auto-save thread"""
        def auto_save():
            while not self._stop_auto_save.is_set():
                try:
                    with self._lock:
                        for run in self.active_runs.values():
                            self._save_run(run)
                    
                    self._stop_auto_save.wait(self.auto_save_interval)
                    
                except Exception as e:
                    logger.error(f"Error in auto-save: {e}")
        
        self._auto_save_thread = threading.Thread(target=auto_save, daemon=True)
        self._auto_save_thread.start()
    
    def cleanup(self):
        """Cleanup resources"""
        self._stop_auto_save.set()
        if self._auto_save_thread:
            self._auto_save_thread.join(timeout=5)

# Global experiment tracker instance
experiment_tracker = ExperimentTracker()
