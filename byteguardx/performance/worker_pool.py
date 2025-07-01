"""
Worker pool for multiprocessing scan operations
Provides scalable parallel processing for large codebases
"""

import logging
import multiprocessing as mp
import threading
import time
import queue
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import os
import pickle
import signal
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import psutil

logger = logging.getLogger(__name__)

class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ScanTask:
    """Scan task for worker pool processing"""
    task_id: str
    task_type: str  # 'file_scan', 'directory_scan', 'pattern_training'
    file_path: str
    content: Optional[str] = None
    scanner_config: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    worker_id: Optional[str] = None
    
    @property
    def execution_time(self) -> Optional[float]:
        """Get task execution time in seconds"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

@dataclass
class WorkerStats:
    """Worker performance statistics"""
    worker_id: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_activity: float = field(default_factory=time.time)
    
    def update_stats(self, task: ScanTask):
        """Update worker statistics with completed task"""
        if task.status == TaskStatus.COMPLETED:
            self.tasks_completed += 1
            if task.execution_time:
                self.total_execution_time += task.execution_time
                self.average_execution_time = self.total_execution_time / self.tasks_completed
        elif task.status == TaskStatus.FAILED:
            self.tasks_failed += 1
        
        self.last_activity = time.time()

class WorkerPool:
    """
    High-performance worker pool for parallel scan processing
    Supports both process-based and thread-based workers
    """
    
    def __init__(self, 
                 max_workers: Optional[int] = None,
                 use_processes: bool = True,
                 task_timeout: float = 300.0,
                 max_queue_size: int = 1000):
        
        # Configuration
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self.use_processes = use_processes
        self.task_timeout = task_timeout
        self.max_queue_size = max_queue_size
        
        # Task management
        self.task_queue = queue.PriorityQueue(maxsize=max_queue_size)
        self.active_tasks: Dict[str, ScanTask] = {}
        self.completed_tasks: Dict[str, ScanTask] = {}
        self.task_results: Dict[str, Any] = {}
        
        # Worker management
        self.executor: Optional[Union[ProcessPoolExecutor, ThreadPoolExecutor]] = None
        self.worker_stats: Dict[str, WorkerStats] = {}
        self.is_running = False
        
        # Monitoring
        self.total_tasks_submitted = 0
        self.total_tasks_completed = 0
        self.total_tasks_failed = 0
        
        # Thread safety
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        
        # Performance monitoring
        self._monitor_thread = None
        self._monitor_interval = 30  # seconds
        
    def start(self):
        """Start the worker pool"""
        with self._lock:
            if self.is_running:
                return
            
            try:
                # Create executor
                if self.use_processes:
                    self.executor = ProcessPoolExecutor(
                        max_workers=self.max_workers,
                        initializer=self._worker_initializer
                    )
                else:
                    self.executor = ThreadPoolExecutor(
                        max_workers=self.max_workers
                    )
                
                self.is_running = True
                
                # Start performance monitoring
                self._start_monitoring()
                
                logger.info(f"Started worker pool with {self.max_workers} {'processes' if self.use_processes else 'threads'}")
                
            except Exception as e:
                logger.error(f"Failed to start worker pool: {e}")
                raise
    
    def stop(self, wait: bool = True, timeout: float = 30.0):
        """Stop the worker pool"""
        with self._lock:
            if not self.is_running:
                return
            
            self.is_running = False
            self._shutdown_event.set()
            
            # Stop monitoring
            if self._monitor_thread:
                self._monitor_thread.join(timeout=5)
            
            # Shutdown executor
            if self.executor:
                self.executor.shutdown(wait=wait, timeout=timeout)
                self.executor = None
            
            logger.info("Worker pool stopped")
    
    def submit_task(self, task: ScanTask) -> bool:
        """Submit task to worker pool"""
        if not self.is_running:
            raise RuntimeError("Worker pool is not running")
        
        try:
            # Add to queue with priority
            priority_value = -task.priority.value  # Negative for max-heap behavior
            self.task_queue.put((priority_value, task.created_at, task), timeout=1.0)
            
            with self._lock:
                self.active_tasks[task.task_id] = task
                self.total_tasks_submitted += 1
            
            # Submit to executor
            future = self.executor.submit(self._execute_task, task)
            
            # Handle completion
            def handle_completion(fut):
                try:
                    result = fut.result()
                    self._handle_task_completion(task.task_id, result, None)
                except Exception as e:
                    self._handle_task_completion(task.task_id, None, str(e))
            
            future.add_done_callback(handle_completion)
            
            logger.debug(f"Submitted task {task.task_id} to worker pool")
            return True
            
        except queue.Full:
            logger.warning(f"Task queue is full, rejecting task {task.task_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to submit task {task.task_id}: {e}")
            return False
    
    def submit_file_scan(self, file_path: str, content: str, 
                        scanner_types: List[str] = None,
                        priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """Submit file scan task"""
        task_id = f"file_scan_{int(time.time() * 1000000)}"
        
        task = ScanTask(
            task_id=task_id,
            task_type="file_scan",
            file_path=file_path,
            content=content,
            scanner_config={
                "scanner_types": scanner_types or ["secret", "dependency", "ai_pattern"]
            },
            priority=priority
        )
        
        if self.submit_task(task):
            return task_id
        else:
            raise RuntimeError("Failed to submit file scan task")
    
    def submit_directory_scan(self, directory_path: str, 
                            recursive: bool = True,
                            scanner_types: List[str] = None,
                            priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """Submit directory scan task"""
        task_id = f"dir_scan_{int(time.time() * 1000000)}"
        
        task = ScanTask(
            task_id=task_id,
            task_type="directory_scan",
            file_path=directory_path,
            scanner_config={
                "recursive": recursive,
                "scanner_types": scanner_types or ["secret", "dependency", "ai_pattern"]
            },
            priority=priority
        )
        
        if self.submit_task(task):
            return task_id
        else:
            raise RuntimeError("Failed to submit directory scan task")
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get task status"""
        with self._lock:
            if task_id in self.active_tasks:
                return self.active_tasks[task_id].status
            elif task_id in self.completed_tasks:
                return self.completed_tasks[task_id].status
            return None
    
    def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task result"""
        with self._lock:
            if task_id in self.completed_tasks:
                return self.completed_tasks[task_id].result
            return None
    
    def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Wait for task completion and return result"""
        start_time = time.time()
        
        while True:
            status = self.get_task_status(task_id)
            
            if status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                return self.get_task_result(task_id)
            
            if timeout and (time.time() - start_time) > timeout:
                logger.warning(f"Task {task_id} timed out after {timeout} seconds")
                return None
            
            time.sleep(0.1)
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel pending or running task"""
        with self._lock:
            if task_id in self.active_tasks:
                task = self.active_tasks[task_id]
                if task.status == TaskStatus.PENDING:
                    task.status = TaskStatus.CANCELLED
                    self._move_to_completed(task_id)
                    return True
        return False
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get worker pool statistics"""
        with self._lock:
            active_count = len(self.active_tasks)
            completed_count = len(self.completed_tasks)
            
            # Calculate success rate
            total_processed = self.total_tasks_completed + self.total_tasks_failed
            success_rate = (self.total_tasks_completed / total_processed * 100) if total_processed > 0 else 0
            
            # Get queue size
            queue_size = self.task_queue.qsize()
            
            return {
                "is_running": self.is_running,
                "max_workers": self.max_workers,
                "worker_type": "processes" if self.use_processes else "threads",
                "active_tasks": active_count,
                "completed_tasks": completed_count,
                "queue_size": queue_size,
                "total_submitted": self.total_tasks_submitted,
                "total_completed": self.total_tasks_completed,
                "total_failed": self.total_tasks_failed,
                "success_rate_percent": round(success_rate, 2),
                "worker_stats": {wid: {
                    "tasks_completed": stats.tasks_completed,
                    "tasks_failed": stats.tasks_failed,
                    "avg_execution_time": stats.average_execution_time,
                    "cpu_usage": stats.cpu_usage,
                    "memory_usage": stats.memory_usage
                } for wid, stats in self.worker_stats.items()}
            }
    
    def _execute_task(self, task: ScanTask) -> Dict[str, Any]:
        """Execute scan task in worker process/thread"""
        task.started_at = time.time()
        task.status = TaskStatus.RUNNING
        task.worker_id = f"worker_{os.getpid()}"
        
        try:
            if task.task_type == "file_scan":
                result = self._execute_file_scan(task)
            elif task.task_type == "directory_scan":
                result = self._execute_directory_scan(task)
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")
            
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = time.time()
            
            return result
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = time.time()
            logger.error(f"Task {task.task_id} failed: {e}")
            raise
    
    def _execute_file_scan(self, task: ScanTask) -> Dict[str, Any]:
        """Execute file scan task"""
        from ..scanners.secret_scanner import SecretScanner
        from ..scanners.dependency_scanner import DependencyScanner
        from ..scanners.ai_pattern_scanner import AIPatternScanner
        
        # Create file info
        file_info = {
            "file_path": task.file_path,
            "content": task.content,
            "size": len(task.content) if task.content else 0,
            "lines": len(task.content.splitlines()) if task.content else 0,
            "extension": os.path.splitext(task.file_path)[1].lower(),
            "name": os.path.basename(task.file_path)
        }
        
        # Run scanners
        all_findings = []
        scanner_types = task.scanner_config.get("scanner_types", ["secret", "dependency", "ai_pattern"])
        
        if "secret" in scanner_types:
            scanner = SecretScanner()
            findings = scanner.scan_file(file_info)
            all_findings.extend(findings)
        
        if "dependency" in scanner_types:
            scanner = DependencyScanner()
            findings = scanner.scan_file(file_info)
            all_findings.extend(findings)
        
        if "ai_pattern" in scanner_types:
            scanner = AIPatternScanner()
            findings = scanner.scan_file(file_info)
            all_findings.extend(findings)
        
        return {
            "file_path": task.file_path,
            "findings": all_findings,
            "scan_duration": task.execution_time,
            "scanner_types": scanner_types
        }
    
    def _execute_directory_scan(self, task: ScanTask) -> Dict[str, Any]:
        """Execute directory scan task"""
        from ..core.file_processor import FileProcessor
        
        # Process directory
        file_processor = FileProcessor()
        processed_files = file_processor.process_directory(
            task.file_path, 
            recursive=task.scanner_config.get("recursive", True)
        )
        
        # Submit individual file scan tasks
        file_tasks = []
        for file_info in processed_files:
            if "error" not in file_info:
                file_task_id = self.submit_file_scan(
                    file_info["file_path"],
                    file_info["content"],
                    task.scanner_config.get("scanner_types"),
                    TaskPriority.NORMAL
                )
                file_tasks.append(file_task_id)
        
        # Wait for all file tasks to complete
        all_findings = []
        for file_task_id in file_tasks:
            result = self.wait_for_task(file_task_id, timeout=self.task_timeout)
            if result and "findings" in result:
                all_findings.extend(result["findings"])
        
        return {
            "directory_path": task.file_path,
            "total_files": len(processed_files),
            "findings": all_findings,
            "scan_duration": task.execution_time
        }
    
    def _handle_task_completion(self, task_id: str, result: Optional[Dict[str, Any]], error: Optional[str]):
        """Handle task completion"""
        with self._lock:
            if task_id in self.active_tasks:
                task = self.active_tasks[task_id]
                
                if error:
                    task.status = TaskStatus.FAILED
                    task.error = error
                    self.total_tasks_failed += 1
                else:
                    task.status = TaskStatus.COMPLETED
                    task.result = result
                    self.total_tasks_completed += 1
                
                task.completed_at = time.time()
                
                # Update worker stats
                if task.worker_id:
                    if task.worker_id not in self.worker_stats:
                        self.worker_stats[task.worker_id] = WorkerStats(task.worker_id)
                    self.worker_stats[task.worker_id].update_stats(task)
                
                # Move to completed tasks
                self._move_to_completed(task_id)
    
    def _move_to_completed(self, task_id: str):
        """Move task from active to completed"""
        if task_id in self.active_tasks:
            task = self.active_tasks.pop(task_id)
            self.completed_tasks[task_id] = task
            
            # Cleanup old completed tasks (keep last 1000)
            if len(self.completed_tasks) > 1000:
                oldest_tasks = sorted(
                    self.completed_tasks.items(),
                    key=lambda x: x[1].completed_at or 0
                )[:100]
                for old_task_id, _ in oldest_tasks:
                    del self.completed_tasks[old_task_id]
    
    def _worker_initializer(self):
        """Initialize worker process"""
        # Ignore SIGINT in worker processes
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    def _start_monitoring(self):
        """Start performance monitoring thread"""
        def monitor():
            while not self._shutdown_event.is_set():
                try:
                    self._update_worker_stats()
                    time.sleep(self._monitor_interval)
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
        
        self._monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._monitor_thread.start()
    
    def _update_worker_stats(self):
        """Update worker performance statistics"""
        try:
            current_process = psutil.Process()
            
            # Update stats for current process (main process)
            main_worker_id = f"main_{os.getpid()}"
            if main_worker_id not in self.worker_stats:
                self.worker_stats[main_worker_id] = WorkerStats(main_worker_id)
            
            stats = self.worker_stats[main_worker_id]
            stats.cpu_usage = current_process.cpu_percent()
            stats.memory_usage = current_process.memory_percent()
            
        except Exception as e:
            logger.error(f"Failed to update worker stats: {e}")

# Global worker pool instance
worker_pool = WorkerPool()
