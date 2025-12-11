"""
Background Job Scheduler for ByteGuardX
Handles persistent job queues, scheduled tasks, and background processing
"""

import time
import threading
import logging
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)

class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"

class JobPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Job:
    """Background job definition"""
    id: str
    name: str
    function_name: str
    args: List[Any]
    kwargs: Dict[str, Any]
    priority: JobPriority
    status: JobStatus
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int = 300
    result: Optional[Any] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class JobScheduler:
    """
    Persistent job scheduler with SQLite backend
    Handles background tasks, scheduled jobs, and retry logic
    """
    
    def __init__(self, db_path: str = "data/jobs.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Job registry
        self.job_functions: Dict[str, Callable] = {}
        
        # Worker management
        self.workers: List[threading.Thread] = []
        self.worker_count = 4
        self.is_running = False
        self.shutdown_event = threading.Event()
        
        # Monitoring
        self.stats = {
            'total_jobs': 0,
            'completed_jobs': 0,
            'failed_jobs': 0,
            'active_jobs': 0
        }
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize database
        self._init_database()
        
        # Register cleanup job
        self.register_function('cleanup_old_jobs', self._cleanup_old_jobs)
        
    def _init_database(self):
        """Initialize SQLite database for job persistence"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    args TEXT NOT NULL,
                    kwargs TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    scheduled_at TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 3,
                    timeout_seconds INTEGER DEFAULT 300,
                    result TEXT,
                    error TEXT,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_jobs_scheduled ON jobs(scheduled_at)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority DESC)
            """)
    
    def register_function(self, name: str, func: Callable):
        """Register a function that can be called by jobs"""
        self.job_functions[name] = func
        logger.debug(f"Registered job function: {name}")
    
    def schedule_job(self, name: str, function_name: str, 
                    args: List[Any] = None, kwargs: Dict[str, Any] = None,
                    priority: JobPriority = JobPriority.NORMAL,
                    scheduled_at: Optional[datetime] = None,
                    max_retries: int = 3, timeout_seconds: int = 300,
                    metadata: Dict[str, Any] = None) -> str:
        """Schedule a new job"""
        job_id = str(uuid.uuid4())
        
        job = Job(
            id=job_id,
            name=name,
            function_name=function_name,
            args=args or [],
            kwargs=kwargs or {},
            priority=priority,
            status=JobStatus.PENDING,
            created_at=datetime.now(),
            scheduled_at=scheduled_at,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            metadata=metadata or {}
        )
        
        self._save_job(job)
        
        with self._lock:
            self.stats['total_jobs'] += 1
        
        logger.info(f"Scheduled job {job_id}: {name}")
        return job_id
    
    def schedule_recurring_job(self, name: str, function_name: str,
                             interval_seconds: int,
                             args: List[Any] = None, kwargs: Dict[str, Any] = None,
                             priority: JobPriority = JobPriority.NORMAL) -> str:
        """Schedule a recurring job"""
        # Schedule first execution
        job_id = self.schedule_job(
            name=f"{name}_recurring",
            function_name=function_name,
            args=args,
            kwargs=kwargs,
            priority=priority,
            metadata={'recurring': True, 'interval_seconds': interval_seconds}
        )
        
        logger.info(f"Scheduled recurring job {job_id}: {name} (every {interval_seconds}s)")
        return job_id
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending job"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "UPDATE jobs SET status = ? WHERE id = ? AND status = ?",
                    (JobStatus.CANCELLED.value, job_id, JobStatus.PENDING.value)
                )
                
                if cursor.rowcount > 0:
                    logger.info(f"Cancelled job {job_id}")
                    return True
                else:
                    logger.warning(f"Could not cancel job {job_id} (not pending)")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to cancel job {job_id}: {e}")
            return False
    
    def get_job_status(self, job_id: str) -> Optional[Job]:
        """Get job status and details"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_job(row)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get job status {job_id}: {e}")
            return None
    
    def start(self):
        """Start the job scheduler"""
        if self.is_running:
            return
        
        self.is_running = True
        self.shutdown_event.clear()
        
        # Start worker threads
        for i in range(self.worker_count):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"JobWorker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        # Start scheduler thread for recurring jobs
        scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="JobScheduler",
            daemon=True
        )
        scheduler_thread.start()
        
        # Schedule daily cleanup
        self.schedule_recurring_job(
            name="daily_cleanup",
            function_name="cleanup_old_jobs",
            interval_seconds=86400,  # 24 hours
            priority=JobPriority.LOW
        )
        
        logger.info(f"Job scheduler started with {self.worker_count} workers")
    
    def stop(self, timeout: int = 30):
        """Stop the job scheduler gracefully"""
        if not self.is_running:
            return
        
        logger.info("Stopping job scheduler...")
        self.is_running = False
        self.shutdown_event.set()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=timeout)
        
        self.workers.clear()
        logger.info("Job scheduler stopped")
    
    def _worker_loop(self):
        """Main worker loop"""
        while self.is_running and not self.shutdown_event.is_set():
            try:
                job = self._get_next_job()
                if job:
                    self._execute_job(job)
                else:
                    # No jobs available, wait a bit
                    self.shutdown_event.wait(1.0)
                    
            except Exception as e:
                logger.error(f"Worker error: {e}")
                time.sleep(1.0)
    
    def _scheduler_loop(self):
        """Scheduler loop for recurring jobs"""
        while self.is_running and not self.shutdown_event.is_set():
            try:
                self._process_scheduled_jobs()
                self.shutdown_event.wait(10.0)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(10.0)
    
    def _get_next_job(self) -> Optional[Job]:
        """Get the next job to execute"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get highest priority pending job
                cursor = conn.execute("""
                    SELECT * FROM jobs 
                    WHERE status = ? AND (scheduled_at IS NULL OR scheduled_at <= ?)
                    ORDER BY priority DESC, created_at ASC 
                    LIMIT 1
                """, (JobStatus.PENDING.value, datetime.now().isoformat()))
                
                row = cursor.fetchone()
                if row:
                    job = self._row_to_job(row)
                    
                    # Mark as running
                    conn.execute(
                        "UPDATE jobs SET status = ?, started_at = ? WHERE id = ?",
                        (JobStatus.RUNNING.value, datetime.now().isoformat(), job.id)
                    )
                    
                    job.status = JobStatus.RUNNING
                    job.started_at = datetime.now()
                    
                    with self._lock:
                        self.stats['active_jobs'] += 1
                    
                    return job
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get next job: {e}")
            return None
    
    def _execute_job(self, job: Job):
        """Execute a job"""
        try:
            logger.info(f"Executing job {job.id}: {job.name}")
            
            # Get function
            func = self.job_functions.get(job.function_name)
            if not func:
                raise ValueError(f"Unknown function: {job.function_name}")
            
            # Execute with timeout
            start_time = time.time()
            result = func(*job.args, **job.kwargs)
            execution_time = time.time() - start_time
            
            # Mark as completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now()
            job.result = result
            job.metadata['execution_time'] = execution_time
            
            self._save_job(job)
            
            # Handle recurring jobs
            if job.metadata.get('recurring'):
                self._schedule_next_occurrence(job)
            
            with self._lock:
                self.stats['completed_jobs'] += 1
                self.stats['active_jobs'] -= 1
            
            logger.info(f"Job {job.id} completed in {execution_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Job {job.id} failed: {e}")
            self._handle_job_failure(job, str(e))
    
    def _handle_job_failure(self, job: Job, error: str):
        """Handle job failure with retry logic"""
        job.error = error
        job.retry_count += 1
        
        if job.retry_count <= job.max_retries:
            # Retry with exponential backoff
            delay_seconds = min(300, 2 ** job.retry_count)  # Max 5 minutes
            job.scheduled_at = datetime.now() + timedelta(seconds=delay_seconds)
            job.status = JobStatus.RETRYING
            
            logger.warning(f"Job {job.id} will retry in {delay_seconds}s (attempt {job.retry_count}/{job.max_retries})")
        else:
            # Max retries exceeded
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now()
            
            with self._lock:
                self.stats['failed_jobs'] += 1
            
            logger.error(f"Job {job.id} failed permanently after {job.retry_count} attempts")
        
        with self._lock:
            self.stats['active_jobs'] -= 1
        
        self._save_job(job)
    
    def _schedule_next_occurrence(self, job: Job):
        """Schedule next occurrence of a recurring job"""
        interval = job.metadata.get('interval_seconds', 3600)
        next_run = datetime.now() + timedelta(seconds=interval)
        
        self.schedule_job(
            name=job.name,
            function_name=job.function_name,
            args=job.args,
            kwargs=job.kwargs,
            priority=job.priority,
            scheduled_at=next_run,
            max_retries=job.max_retries,
            timeout_seconds=job.timeout_seconds,
            metadata=job.metadata
        )
    
    def _process_scheduled_jobs(self):
        """Process jobs that are scheduled to run now"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Update scheduled jobs to pending if their time has come
                conn.execute("""
                    UPDATE jobs 
                    SET status = ?, scheduled_at = NULL 
                    WHERE status = ? AND scheduled_at <= ?
                """, (
                    JobStatus.PENDING.value,
                    JobStatus.RETRYING.value,
                    datetime.now().isoformat()
                ))
                
        except Exception as e:
            logger.error(f"Failed to process scheduled jobs: {e}")
    
    def _cleanup_old_jobs(self, days: int = 30):
        """Clean up old completed/failed jobs"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    DELETE FROM jobs 
                    WHERE status IN (?, ?) AND completed_at < ?
                """, (
                    JobStatus.COMPLETED.value,
                    JobStatus.FAILED.value,
                    cutoff_date.isoformat()
                ))
                
                deleted_count = cursor.rowcount
                
            logger.info(f"Cleaned up {deleted_count} old jobs")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old jobs: {e}")
            return 0
    
    def _save_job(self, job: Job):
        """Save job to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO jobs VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    job.id,
                    job.name,
                    job.function_name,
                    json.dumps(job.args),
                    json.dumps(job.kwargs),
                    job.priority.value,
                    job.status.value,
                    job.created_at.isoformat(),
                    job.scheduled_at.isoformat() if job.scheduled_at else None,
                    job.started_at.isoformat() if job.started_at else None,
                    job.completed_at.isoformat() if job.completed_at else None,
                    job.retry_count,
                    job.max_retries,
                    job.timeout_seconds,
                    json.dumps(job.result) if job.result else None,
                    job.error,
                    json.dumps(job.metadata)
                ))
                
        except Exception as e:
            logger.error(f"Failed to save job {job.id}: {e}")
    
    def _row_to_job(self, row) -> Job:
        """Convert database row to Job object"""
        return Job(
            id=row['id'],
            name=row['name'],
            function_name=row['function_name'],
            args=json.loads(row['args']),
            kwargs=json.loads(row['kwargs']),
            priority=JobPriority(row['priority']),
            status=JobStatus(row['status']),
            created_at=datetime.fromisoformat(row['created_at']),
            scheduled_at=datetime.fromisoformat(row['scheduled_at']) if row['scheduled_at'] else None,
            started_at=datetime.fromisoformat(row['started_at']) if row['started_at'] else None,
            completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
            retry_count=row['retry_count'],
            max_retries=row['max_retries'],
            timeout_seconds=row['timeout_seconds'],
            result=json.loads(row['result']) if row['result'] else None,
            error=row['error'],
            metadata=json.loads(row['metadata'])
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        with self._lock:
            stats = self.stats.copy()
        
        # Add database stats
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status")
                status_counts = dict(cursor.fetchall())
                stats['status_counts'] = status_counts
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            stats['status_counts'] = {}
        
        return stats

# Global job scheduler instance
job_scheduler = JobScheduler()
