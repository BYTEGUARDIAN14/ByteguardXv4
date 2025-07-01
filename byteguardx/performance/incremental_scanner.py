"""
Incremental scanner for detecting and scanning only modified files
Optimizes scan performance by avoiding re-scanning unchanged files
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import threading
import time

from .cache_manager import cache_manager, FileMetadata

logger = logging.getLogger(__name__)

@dataclass
class FileChangeInfo:
    """Information about file changes"""
    file_path: str
    change_type: str  # 'added', 'modified', 'deleted'
    old_checksum: Optional[str] = None
    new_checksum: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    old_mtime: Optional[float] = None
    new_mtime: Optional[float] = None
    detected_at: datetime = None
    
    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.now()

@dataclass
class ScanSnapshot:
    """Snapshot of directory state for incremental scanning"""
    directory_path: str
    snapshot_id: str
    created_at: datetime
    file_metadata: Dict[str, FileMetadata]
    total_files: int
    total_size: int
    scan_config: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'directory_path': self.directory_path,
            'snapshot_id': self.snapshot_id,
            'created_at': self.created_at.isoformat(),
            'file_metadata': {
                path: asdict(metadata) for path, metadata in self.file_metadata.items()
            },
            'total_files': self.total_files,
            'total_size': self.total_size,
            'scan_config': self.scan_config
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanSnapshot':
        """Create from dictionary"""
        file_metadata = {}
        for path, metadata_dict in data['file_metadata'].items():
            metadata_dict['last_scanned'] = datetime.fromisoformat(metadata_dict['last_scanned'])
            file_metadata[path] = FileMetadata(**metadata_dict)
        
        return cls(
            directory_path=data['directory_path'],
            snapshot_id=data['snapshot_id'],
            created_at=datetime.fromisoformat(data['created_at']),
            file_metadata=file_metadata,
            total_files=data['total_files'],
            total_size=data['total_size'],
            scan_config=data['scan_config']
        )

class IncrementalScanner:
    """
    Incremental scanner that tracks file changes and only scans modified files
    Significantly improves performance for large codebases with frequent scans
    """
    
    def __init__(self, snapshots_dir: str = "data/snapshots"):
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        
        # Snapshot storage
        self.snapshots: Dict[str, ScanSnapshot] = {}
        self.directory_snapshots: Dict[str, str] = {}  # directory -> latest snapshot_id
        
        # File watching
        self.watched_directories: Set[str] = set()
        self.file_watchers: Dict[str, Any] = {}
        
        # Change tracking
        self.pending_changes: Dict[str, List[FileChangeInfo]] = {}
        
        # Configuration
        self.max_snapshots_per_directory = 10
        self.snapshot_retention_days = 30
        self.change_detection_interval = 60  # seconds
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Background monitoring
        self._monitor_thread = None
        self._stop_monitoring = threading.Event()
        
        # Load existing snapshots
        self._load_snapshots()
    
    def create_snapshot(self, directory_path: str, scan_config: Dict[str, Any] = None) -> str:
        """Create snapshot of directory state"""
        try:
            directory_path = os.path.abspath(directory_path)
            snapshot_id = self._generate_snapshot_id(directory_path)
            
            logger.info(f"Creating snapshot for {directory_path}")
            
            # Scan directory and collect file metadata
            file_metadata = {}
            total_files = 0
            total_size = 0
            
            for root, dirs, files in os.walk(directory_path):
                # Skip ignored directories
                dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]
                
                for file in files:
                    if self._should_ignore_file(file):
                        continue
                    
                    file_path = str(Path(root) / file)
                    try:
                        metadata = FileMetadata.from_file(file_path)
                        file_metadata[file_path] = metadata
                        total_files += 1
                        total_size += metadata.size
                    except (OSError, FileNotFoundError) as e:
                        logger.warning(f"Failed to process file {file_path}: {e}")
            
            # Create snapshot
            snapshot = ScanSnapshot(
                directory_path=directory_path,
                snapshot_id=snapshot_id,
                created_at=datetime.now(),
                file_metadata=file_metadata,
                total_files=total_files,
                total_size=total_size,
                scan_config=scan_config or {}
            )
            
            with self._lock:
                self.snapshots[snapshot_id] = snapshot
                self.directory_snapshots[directory_path] = snapshot_id
            
            # Save snapshot
            self._save_snapshot(snapshot)
            
            # Cleanup old snapshots
            self._cleanup_old_snapshots(directory_path)
            
            logger.info(f"Created snapshot {snapshot_id} with {total_files} files")
            return snapshot_id
            
        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            raise
    
    def detect_changes(self, directory_path: str, 
                      baseline_snapshot_id: Optional[str] = None) -> List[FileChangeInfo]:
        """Detect changes since last snapshot"""
        try:
            directory_path = os.path.abspath(directory_path)
            
            # Get baseline snapshot
            if baseline_snapshot_id:
                baseline_snapshot = self.snapshots.get(baseline_snapshot_id)
            else:
                baseline_snapshot_id = self.directory_snapshots.get(directory_path)
                baseline_snapshot = self.snapshots.get(baseline_snapshot_id) if baseline_snapshot_id else None
            
            if not baseline_snapshot:
                logger.warning(f"No baseline snapshot found for {directory_path}")
                return []
            
            logger.info(f"Detecting changes since snapshot {baseline_snapshot_id}")
            
            # Get current file state
            current_files = {}
            for root, dirs, files in os.walk(directory_path):
                dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]
                
                for file in files:
                    if self._should_ignore_file(file):
                        continue
                    
                    file_path = str(Path(root) / file)
                    try:
                        current_files[file_path] = FileMetadata.from_file(file_path)
                    except (OSError, FileNotFoundError):
                        continue
            
            # Compare with baseline
            changes = []
            baseline_files = baseline_snapshot.file_metadata
            
            # Check for added and modified files
            for file_path, current_metadata in current_files.items():
                if file_path not in baseline_files:
                    # New file
                    changes.append(FileChangeInfo(
                        file_path=file_path,
                        change_type='added',
                        new_checksum=current_metadata.checksum,
                        new_size=current_metadata.size,
                        new_mtime=current_metadata.mtime
                    ))
                else:
                    # Check if modified
                    baseline_metadata = baseline_files[file_path]
                    if (current_metadata.checksum != baseline_metadata.checksum or
                        current_metadata.size != baseline_metadata.size or
                        current_metadata.mtime != baseline_metadata.mtime):
                        
                        changes.append(FileChangeInfo(
                            file_path=file_path,
                            change_type='modified',
                            old_checksum=baseline_metadata.checksum,
                            new_checksum=current_metadata.checksum,
                            old_size=baseline_metadata.size,
                            new_size=current_metadata.size,
                            old_mtime=baseline_metadata.mtime,
                            new_mtime=current_metadata.mtime
                        ))
            
            # Check for deleted files
            for file_path, baseline_metadata in baseline_files.items():
                if file_path not in current_files:
                    changes.append(FileChangeInfo(
                        file_path=file_path,
                        change_type='deleted',
                        old_checksum=baseline_metadata.checksum,
                        old_size=baseline_metadata.size,
                        old_mtime=baseline_metadata.mtime
                    ))
            
            logger.info(f"Detected {len(changes)} changes: "
                       f"{sum(1 for c in changes if c.change_type == 'added')} added, "
                       f"{sum(1 for c in changes if c.change_type == 'modified')} modified, "
                       f"{sum(1 for c in changes if c.change_type == 'deleted')} deleted")
            
            return changes
            
        except Exception as e:
            logger.error(f"Failed to detect changes: {e}")
            return []
    
    def get_files_to_scan(self, directory_path: str, 
                         force_full_scan: bool = False) -> Tuple[List[str], bool]:
        """
        Get list of files that need to be scanned
        Returns (files_to_scan, is_incremental)
        """
        try:
            directory_path = os.path.abspath(directory_path)
            
            if force_full_scan:
                # Full scan requested
                all_files = []
                for root, dirs, files in os.walk(directory_path):
                    dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]
                    for file in files:
                        if not self._should_ignore_file(file):
                            all_files.append(str(Path(root) / file))
                return all_files, False
            
            # Check if we have a baseline snapshot
            baseline_snapshot_id = self.directory_snapshots.get(directory_path)
            if not baseline_snapshot_id:
                logger.info(f"No baseline snapshot for {directory_path}, performing full scan")
                return self.get_files_to_scan(directory_path, force_full_scan=True)
            
            # Detect changes
            changes = self.detect_changes(directory_path, baseline_snapshot_id)
            
            # Get files that need scanning (added or modified)
            files_to_scan = []
            for change in changes:
                if change.change_type in ['added', 'modified']:
                    files_to_scan.append(change.file_path)
            
            # If too many changes, might be better to do full scan
            baseline_snapshot = self.snapshots[baseline_snapshot_id]
            change_ratio = len(changes) / max(baseline_snapshot.total_files, 1)
            
            if change_ratio > 0.5:  # More than 50% of files changed
                logger.info(f"High change ratio ({change_ratio:.1%}), performing full scan")
                return self.get_files_to_scan(directory_path, force_full_scan=True)
            
            logger.info(f"Incremental scan: {len(files_to_scan)} files to scan "
                       f"({len(changes)} total changes)")
            
            return files_to_scan, True
            
        except Exception as e:
            logger.error(f"Failed to get files to scan: {e}")
            return self.get_files_to_scan(directory_path, force_full_scan=True)
    
    def invalidate_cache_for_changes(self, changes: List[FileChangeInfo]):
        """Invalidate cache entries for changed files"""
        for change in changes:
            if change.change_type in ['modified', 'deleted']:
                cache_manager.invalidate_file(change.file_path)
    
    def start_monitoring(self, directory_path: str):
        """Start monitoring directory for changes"""
        try:
            directory_path = os.path.abspath(directory_path)
            
            with self._lock:
                self.watched_directories.add(directory_path)
            
            # Start monitoring thread if not already running
            if not self._monitor_thread or not self._monitor_thread.is_alive():
                self._stop_monitoring.clear()
                self._monitor_thread = threading.Thread(
                    target=self._monitoring_loop,
                    daemon=True,
                    name="IncrementalScanner-Monitor"
                )
                self._monitor_thread.start()
            
            logger.info(f"Started monitoring {directory_path}")
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self, directory_path: Optional[str] = None):
        """Stop monitoring directory or all directories"""
        with self._lock:
            if directory_path:
                directory_path = os.path.abspath(directory_path)
                self.watched_directories.discard(directory_path)
                logger.info(f"Stopped monitoring {directory_path}")
            else:
                self.watched_directories.clear()
                self._stop_monitoring.set()
                logger.info("Stopped all monitoring")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                with self._lock:
                    directories_to_monitor = list(self.watched_directories)
                
                for directory_path in directories_to_monitor:
                    try:
                        changes = self.detect_changes(directory_path)
                        if changes:
                            # Store pending changes
                            if directory_path not in self.pending_changes:
                                self.pending_changes[directory_path] = []
                            self.pending_changes[directory_path].extend(changes)
                            
                            # Invalidate cache for changed files
                            self.invalidate_cache_for_changes(changes)
                            
                            logger.info(f"Detected {len(changes)} changes in {directory_path}")
                    
                    except Exception as e:
                        logger.error(f"Error monitoring {directory_path}: {e}")
                
                # Wait before next check
                self._stop_monitoring.wait(self.change_detection_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)  # Wait before retrying
    
    def _should_ignore_directory(self, dirname: str) -> bool:
        """Check if directory should be ignored"""
        ignore_dirs = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', 'env', '.env',
            'build', 'dist', '.next', '.nuxt', 'target',
            '.idea', '.vscode', '.vs'
        }
        return dirname in ignore_dirs or dirname.startswith('.')
    
    def _should_ignore_file(self, filename: str) -> bool:
        """Check if file should be ignored"""
        if filename.startswith('.'):
            return True
        
        ignore_extensions = {
            '.pyc', '.pyo', '.pyd', '.so', '.dll', '.dylib',
            '.exe', '.bin', '.obj', '.o', '.a', '.lib',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.zip', '.tar', '.gz', '.rar', '.7z'
        }
        
        _, ext = os.path.splitext(filename)
        return ext.lower() in ignore_extensions
    
    def _generate_snapshot_id(self, directory_path: str) -> str:
        """Generate unique snapshot ID"""
        timestamp = int(time.time() * 1000)
        path_hash = hashlib.md5(directory_path.encode()).hexdigest()[:8]
        return f"snapshot_{path_hash}_{timestamp}"
    
    def _save_snapshot(self, snapshot: ScanSnapshot):
        """Save snapshot to disk"""
        try:
            snapshot_file = self.snapshots_dir / f"{snapshot.snapshot_id}.json"
            with open(snapshot_file, 'w') as f:
                json.dump(snapshot.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save snapshot {snapshot.snapshot_id}: {e}")
    
    def _load_snapshots(self):
        """Load existing snapshots from disk"""
        try:
            for snapshot_file in self.snapshots_dir.glob("snapshot_*.json"):
                try:
                    with open(snapshot_file, 'r') as f:
                        data = json.load(f)
                    
                    snapshot = ScanSnapshot.from_dict(data)
                    self.snapshots[snapshot.snapshot_id] = snapshot
                    self.directory_snapshots[snapshot.directory_path] = snapshot.snapshot_id
                    
                except Exception as e:
                    logger.error(f"Failed to load snapshot {snapshot_file}: {e}")
            
            logger.info(f"Loaded {len(self.snapshots)} snapshots")
            
        except Exception as e:
            logger.error(f"Failed to load snapshots: {e}")
    
    def _cleanup_old_snapshots(self, directory_path: str):
        """Clean up old snapshots for directory"""
        try:
            # Get all snapshots for this directory
            dir_snapshots = [
                snapshot for snapshot in self.snapshots.values()
                if snapshot.directory_path == directory_path
            ]
            
            # Sort by creation time (newest first)
            dir_snapshots.sort(key=lambda s: s.created_at, reverse=True)
            
            # Remove excess snapshots
            if len(dir_snapshots) > self.max_snapshots_per_directory:
                snapshots_to_remove = dir_snapshots[self.max_snapshots_per_directory:]
                for snapshot in snapshots_to_remove:
                    self._remove_snapshot(snapshot.snapshot_id)
            
            # Remove old snapshots
            cutoff_date = datetime.now() - timedelta(days=self.snapshot_retention_days)
            old_snapshots = [
                snapshot for snapshot in dir_snapshots
                if snapshot.created_at < cutoff_date
            ]
            
            for snapshot in old_snapshots:
                self._remove_snapshot(snapshot.snapshot_id)
            
        except Exception as e:
            logger.error(f"Failed to cleanup old snapshots: {e}")
    
    def _remove_snapshot(self, snapshot_id: str):
        """Remove snapshot"""
        try:
            # Remove from memory
            if snapshot_id in self.snapshots:
                del self.snapshots[snapshot_id]
            
            # Remove file
            snapshot_file = self.snapshots_dir / f"{snapshot_id}.json"
            if snapshot_file.exists():
                snapshot_file.unlink()
            
            logger.debug(f"Removed snapshot {snapshot_id}")
            
        except Exception as e:
            logger.error(f"Failed to remove snapshot {snapshot_id}: {e}")

# Global incremental scanner instance
incremental_scanner = IncrementalScanner()
