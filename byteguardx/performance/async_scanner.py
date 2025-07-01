"""
Async file I/O scanner for improved performance
Handles large codebases with non-blocking file operations
"""

import asyncio
import aiofiles
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, AsyncGenerator
import time
from concurrent.futures import ThreadPoolExecutor
import os
from dataclasses import dataclass

from ..core.file_processor import FileProcessor
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner

logger = logging.getLogger(__name__)

@dataclass
class ScanProgress:
    """Scan progress tracking"""
    total_files: int = 0
    processed_files: int = 0
    current_file: str = ""
    start_time: float = 0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    @property
    def progress_percentage(self) -> float:
        if self.total_files == 0:
            return 0.0
        return (self.processed_files / self.total_files) * 100
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def files_per_second(self) -> float:
        elapsed = self.elapsed_time
        if elapsed == 0:
            return 0.0
        return self.processed_files / elapsed

class AsyncScanner:
    """
    Asynchronous file scanner with concurrent processing
    Optimized for large codebases with thousands of files
    """
    
    def __init__(self, max_concurrent_files: int = 50, max_workers: int = None):
        self.max_concurrent_files = max_concurrent_files
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        
        # Scanner instances (thread-safe)
        self.file_processor = FileProcessor()
        self.secret_scanner = SecretScanner()
        self.dependency_scanner = DependencyScanner()
        self.ai_pattern_scanner = AIPatternScanner()
        
        # Progress tracking
        self.progress = ScanProgress()
        self.progress_callbacks: List[Callable[[ScanProgress], None]] = []
        
        # Performance settings
        self.chunk_size = 8192  # File read chunk size
        self.semaphore = None
        
    def add_progress_callback(self, callback: Callable[[ScanProgress], None]):
        """Add callback for progress updates"""
        self.progress_callbacks.append(callback)
    
    def _notify_progress(self):
        """Notify all progress callbacks"""
        for callback in self.progress_callbacks:
            try:
                callback(self.progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    async def scan_directory_async(self, directory_path: str, recursive: bool = True) -> Dict[str, Any]:
        """
        Asynchronously scan directory with concurrent file processing
        """
        start_time = time.time()
        self.progress = ScanProgress(start_time=start_time)
        
        try:
            # Discover files
            files_to_scan = await self._discover_files(directory_path, recursive)
            self.progress.total_files = len(files_to_scan)
            
            if not files_to_scan:
                return {
                    'total_files': 0,
                    'findings': [],
                    'errors': [],
                    'scan_duration': time.time() - start_time
                }
            
            logger.info(f"Starting async scan of {len(files_to_scan)} files")
            
            # Create semaphore for concurrent file processing
            self.semaphore = asyncio.Semaphore(self.max_concurrent_files)
            
            # Process files concurrently
            all_findings = []
            tasks = []
            
            for file_path in files_to_scan:
                task = asyncio.create_task(self._scan_file_async(file_path, directory_path))
                tasks.append(task)
            
            # Process tasks in batches to avoid memory issues
            batch_size = 100
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        error_msg = f"Scan error: {str(result)}"
                        self.progress.errors.append(error_msg)
                        logger.error(error_msg)
                    elif result:
                        all_findings.extend(result)
                
                self._notify_progress()
            
            scan_duration = time.time() - start_time
            
            return {
                'total_files': len(files_to_scan),
                'processed_files': self.progress.processed_files,
                'findings': all_findings,
                'errors': self.progress.errors,
                'scan_duration': scan_duration,
                'files_per_second': self.progress.files_per_second
            }
            
        except Exception as e:
            logger.error(f"Async scan failed: {e}")
            raise
    
    async def _discover_files(self, directory_path: str, recursive: bool) -> List[str]:
        """Asynchronously discover files to scan"""
        files = []
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            raise ValueError(f"Directory does not exist: {directory_path}")
        
        # Patterns to ignore
        ignore_dirs = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', 'env', '.env',
            'build', 'dist', '.next', '.nuxt', 'target'
        }
        
        ignore_files = {
            '.gitignore', '.dockerignore', '.DS_Store', 'Thumbs.db'
        }
        
        def should_scan_file(file_path: Path) -> bool:
            """Check if file should be scanned"""
            if file_path.name.startswith('.'):
                return False
            if file_path.name in ignore_files:
                return False
            if file_path.suffix.lower() not in self.file_processor.ALLOWED_EXTENSIONS:
                return False
            if file_path.stat().st_size > self.file_processor.MAX_FILE_SIZE:
                return False
            return True
        
        if recursive:
            for root, dirs, filenames in os.walk(directory_path):
                # Filter out ignored directories
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                
                for filename in filenames:
                    file_path = Path(root) / filename
                    if should_scan_file(file_path):
                        files.append(str(file_path))
        else:
            for file_path in directory.iterdir():
                if file_path.is_file() and should_scan_file(file_path):
                    files.append(str(file_path))
        
        return files
    
    async def _scan_file_async(self, file_path: str, base_path: str) -> List[Dict[str, Any]]:
        """Asynchronously scan a single file"""
        async with self.semaphore:
            try:
                self.progress.current_file = file_path
                
                # Read file content asynchronously
                file_content = await self._read_file_async(file_path)
                if not file_content:
                    return []
                
                # Create file info
                file_info = {
                    "file_path": file_path,
                    "content": file_content,
                    "size": len(file_content),
                    "lines": len(file_content.splitlines()),
                    "extension": Path(file_path).suffix.lower(),
                    "name": Path(file_path).name
                }
                
                # Run scanners in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor(max_workers=3) as executor:
                    # Run scanners concurrently
                    secret_task = loop.run_in_executor(
                        executor, self._run_secret_scanner, file_info
                    )
                    dependency_task = loop.run_in_executor(
                        executor, self._run_dependency_scanner, file_info
                    )
                    ai_task = loop.run_in_executor(
                        executor, self._run_ai_scanner, file_info
                    )
                    
                    # Wait for all scanners to complete
                    secret_findings, dep_findings, ai_findings = await asyncio.gather(
                        secret_task, dependency_task, ai_task
                    )
                
                # Combine findings
                all_findings = []
                all_findings.extend(secret_findings or [])
                all_findings.extend(dep_findings or [])
                all_findings.extend(ai_findings or [])
                
                # Update progress
                self.progress.processed_files += 1
                
                return all_findings
                
            except Exception as e:
                error_msg = f"Error scanning {file_path}: {str(e)}"
                self.progress.errors.append(error_msg)
                logger.error(error_msg)
                return []
    
    async def _read_file_async(self, file_path: str) -> Optional[str]:
        """Asynchronously read file content"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                return content
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return None
    
    def _run_secret_scanner(self, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run secret scanner in thread pool"""
        try:
            return self.secret_scanner.scan_file(file_info)
        except Exception as e:
            logger.error(f"Secret scanner error: {e}")
            return []
    
    def _run_dependency_scanner(self, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run dependency scanner in thread pool"""
        try:
            return self.dependency_scanner.scan_file(file_info)
        except Exception as e:
            logger.error(f"Dependency scanner error: {e}")
            return []
    
    def _run_ai_scanner(self, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run AI pattern scanner in thread pool"""
        try:
            return self.ai_pattern_scanner.scan_file(file_info)
        except Exception as e:
            logger.error(f"AI scanner error: {e}")
            return []
    
    async def scan_files_stream(self, file_paths: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream scan results as they become available
        Useful for real-time progress updates
        """
        self.progress = ScanProgress(
            total_files=len(file_paths),
            start_time=time.time()
        )
        
        self.semaphore = asyncio.Semaphore(self.max_concurrent_files)
        
        async def scan_and_yield(file_path: str):
            findings = await self._scan_file_async(file_path, "")
            self.progress.processed_files += 1
            self._notify_progress()
            
            return {
                'file_path': file_path,
                'findings': findings,
                'progress': {
                    'processed': self.progress.processed_files,
                    'total': self.progress.total_files,
                    'percentage': self.progress.progress_percentage
                }
            }
        
        # Create tasks for all files
        tasks = [scan_and_yield(file_path) for file_path in file_paths]
        
        # Yield results as they complete
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                yield result
            except Exception as e:
                logger.error(f"Stream scan error: {e}")
                yield {
                    'error': str(e),
                    'progress': {
                        'processed': self.progress.processed_files,
                        'total': self.progress.total_files,
                        'percentage': self.progress.progress_percentage
                    }
                }
