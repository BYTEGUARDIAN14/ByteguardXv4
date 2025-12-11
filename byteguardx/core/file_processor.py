"""
File Processor - Safe file reading with validation and security checks
"""

import os
import mimetypes
import tempfile
import shutil
import atexit
import weakref
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
import logging

# Import circuit breaker for fault tolerance
try:
    from .error_recovery import circuit_breaker, retry, CircuitBreakerConfig
    CIRCUIT_BREAKER_AVAILABLE = True
except ImportError:
    CIRCUIT_BREAKER_AVAILABLE = False
    # Create dummy decorators
    def circuit_breaker(name, config=None): return lambda f: f
    def retry(**kwargs): return lambda f: f

# Optional magic import for MIME detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

logger = logging.getLogger(__name__)

class FileProcessor:
    """
    Secure file processor with MIME validation, size limits, and path traversal protection
    """
    
    # Security configuration
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {
        '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.cpp', '.c', '.h',
        '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
        '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg',
        '.txt', '.md', '.rst', '.dockerfile', '.sh', '.bat', '.ps1',
        '.sql', '.html', '.css', '.scss', '.sass', '.less'
    }
    
    ALLOWED_MIME_TYPES = {
        'text/plain', 'text/x-python', 'text/javascript', 'application/javascript',
        'text/x-java-source', 'text/x-c', 'text/x-c++', 'text/x-csharp',
        'application/json', 'text/xml', 'application/xml', 'text/yaml',
        'text/html', 'text/css', 'text/x-shellscript'
    }
    
    def __init__(self):
        self.processed_files = []
        self.errors = []
        self.temp_files: Set[str] = set()
        self.temp_dirs: Set[str] = set()

        # Register cleanup on exit
        atexit.register(self.cleanup_all_temp_files)
        
    def is_safe_path(self, file_path: str, base_path: str) -> bool:
        """
        Check for path traversal attacks
        """
        try:
            # Resolve absolute paths
            abs_file_path = str(Path(file_path).resolve())
            abs_base_path = str(Path(base_path).resolve())
            
            # Check if file path is within base path
            return abs_file_path.startswith(abs_base_path)
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False
    
    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate file for security and processing requirements
        """
        try:
            # Check if file exists
            if not Path(file_path).is_file():
                return False, "File does not exist"
            
            # Check file size
            file_size = Path(file_path).stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                return False, f"File too large: {file_size} bytes (max: {self.MAX_FILE_SIZE})"
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in self.ALLOWED_EXTENSIONS:
                return False, f"Unsupported file extension: {file_ext}"
            
            # Check MIME type using python-magic (if available)
            if HAS_MAGIC:
                try:
                    mime_type = magic.from_file(file_path, mime=True)
                    if mime_type not in self.ALLOWED_MIME_TYPES and not mime_type.startswith('text/'):
                        return False, f"Unsupported MIME type: {mime_type}"
                except Exception as e:
                    logger.warning(f"MIME type detection failed for {file_path}: {e}")
                    # Fallback to extension-based validation
            else:
                # Use mimetypes as fallback when magic is not available
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type and mime_type not in self.ALLOWED_MIME_TYPES and not mime_type.startswith('text/'):
                    return False, f"Unsupported MIME type: {mime_type}"
                pass
            
            return True, "File validation passed"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    @circuit_breaker('file_read', CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60) if CIRCUIT_BREAKER_AVAILABLE else None)
    @retry(max_attempts=3, base_delay=0.5, exceptions=(IOError, OSError))
    def read_file_safely(self, file_path: str) -> Optional[str]:
        """
        Safely read file content with encoding detection
        Enhanced with circuit breaker and retry logic for fault tolerance
        """
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with latin-1 as fallback
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    @circuit_breaker('file_process', CircuitBreakerConfig(failure_threshold=3, recovery_timeout=120) if CIRCUIT_BREAKER_AVAILABLE else None)
    @retry(max_attempts=2, base_delay=1.0, exceptions=(IOError, OSError))
    def process_file(self, file_path: str, base_path: str = None) -> Dict:
        """
        Process a single file with full validation
        Enhanced with circuit breaker and retry logic for fault tolerance
        """
        if base_path and not self.is_safe_path(file_path, base_path):
            error_msg = f"Path traversal detected: {file_path}"
            self.errors.append(error_msg)
            return {"error": error_msg, "file_path": file_path}
        
        is_valid, validation_msg = self.validate_file(file_path)
        if not is_valid:
            self.errors.append(f"{file_path}: {validation_msg}")
            return {"error": validation_msg, "file_path": file_path}
        
        content = self.read_file_safely(file_path)
        if content is None:
            error_msg = f"Failed to read file content: {file_path}"
            self.errors.append(error_msg)
            return {"error": error_msg, "file_path": file_path}
        
        file_info = {
            "file_path": file_path,
            "content": content,
            "size": len(content),
            "lines": len(content.splitlines()),
            "extension": Path(file_path).suffix.lower(),
            "name": Path(file_path).name
        }
        
        self.processed_files.append(file_info)
        return file_info
    
    def process_directory(self, directory_path: str, recursive: bool = True) -> List[Dict]:
        """
        Process all files in a directory
        """
        results = []
        
        if not Path(directory_path).is_dir():
            self.errors.append(f"Directory does not exist: {directory_path}")
            return results
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Skip hidden directories and common ignore patterns
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
                        'node_modules', '__pycache__', '.git', '.venv', 'venv', 'env'
                    }]
                    
                    for file in files:
                        if not file.startswith('.'):
                            file_path = str(Path(root) / file)
                            result = self.process_file(file_path, directory_path)
                            results.append(result)
            else:
                for file in os.listdir(directory_path):
                    file_path = str(Path(directory_path) / file)
                    if Path(file_path).is_file() and not file.startswith('.'):
                        result = self.process_file(file_path, directory_path)
                        results.append(result)
                        
        except Exception as e:
            error_msg = f"Error processing directory {directory_path}: {str(e)}"
            self.errors.append(error_msg)
            logger.error(error_msg)
        
        return results
    
    def get_stats(self) -> Dict:
        """
        Get processing statistics
        """
        return {
            "total_files_processed": len(self.processed_files),
            "total_errors": len(self.errors),
            "total_lines": sum(f.get("lines", 0) for f in self.processed_files),
            "total_size": sum(f.get("size", 0) for f in self.processed_files),
            "errors": self.errors
        }
    
    def reset(self):
        """
        Reset processor state
        """
        self.processed_files.clear()
        self.errors.clear()
        self.cleanup_all_temp_files()

    def create_temp_file(self, suffix: str = '', prefix: str = 'byteguardx_') -> str:
        """Create a temporary file and track it for cleanup"""
        fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)  # Close the file descriptor
        self.temp_files.add(temp_path)
        logger.debug(f"Created temp file: {temp_path}")
        return temp_path

    def create_temp_dir(self, suffix: str = '', prefix: str = 'byteguardx_') -> str:
        """Create a temporary directory and track it for cleanup"""
        temp_dir = tempfile.mkdtemp(suffix=suffix, prefix=prefix)
        self.temp_dirs.add(temp_dir)
        logger.debug(f"Created temp directory: {temp_dir}")
        return temp_dir

    def cleanup_temp_file(self, file_path: str):
        """Clean up a specific temporary file"""
        try:
            if file_path in self.temp_files:
                if os.path.exists(file_path):
                    os.unlink(file_path)
                    logger.debug(f"Cleaned up temp file: {file_path}")
                self.temp_files.discard(file_path)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp file {file_path}: {e}")

    def cleanup_temp_dir(self, dir_path: str):
        """Clean up a specific temporary directory"""
        try:
            if dir_path in self.temp_dirs:
                if os.path.exists(dir_path):
                    shutil.rmtree(dir_path, ignore_errors=True)
                    logger.debug(f"Cleaned up temp directory: {dir_path}")
                self.temp_dirs.discard(dir_path)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp directory {dir_path}: {e}")

    def cleanup_all_temp_files(self):
        """Clean up all tracked temporary files and directories"""
        # Clean up temporary files
        for temp_file in list(self.temp_files):
            self.cleanup_temp_file(temp_file)

        # Clean up temporary directories
        for temp_dir in list(self.temp_dirs):
            self.cleanup_temp_dir(temp_dir)

        logger.debug("Cleaned up all temporary files and directories")

    def __del__(self):
        """Cleanup on object destruction"""
        try:
            self.cleanup_all_temp_files()
        except Exception:
            pass  # Ignore errors during cleanup
