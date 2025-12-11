"""
Enhanced File Upload and Path Validation for ByteGuardX
Implements strict file validation, MIME type checking, and path traversal protection
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import hashlib
import zipfile
import tarfile

# Optional magic import for MIME detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

logger = logging.getLogger(__name__)

class FileValidationError(Exception):
    """Custom exception for file validation errors"""
    pass

class FileValidator:
    """Comprehensive file validation and security checks"""
    
    # Allowed MIME types for different file categories
    ALLOWED_MIME_TYPES = {
        'code': [
            'text/plain',
            'text/x-python',
            'text/x-javascript',
            'application/javascript',
            'text/x-java-source',
            'text/x-php',
            'text/x-ruby',
            'text/x-go',
            'text/x-rust',
            'text/x-c',
            'text/x-c++',
            'application/json',
            'application/xml',
            'text/xml',
            'text/yaml',
            'application/yaml'
        ],
        'archive': [
            'application/zip',
            'application/x-zip-compressed',
            'application/gzip',
            'application/x-gzip',
            'application/x-tar',
            'application/x-compressed-tar'
        ],
        'document': [
            'text/plain',
            'application/pdf',
            'text/markdown',
            'text/x-markdown'
        ]
    }
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go', '.rs',
        '.c', '.cpp', '.h', '.hpp', '.json', '.xml', '.yaml', '.yml', '.md',
        '.txt', '.zip', '.tar', '.gz', '.tgz', '.pdf'
    }
    
    # Maximum file sizes (in bytes) - STRICT PRODUCTION LIMITS
    MAX_FILE_SIZES = {
        'default': 5 * 1024 * 1024,   # 5 MB (enforced limit)
        'code': 5 * 1024 * 1024,      # 5 MB for code files
        'archive': 5 * 1024 * 1024,   # 5 MB for archives (reduced for security)
        'document': 5 * 1024 * 1024,  # 5 MB for documents
        'plugin': 5 * 1024 * 1024,    # 5 MB for plugins
        'image': 1 * 1024 * 1024      # 1 MB for images
    }
    
    # Dangerous file patterns - ENHANCED SECURITY
    DANGEROUS_PATTERNS = [
        r'\.\./',  # Path traversal
        r'\.\.\\',  # Windows path traversal
        r'/etc/',  # System directories
        r'/proc/',
        r'/sys/',
        r'/root/',
        r'/home/',
        r'C:\\Windows\\',
        r'C:\\System32\\',
        r'C:\\Program Files\\',
        r'__pycache__',
        r'\.pyc$',
        r'\.exe$',
        r'\.bat$',
        r'\.cmd$',
        r'\.sh$',
        r'\.ps1$',
        r'\.scr$',
        r'\.com$',
        r'\.pif$',
        r'\.vbs$',
        r'\.jar$',
        r'\.class$',
        r'\.dll$',
        r'\.so$',
        r'\.dylib$',
        r'eval\s*\(',  # Dangerous code patterns
        r'exec\s*\(',
        r'system\s*\(',
        r'subprocess\.',
        r'os\.system',
        r'__import__',
        r'importlib',
        r'pickle\.loads',
        r'marshal\.loads',
        r'<script',  # XSS patterns
        r'javascript:',
        r'vbscript:',
        r'data:text/html',
        r'\x00',  # Null bytes
        r'[\x01-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]'  # Control characters
    ]
    
    def __init__(self):
        if HAS_MAGIC:
            self.magic_mime = magic.Magic(mime=True)
        else:
            self.magic_mime = None
    
    def validate_file_upload(self, file_path: Union[str, Path], 
                           file_category: str = 'code') -> Tuple[bool, str]:
        """
        Comprehensive file validation
        Returns: (is_valid, error_message)
        """
        try:
            file_path = Path(file_path)
            
            # Check if file exists
            if not file_path.exists():
                return False, "File does not exist"
            
            # Check file size
            if not self._validate_file_size(file_path, file_category):
                max_size = self.MAX_FILE_SIZES.get(file_category, self.MAX_FILE_SIZES['default'])
                return False, f"File size exceeds limit of {max_size / (1024*1024):.1f} MB"
            
            # Check file extension
            if not self._validate_file_extension(file_path):
                return False, f"File extension '{file_path.suffix}' not allowed"
            
            # Check MIME type
            if not self._validate_mime_type(file_path, file_category):
                return False, "File type not allowed"
            
            # Check for dangerous patterns
            if not self._validate_file_content(file_path):
                return False, "File contains potentially dangerous content"
            
            # Check for null byte injection
            if not self._validate_null_bytes(file_path):
                return False, "File path contains null bytes"

            # Check for malicious filename patterns
            if not self._validate_filename_security(file_path):
                return False, "Filename contains potentially dangerous patterns"
            
            # Validate archive contents if applicable
            if file_path.suffix.lower() in ['.zip', '.tar', '.gz', '.tgz']:
                if not self._validate_archive_contents(file_path):
                    return False, "Archive contains dangerous files"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"File validation error: {e}")
            return False, f"Validation error: {str(e)}"
    
    def validate_file_path(self, file_path: str, base_dir: str = None) -> Tuple[bool, str]:
        """
        Validate file path for security issues
        Returns: (is_valid, error_message)
        """
        try:
            # Check for null bytes
            if '\x00' in file_path:
                return False, "Path contains null bytes"
            
            # Check for dangerous patterns
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, file_path, re.IGNORECASE):
                    return False, f"Path contains dangerous pattern: {pattern}"
            
            # Resolve path and check for traversal
            resolved_path = Path(file_path).resolve()
            
            if base_dir:
                base_path = Path(base_dir).resolve()
                try:
                    resolved_path.relative_to(base_path)
                except ValueError:
                    return False, "Path traversal detected"
            
            # Check for symbolic links
            if resolved_path.is_symlink():
                return False, "Symbolic links not allowed"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False, f"Path validation error: {str(e)}"
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        
        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')
        
        # Limit length
        if len(sanitized) > 255:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:255-len(ext)] + ext
        
        return sanitized
    
    def _validate_file_size(self, file_path: Path, category: str) -> bool:
        """Validate file size"""
        file_size = file_path.stat().st_size
        max_size = self.MAX_FILE_SIZES.get(category, self.MAX_FILE_SIZES['default'])
        return file_size <= max_size
    
    def _validate_file_extension(self, file_path: Path) -> bool:
        """Validate file extension"""
        return file_path.suffix.lower() in self.ALLOWED_EXTENSIONS
    
    def _validate_mime_type(self, file_path: Path, category: str) -> bool:
        """Validate MIME type"""
        try:
            if self.magic_mime:
                mime_type = self.magic_mime.from_file(str(file_path))
            else:
                # Fallback to mimetypes when magic is not available
                import mimetypes
                mime_type, _ = mimetypes.guess_type(str(file_path))
                if not mime_type:
                    return True  # Allow if we can't determine MIME type

            allowed_types = self.ALLOWED_MIME_TYPES.get(category, [])

            # Check if MIME type is allowed
            for allowed_type in allowed_types:
                if mime_type.startswith(allowed_type):
                    return True

            return False

        except Exception as e:
            logger.error(f"MIME type validation error: {e}")
            return False
    
    def _validate_file_content(self, file_path: Path) -> bool:
        """Validate file content for dangerous patterns"""
        try:
            # Read first 1MB of file for content analysis
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)
            
            # Check for executable signatures
            executable_signatures = [
                b'\x4d\x5a',  # PE executable
                b'\x7f\x45\x4c\x46',  # ELF executable
                b'\xfe\xed\xfa',  # Mach-O executable
                b'\xcf\xfa\xed\xfe'  # Mach-O executable (reverse)
            ]
            
            for signature in executable_signatures:
                if content.startswith(signature):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Content validation error: {e}")
            return False
    
    def _validate_null_bytes(self, file_path: Path) -> bool:
        """Check for null byte injection in path"""
        path_str = str(file_path)
        return '\x00' not in path_str and '\0' not in path_str

    def _validate_filename_security(self, file_path: Path) -> bool:
        """Enhanced filename security validation"""
        try:
            filename = file_path.name
            path_str = str(file_path)

            # Check for dangerous filename patterns
            dangerous_names = [
                'con', 'prn', 'aux', 'nul',  # Windows reserved names
                'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
                'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'
            ]

            if filename.lower().split('.')[0] in dangerous_names:
                return False

            # Check for excessive length
            if len(filename) > 255 or len(path_str) > 4096:
                return False

            # Check for hidden files (security risk)
            if filename.startswith('.') and filename not in ['.gitignore', '.env.example']:
                return False

            # Check for Unicode normalization attacks
            try:
                import unicodedata
                normalized = unicodedata.normalize('NFKC', filename)
                if normalized != filename:
                    logger.warning(f"Unicode normalization difference detected: {filename}")
                    return False
            except Exception:
                pass  # Skip Unicode check if not available

            return True

        except Exception as e:
            logger.error(f"Filename security validation error: {e}")
            return False
    
    def _validate_archive_contents(self, archive_path: Path) -> bool:
        """Validate contents of archive files"""
        try:
            if archive_path.suffix.lower() == '.zip':
                return self._validate_zip_contents(archive_path)
            elif archive_path.suffix.lower() in ['.tar', '.gz', '.tgz']:
                return self._validate_tar_contents(archive_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Archive validation error: {e}")
            return False
    
    def _validate_zip_contents(self, zip_path: Path) -> bool:
        """Validate ZIP file contents"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                for file_info in zip_file.filelist:
                    # Check for path traversal in archive
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        return False
                    
                    # Check file size (zip bomb protection)
                    if file_info.file_size > 100 * 1024 * 1024:  # 100MB per file
                        return False
                    
                    # Check compression ratio (zip bomb protection)
                    if file_info.compress_size > 0:
                        ratio = file_info.file_size / file_info.compress_size
                        if ratio > 100:  # Suspicious compression ratio
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"ZIP validation error: {e}")
            return False
    
    def _validate_tar_contents(self, tar_path: Path) -> bool:
        """Validate TAR file contents"""
        try:
            with tarfile.open(tar_path, 'r:*') as tar_file:
                for member in tar_file.getmembers():
                    # Check for path traversal
                    if '..' in member.name or member.name.startswith('/'):
                        return False
                    
                    # Check for symbolic links
                    if member.issym() or member.islnk():
                        return False
                    
                    # Check file size
                    if member.size > 100 * 1024 * 1024:  # 100MB per file
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"TAR validation error: {e}")
            return False

# Global instance
file_validator = FileValidator()
