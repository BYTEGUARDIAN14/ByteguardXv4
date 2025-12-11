"""
Comprehensive Input Sanitization and Validation for ByteGuardX
Protects against ZIP bombs, path traversal, symlink attacks, and malicious payloads
"""

import os
import re
import zipfile
import tarfile
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import magic
import hashlib
import time

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of security threats"""
    ZIP_BOMB = "zip_bomb"
    PATH_TRAVERSAL = "path_traversal"
    SYMLINK_ATTACK = "symlink_attack"
    MALICIOUS_FILENAME = "malicious_filename"
    OVERSIZED_FILE = "oversized_file"
    SUSPICIOUS_MIME = "suspicious_mime"
    RECURSIVE_ARCHIVE = "recursive_archive"
    EXECUTABLE_CONTENT = "executable_content"
    SCRIPT_INJECTION = "script_injection"

@dataclass
class SecurityThreat:
    """Security threat detection result"""
    threat_type: ThreatType
    severity: str  # low, medium, high, critical
    description: str
    file_path: str
    details: Dict[str, Any]
    mitigation: str

@dataclass
class SanitizationConfig:
    """Configuration for input sanitization"""
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    max_archive_size: int = 500 * 1024 * 1024  # 500MB
    max_files_in_archive: int = 1000
    max_compression_ratio: float = 100.0  # Max 100:1 compression ratio
    max_path_depth: int = 20
    max_filename_length: int = 255
    allowed_mime_types: List[str] = None
    blocked_extensions: List[str] = None
    scan_timeout: int = 300  # 5 minutes
    
    def __post_init__(self):
        if self.allowed_mime_types is None:
            self.allowed_mime_types = [
                'text/plain', 'text/x-python', 'text/javascript', 'text/css',
                'text/html', 'text/xml', 'application/json', 'application/xml',
                'application/yaml', 'text/yaml', 'text/x-yaml',
                'application/zip', 'application/x-tar', 'application/gzip',
                'text/x-java-source', 'text/x-c', 'text/x-c++',
                'text/x-shellscript', 'text/x-dockerfile'
            ]
        
        if self.blocked_extensions is None:
            self.blocked_extensions = [
                '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
                '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi'
            ]

class InputSanitizer:
    """Comprehensive input sanitization and validation"""
    
    def __init__(self, config: Optional[SanitizationConfig] = None):
        self.config = config or SanitizationConfig()
        self.threats_detected = []
        
        # Dangerous path patterns
        self.dangerous_patterns = [
            r'\.\./',  # Path traversal
            r'\.\.\\\\',  # Windows path traversal
            r'/etc/',  # Unix system files
            r'/proc/',  # Unix process files
            r'/sys/',  # Unix system files
            r'C:\\Windows\\',  # Windows system files
            r'C:\\Program Files\\',  # Windows program files
            r'__pycache__',  # Python cache
            r'\.git/',  # Git repository
            r'\.svn/',  # SVN repository
        ]
        
        # Suspicious filename patterns
        self.suspicious_filenames = [
            r'.*\.(exe|bat|cmd|com|scr|pif|vbs)$',
            r'.*\$.*',  # Variables in filenames
            r'.*[<>:"|?*].*',  # Invalid filename characters
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)',  # Windows reserved names
        ]
    
    def sanitize_file_upload(self, file_path: str, original_filename: str = None) -> Tuple[bool, List[SecurityThreat]]:
        """
        Comprehensive file upload sanitization
        Returns: (is_safe, threats_detected)
        """
        threats = []
        
        try:
            # Basic file validation
            if not os.path.exists(file_path):
                threats.append(SecurityThreat(
                    threat_type=ThreatType.MALICIOUS_FILENAME,
                    severity="high",
                    description="File does not exist",
                    file_path=file_path,
                    details={"reason": "file_not_found"},
                    mitigation="Reject the upload"
                ))
                return False, threats
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.config.max_file_size:
                threats.append(SecurityThreat(
                    threat_type=ThreatType.OVERSIZED_FILE,
                    severity="medium",
                    description=f"File size {file_size} exceeds limit {self.config.max_file_size}",
                    file_path=file_path,
                    details={"file_size": file_size, "limit": self.config.max_file_size},
                    mitigation="Reject files exceeding size limit"
                ))
                return False, threats
            
            # Validate filename
            filename = original_filename or os.path.basename(file_path)
            filename_threats = self._validate_filename(filename)
            threats.extend(filename_threats)
            
            # Check MIME type
            mime_threats = self._validate_mime_type(file_path)
            threats.extend(mime_threats)
            
            # Check for executable content
            exec_threats = self._check_executable_content(file_path)
            threats.extend(exec_threats)
            
            # If it's an archive, perform deep inspection
            if self._is_archive(file_path):
                archive_threats = self._validate_archive(file_path)
                threats.extend(archive_threats)
            
            # Check for script injection in text files
            if self._is_text_file(file_path):
                script_threats = self._check_script_injection(file_path)
                threats.extend(script_threats)
            
            # Determine if file is safe
            critical_threats = [t for t in threats if t.severity == "critical"]
            high_threats = [t for t in threats if t.severity == "high"]
            
            is_safe = len(critical_threats) == 0 and len(high_threats) == 0
            
            return is_safe, threats
            
        except Exception as e:
            logger.error(f"File sanitization failed: {e}")
            threats.append(SecurityThreat(
                threat_type=ThreatType.MALICIOUS_FILENAME,
                severity="critical",
                description=f"Sanitization error: {str(e)}",
                file_path=file_path,
                details={"error": str(e)},
                mitigation="Reject the upload due to processing error"
            ))
            return False, threats
    
    def _validate_filename(self, filename: str) -> List[SecurityThreat]:
        """Validate filename for security threats"""
        threats = []
        
        # Check filename length
        if len(filename) > self.config.max_filename_length:
            threats.append(SecurityThreat(
                threat_type=ThreatType.MALICIOUS_FILENAME,
                severity="medium",
                description=f"Filename too long: {len(filename)} characters",
                file_path=filename,
                details={"length": len(filename), "limit": self.config.max_filename_length},
                mitigation="Truncate or reject filename"
            ))
        
        # Check for path traversal
        for pattern in self.dangerous_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                threats.append(SecurityThreat(
                    threat_type=ThreatType.PATH_TRAVERSAL,
                    severity="high",
                    description=f"Path traversal pattern detected: {pattern}",
                    file_path=filename,
                    details={"pattern": pattern},
                    mitigation="Sanitize or reject filename"
                ))
        
        # Check for suspicious patterns
        for pattern in self.suspicious_filenames:
            if re.match(pattern, filename, re.IGNORECASE):
                threats.append(SecurityThreat(
                    threat_type=ThreatType.MALICIOUS_FILENAME,
                    severity="high",
                    description=f"Suspicious filename pattern: {pattern}",
                    file_path=filename,
                    details={"pattern": pattern},
                    mitigation="Reject or rename file"
                ))
        
        # Check for blocked extensions
        file_ext = Path(filename).suffix.lower()
        if file_ext in self.config.blocked_extensions:
            threats.append(SecurityThreat(
                threat_type=ThreatType.EXECUTABLE_CONTENT,
                severity="high",
                description=f"Blocked file extension: {file_ext}",
                file_path=filename,
                details={"extension": file_ext},
                mitigation="Reject file with blocked extension"
            ))
        
        return threats
    
    def _validate_mime_type(self, file_path: str) -> List[SecurityThreat]:
        """Validate MIME type of file"""
        threats = []
        
        try:
            # Get MIME type
            mime_type = magic.from_file(file_path, mime=True)
            
            # Check if MIME type is allowed
            if mime_type not in self.config.allowed_mime_types:
                # Check if it's a known dangerous type
                dangerous_mimes = [
                    'application/x-executable', 'application/x-msdos-program',
                    'application/x-msdownload', 'application/x-dosexec'
                ]
                
                severity = "high" if mime_type in dangerous_mimes else "medium"
                
                threats.append(SecurityThreat(
                    threat_type=ThreatType.SUSPICIOUS_MIME,
                    severity=severity,
                    description=f"Suspicious MIME type: {mime_type}",
                    file_path=file_path,
                    details={"mime_type": mime_type},
                    mitigation="Reject file with suspicious MIME type"
                ))
            
        except Exception as e:
            logger.warning(f"MIME type detection failed for {file_path}: {e}")
            threats.append(SecurityThreat(
                threat_type=ThreatType.SUSPICIOUS_MIME,
                severity="medium",
                description="Could not determine MIME type",
                file_path=file_path,
                details={"error": str(e)},
                mitigation="Treat as suspicious due to MIME detection failure"
            ))
        
        return threats
    
    def _check_executable_content(self, file_path: str) -> List[SecurityThreat]:
        """Check for executable content in files"""
        threats = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read first few bytes to check for executable signatures
                header = f.read(512)
            
            # Check for executable signatures
            executable_signatures = [
                b'MZ',  # Windows PE
                b'\x7fELF',  # Linux ELF
                b'\xfe\xed\xfa\xce',  # macOS Mach-O (32-bit)
                b'\xfe\xed\xfa\xcf',  # macOS Mach-O (64-bit)
                b'\xca\xfe\xba\xbe',  # macOS Universal Binary
                b'#!/bin/',  # Shell script
                b'#!/usr/bin/',  # Shell script
                b'@echo off',  # Batch file
            ]
            
            for signature in executable_signatures:
                if header.startswith(signature):
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.EXECUTABLE_CONTENT,
                        severity="high",
                        description=f"Executable signature detected: {signature}",
                        file_path=file_path,
                        details={"signature": signature.hex()},
                        mitigation="Reject executable content"
                    ))
                    break
            
        except Exception as e:
            logger.warning(f"Executable content check failed for {file_path}: {e}")
        
        return threats
    
    def _is_archive(self, file_path: str) -> bool:
        """Check if file is an archive"""
        try:
            mime_type = magic.from_file(file_path, mime=True)
            archive_types = [
                'application/zip', 'application/x-tar', 'application/gzip',
                'application/x-bzip2', 'application/x-7z-compressed'
            ]
            return mime_type in archive_types
        except Exception:
            return False
    
    def _validate_archive(self, file_path: str) -> List[SecurityThreat]:
        """Validate archive files for security threats"""
        threats = []
        
        try:
            if zipfile.is_zipfile(file_path):
                threats.extend(self._validate_zip_file(file_path))
            elif tarfile.is_tarfile(file_path):
                threats.extend(self._validate_tar_file(file_path))
            
        except Exception as e:
            logger.error(f"Archive validation failed for {file_path}: {e}")
            threats.append(SecurityThreat(
                threat_type=ThreatType.RECURSIVE_ARCHIVE,
                severity="high",
                description=f"Archive validation error: {str(e)}",
                file_path=file_path,
                details={"error": str(e)},
                mitigation="Reject archive due to validation error"
            ))
        
        return threats
    
    def _validate_zip_file(self, file_path: str) -> List[SecurityThreat]:
        """Validate ZIP file for security threats"""
        threats = []
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Check for ZIP bomb
                total_uncompressed = 0
                total_compressed = 0
                file_count = 0
                
                for info in zip_file.infolist():
                    file_count += 1
                    total_uncompressed += info.file_size
                    total_compressed += info.compress_size
                    
                    # Check individual file size
                    if info.file_size > self.config.max_file_size:
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.ZIP_BOMB,
                            severity="high",
                            description=f"Large file in archive: {info.filename} ({info.file_size} bytes)",
                            file_path=file_path,
                            details={"filename": info.filename, "size": info.file_size},
                            mitigation="Reject archive with oversized files"
                        ))
                    
                    # Check for path traversal
                    if '..' in info.filename or info.filename.startswith('/'):
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.PATH_TRAVERSAL,
                            severity="high",
                            description=f"Path traversal in archive: {info.filename}",
                            file_path=file_path,
                            details={"filename": info.filename},
                            mitigation="Sanitize file paths in archive"
                        ))
                    
                    # Check path depth
                    path_depth = len(Path(info.filename).parts)
                    if path_depth > self.config.max_path_depth:
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.PATH_TRAVERSAL,
                            severity="medium",
                            description=f"Deep path in archive: {info.filename} (depth: {path_depth})",
                            file_path=file_path,
                            details={"filename": info.filename, "depth": path_depth},
                            mitigation="Limit path depth in archives"
                        ))
                
                # Check total file count
                if file_count > self.config.max_files_in_archive:
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.ZIP_BOMB,
                        severity="high",
                        description=f"Too many files in archive: {file_count}",
                        file_path=file_path,
                        details={"file_count": file_count, "limit": self.config.max_files_in_archive},
                        mitigation="Reject archives with too many files"
                    ))
                
                # Check total uncompressed size
                if total_uncompressed > self.config.max_archive_size:
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.ZIP_BOMB,
                        severity="high",
                        description=f"Archive too large when uncompressed: {total_uncompressed} bytes",
                        file_path=file_path,
                        details={"uncompressed_size": total_uncompressed, "limit": self.config.max_archive_size},
                        mitigation="Reject oversized archives"
                    ))
                
                # Check compression ratio
                if total_compressed > 0:
                    compression_ratio = total_uncompressed / total_compressed
                    if compression_ratio > self.config.max_compression_ratio:
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.ZIP_BOMB,
                            severity="critical",
                            description=f"Suspicious compression ratio: {compression_ratio:.2f}:1",
                            file_path=file_path,
                            details={"compression_ratio": compression_ratio, "limit": self.config.max_compression_ratio},
                            mitigation="Reject archive with suspicious compression ratio"
                        ))
                
        except zipfile.BadZipFile:
            threats.append(SecurityThreat(
                threat_type=ThreatType.MALICIOUS_FILENAME,
                severity="medium",
                description="Corrupted or invalid ZIP file",
                file_path=file_path,
                details={"error": "bad_zip_file"},
                mitigation="Reject corrupted archive"
            ))
        
        return threats
    
    def _validate_tar_file(self, file_path: str) -> List[SecurityThreat]:
        """Validate TAR file for security threats"""
        threats = []
        
        try:
            with tarfile.open(file_path, 'r') as tar_file:
                file_count = 0
                total_size = 0
                
                for member in tar_file.getmembers():
                    file_count += 1
                    total_size += member.size
                    
                    # Check for symlink attacks
                    if member.issym() or member.islnk():
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.SYMLINK_ATTACK,
                            severity="high",
                            description=f"Symbolic link in archive: {member.name}",
                            file_path=file_path,
                            details={"filename": member.name, "linkname": member.linkname},
                            mitigation="Reject archives with symbolic links"
                        ))
                    
                    # Check for path traversal
                    if '..' in member.name or member.name.startswith('/'):
                        threats.append(SecurityThreat(
                            threat_type=ThreatType.PATH_TRAVERSAL,
                            severity="high",
                            description=f"Path traversal in TAR: {member.name}",
                            file_path=file_path,
                            details={"filename": member.name},
                            mitigation="Sanitize file paths in archive"
                        ))
                
                # Check limits
                if file_count > self.config.max_files_in_archive:
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.ZIP_BOMB,
                        severity="high",
                        description=f"Too many files in TAR: {file_count}",
                        file_path=file_path,
                        details={"file_count": file_count},
                        mitigation="Reject archives with too many files"
                    ))
                
                if total_size > self.config.max_archive_size:
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.ZIP_BOMB,
                        severity="high",
                        description=f"TAR archive too large: {total_size} bytes",
                        file_path=file_path,
                        details={"total_size": total_size},
                        mitigation="Reject oversized archives"
                    ))
                
        except tarfile.TarError as e:
            threats.append(SecurityThreat(
                threat_type=ThreatType.MALICIOUS_FILENAME,
                severity="medium",
                description=f"Corrupted or invalid TAR file: {str(e)}",
                file_path=file_path,
                details={"error": str(e)},
                mitigation="Reject corrupted archive"
            ))
        
        return threats
    
    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is a text file"""
        try:
            mime_type = magic.from_file(file_path, mime=True)
            return mime_type.startswith('text/') or mime_type in [
                'application/json', 'application/xml', 'application/yaml'
            ]
        except Exception:
            return False
    
    def _check_script_injection(self, file_path: str) -> List[SecurityThreat]:
        """Check for script injection in text files"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Read first 10KB
            
            # Check for suspicious script patterns
            suspicious_patterns = [
                r'<script[^>]*>.*?</script>',  # HTML script tags
                r'javascript:',  # JavaScript protocol
                r'eval\s*\(',  # eval() function
                r'exec\s*\(',  # exec() function
                r'system\s*\(',  # system() function
                r'shell_exec\s*\(',  # shell_exec() function
                r'passthru\s*\(',  # passthru() function
                r'`[^`]*`',  # Backtick execution
                r'\$\([^)]*\)',  # Command substitution
            ]
            
            for pattern in suspicious_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    threats.append(SecurityThreat(
                        threat_type=ThreatType.SCRIPT_INJECTION,
                        severity="medium",
                        description=f"Suspicious script pattern detected: {pattern}",
                        file_path=file_path,
                        details={"pattern": pattern, "matches": len(matches)},
                        mitigation="Review and sanitize script content"
                    ))
            
        except Exception as e:
            logger.warning(f"Script injection check failed for {file_path}: {e}")
        
        return threats
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to make it safe"""
        # Remove path components
        filename = os.path.basename(filename)
        
        # Replace dangerous characters
        filename = re.sub(r'[<>:"|?*]', '_', filename)
        
        # Remove path traversal patterns
        filename = filename.replace('..', '_')
        
        # Limit length
        if len(filename) > self.config.max_filename_length:
            name, ext = os.path.splitext(filename)
            max_name_length = self.config.max_filename_length - len(ext)
            filename = name[:max_name_length] + ext
        
        # Ensure it's not empty
        if not filename or filename == '.':
            filename = 'sanitized_file'
        
        return filename
    
    def create_safe_extraction_path(self, base_dir: str, archive_path: str) -> str:
        """Create a safe path for archive extraction"""
        # Create a unique subdirectory
        archive_hash = hashlib.md5(archive_path.encode()).hexdigest()[:8]
        timestamp = int(time.time())
        safe_dir = os.path.join(base_dir, f"extract_{timestamp}_{archive_hash}")
        
        os.makedirs(safe_dir, exist_ok=True)
        return safe_dir

# Global instance
input_sanitizer = InputSanitizer()
