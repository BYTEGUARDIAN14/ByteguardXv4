#!/usr/bin/env python3
"""
ByteGuardX CLI Upload Validator
Command-line tool for validating files and folders before upload
"""

import os
import sys
import argparse
import json
import time
from pathlib import Path
import hashlib
from typing import List, Dict, Tuple

# Optional import for file type detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

class UploadValidator:
    """CLI validator for ByteGuardX uploads"""
    
    # Security constants matching frontend
    MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
    MAX_INDIVIDUAL_FILE_SIZE = 500 * 1024 * 1024  # 500MB
    MAX_FILE_COUNT = 10000
    
    ALLOWED_EXTENSIONS = {
        'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb',
        'go', 'rs', 'swift', 'kt', 'scala', 'json', 'xml', 'yml', 'yaml', 'txt',
        'md', 'rst', 'dockerfile', 'sh', 'bat', 'ps1', 'sql', 'html', 'css', 'scss',
        'sass', 'less', 'vue', 'svelte', 'dart', 'r', 'matlab', 'm', 'pl', 'pm'
    }
    
    BLOCKED_EXTENSIONS = {
        'exe', 'dll', 'so', 'dylib', 'bin', 'app', 'deb', 'rpm', 'msi', 'dmg',
        'iso', 'img', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'
    }
    
    DANGEROUS_PATTERNS = [
        '..',  # Path traversal
        '\x00',  # Null bytes
        '\r', '\n',  # Line breaks in filenames
    ]
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = {
            'valid_files': [],
            'invalid_files': [],
            'warnings': [],
            'summary': {}
        }
    
    def log(self, message, level='INFO'):
        """Log message if verbose mode enabled"""
        if self.verbose or level == 'ERROR':
            timestamp = time.strftime('%H:%M:%S')
            print(f"[{timestamp}] {level}: {message}")
    
    def validate_filename(self, filepath: Path) -> Tuple[bool, str]:
        """Validate individual filename"""
        filename = filepath.name
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in str(filepath):
                return False, f"Dangerous pattern '{pattern}' found in path"
        
        # Check for hidden files (optional warning)
        if filename.startswith('.') and filename not in ['.gitignore', '.env.example']:
            return False, "Hidden files not allowed"
        
        # Check file extension
        if '.' not in filename:
            return False, "File has no extension"
        
        extension = filename.split('.')[-1].lower()
        
        if extension in self.BLOCKED_EXTENSIONS:
            return False, f"Blocked file type: .{extension}"
        
        if extension not in self.ALLOWED_EXTENSIONS:
            return False, f"Unsupported file type: .{extension}"
        
        return True, "Valid filename"
    
    def validate_file_content(self, filepath: Path) -> Tuple[bool, str]:
        """Validate file content and detect file type"""
        try:
            # Check file size
            file_size = filepath.stat().st_size
            if file_size > self.MAX_INDIVIDUAL_FILE_SIZE:
                return False, f"File too large: {self.format_size(file_size)} (max: {self.format_size(self.MAX_INDIVIDUAL_FILE_SIZE)})"
            
            # Try to detect file type using python-magic (if available)
            if HAS_MAGIC:
                try:
                    file_type = magic.from_file(str(filepath), mime=True)

                    # Check for executable files
                    if 'executable' in file_type or 'application/x-' in file_type:
                        return False, f"Executable file detected: {file_type}"

                    # Check for archive files
                    if any(archive_type in file_type for archive_type in ['zip', 'tar', 'gzip', 'compress']):
                        return False, f"Archive file detected: {file_type}"

                except Exception:
                    # If magic fails, continue with basic validation
                    pass
            else:
                # Basic file type detection without magic
                with open(filepath, 'rb') as f:
                    header = f.read(16)

                    # Check for common executable headers
                    if header.startswith(b'MZ') or header.startswith(b'\x7fELF'):
                        return False, "Executable file detected (binary header)"

                    # Check for archive headers
                    if header.startswith(b'PK') or header.startswith(b'\x1f\x8b'):
                        return False, "Archive file detected (binary header)"
            
            # Try to read file as text (basic content validation)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024)  # Read first 1KB
                    
                    # Check for binary content indicators
                    if '\x00' in content:
                        return False, "Binary content detected in text file"
                        
            except Exception as e:
                return False, f"Cannot read file content: {str(e)}"
            
            return True, "Valid file content"
            
        except Exception as e:
            return False, f"File validation error: {str(e)}"
    
    def scan_directory(self, directory: Path) -> List[Path]:
        """Recursively scan directory for files"""
        files = []
        try:
            for item in directory.rglob('*'):
                if item.is_file():
                    files.append(item)
                    if len(files) > self.MAX_FILE_COUNT:
                        break
        except Exception as e:
            self.log(f"Error scanning directory {directory}: {e}", 'ERROR')
        
        return files
    
    def validate_upload(self, path: str) -> Dict:
        """Main validation function"""
        target_path = Path(path)
        
        if not target_path.exists():
            return {'error': f"Path does not exist: {path}"}
        
        # Collect all files to validate
        if target_path.is_file():
            files_to_check = [target_path]
            self.log(f"Validating single file: {target_path}")
        else:
            files_to_check = self.scan_directory(target_path)
            self.log(f"Validating directory with {len(files_to_check)} files: {target_path}")
        
        # Check file count limit
        if len(files_to_check) > self.MAX_FILE_COUNT:
            return {'error': f"Too many files: {len(files_to_check)} (max: {self.MAX_FILE_COUNT})"}
        
        # Validate each file
        total_size = 0
        valid_count = 0
        
        for file_path in files_to_check:
            self.log(f"Checking: {file_path}")
            
            # Validate filename
            filename_valid, filename_msg = self.validate_filename(file_path)
            if not filename_valid:
                self.results['invalid_files'].append({
                    'path': str(file_path),
                    'reason': filename_msg,
                    'type': 'filename'
                })
                continue
            
            # Validate file content
            content_valid, content_msg = self.validate_file_content(file_path)
            if not content_valid:
                self.results['invalid_files'].append({
                    'path': str(file_path),
                    'reason': content_msg,
                    'type': 'content'
                })
                continue
            
            # File is valid
            file_size = file_path.stat().st_size
            total_size += file_size
            valid_count += 1
            
            self.results['valid_files'].append({
                'path': str(file_path),
                'size': file_size,
                'extension': file_path.suffix.lower()
            })
        
        # Check total size limit
        if total_size > self.MAX_TOTAL_SIZE:
            return {'error': f"Total size too large: {self.format_size(total_size)} (max: {self.format_size(self.MAX_TOTAL_SIZE)})"}
        
        # Generate summary
        self.results['summary'] = {
            'total_files_checked': len(files_to_check),
            'valid_files': valid_count,
            'invalid_files': len(self.results['invalid_files']),
            'total_size': total_size,
            'total_size_formatted': self.format_size(total_size),
            'validation_passed': len(self.results['invalid_files']) == 0
        }
        
        return self.results
    
    def format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"
    
    def print_results(self):
        """Print validation results to console"""
        summary = self.results['summary']
        
        print("\n" + "="*60)
        print("BYTEGUARDX UPLOAD VALIDATION RESULTS")
        print("="*60)
        print(f"Total Files Checked: {summary['total_files_checked']}")
        print(f"Valid Files: {summary['valid_files']}")
        print(f"Invalid Files: {summary['invalid_files']}")
        print(f"Total Size: {summary['total_size_formatted']}")
        print(f"Validation Status: {'✅ PASSED' if summary['validation_passed'] else '❌ FAILED'}")
        print("="*60)
        
        # Show invalid files
        if self.results['invalid_files']:
            print("\nINVALID FILES:")
            for invalid_file in self.results['invalid_files'][:10]:  # Show first 10
                print(f"❌ {invalid_file['path']}: {invalid_file['reason']}")
            
            if len(self.results['invalid_files']) > 10:
                print(f"... and {len(self.results['invalid_files']) - 10} more invalid files")
        
        # Show warnings
        if self.results['warnings']:
            print("\nWARNINGS:")
            for warning in self.results['warnings']:
                print(f"⚠️  {warning}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='ByteGuardX Upload Validator - Validate files and folders before upload'
    )
    parser.add_argument('path', help='File or directory path to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    
    args = parser.parse_args()
    
    # Create validator
    validator = UploadValidator(verbose=args.verbose)
    
    # Run validation
    try:
        results = validator.validate_upload(args.path)
        
        if 'error' in results:
            print(f"❌ Validation Error: {results['error']}")
            sys.exit(1)
        
        # Output results
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            validator.print_results()
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        
        # Exit with appropriate code
        sys.exit(0 if results['summary']['validation_passed'] else 1)
        
    except KeyboardInterrupt:
        print("\n❌ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Validation failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
