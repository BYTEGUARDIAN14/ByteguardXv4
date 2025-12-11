#!/usr/bin/env python3
"""
ByteGuardX Folder Upload Security Test Suite
Comprehensive testing for file and folder upload functionality
"""

import os
import sys
import requests
import tempfile
import zipfile
import json
import time
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FolderUploadTester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.test_results = []
        
    def log_test(self, test_name, passed, message):
        """Log test result"""
        status = "PASS" if passed else "FAIL"
        logger.info(f"[{status}] {test_name}: {message}")
        self.test_results.append({
            'test': test_name,
            'passed': passed,
            'message': message,
            'timestamp': time.time()
        })
    
    def create_test_files(self, temp_dir):
        """Create test files for upload testing"""
        test_files = []
        
        # Create various file types
        files_to_create = [
            ('test.py', 'print("Hello World")\npassword = "secret123"'),
            ('config.js', 'const API_KEY = "test-api-key-12345";\nmodule.exports = config;'),
            ('app.java', 'public class App {\n    private String password = "hardcoded";\n}'),
            ('style.css', 'body { background: black; color: cyan; }'),
            ('README.md', '# Test Project\nThis is a test project for ByteGuardX'),
            ('package.json', '{"name": "test", "version": "1.0.0"}'),
            ('Dockerfile', 'FROM node:16\nCOPY . /app\nWORKDIR /app'),
            ('script.sh', '#!/bin/bash\necho "Test script"'),
        ]
        
        for filename, content in files_to_create:
            file_path = temp_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            test_files.append(file_path)
        
        # Create subdirectory with files
        sub_dir = temp_dir / 'src'
        sub_dir.mkdir()
        
        sub_files = [
            ('main.py', 'import os\napi_key = "secret-key-here"'),
            ('utils.js', 'function getPassword() { return "admin123"; }'),
        ]
        
        for filename, content in sub_files:
            file_path = sub_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            test_files.append(file_path)
        
        return test_files
    
    def test_single_file_upload(self):
        """Test single file upload functionality"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create test file
                test_file = temp_path / 'test.py'
                with open(test_file, 'w') as f:
                    f.write('print("Hello World")\npassword = "secret123"')
                
                # Upload file
                with open(test_file, 'rb') as f:
                    files = {'files': f}
                    response = requests.post(
                        f'{self.base_url}/api/scan/file',
                        files=files,
                        data={'scan_mode': 'comprehensive'}
                    )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'findings' in result and len(result['findings']) > 0:
                        self.log_test('Single File Upload', True, 
                                    f'Successfully uploaded and scanned file, found {len(result["findings"])} issues')
                    else:
                        self.log_test('Single File Upload', True, 'File uploaded successfully, no issues found')
                else:
                    self.log_test('Single File Upload', False, 
                                f'Upload failed with status {response.status_code}: {response.text}')
        
        except Exception as e:
            self.log_test('Single File Upload', False, f'Exception: {str(e)}')
    
    def test_multiple_file_upload(self):
        """Test multiple file upload functionality"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                test_files = self.create_test_files(temp_path)
                
                # Prepare files for upload
                files = []
                for file_path in test_files:
                    files.append(('files', (file_path.name, open(file_path, 'rb'), 'text/plain')))
                
                try:
                    response = requests.post(
                        f'{self.base_url}/api/scan/folder',
                        files=files,
                        data={
                            'scan_mode': 'comprehensive',
                            'upload_type': 'multiple_files'
                        }
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        total_files = result.get('summary', {}).get('total_files', 0)
                        total_issues = result.get('summary', {}).get('total_issues', 0)
                        self.log_test('Multiple File Upload', True, 
                                    f'Successfully uploaded {total_files} files, found {total_issues} issues')
                    else:
                        self.log_test('Multiple File Upload', False, 
                                    f'Upload failed with status {response.status_code}: {response.text}')
                
                finally:
                    # Close all file handles
                    for _, file_tuple in files:
                        if hasattr(file_tuple[1], 'close'):
                            file_tuple[1].close()
        
        except Exception as e:
            self.log_test('Multiple File Upload', False, f'Exception: {str(e)}')
    
    def test_large_file_rejection(self):
        """Test that large files are properly rejected"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create large file (simulate 600MB file)
                large_file = temp_path / 'large_file.py'
                with open(large_file, 'w') as f:
                    # Write enough content to exceed 500MB limit
                    content = 'x' * (600 * 1024 * 1024)  # 600MB
                    f.write(content)
                
                # Try to upload large file
                with open(large_file, 'rb') as f:
                    files = {'files': f}
                    response = requests.post(
                        f'{self.base_url}/api/scan/file',
                        files=files
                    )
                
                if response.status_code == 400:
                    self.log_test('Large File Rejection', True, 
                                'Large file properly rejected')
                else:
                    self.log_test('Large File Rejection', False, 
                                f'Large file not rejected, status: {response.status_code}')
        
        except Exception as e:
            self.log_test('Large File Rejection', False, f'Exception: {str(e)}')
    
    def test_invalid_file_type_rejection(self):
        """Test that invalid file types are rejected"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create invalid file types
                invalid_files = [
                    ('malware.exe', b'\x4d\x5a\x90\x00'),  # PE header
                    ('archive.zip', b'PK\x03\x04'),        # ZIP header
                    ('binary.dll', b'\x4d\x5a\x90\x00'),  # DLL header
                ]
                
                for filename, content in invalid_files:
                    file_path = temp_path / filename
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    # Try to upload invalid file
                    with open(file_path, 'rb') as f:
                        files = {'files': (filename, f)}
                        response = requests.post(
                            f'{self.base_url}/api/scan/file',
                            files=files
                        )
                    
                    if response.status_code == 400:
                        self.log_test(f'Invalid File Rejection ({filename})', True, 
                                    'Invalid file type properly rejected')
                    else:
                        self.log_test(f'Invalid File Rejection ({filename})', False, 
                                    f'Invalid file not rejected, status: {response.status_code}')
        
        except Exception as e:
            self.log_test('Invalid File Type Rejection', False, f'Exception: {str(e)}')
    
    def test_path_traversal_protection(self):
        """Test protection against path traversal attacks"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create file with dangerous path
                dangerous_paths = [
                    '../../../etc/passwd',
                    '..\\..\\windows\\system32\\config\\sam',
                    '/etc/shadow',
                    'C:\\Windows\\System32\\config\\SAM'
                ]
                
                for dangerous_path in dangerous_paths:
                    # Create file with safe content but dangerous name
                    safe_file = temp_path / 'safe.py'
                    with open(safe_file, 'w') as f:
                        f.write('print("safe content")')
                    
                    # Try to upload with dangerous filename
                    with open(safe_file, 'rb') as f:
                        files = {'files': (dangerous_path, f)}
                        response = requests.post(
                            f'{self.base_url}/api/scan/file',
                            files=files
                        )
                    
                    if response.status_code == 400:
                        self.log_test(f'Path Traversal Protection ({dangerous_path})', True, 
                                    'Dangerous path properly rejected')
                    else:
                        self.log_test(f'Path Traversal Protection ({dangerous_path})', False, 
                                    f'Dangerous path not rejected, status: {response.status_code}')
        
        except Exception as e:
            self.log_test('Path Traversal Protection', False, f'Exception: {str(e)}')
    
    def run_all_tests(self):
        """Run all security tests"""
        logger.info("Starting ByteGuardX folder upload security tests...")
        
        # Test server availability
        try:
            response = requests.get(f'{self.base_url}/api/health', timeout=5)
            if response.status_code != 200:
                logger.error(f"Server not available at {self.base_url}")
                return False
        except requests.RequestException:
            logger.error(f"Cannot connect to server at {self.base_url}")
            return False
        
        # Run all tests
        self.test_single_file_upload()
        self.test_multiple_file_upload()
        self.test_large_file_rejection()
        self.test_invalid_file_type_rejection()
        self.test_path_traversal_protection()
        
        # Generate report
        passed_tests = len([t for t in self.test_results if t['passed']])
        total_tests = len(self.test_results)
        
        print("\n" + "="*60)
        print("BYTEGUARDX FOLDER UPLOAD TEST RESULTS")
        print("="*60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        print("="*60)
        
        # Save detailed results
        with open('folder_upload_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        return passed_tests == total_tests

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test ByteGuardX folder upload functionality')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL of ByteGuardX server')
    
    args = parser.parse_args()
    
    tester = FolderUploadTester(args.url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
