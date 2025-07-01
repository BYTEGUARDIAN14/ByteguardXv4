"""
Unit tests for ByteGuardX scanners
"""

import pytest
from pathlib import Path

class TestSecretScanner:
    """Test SecretScanner functionality"""
    
    def test_detect_github_token(self, secret_scanner, sample_files):
        """Test GitHub token detection"""
        secret_scanner.reset()
        file_info = {'file_path': str(sample_files['javascript']), 'content': sample_files['javascript'].read_text()}
        
        findings = secret_scanner.scan_file(file_info)
        
        # Should detect GitHub token
        github_findings = [f for f in findings if 'github' in f.get('subtype', '').lower()]
        assert len(github_findings) > 0
        assert github_findings[0]['severity'] == 'critical'
    
    def test_detect_api_keys(self, secret_scanner, sample_files):
        """Test API key detection"""
        secret_scanner.reset()
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        
        findings = secret_scanner.scan_file(file_info)
        
        # Should detect Stripe API key
        api_key_findings = [f for f in findings if 'api' in f.get('subtype', '').lower()]
        assert len(api_key_findings) > 0
    
    def test_entropy_analysis(self, secret_scanner):
        """Test high-entropy string detection"""
        secret_scanner.reset()
        
        # High entropy string (likely secret)
        high_entropy_content = 'secret_key = "aB3$kL9#mN2@pQ7&rS5%tU8!vW1^xY4*"'
        file_info = {'file_path': 'test.py', 'content': high_entropy_content}
        
        findings = secret_scanner.scan_file(file_info)
        
        # Should detect high entropy string
        entropy_findings = [f for f in findings if 'entropy' in f.get('subtype', '').lower()]
        assert len(entropy_findings) > 0
    
    def test_false_positive_filtering(self, secret_scanner):
        """Test false positive filtering"""
        secret_scanner.reset()
        
        # Common false positives
        false_positive_content = '''
        # These should not be detected as secrets
        example_key = "EXAMPLE_API_KEY_HERE"
        placeholder = "your_api_key_here"
        test_token = "test_token_123"
        dummy_secret = "dummy_secret_value"
        '''
        file_info = {'file_path': 'test.py', 'content': false_positive_content}
        
        findings = secret_scanner.scan_file(file_info)
        
        # Should filter out obvious false positives
        assert len(findings) == 0 or all(f['confidence'] < 0.7 for f in findings)
    
    def test_context_extraction(self, secret_scanner, sample_files):
        """Test context extraction around findings"""
        secret_scanner.reset()
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        
        findings = secret_scanner.scan_file(file_info)
        
        # All findings should have context
        for finding in findings:
            assert 'context' in finding
            assert len(finding['context']) > 0

class TestDependencyScanner:
    """Test DependencyScanner functionality"""
    
    def test_scan_package_json(self, dependency_scanner, sample_files):
        """Test scanning package.json for vulnerabilities"""
        dependency_scanner.reset()
        file_info = {'file_path': str(sample_files['package_json']), 'content': sample_files['package_json'].read_text()}
        
        findings = dependency_scanner.scan_file(file_info)
        
        # Should detect vulnerable lodash version
        lodash_findings = [f for f in findings if 'lodash' in f.get('package_name', '').lower()]
        assert len(lodash_findings) > 0
        assert lodash_findings[0]['severity'] in ['high', 'critical']
    
    def test_scan_requirements_txt(self, dependency_scanner, sample_files):
        """Test scanning requirements.txt for vulnerabilities"""
        dependency_scanner.reset()
        file_info = {'file_path': str(sample_files['requirements']), 'content': sample_files['requirements'].read_text()}
        
        findings = dependency_scanner.scan_file(file_info)
        
        # Should detect vulnerable packages
        assert len(findings) > 0
        
        # Check for specific vulnerable packages
        package_names = [f.get('package_name', '').lower() for f in findings]
        assert any('django' in name for name in package_names)
    
    def test_version_comparison(self, dependency_scanner):
        """Test version comparison logic"""
        # Test various version formats
        assert dependency_scanner._is_version_vulnerable("1.0.0", "<1.1.0")
        assert not dependency_scanner._is_version_vulnerable("1.1.0", "<1.1.0")
        assert dependency_scanner._is_version_vulnerable("2.0.0", ">=2.0.0,<2.1.0")
        assert not dependency_scanner._is_version_vulnerable("2.1.0", ">=2.0.0,<2.1.0")
    
    def test_cve_information(self, dependency_scanner, sample_files):
        """Test CVE information extraction"""
        dependency_scanner.reset()
        file_info = {'file_path': str(sample_files['package_json']), 'content': sample_files['package_json'].read_text()}
        
        findings = dependency_scanner.scan_file(file_info)
        
        # Findings should include CVE information
        for finding in findings:
            assert 'cve_id' in finding or 'vulnerability_id' in finding
            assert 'description' in finding
            assert 'fixed_version' in finding

class TestAIPatternScanner:
    """Test AIPatternScanner functionality"""
    
    def test_detect_sql_injection(self, ai_pattern_scanner, sample_files):
        """Test SQL injection pattern detection"""
        ai_pattern_scanner.reset()
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        
        findings = ai_pattern_scanner.scan_file(file_info)
        
        # Should detect SQL injection pattern
        sql_findings = [f for f in findings if 'sql' in f.get('subtype', '').lower()]
        assert len(sql_findings) > 0
    
    def test_detect_weak_authentication(self, ai_pattern_scanner, sample_files):
        """Test weak authentication pattern detection"""
        ai_pattern_scanner.reset()
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        
        findings = ai_pattern_scanner.scan_file(file_info)
        
        # Should detect weak password check
        auth_findings = [f for f in findings if 'password' in f.get('subtype', '').lower() or 'auth' in f.get('subtype', '').lower()]
        assert len(auth_findings) > 0
    
    def test_confidence_scoring(self, ai_pattern_scanner, sample_files):
        """Test confidence scoring for AI patterns"""
        ai_pattern_scanner.reset()
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        
        findings = ai_pattern_scanner.scan_file(file_info)
        
        # All findings should have confidence scores
        for finding in findings:
            assert 'confidence' in finding
            assert 0.0 <= finding['confidence'] <= 1.0
    
    def test_context_analysis(self, ai_pattern_scanner):
        """Test context-aware pattern detection"""
        ai_pattern_scanner.reset()
        
        # Code with context that should affect detection
        contextual_code = '''
        def safe_query(user_id):
            # This is safe - using parameterized query
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            
        def unsafe_query(user_id):
            # This is unsafe - string formatting
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        '''
        
        file_info = {'file_path': 'test.py', 'content': contextual_code}
        findings = ai_pattern_scanner.scan_file(file_info)
        
        # Should detect the unsafe pattern but not the safe one
        unsafe_findings = [f for f in findings if 'unsafe_query' in f.get('context', '')]
        safe_findings = [f for f in findings if 'safe_query' in f.get('context', '')]
        
        assert len(unsafe_findings) > 0
        assert len(safe_findings) == 0 or all(f['confidence'] < 0.5 for f in safe_findings)

class TestScannerIntegration:
    """Test scanner integration and coordination"""
    
    def test_multiple_scanners(self, secret_scanner, dependency_scanner, ai_pattern_scanner, sample_files):
        """Test running multiple scanners on the same files"""
        # Reset all scanners
        secret_scanner.reset()
        dependency_scanner.reset()
        ai_pattern_scanner.reset()
        
        all_findings = []
        
        # Scan with all scanners
        for file_path in sample_files.values():
            file_info = {'file_path': str(file_path), 'content': file_path.read_text()}
            
            all_findings.extend(secret_scanner.scan_file(file_info))
            all_findings.extend(dependency_scanner.scan_file(file_info))
            all_findings.extend(ai_pattern_scanner.scan_file(file_info))
        
        # Should have findings from all scanner types
        finding_types = set(f['type'] for f in all_findings)
        assert 'secret' in finding_types
        assert 'vulnerability' in finding_types
        assert 'ai_pattern' in finding_types
    
    def test_scanner_performance(self, secret_scanner, large_codebase):
        """Test scanner performance on large codebase"""
        import time
        
        secret_scanner.reset()
        start_time = time.time()
        
        total_findings = 0
        for file_path in large_codebase[:10]:  # Test with first 10 files
            file_info = {'file_path': str(file_path), 'content': file_path.read_text()}
            findings = secret_scanner.scan_file(file_info)
            total_findings += len(findings)
        
        end_time = time.time()
        scan_time = end_time - start_time
        
        # Performance assertions
        assert scan_time < 30  # Should complete within 30 seconds
        assert total_findings > 0  # Should find some issues
        
        # Check scan rate
        files_per_second = 10 / scan_time
        assert files_per_second > 0.5  # Should process at least 0.5 files per second
    
    def test_scanner_memory_usage(self, secret_scanner, large_codebase):
        """Test scanner memory usage"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        secret_scanner.reset()
        
        # Scan multiple files
        for file_path in large_codebase[:20]:
            file_info = {'file_path': str(file_path), 'content': file_path.read_text()}
            secret_scanner.scan_file(file_info)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory usage should be reasonable (less than 100MB increase)
        assert memory_increase < 100 * 1024 * 1024
    
    def test_concurrent_scanning(self, secret_scanner):
        """Test concurrent scanning capabilities"""
        import threading
        import time
        
        secret_scanner.reset()
        results = []
        errors = []
        
        def scan_worker(file_content, worker_id):
            try:
                file_info = {'file_path': f'worker_{worker_id}.py', 'content': file_content}
                findings = secret_scanner.scan_file(file_info)
                results.append((worker_id, len(findings)))
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Create test content
        test_content = 'api_key = "sk_test_' + 'x' * 24 + '"'
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=scan_worker, args=(test_content, i))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10)
        
        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5
        
        # All workers should find the same number of issues
        finding_counts = [count for _, count in results]
        assert all(count == finding_counts[0] for count in finding_counts)

class TestScannerEdgeCases:
    """Test scanner edge cases and error handling"""
    
    def test_empty_file(self, secret_scanner):
        """Test scanning empty file"""
        secret_scanner.reset()
        file_info = {'file_path': 'empty.py', 'content': ''}
        
        findings = secret_scanner.scan_file(file_info)
        assert findings == []
    
    def test_binary_file(self, secret_scanner, temp_dir):
        """Test scanning binary file"""
        secret_scanner.reset()
        
        # Create a binary file
        binary_file = temp_dir / "test.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03\x04\x05')
        
        file_info = {'file_path': str(binary_file), 'content': binary_file.read_text(errors='ignore')}
        
        # Should handle binary files gracefully
        findings = secret_scanner.scan_file(file_info)
        assert isinstance(findings, list)
    
    def test_very_large_file(self, secret_scanner):
        """Test scanning very large file"""
        secret_scanner.reset()
        
        # Create large content
        large_content = "# Comment line\n" * 10000 + 'api_key = "sk_test_' + 'x' * 24 + '"\n'
        file_info = {'file_path': 'large.py', 'content': large_content}
        
        findings = secret_scanner.scan_file(file_info)
        
        # Should still find the secret
        assert len(findings) > 0
    
    def test_unicode_content(self, secret_scanner):
        """Test scanning file with unicode content"""
        secret_scanner.reset()
        
        unicode_content = '''
        # Unicode test: 你好世界 🔐 🚀
        api_key = "sk_test_abcdef123456789012345678"
        message = "Hello 世界! 🌍"
        '''
        
        file_info = {'file_path': 'unicode.py', 'content': unicode_content}
        findings = secret_scanner.scan_file(file_info)
        
        # Should handle unicode and still find secrets
        assert len(findings) > 0
    
    def test_malformed_json(self, dependency_scanner, temp_dir):
        """Test scanning malformed package.json"""
        dependency_scanner.reset()
        
        malformed_json = temp_dir / "malformed.json"
        malformed_json.write_text('{"name": "test", "dependencies": {')  # Incomplete JSON
        
        file_info = {'file_path': str(malformed_json), 'content': malformed_json.read_text()}
        
        # Should handle malformed JSON gracefully
        findings = dependency_scanner.scan_file(file_info)
        assert isinstance(findings, list)
    
    def test_scanner_reset(self, secret_scanner, sample_files):
        """Test scanner reset functionality"""
        # First scan
        file_info = {'file_path': str(sample_files['python']), 'content': sample_files['python'].read_text()}
        findings1 = secret_scanner.scan_file(file_info)
        
        # Reset and scan again
        secret_scanner.reset()
        findings2 = secret_scanner.scan_file(file_info)
        
        # Results should be identical
        assert len(findings1) == len(findings2)
        assert secret_scanner.get_summary()['total'] == len(findings2)
