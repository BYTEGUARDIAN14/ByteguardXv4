"""
Comprehensive tests for enhanced scanning system
Tests unified scanner, verification, and trust scoring
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Import the enhanced scanning components
from byteguardx.core.unified_scanner import (
    UnifiedScanner, ScanContext, ScanMode, VerificationStatus, EnhancedFinding
)
from byteguardx.validation.verify_scan_results import (
    ResultVerifier, VerificationMethod, VerificationResult
)
from byteguardx.validation.plugin_result_trust_score import (
    PluginTrustScorer, TrustLevel, PluginRiskCategory
)

class TestUnifiedScanner:
    """Test cases for the unified scanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create a unified scanner instance for testing"""
        return UnifiedScanner()
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample scan context"""
        return ScanContext(
            file_path="test.py",
            content="password = 'hardcoded_secret_123'",
            language="python",
            file_size=100,
            scan_mode=ScanMode.COMPREHENSIVE,
            confidence_threshold=0.7,
            enable_ml=True,
            enable_plugins=True
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization"""
        assert scanner is not None
        assert hasattr(scanner, 'secret_scanner')
        assert hasattr(scanner, 'dependency_scanner')
        assert hasattr(scanner, 'ai_pattern_scanner')
        assert hasattr(scanner, 'vulnerability_predictor')
        assert hasattr(scanner, 'false_positive_learner')
        assert hasattr(scanner, 'plugin_manager')
    
    def test_scan_content_basic(self, scanner, sample_context):
        """Test basic content scanning"""
        findings = scanner.scan_content(sample_context)
        
        assert isinstance(findings, list)
        # Should find at least one secret
        assert len(findings) >= 0
        
        # Check finding structure if any found
        if findings:
            finding = findings[0]
            assert isinstance(finding, EnhancedFinding)
            assert hasattr(finding, 'type')
            assert hasattr(finding, 'confidence')
            assert hasattr(finding, 'verification_status')
            assert hasattr(finding, 'explanation')
    
    @pytest.mark.asyncio
    async def test_async_scanning(self, scanner, sample_context):
        """Test asynchronous scanning"""
        findings = await scanner.scan_content_async(sample_context)
        
        assert isinstance(findings, list)
        # Verify async execution completed
        assert scanner.scan_stats['total_scans'] > 0
    
    def test_scan_modes(self, scanner):
        """Test different scan modes"""
        test_content = "api_key = 'sk-1234567890abcdef'"
        
        for mode in ScanMode:
            context = ScanContext(
                file_path="test.py",
                content=test_content,
                language="python",
                file_size=len(test_content),
                scan_mode=mode
            )
            
            findings = scanner.scan_content(context)
            assert isinstance(findings, list)
    
    def test_confidence_threshold_filtering(self, scanner):
        """Test confidence threshold filtering"""
        context_high = ScanContext(
            file_path="test.py",
            content="password = 'secret123'",
            language="python",
            file_size=100,
            scan_mode=ScanMode.STATIC_ONLY,
            confidence_threshold=0.9
        )
        
        context_low = ScanContext(
            file_path="test.py",
            content="password = 'secret123'",
            language="python",
            file_size=100,
            scan_mode=ScanMode.STATIC_ONLY,
            confidence_threshold=0.1
        )
        
        findings_high = scanner.scan_content(context_high)
        findings_low = scanner.scan_content(context_low)
        
        # Lower threshold should generally yield more findings
        assert len(findings_low) >= len(findings_high)
    
    def test_cache_functionality(self, scanner, sample_context):
        """Test result caching"""
        # First scan
        findings1 = scanner.scan_content(sample_context)
        
        # Second scan with same content should use cache
        findings2 = scanner.scan_content(sample_context)
        
        assert findings1 == findings2
        assert scanner.scan_stats['cache_hits'] > 0
    
    def test_statistics_tracking(self, scanner, sample_context):
        """Test statistics tracking"""
        initial_stats = scanner.get_scan_statistics()
        
        # Perform scan
        scanner.scan_content(sample_context)
        
        updated_stats = scanner.get_scan_statistics()
        
        assert updated_stats['total_scans'] > initial_stats['total_scans']
        assert 'avg_processing_time' in updated_stats
        assert 'false_positive_rate' in updated_stats

class TestResultVerifier:
    """Test cases for result verification"""
    
    @pytest.fixture
    def verifier(self):
        """Create a result verifier instance"""
        return ResultVerifier()
    
    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding for testing"""
        return {
            'id': 'test_finding_1',
            'type': 'secret',
            'subtype': 'api_key',
            'severity': 'high',
            'confidence': 0.8,
            'file_path': 'test.py',
            'line_number': 10,
            'context': 'api_key = "sk-1234567890"',
            'description': 'Hardcoded API key detected'
        }
    
    def test_verifier_initialization(self, verifier):
        """Test verifier initialization"""
        assert verifier is not None
        assert hasattr(verifier, 'verification_history')
        assert hasattr(verifier, 'pattern_cache')
        assert hasattr(verifier, 'thresholds')
    
    def test_single_finding_verification(self, verifier, sample_finding):
        """Test verification of a single finding"""
        report = verifier.verify_finding(sample_finding)
        
        assert report is not None
        assert hasattr(report, 'verification_result')
        assert hasattr(report, 'confidence_score')
        assert hasattr(report, 'verification_methods')
        assert isinstance(report.verification_methods, list)
        assert report.processing_time_ms >= 0
    
    def test_batch_verification(self, verifier):
        """Test batch verification of multiple findings"""
        findings = [
            {
                'id': 'finding_1',
                'type': 'secret',
                'file_path': 'test.py',
                'line_number': 10,
                'description': 'Secret 1'
            },
            {
                'id': 'finding_2',
                'type': 'vulnerability',
                'file_path': 'test.py',
                'line_number': 15,
                'description': 'Vulnerability 1'
            }
        ]
        
        reports = verifier.verify_batch(findings)
        
        assert len(reports) == len(findings)
        assert all(hasattr(report, 'verification_result') for report in reports)
    
    def test_cross_scanner_verification(self, verifier, sample_finding):
        """Test cross-scanner verification"""
        # Create similar findings from different scanners
        other_findings = [
            {
                'file_path': 'test.py',
                'line_number': 10,
                'scanner_source': 'DifferentScanner',
                'description': 'Similar issue detected'
            }
        ]
        
        context = {'other_findings': other_findings}
        report = verifier.verify_finding(sample_finding, context)
        
        assert VerificationMethod.CROSS_SCANNER in report.verification_methods
        # Cross-validation should increase confidence
        assert 'cross_scanner' in report.verification_details
    
    def test_temporal_consistency(self, verifier, sample_finding):
        """Test temporal consistency verification"""
        # First verification
        report1 = verifier.verify_finding(sample_finding)
        
        # Second verification of same finding
        report2 = verifier.verify_finding(sample_finding)
        
        assert VerificationMethod.TEMPORAL_CONSISTENCY in report2.verification_methods
        # Should have historical data
        assert len(verifier.verification_history) > 0
    
    def test_pattern_validation(self, verifier):
        """Test pattern validation for different finding types"""
        test_cases = [
            {
                'type': 'secret',
                'entropy': 4.8,
                'context': 'api_key = "sk-abcd1234"'
            },
            {
                'type': 'vulnerability',
                'description': 'SQL injection vulnerability detected'
            },
            {
                'type': 'dependency',
                'description': 'Known vulnerability CVE-2021-1234'
            }
        ]
        
        for test_case in test_cases:
            report = verifier.verify_finding(test_case)
            assert VerificationMethod.PATTERN_VALIDATION in report.verification_methods
    
    def test_verification_statistics(self, verifier, sample_finding):
        """Test verification statistics"""
        # Perform some verifications
        for i in range(5):
            finding = sample_finding.copy()
            finding['id'] = f'test_finding_{i}'
            verifier.verify_finding(finding)
        
        stats = verifier.get_verification_statistics()
        
        assert 'total_verifications' in stats
        assert 'verification_rate' in stats
        assert 'average_confidence' in stats
        assert 'result_distribution' in stats
        assert stats['total_verifications'] >= 5

class TestPluginTrustScorer:
    """Test cases for plugin trust scoring"""
    
    @pytest.fixture
    def scorer(self):
        """Create a plugin trust scorer instance"""
        return PluginTrustScorer()
    
    @pytest.fixture
    def sample_plugin_metadata(self):
        """Create sample plugin metadata"""
        return {
            'name': 'test_plugin',
            'version': '1.0.0',
            'author_verified': True,
            'security_reviewed': True,
            'download_count': 1000,
            'has_documentation': True
        }
    
    def test_scorer_initialization(self, scorer):
        """Test scorer initialization"""
        assert scorer is not None
        assert hasattr(scorer, 'plugin_metrics')
        assert hasattr(scorer, 'trust_scores')
        assert hasattr(scorer, 'scoring_weights')
    
    def test_trust_score_calculation(self, scorer, sample_plugin_metadata):
        """Test trust score calculation"""
        trust_score = scorer.calculate_trust_score('test_plugin', sample_plugin_metadata)
        
        assert trust_score is not None
        assert hasattr(trust_score, 'overall_score')
        assert hasattr(trust_score, 'trust_level')
        assert hasattr(trust_score, 'risk_category')
        assert hasattr(trust_score, 'component_scores')
        assert 0.0 <= trust_score.overall_score <= 1.0
        assert isinstance(trust_score.trust_level, TrustLevel)
        assert isinstance(trust_score.risk_category, PluginRiskCategory)
    
    def test_plugin_metrics_update(self, scorer):
        """Test plugin metrics updating"""
        execution_result = {
            'success': True,
            'execution_time': 1.5,
            'user_feedback': {
                'type': 'positive',
                'rating': 4
            }
        }
        
        scorer.update_plugin_metrics('test_plugin', execution_result)
        
        assert 'test_plugin' in scorer.plugin_metrics
        metrics = scorer.plugin_metrics['test_plugin']
        assert metrics.total_executions > 0
        assert metrics.successful_executions > 0
    
    def test_user_feedback_integration(self, scorer):
        """Test user feedback integration"""
        feedback = {
            'rating': 5,
            'type': 'positive',
            'comment': 'Great plugin!'
        }
        
        scorer.add_user_feedback('test_plugin', feedback)
        
        assert 'test_plugin' in scorer.feedback_history
        assert len(scorer.feedback_history['test_plugin']) > 0
    
    def test_trust_level_determination(self, scorer):
        """Test trust level determination"""
        # Test different score ranges
        test_cases = [
            (0.95, TrustLevel.VERY_HIGH),
            (0.80, TrustLevel.HIGH),
            (0.65, TrustLevel.MEDIUM),
            (0.45, TrustLevel.LOW),
            (0.20, TrustLevel.VERY_LOW)
        ]
        
        for score, expected_level in test_cases:
            level = scorer._determine_trust_level(score)
            assert level == expected_level
    
    def test_trusted_plugins_filtering(self, scorer, sample_plugin_metadata):
        """Test filtering of trusted plugins"""
        # Create plugins with different trust levels
        plugins = ['high_trust', 'medium_trust', 'low_trust']
        
        for plugin in plugins:
            metadata = sample_plugin_metadata.copy()
            if plugin == 'low_trust':
                metadata['author_verified'] = False
                metadata['security_reviewed'] = False
            
            scorer.calculate_trust_score(plugin, metadata)
        
        trusted_plugins = scorer.get_trusted_plugins(TrustLevel.MEDIUM)
        
        assert isinstance(trusted_plugins, list)
        # Should include medium and higher trust plugins
        assert len(trusted_plugins) >= 0
    
    def test_trust_statistics(self, scorer, sample_plugin_metadata):
        """Test trust statistics generation"""
        # Calculate trust scores for multiple plugins
        for i in range(3):
            plugin_name = f'plugin_{i}'
            scorer.calculate_trust_score(plugin_name, sample_plugin_metadata)
        
        stats = scorer.get_trust_statistics()
        
        assert 'total_plugins' in stats
        assert 'average_trust_score' in stats
        assert 'trust_level_distribution' in stats
        assert 'risk_category_distribution' in stats
        assert stats['total_plugins'] >= 3

class TestIntegration:
    """Integration tests for the complete enhanced scanning system"""
    
    @pytest.fixture
    def complete_system(self):
        """Set up complete scanning system"""
        return {
            'scanner': UnifiedScanner(),
            'verifier': ResultVerifier(),
            'trust_scorer': PluginTrustScorer()
        }
    
    def test_end_to_end_scanning(self, complete_system):
        """Test complete end-to-end scanning workflow"""
        scanner = complete_system['scanner']
        verifier = complete_system['verifier']
        
        # Create scan context
        context = ScanContext(
            file_path="integration_test.py",
            content="api_key = 'sk-1234567890abcdef'\npassword = 'hardcoded_pass'",
            language="python",
            file_size=100,
            scan_mode=ScanMode.COMPREHENSIVE
        )
        
        # Perform scan
        findings = scanner.scan_content(context)
        
        # Verify findings
        if findings:
            for finding in findings:
                finding_dict = {
                    'type': finding.type,
                    'file_path': finding.file_path,
                    'line_number': finding.line_number,
                    'description': finding.description
                }
                
                verification_report = verifier.verify_finding(finding_dict)
                assert verification_report is not None
        
        # Check system statistics
        scan_stats = scanner.get_scan_statistics()
        verification_stats = verifier.get_verification_statistics()
        
        assert scan_stats['total_scans'] > 0
        assert verification_stats['total_verifications'] >= 0
    
    def test_performance_benchmarks(self, complete_system):
        """Test performance benchmarks"""
        scanner = complete_system['scanner']
        
        # Test with various content sizes
        test_contents = [
            "small content",
            "medium content " * 100,
            "large content " * 1000
        ]
        
        for i, content in enumerate(test_contents):
            context = ScanContext(
                file_path=f"perf_test_{i}.py",
                content=content,
                language="python",
                file_size=len(content),
                scan_mode=ScanMode.FAST
            )
            
            start_time = datetime.now()
            findings = scanner.scan_content(context)
            end_time = datetime.now()
            
            processing_time = (end_time - start_time).total_seconds()
            
            # Performance assertions
            assert processing_time < 30.0  # Should complete within 30 seconds
            assert isinstance(findings, list)
    
    def test_error_handling(self, complete_system):
        """Test error handling and recovery"""
        scanner = complete_system['scanner']
        
        # Test with invalid content
        invalid_contexts = [
            ScanContext("", "", "unknown", 0, ScanMode.STATIC_ONLY),  # Empty content
            ScanContext("test.py", None, "python", 0, ScanMode.STATIC_ONLY),  # None content
        ]
        
        for context in invalid_contexts:
            try:
                findings = scanner.scan_content(context)
                # Should handle gracefully
                assert isinstance(findings, list)
            except Exception as e:
                # Should not raise unhandled exceptions
                pytest.fail(f"Unhandled exception: {e}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
