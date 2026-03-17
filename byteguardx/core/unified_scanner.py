"""
Unified Scanning Engine for ByteGuardX
Orchestrates all scanning components with enhanced integration and accuracy
"""

import os
import time
import logging
import hashlib
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import concurrent.futures
from threading import Lock
import json

from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner
from ..scanners.intelligent_fallback import intelligent_fallback, FallbackReason
from ..ml.vulnerability_predictor import VulnerabilityPredictor
from ..ml.false_positive_learner import FalsePositiveLearner
from ..security.ai_audit_system import ai_audit_system
from ..plugins.plugin_manager import PluginManager
from ..plugins.plugin_registry import plugin_registry, initialize_plugin_system
from .file_processor import FileProcessor
from .event_bus import event_bus, EventTypes

logger = logging.getLogger(__name__)

class ScanMode(Enum):
    """Enhanced scanning modes"""
    STATIC_ONLY = "static_only"
    DYNAMIC_ONLY = "dynamic_only"
    HYBRID = "hybrid"
    ML_ENHANCED = "ml_enhanced"
    COMPREHENSIVE = "comprehensive"
    FAST = "fast"

class VerificationStatus(Enum):
    """Result verification status"""
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PENDING = "pending"
    FAILED = "failed"
    CROSS_VALIDATED = "cross_validated"

class ConfidenceLevel(Enum):
    """Confidence levels for findings"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class ScanContext:
    """Enhanced context information for scanning"""
    file_path: str
    content: str
    language: str
    file_size: int
    scan_mode: ScanMode
    confidence_threshold: float = 0.7
    enable_ml: bool = True
    enable_plugins: bool = True
    enable_cross_validation: bool = True
    enable_false_positive_filtering: bool = True
    max_processing_time: float = 30.0
    user_id: Optional[str] = None
    session_id: Optional[str] = None

@dataclass
class EnhancedFinding:
    """Enhanced finding with comprehensive metadata"""
    # Core finding data
    type: str
    subtype: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    context: str
    description: str
    
    # Verification and attribution
    verification_status: VerificationStatus
    scanner_source: str
    plugin_source: Optional[str]
    timestamp: datetime
    result_hash: str
    
    # Explainability and ML insights
    explanation: Dict[str, Any]
    feature_importance: Dict[str, float]
    confidence_breakdown: Dict[str, float]
    similar_patterns: List[Dict[str, Any]]
    ml_prediction: Optional[Dict[str, Any]]
    false_positive_likelihood: float
    
    # Attribution and provenance
    detection_method: str
    model_version: str
    rule_version: str
    cross_validation_results: List[Dict[str, Any]]
    
    # Additional metadata
    recommendation: Optional[str] = None
    fix_suggestion: Optional[str] = None
    cve_references: List[str] = None
    compliance_tags: List[str] = None

class UnifiedScanner:
    """
    Unified scanning engine with comprehensive integration
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.lock = Lock()
        
        # Initialize core scanners
        self.secret_scanner = SecretScanner()
        self.dependency_scanner = DependencyScanner()
        self.ai_pattern_scanner = AIPatternScanner()
        
        # Initialize ML components
        self.vulnerability_predictor = VulnerabilityPredictor()
        self.false_positive_learner = FalsePositiveLearner()
        
        # Initialize plugin system
        self.plugin_manager = PluginManager()
        self.plugin_system_initialized = False
        
        # Initialize file processor
        self.file_processor = FileProcessor()
        
        # Initialize result cache for deduplication
        self.result_cache = {}
        self.cache_lock = Lock()
        
        # Scanning statistics
        self.scan_stats = {
            'total_scans': 0,
            'verified_findings': 0,
            'false_positives_filtered': 0,
            'ml_predictions': 0,
            'plugin_executions': 0,
            'cross_validations': 0,
            'cache_hits': 0,
            'processing_time_total': 0.0
        }
        
        # Performance thresholds
        self.performance_thresholds = {
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'max_processing_time': 30.0,  # 30 seconds
            'confidence_threshold': 0.7,
            'false_positive_threshold': 0.3
        }
        
    async def scan_content_async(self, context: ScanContext) -> List[EnhancedFinding]:
        """
        Asynchronous comprehensive scanning with full integration
        """
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(context)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                with self.lock:
                    self.scan_stats['cache_hits'] += 1
                return cached_result
            
            # Emit scan start event
            event_bus.publish(EventTypes.SCAN_STARTED, {
                'file_path': context.file_path,
                'scan_mode': context.scan_mode.value,
                'timestamp': datetime.now().isoformat()
            })
            
            # Phase 1: Parallel Static Analysis
            static_findings = await self._perform_parallel_static_analysis(context)
            
            # Phase 2: ML Enhancement and Validation
            if context.enable_ml:
                ml_enhanced_findings = await self._perform_ml_enhancement(context, static_findings)
            else:
                ml_enhanced_findings = static_findings
            
            # Phase 3: Plugin Analysis
            if context.enable_plugins:
                plugin_findings = await self._perform_plugin_analysis(context)
                ml_enhanced_findings.extend(plugin_findings)
            
            # Phase 4: Cross-Validation
            if context.enable_cross_validation:
                cross_validated_findings = await self._perform_cross_validation(ml_enhanced_findings, context)
            else:
                cross_validated_findings = ml_enhanced_findings
            
            # Phase 5: Result Verification and Deduplication
            verified_findings = await self._verify_and_deduplicate_findings(cross_validated_findings, context)
            
            # Phase 6: False Positive Filtering
            if context.enable_false_positive_filtering:
                filtered_findings = await self._filter_false_positives(verified_findings, context)
            else:
                filtered_findings = verified_findings
            
            # Phase 7: Final Enhancement and Attribution
            final_findings = await self._enhance_final_findings(filtered_findings, context)
            
            # Cache results
            self._cache_result(cache_key, final_findings)
            
            # Update statistics
            processing_time = time.time() - start_time
            with self.lock:
                self.scan_stats['total_scans'] += 1
                self.scan_stats['verified_findings'] += len(final_findings)
                self.scan_stats['processing_time_total'] += processing_time
            
            # Emit scan completion event
            event_bus.publish(EventTypes.SCAN_COMPLETED, {
                'file_path': context.file_path,
                'findings_count': len(final_findings),
                'processing_time': processing_time,
                'timestamp': datetime.now().isoformat()
            })
            
            logger.info(f"Unified scan completed in {processing_time:.2f}s with {len(final_findings)} findings")
            
            return final_findings
            
        except Exception as e:
            logger.error(f"Unified scan failed for {context.file_path}: {e}")
            
            # Emit scan error event
            event_bus.publish(EventTypes.SCAN_ERROR, {
                'file_path': context.file_path,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
            return []

    def scan_content(self, context: ScanContext) -> List[EnhancedFinding]:
        """
        Synchronous wrapper for async scanning
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.scan_content_async(context))

    async def _perform_parallel_static_analysis(self, context: ScanContext) -> List[EnhancedFinding]:
        """
        Perform parallel static analysis using all core scanners
        """
        findings = []
        
        try:
            # Create tasks for parallel execution
            tasks = []
            
            # Secret scanning task
            tasks.append(self._run_secret_scanner(context))

            # Plugin scanning task
            tasks.append(self._run_plugin_scanners(context))

            # Dependency scanning task (if applicable)
            if self._is_dependency_file(context.file_path):
                tasks.append(self._run_dependency_scanner(context))
            
            # AI pattern scanning task
            tasks.append(self._run_ai_pattern_scanner(context))
            
            # Execute all tasks in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Scanner task failed: {result}")
                elif isinstance(result, list):
                    findings.extend(result)
                    
        except Exception as e:
            logger.error(f"Parallel static analysis failed: {e}")
            
        return findings

    async def _perform_ml_enhancement(self, context: ScanContext, findings: List[EnhancedFinding]) -> List[EnhancedFinding]:
        """
        Enhance findings with ML predictions and confidence scoring
        """
        enhanced_findings = []

        try:
            # Get ML prediction for the entire content
            ml_prediction = self.vulnerability_predictor.predict_vulnerabilities(
                context.content, context.file_path, context.language
            )

            # Log ML prediction for audit
            ai_audit_system.log_prediction(
                model_name='vulnerability_predictor',
                model_version='1.0.0',
                input_data={'content': context.content[:1000], 'file_path': context.file_path},
                prediction=ml_prediction,
                metadata={
                    'scan_mode': context.scan_mode.value,
                    'user_id': context.user_id,
                    'session_id': context.session_id
                }
            )

            # Enhance existing findings with ML insights
            for finding in findings:
                # Add ML prediction data
                finding.ml_prediction = {
                    'vulnerability_probability': ml_prediction.vulnerability_probability,
                    'vulnerability_types': ml_prediction.vulnerability_types,
                    'confidence_score': ml_prediction.confidence_score,
                    'risk_factors': ml_prediction.risk_factors,
                    'feature_importance': ml_prediction.feature_importance
                }

                # Adjust confidence based on ML prediction
                ml_confidence = ml_prediction.confidence_score
                original_confidence = finding.confidence

                # Weighted average with ML confidence
                finding.confidence = self._calculate_weighted_confidence(
                    original_confidence, ml_confidence, finding.type
                )

                # Update confidence breakdown
                finding.confidence_breakdown.update({
                    'original_confidence': original_confidence,
                    'ml_confidence': ml_confidence,
                    'combined_confidence': finding.confidence,
                    'ml_weight': self._get_ml_weight(finding.type)
                })

                # Calculate false positive likelihood
                finding.false_positive_likelihood = self.false_positive_learner.predict_false_positive(
                    self._finding_to_dict(finding)
                )

                enhanced_findings.append(finding)

            # Update statistics
            with self.lock:
                self.scan_stats['ml_predictions'] += 1

        except Exception as e:
            logger.error(f"ML enhancement failed: {e}")
            enhanced_findings = findings

        return enhanced_findings

    async def _perform_plugin_analysis(self, context: ScanContext) -> List[EnhancedFinding]:
        """
        Execute plugin analysis with trust scoring
        """
        findings = []

        try:
            # Execute scanner plugins
            plugin_results = self.plugin_manager.execute_scanner_plugins(
                context.content, context.file_path, context.language
            )

            for plugin_result in plugin_results:
                if plugin_result.success and plugin_result.findings:
                    for plugin_finding in plugin_result.findings:
                        enhanced_finding = await self._enhance_plugin_finding(
                            plugin_finding, plugin_result, context
                        )
                        findings.append(enhanced_finding)

            # Update statistics
            with self.lock:
                self.scan_stats['plugin_executions'] += len(plugin_results)

        except Exception as e:
            logger.error(f"Plugin analysis failed: {e}")

        return findings

    async def _perform_cross_validation(self, findings: List[EnhancedFinding], context: ScanContext) -> List[EnhancedFinding]:
        """
        Perform cross-validation between different scanners
        """
        validated_findings = []

        try:
            # Group findings by location (file, line, column)
            location_groups = self._group_findings_by_location(findings)

            for location, location_findings in location_groups.items():
                if len(location_findings) > 1:
                    # Multiple scanners found issues at same location
                    cross_validated_finding = await self._create_cross_validated_finding(
                        location_findings, context
                    )
                    validated_findings.append(cross_validated_finding)
                else:
                    # Single finding - mark as unverified
                    finding = location_findings[0]
                    finding.verification_status = VerificationStatus.UNVERIFIED
                    validated_findings.append(finding)

            # Update statistics
            with self.lock:
                self.scan_stats['cross_validations'] += len(location_groups)

        except Exception as e:
            logger.error(f"Cross-validation failed: {e}")
            validated_findings = findings

        return validated_findings

    async def _verify_and_deduplicate_findings(self, findings: List[EnhancedFinding], context: ScanContext) -> List[EnhancedFinding]:
        """
        Verify findings and remove duplicates
        """
        verified_findings = []
        seen_hashes = set()

        try:
            for finding in findings:
                # Generate unique hash for deduplication
                finding_hash = self._generate_finding_hash(finding)
                finding.result_hash = finding_hash

                if finding_hash not in seen_hashes:
                    # Verify finding integrity
                    if await self._verify_finding_integrity(finding, context):
                        finding.verification_status = VerificationStatus.VERIFIED
                        verified_findings.append(finding)
                        seen_hashes.add(finding_hash)
                    else:
                        finding.verification_status = VerificationStatus.FAILED
                        logger.warning(f"Finding verification failed: {finding.description}")

        except Exception as e:
            logger.error(f"Verification and deduplication failed: {e}")
            verified_findings = findings

        return verified_findings

    async def _filter_false_positives(self, findings: List[EnhancedFinding], context: ScanContext) -> List[EnhancedFinding]:
        """
        Filter out likely false positives
        """
        filtered_findings = []

        try:
            for finding in findings:
                # Check false positive likelihood
                if finding.false_positive_likelihood < self.performance_thresholds['false_positive_threshold']:
                    # Apply additional false positive filters
                    if await self._apply_false_positive_filters(finding, context):
                        filtered_findings.append(finding)
                    else:
                        with self.lock:
                            self.scan_stats['false_positives_filtered'] += 1
                        logger.debug(f"Filtered false positive: {finding.description}")
                else:
                    with self.lock:
                        self.scan_stats['false_positives_filtered'] += 1
                    logger.debug(f"High false positive likelihood: {finding.description}")

        except Exception as e:
            logger.error(f"False positive filtering failed: {e}")
            filtered_findings = findings

        return filtered_findings

    async def _enhance_final_findings(self, findings: List[EnhancedFinding], context: ScanContext) -> List[EnhancedFinding]:
        """
        Final enhancement of findings with recommendations and metadata
        """
        enhanced_findings = []

        try:
            for finding in findings:
                # Add recommendations
                finding.recommendation = await self._generate_recommendation(finding, context)

                # Add fix suggestions
                finding.fix_suggestion = await self._generate_fix_suggestion(finding, context)

                # Add compliance tags
                finding.compliance_tags = self._get_compliance_tags(finding)

                # Add CVE references for vulnerabilities
                if finding.type in ['vulnerability', 'dependency']:
                    finding.cve_references = await self._get_cve_references(finding)

                # Final confidence adjustment
                finding.confidence = self._apply_final_confidence_adjustment(finding)

                enhanced_findings.append(finding)

        except Exception as e:
            logger.error(f"Final enhancement failed: {e}")
            enhanced_findings = findings

        return enhanced_findings

    # Helper Methods

    def _generate_cache_key(self, context: ScanContext) -> str:
        """Generate cache key for scan context"""
        content_hash = hashlib.sha256(context.content.encode()).hexdigest()[:16]
        return f"{context.file_path}:{content_hash}:{context.scan_mode.value}"

    def _get_cached_result(self, cache_key: str) -> Optional[List[EnhancedFinding]]:
        """Get cached scan result"""
        with self.cache_lock:
            return self.result_cache.get(cache_key)

    def _cache_result(self, cache_key: str, findings: List[EnhancedFinding]):
        """Cache scan result"""
        with self.cache_lock:
            # Limit cache size
            if len(self.result_cache) > 1000:
                # Remove oldest entries
                oldest_keys = list(self.result_cache.keys())[:100]
                for key in oldest_keys:
                    del self.result_cache[key]

            self.result_cache[cache_key] = findings

    def _is_dependency_file(self, file_path: str) -> bool:
        """Check if file is a dependency file"""
        dependency_files = {
            'requirements.txt', 'package.json', 'Pipfile', 'poetry.lock',
            'Cargo.toml', 'go.mod', 'pom.xml', 'build.gradle', 'composer.json'
        }
        return Path(file_path).name in dependency_files

    def _convert_secret_finding(self, finding) -> Dict[str, Any]:
        """Convert secret scanner finding to dict format"""
        return {
            'type': 'secret',
            'subtype': finding.type,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'column_start': finding.column_start,
            'column_end': finding.column_end,
            'context': finding.context,
            'description': f"Secret detected: {finding.type}",
            'value': finding.value[:50] + "..." if len(finding.value) > 50 else finding.value,
            'entropy': getattr(finding, 'entropy', 0.0)
        }

    def _convert_ai_pattern_finding(self, finding) -> Dict[str, Any]:
        """Convert AI pattern finding to dict format"""
        return {
            'type': 'ai_pattern',
            'subtype': finding.pattern_type,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'column_start': finding.column_start,
            'column_end': finding.column_end,
            'context': finding.context,
            'description': finding.description,
            'pattern_name': getattr(finding, 'pattern_name', ''),
            'category': getattr(finding, 'category', '')
        }

    async def _enhance_finding(self, finding_dict: Dict[str, Any], scanner_source: str, context: ScanContext) -> EnhancedFinding:
        """Convert dict finding to enhanced finding"""
        timestamp = datetime.now()

        # Generate explanation
        explanation = await self._generate_explanation(finding_dict, scanner_source, context)

        # Calculate feature importance
        feature_importance = self._calculate_feature_importance(finding_dict, scanner_source)

        # Initialize confidence breakdown
        confidence_breakdown = {
            'scanner_confidence': finding_dict.get('confidence', 0.0),
            'pattern_confidence': finding_dict.get('pattern_confidence', 0.0),
            'context_confidence': finding_dict.get('context_confidence', 0.0)
        }

        return EnhancedFinding(
            type=finding_dict.get('type', 'unknown'),
            subtype=finding_dict.get('subtype', ''),
            severity=finding_dict.get('severity', 'medium'),
            confidence=finding_dict.get('confidence', 0.0),
            file_path=finding_dict.get('file_path', context.file_path),
            line_number=finding_dict.get('line_number', 0),
            column_start=finding_dict.get('column_start', 0),
            column_end=finding_dict.get('column_end', 0),
            context=finding_dict.get('context', ''),
            description=finding_dict.get('description', ''),
            verification_status=VerificationStatus.PENDING,
            scanner_source=scanner_source,
            plugin_source=None,
            timestamp=timestamp,
            result_hash='',
            explanation=explanation,
            feature_importance=feature_importance,
            confidence_breakdown=confidence_breakdown,
            similar_patterns=[],
            ml_prediction=None,
            false_positive_likelihood=0.0,
            detection_method=scanner_source,
            model_version='1.0.0',
            rule_version='1.0.0',
            cross_validation_results=[]
        )

    async def _enhance_plugin_finding(self, plugin_finding: Dict[str, Any], plugin_result, context: ScanContext) -> EnhancedFinding:
        """Enhance plugin finding with trust scoring"""
        # Calculate plugin trust score
        trust_score = await self._calculate_plugin_trust_score(plugin_result.plugin_name)

        # Adjust confidence based on trust score
        original_confidence = plugin_finding.get('confidence', 0.0)
        adjusted_confidence = original_confidence * trust_score

        enhanced_finding = await self._enhance_finding(plugin_finding, "PluginScanner", context)
        enhanced_finding.plugin_source = plugin_result.plugin_name
        enhanced_finding.confidence = adjusted_confidence
        enhanced_finding.confidence_breakdown['plugin_trust_score'] = trust_score
        enhanced_finding.confidence_breakdown['trust_adjusted_confidence'] = adjusted_confidence

        return enhanced_finding

    def _calculate_weighted_confidence(self, original_confidence: float, ml_confidence: float, finding_type: str) -> float:
        """Calculate weighted confidence based on finding type"""
        # Different weights for different finding types
        weights = {
            'secret': {'original': 0.7, 'ml': 0.3},
            'vulnerability': {'original': 0.5, 'ml': 0.5},
            'ai_pattern': {'original': 0.6, 'ml': 0.4},
            'dependency': {'original': 0.8, 'ml': 0.2}
        }

        weight_config = weights.get(finding_type, {'original': 0.6, 'ml': 0.4})

        return (original_confidence * weight_config['original']) + (ml_confidence * weight_config['ml'])

    def _get_ml_weight(self, finding_type: str) -> float:
        """Get ML weight for finding type"""
        weights = {
            'secret': 0.3,
            'vulnerability': 0.5,
            'ai_pattern': 0.4,
            'dependency': 0.2
        }
        return weights.get(finding_type, 0.4)

    def _finding_to_dict(self, finding: EnhancedFinding) -> Dict[str, Any]:
        """Convert enhanced finding to dict for ML processing and API response"""
        return {
            'type': finding.type,
            'subtype': finding.subtype,
            'severity': finding.severity,
            'confidence': finding.confidence,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'context': finding.context,
            'description': finding.description,
            'scanner_source': finding.scanner_source,
            'title': finding.description,
            'scanner_name': finding.scanner_source,
            'verification_status': finding.verification_status.value if hasattr(finding.verification_status, 'value') else str(finding.verification_status),
            'false_positive_likelihood': finding.false_positive_likelihood,
            'recommendation': finding.recommendation,
            'fix_suggestion': finding.fix_suggestion,
        }

    def _group_findings_by_location(self, findings: List[EnhancedFinding]) -> Dict[str, List[EnhancedFinding]]:
        """Group findings by file location"""
        location_groups = {}

        for finding in findings:
            location_key = f"{finding.file_path}:{finding.line_number}:{finding.column_start}"
            if location_key not in location_groups:
                location_groups[location_key] = []
            location_groups[location_key].append(finding)

        return location_groups

    async def _create_cross_validated_finding(self, findings: List[EnhancedFinding], context: ScanContext) -> EnhancedFinding:
        """Create cross-validated finding from multiple scanner results"""
        # Use the finding with highest confidence as base
        base_finding = max(findings, key=lambda f: f.confidence)

        # Calculate combined confidence
        confidences = [f.confidence for f in findings]
        combined_confidence = sum(confidences) / len(confidences)

        # Boost confidence for cross-validation
        combined_confidence = min(combined_confidence * 1.2, 1.0)

        # Create cross-validation results
        cross_validation_results = []
        for finding in findings:
            cross_validation_results.append({
                'scanner': finding.scanner_source,
                'confidence': finding.confidence,
                'severity': finding.severity,
                'description': finding.description
            })

        # Update base finding
        base_finding.confidence = combined_confidence
        base_finding.verification_status = VerificationStatus.CROSS_VALIDATED
        base_finding.cross_validation_results = cross_validation_results
        base_finding.confidence_breakdown['cross_validation_boost'] = 1.2
        base_finding.confidence_breakdown['cross_validated_confidence'] = combined_confidence

        return base_finding

    def _generate_finding_hash(self, finding: EnhancedFinding) -> str:
        """Generate unique hash for finding deduplication"""
        hash_data = f"{finding.file_path}:{finding.line_number}:{finding.type}:{finding.subtype}:{finding.description}"
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]

    async def _verify_finding_integrity(self, finding: EnhancedFinding, context: ScanContext) -> bool:
        """Verify finding integrity and validity"""
        try:
            # Check basic integrity
            if not finding.file_path or not finding.description:
                return False

            # Check line number validity
            lines = context.content.splitlines()
            if finding.line_number > len(lines) or finding.line_number < 1:
                return False

            # Check column bounds
            if finding.line_number <= len(lines):
                line_length = len(lines[finding.line_number - 1])
                if finding.column_start > line_length or finding.column_end > line_length:
                    return False

            # Check confidence bounds
            if not (0.0 <= finding.confidence <= 1.0):
                return False

            return True

        except Exception as e:
            logger.error(f"Finding integrity verification failed: {e}")
            return False

    async def _apply_false_positive_filters(self, finding: EnhancedFinding, context: ScanContext) -> bool:
        """Apply additional false positive filters"""
        try:
            # File-based filters
            file_path_lower = finding.file_path.lower()
            if any(pattern in file_path_lower for pattern in ['test', 'example', 'demo', 'sample', 'mock']):
                if finding.confidence < 0.8:  # Higher threshold for test files
                    return False

            # Context-based filters
            context_lower = finding.context.lower()
            false_positive_indicators = [
                'placeholder', 'dummy', 'fake', 'example', 'test', 'todo', 'fixme'
            ]

            if any(indicator in context_lower for indicator in false_positive_indicators):
                if finding.confidence < 0.9:  # Very high threshold for obvious false positives
                    return False

            # Type-specific filters
            if finding.type == 'secret':
                # Additional secret-specific filters
                if len(finding.context) < 10:  # Too short context
                    return False

                # Check for common false positive patterns
                if any(pattern in finding.description.lower() for pattern in ['password', 'key', 'token']):
                    if 'example' in finding.context.lower() or 'test' in finding.context.lower():
                        return False

            return True

        except Exception as e:
            logger.error(f"False positive filtering failed: {e}")
            return True  # Default to keeping finding if filter fails

    async def _generate_explanation(self, finding_dict: Dict[str, Any], scanner_source: str, context: ScanContext) -> Dict[str, Any]:
        """Generate explanation for finding"""
        return {
            'detection_method': scanner_source,
            'pattern_matched': finding_dict.get('pattern_name', 'N/A'),
            'confidence_factors': [
                f"Scanner confidence: {finding_dict.get('confidence', 0.0):.2f}",
                f"Pattern strength: {finding_dict.get('pattern_confidence', 0.0):.2f}",
                f"Context relevance: {finding_dict.get('context_confidence', 0.0):.2f}"
            ],
            'risk_assessment': self._assess_risk_level(finding_dict),
            'remediation_priority': self._calculate_remediation_priority(finding_dict)
        }

    def _calculate_feature_importance(self, finding_dict: Dict[str, Any], scanner_source: str) -> Dict[str, float]:
        """Calculate feature importance for finding"""
        importance = {}

        # Base importance factors
        importance['pattern_match'] = 0.4
        importance['context_relevance'] = 0.3
        importance['file_location'] = 0.2
        importance['scanner_reliability'] = 0.1

        # Adjust based on scanner type
        if scanner_source == 'SecretScanner':
            importance['entropy'] = 0.3
            importance['pattern_match'] = 0.5
        elif scanner_source == 'DependencyScanner':
            importance['version_analysis'] = 0.4
            importance['vulnerability_database'] = 0.4
        elif scanner_source == 'AIPatternScanner':
            importance['ai_confidence'] = 0.4
            importance['pattern_complexity'] = 0.3

        return importance

    def _assess_risk_level(self, finding_dict: Dict[str, Any]) -> str:
        """Assess risk level for finding"""
        severity = finding_dict.get('severity', 'medium').lower()
        confidence = finding_dict.get('confidence', 0.0)

        if severity == 'critical' and confidence > 0.8:
            return 'very_high'
        elif severity in ['critical', 'high'] and confidence > 0.6:
            return 'high'
        elif severity == 'medium' and confidence > 0.7:
            return 'medium'
        elif confidence > 0.5:
            return 'low'
        else:
            return 'very_low'

    def _calculate_remediation_priority(self, finding_dict: Dict[str, Any]) -> int:
        """Calculate remediation priority (1-10, 10 being highest)"""
        severity_weights = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }

        severity = finding_dict.get('severity', 'medium').lower()
        confidence = finding_dict.get('confidence', 0.0)

        base_priority = severity_weights.get(severity, 2)
        confidence_multiplier = confidence * 2.5

        priority = int(base_priority * confidence_multiplier)
        return min(max(priority, 1), 10)  # Clamp between 1-10

    async def _calculate_plugin_trust_score(self, plugin_name: str) -> float:
        """Calculate trust score for plugin"""
        try:
            # Get plugin metadata
            plugin_metadata = self.plugin_manager.registry.get_plugin_metadata(plugin_name)
            if not plugin_metadata:
                return 0.5  # Default trust score

            trust_score = 0.5  # Base score

            # Factor in plugin age and stability
            if hasattr(plugin_metadata, 'version') and plugin_metadata.version:
                trust_score += 0.1

            # Factor in plugin author verification
            if hasattr(plugin_metadata, 'verified') and plugin_metadata.verified:
                trust_score += 0.2

            # Factor in usage statistics
            if hasattr(plugin_metadata, 'usage_count'):
                usage_factor = min(plugin_metadata.usage_count / 1000, 0.2)
                trust_score += usage_factor

            return min(trust_score, 1.0)

        except Exception as e:
            logger.error(f"Plugin trust score calculation failed: {e}")
            return 0.5

    async def _generate_recommendation(self, finding: EnhancedFinding, context: ScanContext) -> str:
        """Generate recommendation for finding"""
        try:
            if finding.type == 'secret':
                return self._get_secret_recommendation(finding)
            elif finding.type == 'vulnerability':
                return self._get_vulnerability_recommendation(finding)
            elif finding.type == 'dependency':
                return self._get_dependency_recommendation(finding)
            elif finding.type == 'ai_pattern':
                return self._get_ai_pattern_recommendation(finding)
            else:
                return "Review and address this security finding according to your organization's security policies."

        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return "Manual review recommended."

    def _get_secret_recommendation(self, finding: EnhancedFinding) -> str:
        """Get recommendation for secret finding"""
        recommendations = {
            'api_key': "Remove the API key from code and use environment variables or a secure key management system.",
            'password': "Remove hardcoded password and implement secure authentication mechanisms.",
            'token': "Remove the token from code and use secure token storage and rotation practices.",
            'private_key': "Remove private key from code and use secure key management solutions.",
            'database_url': "Remove database connection string and use environment variables with proper access controls."
        }

        subtype = finding.subtype.lower()
        for key, recommendation in recommendations.items():
            if key in subtype:
                return recommendation

        return "Remove the secret from code and use secure secret management practices."

    def _get_vulnerability_recommendation(self, finding: EnhancedFinding) -> str:
        """Get recommendation for vulnerability finding"""
        if 'sql' in finding.description.lower():
            return "Use parameterized queries or prepared statements to prevent SQL injection."
        elif 'xss' in finding.description.lower():
            return "Implement proper input validation and output encoding to prevent XSS attacks."
        elif 'csrf' in finding.description.lower():
            return "Implement CSRF tokens and proper request validation."
        else:
            return "Review the vulnerability and implement appropriate security controls."

    def _get_dependency_recommendation(self, finding: EnhancedFinding) -> str:
        """Get recommendation for dependency finding"""
        return f"Update the vulnerable dependency to a secure version. Current severity: {finding.severity}"

    def _get_ai_pattern_recommendation(self, finding: EnhancedFinding) -> str:
        """Get recommendation for AI pattern finding"""
        return "Review the AI-generated code pattern and ensure it follows security best practices."

    async def _generate_fix_suggestion(self, finding: EnhancedFinding, context: ScanContext) -> str:
        """Generate fix suggestion for finding"""
        try:
            # Use AI suggestions engine if available
            from ..ai_suggestions.fix_engine import FixEngine
            fix_engine = FixEngine()

            fix_suggestion = fix_engine.generate_fix(
                finding_type=finding.type,
                description=finding.description,
                context=finding.context,
                file_path=finding.file_path,
                severity=finding.severity
            )

            return fix_suggestion.get('suggestion', 'No specific fix suggestion available.')

        except Exception as e:
            logger.error(f"Fix suggestion generation failed: {e}")
            return "Manual fix required - consult security documentation."

    def _get_compliance_tags(self, finding: EnhancedFinding) -> List[str]:
        """Get compliance tags for finding"""
        tags = []

        # OWASP Top 10 mapping
        if finding.type == 'secret':
            tags.extend(['OWASP-A02', 'OWASP-A07'])  # Cryptographic Failures, Identification and Authentication Failures
        elif finding.type == 'vulnerability':
            if 'injection' in finding.description.lower():
                tags.append('OWASP-A03')  # Injection
            if 'xss' in finding.description.lower():
                tags.append('OWASP-A03')  # Injection
        elif finding.type == 'dependency':
            tags.extend(['OWASP-A06', 'OWASP-A09'])  # Vulnerable Components, Security Logging

        # Severity-based compliance
        if finding.severity in ['critical', 'high']:
            tags.extend(['PCI-DSS', 'SOX', 'GDPR'])

        # Industry standards
        tags.extend(['CWE', 'NIST'])

        return list(set(tags))  # Remove duplicates

    async def _get_cve_references(self, finding: EnhancedFinding) -> List[str]:
        """Get CVE references for vulnerability findings"""
        cve_references = []

        try:
            # Extract CVE references from description or context
            import re
            cve_pattern = r'CVE-\d{4}-\d{4,7}'

            text_to_search = f"{finding.description} {finding.context}"
            cve_matches = re.findall(cve_pattern, text_to_search, re.IGNORECASE)

            cve_references.extend(cve_matches)

            # For dependency vulnerabilities, try to get CVEs from vulnerability database
            if finding.type == 'dependency' and hasattr(self.dependency_scanner, 'vulnerability_db'):
                # This would require integration with vulnerability database
                pass

        except Exception as e:
            logger.error(f"CVE reference extraction failed: {e}")

        return list(set(cve_references))  # Remove duplicates

    def _apply_final_confidence_adjustment(self, finding: EnhancedFinding) -> float:
        """Apply final confidence adjustments"""
        confidence = finding.confidence

        # Boost confidence for cross-validated findings
        if finding.verification_status == VerificationStatus.CROSS_VALIDATED:
            confidence = min(confidence * 1.1, 1.0)

        # Reduce confidence for unverified findings
        elif finding.verification_status == VerificationStatus.UNVERIFIED:
            confidence = confidence * 0.9

        # Adjust based on false positive likelihood
        if finding.false_positive_likelihood > 0.5:
            confidence = confidence * (1 - finding.false_positive_likelihood * 0.5)

        # Ensure confidence bounds
        return max(min(confidence, 1.0), 0.0)

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        with self.lock:
            stats = self.scan_stats.copy()

            # Calculate derived statistics
            if stats['total_scans'] > 0:
                stats['avg_findings_per_scan'] = stats['verified_findings'] / stats['total_scans']
                stats['false_positive_rate'] = stats['false_positives_filtered'] / (stats['verified_findings'] + stats['false_positives_filtered'])
                stats['avg_processing_time'] = stats['processing_time_total'] / stats['total_scans']
            else:
                stats['avg_findings_per_scan'] = 0
                stats['false_positive_rate'] = 0
                stats['avg_processing_time'] = 0

            return stats

    def reset_statistics(self):
        """Reset scan statistics"""
        with self.lock:
            self.scan_stats = {
                'total_scans': 0,
                'verified_findings': 0,
                'false_positives_filtered': 0,
                'ml_predictions': 0,
                'plugin_executions': 0,
                'cross_validations': 0,
                'cache_hits': 0,
                'processing_time_total': 0.0
            }

    def _ensure_plugins_initialized(self):
        """Ensure plugin system is initialized"""
        if not self.plugin_system_initialized:
            try:
                initialize_plugin_system()
                self.plugin_system_initialized = True
                logger.info("Plugin system initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize plugin system: {e}")

    async def _run_plugin_scanners(self, context: ScanContext) -> List[EnhancedFinding]:
        """Run all registered plugins"""
        findings = []

        try:
            # Ensure plugins are initialized
            self._ensure_plugins_initialized()

            # Get available plugins
            available_plugins = plugin_registry.get_all_plugins()

            for plugin_info in available_plugins.get("plugins", []):
                plugin_name = plugin_info["manifest"]["name"]

                try:
                    # Check if plugin supports this file type
                    supported_types = plugin_info["manifest"]["supported_file_types"]
                    file_ext = Path(context.file_path).suffix.lower()

                    if file_ext not in supported_types and not any(
                        context.file_path.endswith(ext) for ext in supported_types
                    ):
                        continue

                    # Execute plugin
                    plugin_context = {
                        "scan_mode": context.scan_mode.value,
                        "confidence_threshold": context.confidence_threshold,
                        "language": context.language
                    }

                    result = plugin_registry.execute_plugin(
                        plugin_name,
                        context.content,
                        context.file_path,
                        plugin_context
                    )

                    # Convert plugin results to EnhancedFinding objects
                    if result.status.value == "completed":
                        for finding_dict in result.findings:
                            enhanced_finding = await self._enhance_finding(
                                finding_dict,
                                plugin_name,
                                context
                            )
                            findings.append(enhanced_finding)

                    self.scan_stats['plugin_executions'] += 1

                except Exception as e:
                    logger.error(f"Plugin {plugin_name} execution failed: {e}")
                    continue

        except Exception as e:
            logger.error(f"Plugin scanner execution failed: {e}")

        return findings

# Global unified scanner instance
unified_scanner = UnifiedScanner()
