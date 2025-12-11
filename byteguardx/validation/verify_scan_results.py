"""
Real-time Result Verification Module for ByteGuardX
Validates scan results for accuracy and consistency
"""

import os
import time
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re
import json

logger = logging.getLogger(__name__)

class VerificationMethod(Enum):
    """Verification methods"""
    CROSS_SCANNER = "cross_scanner"
    TEMPORAL_CONSISTENCY = "temporal_consistency"
    PATTERN_VALIDATION = "pattern_validation"
    CONTEXT_ANALYSIS = "context_analysis"
    ML_VALIDATION = "ml_validation"
    SIGNATURE_VERIFICATION = "signature_verification"

class VerificationResult(Enum):
    """Verification results"""
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNCERTAIN = "uncertain"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"

@dataclass
class VerificationReport:
    """Verification report for a finding"""
    finding_id: str
    verification_result: VerificationResult
    confidence_score: float
    verification_methods: List[VerificationMethod]
    verification_details: Dict[str, Any]
    timestamp: datetime
    processing_time_ms: float
    
class ResultVerifier:
    """
    Advanced result verification system
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.verification_history = {}
        self.pattern_cache = {}
        
        # Verification thresholds
        self.thresholds = {
            'cross_scanner_agreement': 0.7,
            'temporal_consistency': 0.8,
            'pattern_confidence': 0.6,
            'context_relevance': 0.5,
            'ml_validation': 0.7
        }
        
        # Load verification patterns
        self._load_verification_patterns()
        
    def verify_finding(self, finding: Dict[str, Any], context: Dict[str, Any] = None) -> VerificationReport:
        """
        Comprehensive verification of a single finding
        """
        start_time = time.time()
        finding_id = finding.get('id', self._generate_finding_id(finding))
        
        verification_methods = []
        verification_details = {}
        confidence_scores = []
        
        try:
            # Method 1: Cross-scanner verification
            if context and context.get('other_findings'):
                cross_scanner_result = self._verify_cross_scanner(finding, context['other_findings'])
                verification_methods.append(VerificationMethod.CROSS_SCANNER)
                verification_details['cross_scanner'] = cross_scanner_result
                confidence_scores.append(cross_scanner_result['confidence'])
            
            # Method 2: Temporal consistency check
            temporal_result = self._verify_temporal_consistency(finding)
            verification_methods.append(VerificationMethod.TEMPORAL_CONSISTENCY)
            verification_details['temporal_consistency'] = temporal_result
            confidence_scores.append(temporal_result['confidence'])
            
            # Method 3: Pattern validation
            pattern_result = self._verify_pattern_validity(finding)
            verification_methods.append(VerificationMethod.PATTERN_VALIDATION)
            verification_details['pattern_validation'] = pattern_result
            confidence_scores.append(pattern_result['confidence'])
            
            # Method 4: Context analysis
            context_result = self._verify_context_relevance(finding)
            verification_methods.append(VerificationMethod.CONTEXT_ANALYSIS)
            verification_details['context_analysis'] = context_result
            confidence_scores.append(context_result['confidence'])
            
            # Method 5: ML validation (if available)
            if context and context.get('ml_predictor'):
                ml_result = self._verify_ml_consistency(finding, context['ml_predictor'])
                verification_methods.append(VerificationMethod.ML_VALIDATION)
                verification_details['ml_validation'] = ml_result
                confidence_scores.append(ml_result['confidence'])
            
            # Calculate overall confidence
            overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
            
            # Determine verification result
            verification_result = self._determine_verification_result(overall_confidence, verification_details)
            
            # Store in history
            self._store_verification_history(finding_id, verification_result, overall_confidence)
            
            processing_time = (time.time() - start_time) * 1000
            
            return VerificationReport(
                finding_id=finding_id,
                verification_result=verification_result,
                confidence_score=overall_confidence,
                verification_methods=verification_methods,
                verification_details=verification_details,
                timestamp=datetime.now(),
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            logger.error(f"Verification failed for finding {finding_id}: {e}")
            processing_time = (time.time() - start_time) * 1000
            
            return VerificationReport(
                finding_id=finding_id,
                verification_result=VerificationResult.UNCERTAIN,
                confidence_score=0.0,
                verification_methods=[],
                verification_details={'error': str(e)},
                timestamp=datetime.now(),
                processing_time_ms=processing_time
            )
    
    def verify_batch(self, findings: List[Dict[str, Any]], context: Dict[str, Any] = None) -> List[VerificationReport]:
        """
        Batch verification of multiple findings
        """
        reports = []
        
        # Add cross-reference context for each finding
        for i, finding in enumerate(findings):
            finding_context = context.copy() if context else {}
            finding_context['other_findings'] = [f for j, f in enumerate(findings) if j != i]
            
            report = self.verify_finding(finding, finding_context)
            reports.append(report)
        
        return reports
    
    def _verify_cross_scanner(self, finding: Dict[str, Any], other_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verify finding against results from other scanners
        """
        try:
            # Look for similar findings from different scanners
            similar_findings = []
            finding_location = (finding.get('file_path'), finding.get('line_number'))
            
            for other_finding in other_findings:
                other_location = (other_finding.get('file_path'), other_finding.get('line_number'))
                
                # Check if findings are at same location
                if finding_location == other_location:
                    # Check if they're from different scanners
                    if finding.get('scanner_source') != other_finding.get('scanner_source'):
                        similarity_score = self._calculate_finding_similarity(finding, other_finding)
                        if similarity_score > 0.5:
                            similar_findings.append({
                                'finding': other_finding,
                                'similarity': similarity_score
                            })
            
            # Calculate confidence based on agreement
            if similar_findings:
                avg_similarity = sum(sf['similarity'] for sf in similar_findings) / len(similar_findings)
                confidence = min(avg_similarity * len(similar_findings) * 0.3, 1.0)
            else:
                confidence = 0.3  # Lower confidence for single-scanner findings
            
            return {
                'confidence': confidence,
                'similar_findings_count': len(similar_findings),
                'agreement_score': avg_similarity if similar_findings else 0.0,
                'details': similar_findings
            }
            
        except Exception as e:
            logger.error(f"Cross-scanner verification failed: {e}")
            return {'confidence': 0.0, 'error': str(e)}
    
    def _verify_temporal_consistency(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify finding against historical results
        """
        try:
            finding_signature = self._generate_finding_signature(finding)
            
            # Check if we've seen this finding before
            if finding_signature in self.verification_history:
                history = self.verification_history[finding_signature]
                
                # Calculate consistency score
                recent_verifications = [
                    h for h in history 
                    if h['timestamp'] > datetime.now() - timedelta(days=7)
                ]
                
                if recent_verifications:
                    verified_count = sum(1 for h in recent_verifications if h['result'] == VerificationResult.VERIFIED)
                    consistency_score = verified_count / len(recent_verifications)
                else:
                    consistency_score = 0.5  # Neutral for new findings
                
                confidence = consistency_score
            else:
                confidence = 0.5  # Neutral for first-time findings
            
            return {
                'confidence': confidence,
                'historical_occurrences': len(self.verification_history.get(finding_signature, [])),
                'consistency_score': confidence
            }
            
        except Exception as e:
            logger.error(f"Temporal consistency verification failed: {e}")
            return {'confidence': 0.5, 'error': str(e)}
    
    def _verify_pattern_validity(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify the validity of the detected pattern
        """
        try:
            finding_type = finding.get('type', '')
            subtype = finding.get('subtype', '')
            context = finding.get('context', '')
            
            # Load type-specific validation patterns
            validation_patterns = self.pattern_cache.get(finding_type, {})
            
            confidence = 0.5  # Base confidence
            validation_details = {}
            
            # Pattern-specific validation
            if finding_type == 'secret':
                confidence = self._validate_secret_pattern(finding, validation_patterns)
                validation_details['secret_validation'] = True
            elif finding_type == 'vulnerability':
                confidence = self._validate_vulnerability_pattern(finding, validation_patterns)
                validation_details['vulnerability_validation'] = True
            elif finding_type == 'dependency':
                confidence = self._validate_dependency_pattern(finding, validation_patterns)
                validation_details['dependency_validation'] = True
            elif finding_type == 'ai_pattern':
                confidence = self._validate_ai_pattern(finding, validation_patterns)
                validation_details['ai_pattern_validation'] = True
            
            return {
                'confidence': confidence,
                'pattern_type': finding_type,
                'validation_details': validation_details
            }
            
        except Exception as e:
            logger.error(f"Pattern validation failed: {e}")
            return {'confidence': 0.5, 'error': str(e)}
    
    def _verify_context_relevance(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify the relevance of the finding context
        """
        try:
            context = finding.get('context', '')
            file_path = finding.get('file_path', '')
            description = finding.get('description', '')
            
            relevance_score = 0.5  # Base score
            
            # File path relevance
            if file_path:
                # Check if file type is relevant to finding type
                file_relevance = self._calculate_file_relevance(finding.get('type'), file_path)
                relevance_score += file_relevance * 0.3
            
            # Context content relevance
            if context:
                context_relevance = self._calculate_context_relevance(finding.get('type'), context)
                relevance_score += context_relevance * 0.4
            
            # Description clarity
            if description:
                description_clarity = self._calculate_description_clarity(description)
                relevance_score += description_clarity * 0.3
            
            confidence = min(relevance_score, 1.0)
            
            return {
                'confidence': confidence,
                'file_relevance': file_relevance if file_path else 0.0,
                'context_relevance': context_relevance if context else 0.0,
                'description_clarity': description_clarity if description else 0.0
            }
            
        except Exception as e:
            logger.error(f"Context relevance verification failed: {e}")
            return {'confidence': 0.5, 'error': str(e)}
    
    def _verify_ml_consistency(self, finding: Dict[str, Any], ml_predictor) -> Dict[str, Any]:
        """
        Verify finding consistency with ML predictions
        """
        try:
            # Get ML prediction for the finding context
            context = finding.get('context', '')
            file_path = finding.get('file_path', '')
            
            if hasattr(ml_predictor, 'predict_vulnerabilities'):
                ml_prediction = ml_predictor.predict_vulnerabilities(context, file_path)
                
                # Compare finding with ML prediction
                finding_type = finding.get('type', '')
                ml_types = ml_prediction.vulnerability_types if hasattr(ml_prediction, 'vulnerability_types') else []
                
                # Check if ML agrees with the finding
                type_agreement = finding_type in [t.lower() for t in ml_types]
                confidence_agreement = abs(finding.get('confidence', 0.0) - getattr(ml_prediction, 'confidence_score', 0.0)) < 0.3
                
                if type_agreement and confidence_agreement:
                    confidence = 0.9
                elif type_agreement or confidence_agreement:
                    confidence = 0.7
                else:
                    confidence = 0.3
                
                return {
                    'confidence': confidence,
                    'type_agreement': type_agreement,
                    'confidence_agreement': confidence_agreement,
                    'ml_confidence': getattr(ml_prediction, 'confidence_score', 0.0)
                }
            else:
                return {'confidence': 0.5, 'error': 'ML predictor not available'}
                
        except Exception as e:
            logger.error(f"ML consistency verification failed: {e}")
            return {'confidence': 0.5, 'error': str(e)}

    def _determine_verification_result(self, confidence: float, details: Dict[str, Any]) -> VerificationResult:
        """
        Determine final verification result based on confidence and details
        """
        if confidence >= 0.8:
            return VerificationResult.VERIFIED
        elif confidence >= 0.6:
            # Check for specific conditions that might require manual review
            if any('error' in detail for detail in details.values()):
                return VerificationResult.REQUIRES_MANUAL_REVIEW
            return VerificationResult.VERIFIED
        elif confidence >= 0.4:
            return VerificationResult.UNCERTAIN
        else:
            return VerificationResult.REJECTED

    def _calculate_finding_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two findings
        """
        similarity_score = 0.0

        # Type similarity
        if finding1.get('type') == finding2.get('type'):
            similarity_score += 0.3

        # Subtype similarity
        if finding1.get('subtype') == finding2.get('subtype'):
            similarity_score += 0.2

        # Severity similarity
        if finding1.get('severity') == finding2.get('severity'):
            similarity_score += 0.1

        # Description similarity (simple word overlap)
        desc1_words = set(finding1.get('description', '').lower().split())
        desc2_words = set(finding2.get('description', '').lower().split())

        if desc1_words and desc2_words:
            word_overlap = len(desc1_words.intersection(desc2_words)) / len(desc1_words.union(desc2_words))
            similarity_score += word_overlap * 0.4

        return min(similarity_score, 1.0)

    def _generate_finding_signature(self, finding: Dict[str, Any]) -> str:
        """
        Generate unique signature for finding
        """
        signature_data = f"{finding.get('type')}:{finding.get('subtype')}:{finding.get('file_path')}:{finding.get('line_number')}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]

    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """
        Generate unique ID for finding
        """
        id_data = f"{finding.get('file_path')}:{finding.get('line_number')}:{finding.get('type')}:{datetime.now().isoformat()}"
        return hashlib.sha256(id_data.encode()).hexdigest()[:12]

    def _store_verification_history(self, finding_id: str, result: VerificationResult, confidence: float):
        """
        Store verification result in history
        """
        if finding_id not in self.verification_history:
            self.verification_history[finding_id] = []

        self.verification_history[finding_id].append({
            'result': result,
            'confidence': confidence,
            'timestamp': datetime.now()
        })

        # Limit history size
        if len(self.verification_history[finding_id]) > 100:
            self.verification_history[finding_id] = self.verification_history[finding_id][-50:]

    def _load_verification_patterns(self):
        """
        Load verification patterns for different finding types
        """
        self.pattern_cache = {
            'secret': {
                'high_entropy_threshold': 4.5,
                'min_length': 8,
                'common_false_positives': ['example', 'test', 'demo', 'placeholder'],
                'context_indicators': ['key', 'secret', 'token', 'password', 'credential']
            },
            'vulnerability': {
                'severity_patterns': {
                    'critical': ['remote code execution', 'sql injection', 'authentication bypass'],
                    'high': ['xss', 'csrf', 'path traversal'],
                    'medium': ['information disclosure', 'weak encryption'],
                    'low': ['deprecated function', 'weak random']
                }
            },
            'dependency': {
                'version_patterns': {
                    'outdated': r'\d+\.\d+\.\d+',
                    'vulnerable': ['known vulnerability', 'security advisory']
                }
            },
            'ai_pattern': {
                'confidence_thresholds': {
                    'high': 0.8,
                    'medium': 0.6,
                    'low': 0.4
                }
            }
        }

    def _validate_secret_pattern(self, finding: Dict[str, Any], patterns: Dict[str, Any]) -> float:
        """
        Validate secret-specific patterns
        """
        confidence = 0.5

        # Check entropy if available
        entropy = finding.get('entropy', 0.0)
        if entropy >= patterns.get('high_entropy_threshold', 4.5):
            confidence += 0.3

        # Check length
        value = finding.get('value', '')
        if len(value) >= patterns.get('min_length', 8):
            confidence += 0.1

        # Check for false positive indicators
        context = finding.get('context', '').lower()
        false_positives = patterns.get('common_false_positives', [])

        if any(fp in context for fp in false_positives):
            confidence -= 0.4

        # Check for context indicators
        context_indicators = patterns.get('context_indicators', [])
        if any(indicator in context for indicator in context_indicators):
            confidence += 0.2

        return max(min(confidence, 1.0), 0.0)

    def _validate_vulnerability_pattern(self, finding: Dict[str, Any], patterns: Dict[str, Any]) -> float:
        """
        Validate vulnerability-specific patterns
        """
        confidence = 0.5

        description = finding.get('description', '').lower()
        severity = finding.get('severity', 'medium').lower()

        severity_patterns = patterns.get('severity_patterns', {})

        # Check if description matches severity patterns
        if severity in severity_patterns:
            severity_keywords = severity_patterns[severity]
            if any(keyword in description for keyword in severity_keywords):
                confidence += 0.3

        # Check for specific vulnerability indicators
        vuln_indicators = ['injection', 'overflow', 'bypass', 'disclosure', 'execution']
        if any(indicator in description for indicator in vuln_indicators):
            confidence += 0.2

        return max(min(confidence, 1.0), 0.0)

    def _validate_dependency_pattern(self, finding: Dict[str, Any], patterns: Dict[str, Any]) -> float:
        """
        Validate dependency-specific patterns
        """
        confidence = 0.5

        description = finding.get('description', '').lower()

        # Check for version patterns
        version_patterns = patterns.get('version_patterns', {})

        if 'vulnerable' in version_patterns:
            vuln_keywords = version_patterns['vulnerable']
            if any(keyword in description for keyword in vuln_keywords):
                confidence += 0.4

        # Check for CVE references
        if re.search(r'cve-\d{4}-\d{4,7}', description, re.IGNORECASE):
            confidence += 0.3

        return max(min(confidence, 1.0), 0.0)

    def _validate_ai_pattern(self, finding: Dict[str, Any], patterns: Dict[str, Any]) -> float:
        """
        Validate AI pattern-specific patterns
        """
        confidence = finding.get('confidence', 0.5)

        # Apply confidence thresholds
        thresholds = patterns.get('confidence_thresholds', {})

        if confidence >= thresholds.get('high', 0.8):
            return min(confidence + 0.1, 1.0)
        elif confidence >= thresholds.get('medium', 0.6):
            return confidence
        else:
            return max(confidence - 0.1, 0.0)

    def _calculate_file_relevance(self, finding_type: str, file_path: str) -> float:
        """
        Calculate relevance of file path to finding type
        """
        from pathlib import Path

        file_ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()

        relevance_map = {
            'secret': {
                'high': ['.env', '.config', '.ini', '.yaml', '.yml', '.json'],
                'medium': ['.py', '.js', '.java', '.go', '.rb'],
                'low': ['.txt', '.md']
            },
            'vulnerability': {
                'high': ['.py', '.js', '.php', '.java', '.c', '.cpp'],
                'medium': ['.html', '.jsp', '.asp'],
                'low': ['.txt', '.md']
            },
            'dependency': {
                'high': ['requirements.txt', 'package.json', 'pom.xml', 'cargo.toml'],
                'medium': ['.lock', '.gradle'],
                'low': []
            }
        }

        type_relevance = relevance_map.get(finding_type, {})

        if file_name in type_relevance.get('high', []) or file_ext in type_relevance.get('high', []):
            return 1.0
        elif file_name in type_relevance.get('medium', []) or file_ext in type_relevance.get('medium', []):
            return 0.7
        elif file_name in type_relevance.get('low', []) or file_ext in type_relevance.get('low', []):
            return 0.3
        else:
            return 0.5

    def _calculate_context_relevance(self, finding_type: str, context: str) -> float:
        """
        Calculate relevance of context to finding type
        """
        context_lower = context.lower()

        relevance_keywords = {
            'secret': ['password', 'key', 'token', 'secret', 'credential', 'auth'],
            'vulnerability': ['input', 'user', 'request', 'query', 'execute', 'eval'],
            'dependency': ['import', 'require', 'dependency', 'version', 'package'],
            'ai_pattern': ['generated', 'auto', 'ai', 'model', 'predict']
        }

        keywords = relevance_keywords.get(finding_type, [])
        matches = sum(1 for keyword in keywords if keyword in context_lower)

        return min(matches / len(keywords) if keywords else 0.5, 1.0)

    def _calculate_description_clarity(self, description: str) -> float:
        """
        Calculate clarity of finding description
        """
        if not description:
            return 0.0

        # Basic clarity metrics
        word_count = len(description.split())
        has_specific_terms = any(term in description.lower() for term in [
            'vulnerability', 'secret', 'injection', 'xss', 'csrf', 'token', 'key'
        ])

        clarity_score = 0.5

        # Appropriate length
        if 5 <= word_count <= 50:
            clarity_score += 0.2

        # Contains specific security terms
        if has_specific_terms:
            clarity_score += 0.3

        return min(clarity_score, 1.0)

    def get_verification_statistics(self) -> Dict[str, Any]:
        """
        Get verification statistics
        """
        total_verifications = sum(len(history) for history in self.verification_history.values())

        if total_verifications == 0:
            return {
                'total_verifications': 0,
                'verification_rate': 0.0,
                'average_confidence': 0.0,
                'result_distribution': {}
            }

        # Calculate statistics
        all_results = []
        all_confidences = []

        for history in self.verification_history.values():
            for entry in history:
                all_results.append(entry['result'])
                all_confidences.append(entry['confidence'])

        result_counts = {}
        for result in VerificationResult:
            result_counts[result.value] = sum(1 for r in all_results if r == result)

        return {
            'total_verifications': total_verifications,
            'verification_rate': result_counts.get('verified', 0) / total_verifications,
            'average_confidence': sum(all_confidences) / len(all_confidences),
            'result_distribution': result_counts,
            'unique_findings': len(self.verification_history)
        }

    def clear_verification_history(self):
        """
        Clear verification history
        """
        self.verification_history.clear()
        logger.info("Verification history cleared")

# Global verifier instance
result_verifier = ResultVerifier()
