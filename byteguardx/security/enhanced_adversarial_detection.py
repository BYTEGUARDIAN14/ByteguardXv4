"""
Enhanced Adversarial Input Detection for ByteGuardX
Advanced preprocessing layer with character distribution analysis,
token limits, and obfuscation detection
"""

import re
import math
import logging
import hashlib
import unicodedata
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of adversarial threats"""
    OVERSIZED_INPUT = "oversized_input"
    EXCESSIVE_TOKENS = "excessive_tokens"
    UNUSUAL_CHAR_DISTRIBUTION = "unusual_char_distribution"
    UNICODE_CONFUSABLES = "unicode_confusables"
    HIGH_ENTROPY = "high_entropy"
    EXCESSIVE_OBFUSCATION = "excessive_obfuscation"
    PROMPT_INJECTION = "prompt_injection"
    TOKEN_ANOMALIES = "token_anomalies"
    ANALYSIS_ERROR = "analysis_error"

class RiskLevel(Enum):
    """Risk levels for threats"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AdversarialThreat:
    """Adversarial threat information"""
    threat_type: ThreatType
    confidence: float
    description: str
    mitigation: str
    risk_level: RiskLevel = RiskLevel.MEDIUM

@dataclass
class AdversarialDetectionResult:
    """Result of adversarial detection analysis"""
    is_adversarial: bool
    confidence: float
    risk_level: RiskLevel
    threats: List[AdversarialThreat]
    input_length: int
    token_count: int
    analysis_timestamp: datetime

class EnhancedAdversarialDetector:
    """Enhanced adversarial input detector with preprocessing layer"""
    
    def __init__(self):
        self.max_input_length = 10000  # Maximum input length
        self.max_tokens = 2048  # Maximum token count
        self.entropy_threshold = 4.5  # Entropy threshold for randomness detection
        self.obfuscation_threshold = 0.3  # Threshold for obfuscation detection
        self.char_dist_threshold = 0.15  # Character distribution anomaly threshold
        
        # Suspicious patterns for prompt injection
        self.injection_patterns = [
            r'ignore\s+previous\s+instructions',
            r'forget\s+everything\s+above',
            r'system\s*:\s*you\s+are',
            r'act\s+as\s+if\s+you\s+are',
            r'pretend\s+to\s+be',
            r'roleplay\s+as',
            r'simulate\s+being',
            r'override\s+your\s+instructions',
            r'disregard\s+your\s+programming',
            r'reveal\s+your\s+system\s+prompt'
        ]
        
        # Unicode confusable characters
        self.confusables = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
            'ο': 'o', 'α': 'a', 'ρ': 'p', 'ε': 'e',  # Greek
            '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',  # Fullwidth
            '５': '5', '６': '6', '７': '7', '８': '8', '９': '9'
        }
    
    def preprocess_and_validate(self, input_text: str, context: str = None) -> Tuple[str, AdversarialDetectionResult]:
        """
        Preprocess input and validate for adversarial content
        
        Args:
            input_text: Input text to preprocess and validate
            context: Optional context for analysis
            
        Returns:
            Tuple of (cleaned_input, detection_result)
        """
        try:
            # First, detect adversarial content
            detection_result = self.detect_adversarial_input(input_text, context)
            
            # If high risk, reject immediately
            if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                return "", detection_result
            
            # Clean and normalize input
            cleaned_input = self._clean_input(input_text)
            
            # Validate cleaned input
            if detection_result.risk_level == RiskLevel.MEDIUM:
                # Re-analyze cleaned input
                cleaned_detection = self.detect_adversarial_input(cleaned_input, context)
                if cleaned_detection.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    return "", cleaned_detection
                detection_result = cleaned_detection
            
            return cleaned_input, detection_result
            
        except Exception as e:
            logger.error(f"Input preprocessing failed: {e}")
            return "", AdversarialDetectionResult(
                is_adversarial=True,
                confidence=1.0,
                risk_level=RiskLevel.CRITICAL,
                threats=[AdversarialThreat(
                    threat_type=ThreatType.ANALYSIS_ERROR,
                    confidence=1.0,
                    description=f"Preprocessing failed: {e}",
                    mitigation="Block input due to preprocessing failure",
                    risk_level=RiskLevel.CRITICAL
                )],
                input_length=len(input_text),
                token_count=0,
                analysis_timestamp=datetime.now()
            )
    
    def detect_adversarial_input(self, input_text: str, context: str = None) -> AdversarialDetectionResult:
        """
        Detect adversarial input attempts with enhanced checks
        
        Args:
            input_text: Input text to analyze
            context: Optional context for analysis
            
        Returns:
            AdversarialDetectionResult with detection results
        """
        try:
            threats = []
            
            # Length check
            if len(input_text) > self.max_input_length:
                threats.append(AdversarialThreat(
                    threat_type=ThreatType.OVERSIZED_INPUT,
                    confidence=1.0,
                    description=f"Input length {len(input_text)} exceeds maximum {self.max_input_length}",
                    mitigation="Truncate input to maximum allowed length",
                    risk_level=RiskLevel.HIGH
                ))
            
            # Token count check
            token_count = self._estimate_token_count(input_text)
            if token_count > self.max_tokens:
                threats.append(AdversarialThreat(
                    threat_type=ThreatType.EXCESSIVE_TOKENS,
                    confidence=1.0,
                    description=f"Token count {token_count} exceeds maximum {self.max_tokens}",
                    mitigation="Reduce input complexity or split into smaller chunks",
                    risk_level=RiskLevel.HIGH
                ))
            
            # Character distribution analysis
            char_dist_threats = self._analyze_character_distribution(input_text)
            threats.extend(char_dist_threats)
            
            # Unicode confusables detection
            unicode_threats = self._detect_unicode_confusables(input_text)
            threats.extend(unicode_threats)
            
            # Entropy analysis
            entropy_threats = self._detect_high_entropy(input_text)
            threats.extend(entropy_threats)
            
            # Obfuscation detection
            obfuscation_threats = self._detect_obfuscation(input_text)
            threats.extend(obfuscation_threats)
            
            # Prompt injection detection
            injection_threats = self._detect_prompt_injection(input_text)
            threats.extend(injection_threats)
            
            # Calculate overall risk
            risk_level = self._calculate_risk_level(threats)
            overall_confidence = max([t.confidence for t in threats]) if threats else 0.0
            
            return AdversarialDetectionResult(
                is_adversarial=len(threats) > 0,
                confidence=overall_confidence,
                risk_level=risk_level,
                threats=threats,
                input_length=len(input_text),
                token_count=token_count,
                analysis_timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Adversarial detection failed: {e}")
            return AdversarialDetectionResult(
                is_adversarial=True,
                confidence=1.0,
                risk_level=RiskLevel.CRITICAL,
                threats=[AdversarialThreat(
                    threat_type=ThreatType.ANALYSIS_ERROR,
                    confidence=1.0,
                    description=f"Detection analysis failed: {e}",
                    mitigation="Block input due to analysis failure",
                    risk_level=RiskLevel.CRITICAL
                )],
                input_length=len(input_text),
                token_count=0,
                analysis_timestamp=datetime.now()
            )
    
    def _estimate_token_count(self, text: str) -> int:
        """Estimate token count (simplified)"""
        # Rough estimation: 1 token ≈ 4 characters for English text
        return len(text) // 4
    
    def _analyze_character_distribution(self, text: str) -> List[AdversarialThreat]:
        """Analyze character distribution for anomalies"""
        threats = []
        
        if not text:
            return threats
        
        # Calculate character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        total_chars = len(text)
        
        # Check for unusual character distributions
        non_ascii_count = sum(1 for char in text if ord(char) > 127)
        non_ascii_ratio = non_ascii_count / total_chars
        
        if non_ascii_ratio > self.char_dist_threshold:
            threats.append(AdversarialThreat(
                threat_type=ThreatType.UNUSUAL_CHAR_DISTRIBUTION,
                confidence=min(non_ascii_ratio * 2, 1.0),
                description=f"High non-ASCII character ratio: {non_ascii_ratio:.2%}",
                mitigation="Review input for unusual character usage",
                risk_level=RiskLevel.MEDIUM if non_ascii_ratio < 0.5 else RiskLevel.HIGH
            ))
        
        return threats
    
    def _detect_unicode_confusables(self, text: str) -> List[AdversarialThreat]:
        """Detect Unicode confusable characters"""
        threats = []
        confusable_count = 0
        
        for char in text:
            if char in self.confusables:
                confusable_count += 1
        
        if confusable_count > 0:
            confidence = min(confusable_count / len(text) * 10, 1.0)
            threats.append(AdversarialThreat(
                threat_type=ThreatType.UNICODE_CONFUSABLES,
                confidence=confidence,
                description=f"Found {confusable_count} confusable Unicode characters",
                mitigation="Replace confusable characters with ASCII equivalents",
                risk_level=RiskLevel.MEDIUM
            ))
        
        return threats
    
    def _detect_high_entropy(self, text: str) -> List[AdversarialThreat]:
        """Detect high entropy (randomness) in text"""
        threats = []
        
        if len(text) < 10:
            return threats
        
        # Calculate Shannon entropy
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        if entropy > self.entropy_threshold:
            confidence = min((entropy - self.entropy_threshold) / 3, 1.0)
            threats.append(AdversarialThreat(
                threat_type=ThreatType.HIGH_ENTROPY,
                confidence=confidence,
                description=f"High entropy detected: {entropy:.2f}",
                mitigation="Review input for random or encoded content",
                risk_level=RiskLevel.MEDIUM
            ))
        
        return threats
    
    def _detect_obfuscation(self, text: str) -> List[AdversarialThreat]:
        """Detect excessive obfuscation"""
        threats = []
        
        # Count obfuscation indicators
        obfuscation_score = 0
        
        # Base64-like patterns
        base64_matches = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text))
        obfuscation_score += base64_matches * 0.1
        
        # Hex encoding
        hex_matches = len(re.findall(r'\\x[0-9a-fA-F]{2}', text))
        obfuscation_score += hex_matches * 0.05
        
        # Unicode escapes
        unicode_matches = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))
        obfuscation_score += unicode_matches * 0.05
        
        # Excessive special characters
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', text)) / len(text)
        if special_char_ratio > 0.3:
            obfuscation_score += special_char_ratio
        
        if obfuscation_score > self.obfuscation_threshold:
            confidence = min(obfuscation_score, 1.0)
            threats.append(AdversarialThreat(
                threat_type=ThreatType.EXCESSIVE_OBFUSCATION,
                confidence=confidence,
                description=f"Excessive obfuscation detected (score: {obfuscation_score:.2f})",
                mitigation="Decode and review obfuscated content",
                risk_level=RiskLevel.HIGH if obfuscation_score > 0.7 else RiskLevel.MEDIUM
            ))
        
        return threats
    
    def _detect_prompt_injection(self, text: str) -> List[AdversarialThreat]:
        """Detect prompt injection attempts"""
        threats = []
        
        text_lower = text.lower()
        
        for pattern in self.injection_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                confidence = min(len(matches) * 0.3, 1.0)
                threats.append(AdversarialThreat(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    confidence=confidence,
                    description=f"Prompt injection pattern detected: {pattern}",
                    mitigation="Block or sanitize prompt injection attempts",
                    risk_level=RiskLevel.HIGH
                ))
        
        return threats
    
    def _clean_input(self, text: str) -> str:
        """Clean and normalize input text"""
        # Normalize Unicode
        text = unicodedata.normalize('NFKC', text)
        
        # Replace confusable characters
        for confusable, replacement in self.confusables.items():
            text = text.replace(confusable, replacement)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Limit length
        if len(text) > self.max_input_length:
            text = text[:self.max_input_length]
        
        return text
    
    def _calculate_risk_level(self, threats: List[AdversarialThreat]) -> RiskLevel:
        """Calculate overall risk level from threats"""
        if not threats:
            return RiskLevel.LOW
        
        # Count threats by risk level
        critical_count = sum(1 for t in threats if t.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for t in threats if t.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for t in threats if t.risk_level == RiskLevel.MEDIUM)
        
        if critical_count > 0:
            return RiskLevel.CRITICAL
        elif high_count > 0:
            return RiskLevel.HIGH
        elif medium_count > 1:
            return RiskLevel.HIGH
        elif medium_count > 0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

# Global instance
enhanced_adversarial_detector = EnhancedAdversarialDetector()
