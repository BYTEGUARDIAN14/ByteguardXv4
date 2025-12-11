"""
Adversarial Input Detection for ML Models
Detects and prevents adversarial attacks on AI/ML components
"""

import re
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import time
from pathlib import Path

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat levels for adversarial inputs"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AdversarialThreat:
    """Detected adversarial threat"""
    threat_type: str
    level: ThreatLevel
    confidence: float
    description: str
    indicators: List[str]
    mitigation: str

class AdversarialInputDetector:
    """Detects adversarial inputs targeting ML models"""
    
    # Patterns that indicate adversarial attacks
    ADVERSARIAL_PATTERNS = [
        # Prompt injection patterns
        (r'ignore\s+previous\s+instructions', 'prompt_injection', ThreatLevel.HIGH),
        (r'forget\s+everything\s+above', 'prompt_injection', ThreatLevel.HIGH),
        (r'system\s*:\s*you\s+are\s+now', 'role_manipulation', ThreatLevel.CRITICAL),
        (r'act\s+as\s+if\s+you\s+are', 'role_manipulation', ThreatLevel.HIGH),
        (r'pretend\s+to\s+be', 'role_manipulation', ThreatLevel.MEDIUM),
        
        # Code injection in prompts
        (r'```\s*python\s*\n.*exec\s*\(', 'code_injection', ThreatLevel.CRITICAL),
        (r'```\s*javascript\s*\n.*eval\s*\(', 'code_injection', ThreatLevel.CRITICAL),
        (r'<script[^>]*>', 'script_injection', ThreatLevel.HIGH),
        (r'javascript\s*:', 'script_injection', ThreatLevel.HIGH),
        
        # Data exfiltration attempts
        (r'show\s+me\s+your\s+training\s+data', 'data_exfiltration', ThreatLevel.HIGH),
        (r'what\s+are\s+your\s+instructions', 'instruction_leak', ThreatLevel.MEDIUM),
        (r'reveal\s+your\s+system\s+prompt', 'prompt_leak', ThreatLevel.HIGH),
        
        # Jailbreak attempts
        (r'DAN\s+mode', 'jailbreak', ThreatLevel.HIGH),
        (r'developer\s+mode', 'jailbreak', ThreatLevel.MEDIUM),
        (r'unrestricted\s+mode', 'jailbreak', ThreatLevel.HIGH),
        
        # Encoding/obfuscation attempts
        (r'base64\s*:', 'encoding_attack', ThreatLevel.MEDIUM),
        (r'\\x[0-9a-fA-F]{2}', 'hex_encoding', ThreatLevel.MEDIUM),
        (r'\\u[0-9a-fA-F]{4}', 'unicode_encoding', ThreatLevel.MEDIUM),
        
        # Repetitive/flooding patterns
        (r'(.{1,10})\1{20,}', 'repetitive_flood', ThreatLevel.MEDIUM),
        (r'[A-Z]{50,}', 'caps_flood', ThreatLevel.LOW),
        
        # Malicious file patterns
        (r'\.exe\s*$', 'executable_file', ThreatLevel.HIGH),
        (r'\.bat\s*$', 'batch_file', ThreatLevel.HIGH),
        (r'\.ps1\s*$', 'powershell_script', ThreatLevel.HIGH),
    ]
    
    # Suspicious keywords that might indicate attacks
    SUSPICIOUS_KEYWORDS = [
        'bypass', 'override', 'exploit', 'vulnerability', 'payload',
        'shellcode', 'backdoor', 'rootkit', 'malware', 'trojan',
        'keylogger', 'ransomware', 'phishing', 'social engineering'
    ]
    
    def __init__(self):
        self.detection_cache = {}
        self.threat_history = []
        self.max_input_length = 10000  # Maximum allowed input length
        self.max_tokens = 2000  # Maximum tokens for ML input
        
    def detect_adversarial_input(self, input_text: str, context: Dict[str, Any] = None) -> List[AdversarialThreat]:
        """
        Detect adversarial patterns in input text
        Returns list of detected threats
        """
        if not input_text:
            return []
        
        threats = []
        context = context or {}
        
        # Basic input validation
        basic_threats = self._validate_basic_input(input_text)
        threats.extend(basic_threats)
        
        # Pattern-based detection
        pattern_threats = self._detect_patterns(input_text)
        threats.extend(pattern_threats)
        
        # Statistical analysis
        statistical_threats = self._statistical_analysis(input_text)
        threats.extend(statistical_threats)
        
        # Context-aware detection
        if context:
            context_threats = self._context_aware_detection(input_text, context)
            threats.extend(context_threats)
        
        # Cache results for performance
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()
        self.detection_cache[input_hash] = threats
        
        # Log threats
        if threats:
            self._log_threats(input_text, threats, context)
        
        return threats
    
    def _validate_basic_input(self, input_text: str) -> List[AdversarialThreat]:
        """Basic input validation checks"""
        threats = []
        
        # Check input length
        if len(input_text) > self.max_input_length:
            threats.append(AdversarialThreat(
                threat_type="oversized_input",
                level=ThreatLevel.MEDIUM,
                confidence=1.0,
                description=f"Input exceeds maximum length ({len(input_text)} > {self.max_input_length})",
                indicators=[f"length:{len(input_text)}"],
                mitigation="Truncate input to maximum allowed length"
            ))
        
        # Check for null bytes
        if '\x00' in input_text:
            threats.append(AdversarialThreat(
                threat_type="null_byte_injection",
                level=ThreatLevel.HIGH,
                confidence=1.0,
                description="Input contains null bytes",
                indicators=["null_bytes"],
                mitigation="Remove null bytes from input"
            ))
        
        # Check for control characters
        control_chars = [c for c in input_text if ord(c) < 32 and c not in '\t\n\r']
        if control_chars:
            threats.append(AdversarialThreat(
                threat_type="control_characters",
                level=ThreatLevel.MEDIUM,
                confidence=0.8,
                description="Input contains suspicious control characters",
                indicators=[f"control_chars:{len(control_chars)}"],
                mitigation="Remove or escape control characters"
            ))
        
        return threats
    
    def _detect_patterns(self, input_text: str) -> List[AdversarialThreat]:
        """Pattern-based adversarial detection"""
        threats = []
        
        for pattern, threat_type, level in self.ADVERSARIAL_PATTERNS:
            matches = re.finditer(pattern, input_text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                threats.append(AdversarialThreat(
                    threat_type=threat_type,
                    level=level,
                    confidence=0.9,
                    description=f"Detected {threat_type} pattern",
                    indicators=[f"pattern:{pattern}", f"match:{match.group(0)[:50]}"],
                    mitigation=f"Remove or sanitize {threat_type} content"
                ))
        
        # Check for suspicious keywords
        suspicious_count = 0
        found_keywords = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword.lower() in input_text.lower():
                suspicious_count += 1
                found_keywords.append(keyword)
        
        if suspicious_count >= 3:
            threats.append(AdversarialThreat(
                threat_type="suspicious_keywords",
                level=ThreatLevel.MEDIUM,
                confidence=min(0.9, suspicious_count * 0.2),
                description=f"Multiple suspicious keywords detected ({suspicious_count})",
                indicators=[f"keywords:{','.join(found_keywords[:5])}"],
                mitigation="Review and sanitize suspicious content"
            ))
        
        return threats
    
    def _statistical_analysis(self, input_text: str) -> List[AdversarialThreat]:
        """Statistical analysis for anomaly detection"""
        threats = []
        
        # Entropy analysis
        entropy = self._calculate_entropy(input_text)
        if entropy > 7.5:  # High entropy might indicate encoded content
            threats.append(AdversarialThreat(
                threat_type="high_entropy",
                level=ThreatLevel.MEDIUM,
                confidence=min(0.9, (entropy - 7.5) * 0.4),
                description=f"High entropy content detected (entropy: {entropy:.2f})",
                indicators=[f"entropy:{entropy:.2f}"],
                mitigation="Verify content is not encoded or obfuscated"
            ))
        
        # Repetition analysis
        repetition_ratio = self._calculate_repetition_ratio(input_text)
        if repetition_ratio > 0.7:
            threats.append(AdversarialThreat(
                threat_type="repetitive_content",
                level=ThreatLevel.LOW,
                confidence=repetition_ratio,
                description=f"Highly repetitive content (ratio: {repetition_ratio:.2f})",
                indicators=[f"repetition:{repetition_ratio:.2f}"],
                mitigation="Remove repetitive content"
            ))
        
        # Character distribution analysis
        char_dist_anomaly = self._analyze_character_distribution(input_text)
        if char_dist_anomaly > 0.8:
            threats.append(AdversarialThreat(
                threat_type="character_anomaly",
                level=ThreatLevel.MEDIUM,
                confidence=char_dist_anomaly,
                description="Unusual character distribution detected",
                indicators=[f"char_anomaly:{char_dist_anomaly:.2f}"],
                mitigation="Review character patterns in input"
            ))
        
        return threats
    
    def _context_aware_detection(self, input_text: str, context: Dict[str, Any]) -> List[AdversarialThreat]:
        """Context-aware threat detection"""
        threats = []
        
        # Check if input is appropriate for the context
        input_type = context.get('input_type', 'general')
        user_role = context.get('user_role', 'user')
        
        # Admin-specific checks
        if user_role == 'admin':
            # Admins might legitimately use system commands
            pass
        else:
            # Regular users shouldn't use system commands
            system_patterns = [r'sudo\s+', r'rm\s+-rf', r'chmod\s+', r'>/dev/']
            for pattern in system_patterns:
                if re.search(pattern, input_text, re.IGNORECASE):
                    threats.append(AdversarialThreat(
                        threat_type="unauthorized_system_command",
                        level=ThreatLevel.HIGH,
                        confidence=0.9,
                        description="System command detected from non-admin user",
                        indicators=[f"pattern:{pattern}"],
                        mitigation="Block system commands for regular users"
                    ))
        
        # File upload context
        if input_type == 'file_upload':
            if any(ext in input_text.lower() for ext in ['.exe', '.bat', '.ps1', '.sh']):
                threats.append(AdversarialThreat(
                    threat_type="malicious_file_upload",
                    level=ThreatLevel.HIGH,
                    confidence=0.95,
                    description="Potentially malicious file extension in upload",
                    indicators=["malicious_extension"],
                    mitigation="Block executable file uploads"
                ))
        
        return threats
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_repetition_ratio(self, text: str) -> float:
        """Calculate ratio of repetitive content"""
        if len(text) < 10:
            return 0.0
        
        # Find repeated substrings
        repeated_chars = 0
        for i in range(len(text) - 1):
            if text[i] == text[i + 1]:
                repeated_chars += 1
        
        return repeated_chars / len(text)
    
    def _analyze_character_distribution(self, text: str) -> float:
        """Analyze character distribution for anomalies"""
        if not text:
            return 0.0
        
        # Count different character types
        alpha_count = sum(1 for c in text if c.isalpha())
        digit_count = sum(1 for c in text if c.isdigit())
        special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
        
        total_chars = len(text)
        
        # Calculate ratios
        alpha_ratio = alpha_count / total_chars
        digit_ratio = digit_count / total_chars
        special_ratio = special_count / total_chars
        
        # Detect anomalies (too many special characters or digits)
        anomaly_score = 0.0
        if special_ratio > 0.3:  # More than 30% special characters
            anomaly_score += special_ratio
        if digit_ratio > 0.5:  # More than 50% digits
            anomaly_score += digit_ratio * 0.5
        
        return min(1.0, anomaly_score)
    
    def _log_threats(self, input_text: str, threats: List[AdversarialThreat], context: Dict[str, Any]):
        """Log detected threats"""
        for threat in threats:
            logger.warning(f"Adversarial threat detected: {threat.threat_type} "
                         f"(level: {threat.level.value}, confidence: {threat.confidence:.2f})")
            
            # Store in threat history
            self.threat_history.append({
                'timestamp': time.time(),
                'threat_type': threat.threat_type,
                'level': threat.level.value,
                'confidence': threat.confidence,
                'input_hash': hashlib.sha256(input_text.encode()).hexdigest()[:16],
                'context': context
            })
            
            # Keep only recent history (last 1000 entries)
            if len(self.threat_history) > 1000:
                self.threat_history = self.threat_history[-1000:]
    
    def is_input_safe(self, input_text: str, context: Dict[str, Any] = None, 
                     max_threat_level: ThreatLevel = ThreatLevel.MEDIUM) -> Tuple[bool, List[AdversarialThreat]]:
        """
        Check if input is safe based on threat level threshold
        Returns: (is_safe, detected_threats)
        """
        threats = self.detect_adversarial_input(input_text, context)
        
        # Check if any threat exceeds the maximum allowed level
        threat_levels = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        max_level_value = threat_levels[max_threat_level]
        
        for threat in threats:
            if threat_levels[threat.level] > max_level_value:
                return False, threats
        
        return True, threats
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about detected threats"""
        if not self.threat_history:
            return {'total_threats': 0}
        
        # Count by type
        threat_counts = {}
        level_counts = {}
        
        for entry in self.threat_history:
            threat_type = entry['threat_type']
            level = entry['level']
            
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            level_counts[level] = level_counts.get(level, 0) + 1
        
        return {
            'total_threats': len(self.threat_history),
            'threat_types': threat_counts,
            'threat_levels': level_counts,
            'recent_threats': self.threat_history[-10:]  # Last 10 threats
        }

# Global adversarial input detector
adversarial_detector = AdversarialInputDetector()
