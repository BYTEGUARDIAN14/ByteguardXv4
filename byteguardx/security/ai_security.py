"""
AI/ML Security Hardening for ByteGuardX
Implements adversarial input detection and AI explanation auditing
"""

import numpy as np
import logging
import json
import hashlib
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
from pathlib import Path
import re

logger = logging.getLogger(__name__)

class AdversarialInputDetector:
    """Detects adversarial inputs to ML models"""
    
    def __init__(self):
        self.similarity_threshold = 0.95  # Cosine similarity threshold
        self.noise_threshold = 0.1  # Noise detection threshold
        self.max_input_length = 10000  # Maximum input length
        self.suspicious_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'%[0-9a-fA-F]{2}',    # URL encoding
            r'&#x?[0-9a-fA-F]+;',  # HTML entities
            r'\\u[0-9a-fA-F]{4}',  # Unicode escapes
            r'eval\s*\(',          # Code injection
            r'exec\s*\(',          # Code execution
            r'<script[^>]*>',      # Script tags
        ]
    
    def validate_input(self, input_data: Any, input_type: str = 'text') -> Tuple[bool, str]:
        """
        Validate input for adversarial patterns
        Returns: (is_valid, reason)
        """
        try:
            if input_type == 'text':
                return self._validate_text_input(input_data)
            elif input_type == 'embedding':
                return self._validate_embedding_input(input_data)
            elif input_type == 'code':
                return self._validate_code_input(input_data)
            else:
                return True, ""
                
        except Exception as e:
            logger.error(f"Input validation error: {e}")
            return False, f"Validation error: {str(e)}"
    
    def _validate_text_input(self, text: str) -> Tuple[bool, str]:
        """Validate text input for adversarial patterns"""
        if not isinstance(text, str):
            return False, "Input must be a string"
        
        # Check length
        if len(text) > self.max_input_length:
            return False, f"Input too long (max {self.max_input_length} characters)"
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False, f"Suspicious pattern detected: {pattern}"
        
        # Check for excessive repetition (potential adversarial)
        if self._detect_excessive_repetition(text):
            return False, "Excessive character repetition detected"
        
        # Check for unusual character distribution
        if self._detect_unusual_distribution(text):
            return False, "Unusual character distribution detected"
        
        return True, ""
    
    def _validate_embedding_input(self, embedding: np.ndarray) -> Tuple[bool, str]:
        """Validate embedding input for adversarial patterns"""
        if not isinstance(embedding, np.ndarray):
            return False, "Embedding must be a numpy array"
        
        # Check for NaN or infinite values
        if np.any(np.isnan(embedding)) or np.any(np.isinf(embedding)):
            return False, "Embedding contains NaN or infinite values"
        
        # Check embedding magnitude
        magnitude = np.linalg.norm(embedding)
        if magnitude > 100:  # Unusually large magnitude
            return False, f"Embedding magnitude too large: {magnitude}"
        
        # Check for adversarial noise patterns
        if self._detect_adversarial_noise(embedding):
            return False, "Adversarial noise pattern detected"
        
        return True, ""
    
    def _validate_code_input(self, code: str) -> Tuple[bool, str]:
        """Validate code input for malicious patterns"""
        if not isinstance(code, str):
            return False, "Code input must be a string"
        
        # Check for dangerous code patterns
        dangerous_patterns = [
            r'import\s+os',
            r'import\s+sys',
            r'import\s+subprocess',
            r'__import__\s*\(',
            r'eval\s*\(',
            r'exec\s*\(',
            r'open\s*\(',
            r'file\s*\(',
            r'input\s*\(',
            r'raw_input\s*\(',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return False, f"Dangerous code pattern detected: {pattern}"
        
        return True, ""
    
    def _detect_excessive_repetition(self, text: str) -> bool:
        """Detect excessive character repetition"""
        if len(text) < 10:
            return False
        
        # Check for repeated characters
        for i in range(len(text) - 5):
            char = text[i]
            count = 1
            for j in range(i + 1, min(i + 20, len(text))):
                if text[j] == char:
                    count += 1
                else:
                    break
            
            if count > 10:  # More than 10 consecutive identical characters
                return True
        
        return False
    
    def _detect_unusual_distribution(self, text: str) -> bool:
        """Detect unusual character distribution"""
        if len(text) < 50:
            return False
        
        # Calculate character frequency
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Check for highly skewed distribution
        total_chars = len(text)
        for char, count in char_counts.items():
            frequency = count / total_chars
            if frequency > 0.5:  # Single character makes up >50% of text
                return True
        
        return False
    
    def _detect_adversarial_noise(self, embedding: np.ndarray) -> bool:
        """Detect adversarial noise in embeddings"""
        # Check for unusual variance patterns
        variance = np.var(embedding)
        if variance > 10:  # Unusually high variance
            return True
        
        # Check for periodic patterns (potential adversarial)
        if len(embedding) > 10:
            # Simple autocorrelation check
            autocorr = np.correlate(embedding, embedding, mode='full')
            max_autocorr = np.max(autocorr[len(autocorr)//2 + 1:])
            if max_autocorr > 0.9 * np.max(autocorr):
                return True
        
        return False

class AIExplanationAuditor:
    """Audits AI/ML predictions and explanations"""
    
    def __init__(self, audit_file: str = "logs/ai_audit.log"):
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(exist_ok=True)
        
        # Confidence thresholds
        self.low_confidence_threshold = 0.3
        self.high_confidence_threshold = 0.8
    
    def audit_prediction(self, model_name: str, input_data: Any, 
                        prediction: Any, confidence: float,
                        explanation: Dict[str, Any] = None,
                        user_id: str = None) -> str:
        """
        Audit ML prediction with explanation
        Returns: audit_id
        """
        audit_id = self._generate_audit_id(model_name, input_data)
        
        audit_record = {
            'audit_id': audit_id,
            'timestamp': datetime.now().isoformat(),
            'model_name': model_name,
            'user_id': user_id,
            'input_hash': self._hash_input(input_data),
            'prediction': self._serialize_prediction(prediction),
            'confidence': confidence,
            'explanation': explanation or {},
            'risk_level': self._assess_risk_level(confidence, explanation),
            'flags': self._generate_flags(confidence, explanation)
        }
        
        # Log audit record
        self._log_audit_record(audit_record)
        
        # Check for anomalies
        self._check_prediction_anomalies(audit_record)
        
        return audit_id
    
    def audit_model_performance(self, model_name: str, 
                              performance_metrics: Dict[str, float],
                              test_data_hash: str = None):
        """Audit model performance metrics"""
        audit_record = {
            'audit_id': f"perf_{model_name}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'audit_type': 'performance',
            'model_name': model_name,
            'metrics': performance_metrics,
            'test_data_hash': test_data_hash,
            'anomalies': self._detect_performance_anomalies(performance_metrics)
        }
        
        self._log_audit_record(audit_record)
    
    def get_audit_summary(self, model_name: str = None, 
                         start_date: str = None, 
                         end_date: str = None) -> Dict[str, Any]:
        """Get audit summary for analysis"""
        # This would typically query a database
        # For now, return a basic summary structure
        return {
            'total_predictions': 0,
            'confidence_distribution': {},
            'risk_level_counts': {},
            'common_flags': [],
            'model_performance_trends': {}
        }
    
    def _generate_audit_id(self, model_name: str, input_data: Any) -> str:
        """Generate unique audit ID"""
        timestamp = str(int(datetime.now().timestamp()))
        input_hash = self._hash_input(input_data)[:8]
        return f"{model_name}_{timestamp}_{input_hash}"
    
    def _hash_input(self, input_data: Any) -> str:
        """Create hash of input data"""
        if isinstance(input_data, str):
            data_str = input_data
        elif isinstance(input_data, np.ndarray):
            data_str = str(input_data.tolist())
        else:
            data_str = str(input_data)
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _serialize_prediction(self, prediction: Any) -> Any:
        """Serialize prediction for logging"""
        if isinstance(prediction, np.ndarray):
            return prediction.tolist()
        elif hasattr(prediction, '__dict__'):
            return str(prediction)
        else:
            return prediction
    
    def _assess_risk_level(self, confidence: float, explanation: Dict[str, Any]) -> str:
        """Assess risk level of prediction"""
        if confidence < self.low_confidence_threshold:
            return 'HIGH'
        elif confidence > self.high_confidence_threshold:
            return 'LOW'
        else:
            return 'MEDIUM'
    
    def _generate_flags(self, confidence: float, explanation: Dict[str, Any]) -> List[str]:
        """Generate flags for prediction"""
        flags = []
        
        if confidence < self.low_confidence_threshold:
            flags.append('LOW_CONFIDENCE')
        
        if explanation:
            # Check for missing explanations
            if not explanation.get('reasoning'):
                flags.append('MISSING_REASONING')
            
            # Check for unusual patterns
            if explanation.get('pattern_count', 0) > 100:
                flags.append('HIGH_PATTERN_COUNT')
        
        return flags
    
    def _check_prediction_anomalies(self, audit_record: Dict[str, Any]):
        """Check for prediction anomalies"""
        # This would typically compare against historical data
        # For now, just log high-risk predictions
        if audit_record['risk_level'] == 'HIGH':
            logger.warning(f"High-risk prediction detected: {audit_record['audit_id']}")
    
    def _detect_performance_anomalies(self, metrics: Dict[str, float]) -> List[str]:
        """Detect performance anomalies"""
        anomalies = []
        
        # Check for unusual accuracy
        accuracy = metrics.get('accuracy', 0)
        if accuracy < 0.5:
            anomalies.append('LOW_ACCURACY')
        elif accuracy > 0.99:
            anomalies.append('SUSPICIOUSLY_HIGH_ACCURACY')
        
        # Check for unusual precision/recall
        precision = metrics.get('precision', 0)
        recall = metrics.get('recall', 0)
        
        if precision > 0 and recall > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
            if f1_score < 0.3:
                anomalies.append('LOW_F1_SCORE')
        
        return anomalies
    
    def _log_audit_record(self, record: Dict[str, Any]):
        """Log audit record to file"""
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(record) + '\n')

# Global instances
adversarial_detector = AdversarialInputDetector()
ai_auditor = AIExplanationAuditor()
