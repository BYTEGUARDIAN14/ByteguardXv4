"""
AI/ML Audit System with Explainability
Stores and audits all AI/ML predictions with detailed explanations
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from enum import Enum

from .audit_logger import audit_logger, SecurityEventType, EventSeverity

logger = logging.getLogger(__name__)

class PredictionType(Enum):
    """Types of AI/ML predictions"""
    VULNERABILITY_DETECTION = "vulnerability_detection"
    MALWARE_CLASSIFICATION = "malware_classification"
    ANOMALY_DETECTION = "anomaly_detection"
    RISK_ASSESSMENT = "risk_assessment"
    PATTERN_MATCHING = "pattern_matching"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"

class ConfidenceLevel(Enum):
    """Confidence levels for predictions"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class AIExplanation:
    """Detailed explanation of AI prediction"""
    prediction_id: str
    model_name: str
    model_version: str
    prediction_type: PredictionType
    input_hash: str
    prediction: Any
    confidence_score: float
    confidence_level: ConfidenceLevel
    explanation: Dict[str, Any]
    feature_importance: Dict[str, float]
    decision_path: List[str]
    fallback_used: bool
    processing_time_ms: float
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    model_name: str
    model_version: str
    total_predictions: int
    accuracy_score: float
    precision_score: float
    recall_score: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    average_confidence: float
    average_processing_time_ms: float
    last_updated: datetime

class AIAuditSystem:
    """Comprehensive AI/ML audit and explainability system"""
    
    def __init__(self, audit_dir: str = "data/ai_audit"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        
        # Storage files
        self.predictions_file = self.audit_dir / "predictions.jsonl"
        self.metrics_file = self.audit_dir / "model_metrics.json"
        self.explanations_file = self.audit_dir / "explanations.jsonl"
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Model registry
        self.registered_models = {}
        
        # Performance tracking
        self.model_metrics = self._load_model_metrics()
        
        logger.info("AI Audit System initialized")
    
    def register_model(self, model_name: str, model_version: str, 
                      model_type: str, description: str):
        """Register an AI/ML model for auditing"""
        with self.lock:
            self.registered_models[model_name] = {
                'name': model_name,
                'version': model_version,
                'type': model_type,
                'description': description,
                'registered_at': datetime.now(timezone.utc).isoformat(),
                'prediction_count': 0
            }
            
            logger.info(f"Registered model: {model_name} v{model_version}")
    
    def log_prediction(self, model_name: str, model_version: str,
                      prediction_type: PredictionType, input_data: Any,
                      prediction: Any, confidence_score: float,
                      explanation: Dict[str, Any], feature_importance: Dict[str, float],
                      decision_path: List[str], fallback_used: bool = False,
                      processing_time_ms: float = 0.0,
                      user_id: Optional[str] = None,
                      session_id: Optional[str] = None) -> str:
        """Log an AI/ML prediction with full explanation"""
        
        prediction_id = self._generate_prediction_id(model_name, input_data)
        
        # Calculate input hash for deduplication and tracking
        input_hash = self._calculate_input_hash(input_data)
        
        # Determine confidence level
        confidence_level = self._determine_confidence_level(confidence_score)
        
        # Create explanation record
        ai_explanation = AIExplanation(
            prediction_id=prediction_id,
            model_name=model_name,
            model_version=model_version,
            prediction_type=prediction_type,
            input_hash=input_hash,
            prediction=prediction,
            confidence_score=confidence_score,
            confidence_level=confidence_level,
            explanation=explanation,
            feature_importance=feature_importance,
            decision_path=decision_path,
            fallback_used=fallback_used,
            processing_time_ms=processing_time_ms,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id
        )
        
        # Store explanation
        self._store_explanation(ai_explanation)
        
        # Update model metrics
        self._update_model_metrics(model_name, confidence_score, processing_time_ms)
        
        # Log security event for high-risk predictions
        if confidence_score > 0.8 and prediction_type in [
            PredictionType.VULNERABILITY_DETECTION,
            PredictionType.MALWARE_CLASSIFICATION,
            PredictionType.ANOMALY_DETECTION
        ]:
            audit_logger.log_event_simple(
                event_type=SecurityEventType.AI_PREDICTION,
                severity=EventSeverity.MEDIUM,
                user_id=user_id,
                details={
                    'prediction_id': prediction_id,
                    'model_name': model_name,
                    'prediction_type': prediction_type.value,
                    'confidence_score': confidence_score,
                    'fallback_used': fallback_used,
                    'high_confidence': True
                }
            )
        
        logger.info(f"Logged AI prediction: {prediction_id} ({model_name})")
        return prediction_id
    
    def get_prediction_explanation(self, prediction_id: str) -> Optional[AIExplanation]:
        """Get detailed explanation for a prediction"""
        try:
            with open(self.explanations_file, 'r') as f:
                for line in f:
                    explanation_data = json.loads(line)
                    if explanation_data['prediction_id'] == prediction_id:
                        return AIExplanation(**explanation_data)
            return None
        except Exception as e:
            logger.error(f"Error retrieving prediction explanation: {e}")
            return None
    
    def get_model_explanations(self, model_name: str, limit: int = 100) -> List[AIExplanation]:
        """Get recent explanations for a specific model"""
        explanations = []
        try:
            with open(self.explanations_file, 'r') as f:
                for line in f:
                    explanation_data = json.loads(line)
                    if explanation_data['model_name'] == model_name:
                        explanations.append(AIExplanation(**explanation_data))
                        if len(explanations) >= limit:
                            break
            return explanations
        except Exception as e:
            logger.error(f"Error retrieving model explanations: {e}")
            return []
    
    def analyze_model_performance(self, model_name: str) -> Dict[str, Any]:
        """Analyze model performance and bias"""
        explanations = self.get_model_explanations(model_name, limit=1000)
        
        if not explanations:
            return {'error': 'No predictions found for model'}
        
        # Performance analysis
        confidence_scores = [exp.confidence_score for exp in explanations]
        processing_times = [exp.processing_time_ms for exp in explanations]
        fallback_usage = sum(1 for exp in explanations if exp.fallback_used)
        
        # Confidence distribution
        confidence_distribution = {
            'very_low': sum(1 for score in confidence_scores if score < 0.2),
            'low': sum(1 for score in confidence_scores if 0.2 <= score < 0.4),
            'medium': sum(1 for score in confidence_scores if 0.4 <= score < 0.6),
            'high': sum(1 for score in confidence_scores if 0.6 <= score < 0.8),
            'very_high': sum(1 for score in confidence_scores if score >= 0.8)
        }
        
        # Feature importance analysis
        all_features = {}
        for exp in explanations:
            for feature, importance in exp.feature_importance.items():
                if feature not in all_features:
                    all_features[feature] = []
                all_features[feature].append(importance)
        
        avg_feature_importance = {
            feature: sum(values) / len(values)
            for feature, values in all_features.items()
        }
        
        return {
            'model_name': model_name,
            'total_predictions': len(explanations),
            'average_confidence': sum(confidence_scores) / len(confidence_scores),
            'average_processing_time_ms': sum(processing_times) / len(processing_times),
            'fallback_usage_rate': fallback_usage / len(explanations),
            'confidence_distribution': confidence_distribution,
            'top_features': dict(sorted(avg_feature_importance.items(), 
                                      key=lambda x: x[1], reverse=True)[:10]),
            'performance_trends': self._analyze_performance_trends(explanations)
        }
    
    def detect_model_drift(self, model_name: str, window_size: int = 100) -> Dict[str, Any]:
        """Detect model drift and performance degradation"""
        explanations = self.get_model_explanations(model_name, limit=window_size * 2)
        
        if len(explanations) < window_size * 2:
            return {'error': 'Insufficient data for drift detection'}
        
        # Split into recent and historical windows
        recent_explanations = explanations[:window_size]
        historical_explanations = explanations[window_size:window_size * 2]
        
        # Compare confidence distributions
        recent_confidence = [exp.confidence_score for exp in recent_explanations]
        historical_confidence = [exp.confidence_score for exp in historical_explanations]
        
        recent_avg = sum(recent_confidence) / len(recent_confidence)
        historical_avg = sum(historical_confidence) / len(historical_confidence)
        
        confidence_drift = abs(recent_avg - historical_avg)
        
        # Compare processing times
        recent_times = [exp.processing_time_ms for exp in recent_explanations]
        historical_times = [exp.processing_time_ms for exp in historical_explanations]
        
        recent_time_avg = sum(recent_times) / len(recent_times)
        historical_time_avg = sum(historical_times) / len(historical_times)
        
        performance_drift = abs(recent_time_avg - historical_time_avg) / historical_time_avg
        
        # Fallback usage comparison
        recent_fallback_rate = sum(1 for exp in recent_explanations if exp.fallback_used) / len(recent_explanations)
        historical_fallback_rate = sum(1 for exp in historical_explanations if exp.fallback_used) / len(historical_explanations)
        
        fallback_drift = abs(recent_fallback_rate - historical_fallback_rate)
        
        # Determine drift severity
        drift_severity = 'low'
        if confidence_drift > 0.1 or performance_drift > 0.2 or fallback_drift > 0.1:
            drift_severity = 'medium'
        if confidence_drift > 0.2 or performance_drift > 0.5 or fallback_drift > 0.2:
            drift_severity = 'high'
        
        return {
            'model_name': model_name,
            'drift_severity': drift_severity,
            'confidence_drift': confidence_drift,
            'performance_drift': performance_drift,
            'fallback_drift': fallback_drift,
            'recent_avg_confidence': recent_avg,
            'historical_avg_confidence': historical_avg,
            'recommendations': self._generate_drift_recommendations(drift_severity, confidence_drift, performance_drift, fallback_drift)
        }
    
    def _generate_prediction_id(self, model_name: str, input_data: Any) -> str:
        """Generate unique prediction ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        data_str = json.dumps(input_data, sort_keys=True, default=str)
        combined = f"{model_name}:{timestamp}:{data_str}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def _calculate_input_hash(self, input_data: Any) -> str:
        """Calculate hash of input data"""
        data_str = json.dumps(input_data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _determine_confidence_level(self, confidence_score: float) -> ConfidenceLevel:
        """Determine confidence level from score"""
        if confidence_score < 0.2:
            return ConfidenceLevel.VERY_LOW
        elif confidence_score < 0.4:
            return ConfidenceLevel.LOW
        elif confidence_score < 0.6:
            return ConfidenceLevel.MEDIUM
        elif confidence_score < 0.8:
            return ConfidenceLevel.HIGH
        else:
            return ConfidenceLevel.VERY_HIGH
    
    def _store_explanation(self, explanation: AIExplanation):
        """Store explanation to file"""
        with self.lock:
            try:
                with open(self.explanations_file, 'a') as f:
                    explanation_dict = asdict(explanation)
                    explanation_dict['timestamp'] = explanation.timestamp.isoformat()
                    explanation_dict['prediction_type'] = explanation.prediction_type.value
                    explanation_dict['confidence_level'] = explanation.confidence_level.value
                    f.write(json.dumps(explanation_dict) + '\n')
            except Exception as e:
                logger.error(f"Error storing explanation: {e}")
    
    def _update_model_metrics(self, model_name: str, confidence_score: float, processing_time_ms: float):
        """Update model performance metrics"""
        with self.lock:
            if model_name not in self.model_metrics:
                self.model_metrics[model_name] = {
                    'total_predictions': 0,
                    'total_confidence': 0.0,
                    'total_processing_time': 0.0
                }
            
            metrics = self.model_metrics[model_name]
            metrics['total_predictions'] += 1
            metrics['total_confidence'] += confidence_score
            metrics['total_processing_time'] += processing_time_ms
            
            # Update registered model count
            if model_name in self.registered_models:
                self.registered_models[model_name]['prediction_count'] = metrics['total_predictions']
            
            # Save metrics periodically
            if metrics['total_predictions'] % 100 == 0:
                self._save_model_metrics()
    
    def _load_model_metrics(self) -> Dict[str, Any]:
        """Load model metrics from file"""
        try:
            if self.metrics_file.exists():
                with open(self.metrics_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading model metrics: {e}")
            return {}
    
    def _save_model_metrics(self):
        """Save model metrics to file"""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(self.model_metrics, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving model metrics: {e}")
    
    def _analyze_performance_trends(self, explanations: List[AIExplanation]) -> Dict[str, Any]:
        """Analyze performance trends over time"""
        if len(explanations) < 10:
            return {'error': 'Insufficient data for trend analysis'}
        
        # Sort by timestamp
        sorted_explanations = sorted(explanations, key=lambda x: x.timestamp)
        
        # Calculate moving averages
        window_size = min(10, len(sorted_explanations) // 4)
        confidence_trend = []
        time_trend = []
        
        for i in range(window_size, len(sorted_explanations)):
            window = sorted_explanations[i-window_size:i]
            avg_confidence = sum(exp.confidence_score for exp in window) / len(window)
            avg_time = sum(exp.processing_time_ms for exp in window) / len(window)
            
            confidence_trend.append(avg_confidence)
            time_trend.append(avg_time)
        
        return {
            'confidence_trend': confidence_trend[-20:],  # Last 20 points
            'processing_time_trend': time_trend[-20:],
            'trend_direction': self._calculate_trend_direction(confidence_trend)
        }
    
    def _calculate_trend_direction(self, values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return 'stable'
        
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]
        
        first_avg = sum(first_half) / len(first_half)
        second_avg = sum(second_half) / len(second_half)
        
        diff = second_avg - first_avg
        
        if abs(diff) < 0.05:
            return 'stable'
        elif diff > 0:
            return 'improving'
        else:
            return 'declining'
    
    def _generate_drift_recommendations(self, severity: str, confidence_drift: float, 
                                      performance_drift: float, fallback_drift: float) -> List[str]:
        """Generate recommendations based on drift analysis"""
        recommendations = []
        
        if severity == 'high':
            recommendations.append("URGENT: Model requires immediate attention")
            recommendations.append("Consider retraining the model with recent data")
        
        if confidence_drift > 0.15:
            recommendations.append("Confidence scores have significantly changed - review model calibration")
        
        if performance_drift > 0.3:
            recommendations.append("Processing time has increased significantly - optimize model performance")
        
        if fallback_drift > 0.15:
            recommendations.append("Fallback usage has increased - investigate model reliability")
        
        if not recommendations:
            recommendations.append("Model performance is stable")
        
        return recommendations

# Global AI audit system instance
ai_audit_system = AIAuditSystem()
