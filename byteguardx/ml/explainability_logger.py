"""
ML Explainability Logger for ByteGuardX
Stores model predictions with explanations, confidence scores, and audit trails
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from ..database.connection_pool import db_manager
from ..database.models import MLPredictionLog, MLModelVersion

logger = logging.getLogger(__name__)

class ExplanationType(Enum):
    """Types of ML explanations"""
    FEATURE_IMPORTANCE = "feature_importance"
    ATTENTION_WEIGHTS = "attention_weights"
    GRADIENT_BASED = "gradient_based"
    RULE_BASED = "rule_based"
    SIMILARITY_BASED = "similarity_based"
    COUNTERFACTUAL = "counterfactual"

class PredictionOutcome(Enum):
    """Prediction outcomes"""
    VULNERABILITY_DETECTED = "vulnerability_detected"
    NO_VULNERABILITY = "no_vulnerability"
    UNCERTAIN = "uncertain"
    ERROR = "error"

@dataclass
class FeatureImportance:
    """Feature importance information"""
    feature_name: str
    importance_score: float
    feature_value: Any
    contribution: float  # Positive or negative contribution to prediction

@dataclass
class MLExplanation:
    """ML model explanation"""
    explanation_type: ExplanationType
    confidence_score: float
    feature_importances: List[FeatureImportance]
    reasoning_text: str
    supporting_evidence: List[str]
    uncertainty_factors: List[str]
    alternative_predictions: List[Dict[str, Any]]

@dataclass
class MLPredictionRecord:
    """Complete ML prediction record"""
    prediction_id: str
    model_name: str
    model_version: str
    input_hash: str
    input_snippet: str  # First 500 chars for reference
    prediction_outcome: PredictionOutcome
    confidence_score: float
    explanation: MLExplanation
    processing_time_ms: float
    timestamp: datetime
    metadata: Dict[str, Any]

class ExplainabilityLogger:
    """Logger for ML model explainability and audit trails"""
    
    def __init__(self):
        self.max_input_snippet_length = 500
        self.retention_days = 90
        self.enable_detailed_logging = os.environ.get('ML_DETAILED_LOGGING', 'true').lower() == 'true'
        
    def log_prediction(self, model_name: str, model_version: str, 
                      input_data: Any, prediction: Dict[str, Any],
                      explanation: MLExplanation, processing_time_ms: float,
                      metadata: Dict[str, Any] = None) -> str:
        """
        Log ML prediction with explanation
        
        Args:
            model_name: Name of the ML model
            model_version: Version of the model
            input_data: Input data for prediction
            prediction: Model prediction results
            explanation: Model explanation
            processing_time_ms: Processing time in milliseconds
            metadata: Additional metadata
            
        Returns:
            Prediction ID for tracking
        """
        try:
            # Generate prediction ID
            prediction_id = self._generate_prediction_id(model_name, input_data)
            
            # Create input hash and snippet
            input_str = str(input_data)
            input_hash = hashlib.sha256(input_str.encode()).hexdigest()
            input_snippet = input_str[:self.max_input_snippet_length]
            
            # Determine prediction outcome
            outcome = self._determine_outcome(prediction)
            
            # Create prediction record
            record = MLPredictionRecord(
                prediction_id=prediction_id,
                model_name=model_name,
                model_version=model_version,
                input_hash=input_hash,
                input_snippet=input_snippet,
                prediction_outcome=outcome,
                confidence_score=prediction.get('confidence', 0.0),
                explanation=explanation,
                processing_time_ms=processing_time_ms,
                timestamp=datetime.now(),
                metadata=metadata or {}
            )
            
            # Store in database
            self._store_prediction_record(record)
            
            # Log for audit trail
            if self.enable_detailed_logging:
                self._log_detailed_prediction(record)
            
            logger.info(f"Logged ML prediction {prediction_id} for model {model_name}")
            return prediction_id
            
        except Exception as e:
            logger.error(f"Failed to log ML prediction: {e}")
            return ""
    
    def get_prediction_explanation(self, prediction_id: str) -> Optional[MLPredictionRecord]:
        """
        Get prediction explanation by ID
        
        Args:
            prediction_id: Prediction ID
            
        Returns:
            MLPredictionRecord if found, None otherwise
        """
        try:
            with db_manager.get_session() as session:
                log_entry = session.query(MLPredictionLog).filter(
                    MLPredictionLog.prediction_id == prediction_id
                ).first()
                
                if not log_entry:
                    return None
                
                # Reconstruct explanation
                explanation_data = json.loads(log_entry.explanation_data)
                explanation = self._deserialize_explanation(explanation_data)
                
                return MLPredictionRecord(
                    prediction_id=log_entry.prediction_id,
                    model_name=log_entry.model_name,
                    model_version=log_entry.model_version,
                    input_hash=log_entry.input_hash,
                    input_snippet=log_entry.input_snippet,
                    prediction_outcome=PredictionOutcome(log_entry.prediction_outcome),
                    confidence_score=log_entry.confidence_score,
                    explanation=explanation,
                    processing_time_ms=log_entry.processing_time_ms,
                    timestamp=log_entry.timestamp,
                    metadata=json.loads(log_entry.metadata or '{}')
                )
                
        except Exception as e:
            logger.error(f"Failed to get prediction explanation: {e}")
            return None
    
    def get_model_performance_metrics(self, model_name: str, 
                                    days: int = 7) -> Dict[str, Any]:
        """
        Get model performance metrics
        
        Args:
            model_name: Name of the model
            days: Number of days to analyze
            
        Returns:
            Dict containing performance metrics
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            with db_manager.get_session() as session:
                predictions = session.query(MLPredictionLog).filter(
                    MLPredictionLog.model_name == model_name,
                    MLPredictionLog.timestamp >= cutoff_date
                ).all()
                
                if not predictions:
                    return {"error": "No predictions found"}
                
                # Calculate metrics
                total_predictions = len(predictions)
                avg_confidence = sum(p.confidence_score for p in predictions) / total_predictions
                avg_processing_time = sum(p.processing_time_ms for p in predictions) / total_predictions
                
                # Outcome distribution
                outcome_counts = {}
                for prediction in predictions:
                    outcome = prediction.prediction_outcome
                    outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
                
                # Confidence distribution
                high_confidence = sum(1 for p in predictions if p.confidence_score > 0.8)
                medium_confidence = sum(1 for p in predictions if 0.5 <= p.confidence_score <= 0.8)
                low_confidence = sum(1 for p in predictions if p.confidence_score < 0.5)
                
                return {
                    "model_name": model_name,
                    "analysis_period_days": days,
                    "total_predictions": total_predictions,
                    "average_confidence": avg_confidence,
                    "average_processing_time_ms": avg_processing_time,
                    "outcome_distribution": outcome_counts,
                    "confidence_distribution": {
                        "high_confidence": high_confidence,
                        "medium_confidence": medium_confidence,
                        "low_confidence": low_confidence
                    },
                    "performance_trends": self._calculate_performance_trends(predictions)
                }
                
        except Exception as e:
            logger.error(f"Failed to get model performance metrics: {e}")
            return {"error": str(e)}
    
    def generate_explanation_report(self, model_name: str, 
                                  prediction_ids: List[str] = None) -> Dict[str, Any]:
        """
        Generate explanation report for model predictions
        
        Args:
            model_name: Name of the model
            prediction_ids: Optional list of specific prediction IDs
            
        Returns:
            Dict containing explanation report
        """
        try:
            with db_manager.get_session() as session:
                query = session.query(MLPredictionLog).filter(
                    MLPredictionLog.model_name == model_name
                )
                
                if prediction_ids:
                    query = query.filter(MLPredictionLog.prediction_id.in_(prediction_ids))
                
                predictions = query.limit(100).all()  # Limit for performance
                
                if not predictions:
                    return {"error": "No predictions found"}
                
                # Analyze explanations
                explanation_analysis = self._analyze_explanations(predictions)
                
                # Generate insights
                insights = self._generate_explanation_insights(explanation_analysis)
                
                return {
                    "model_name": model_name,
                    "total_predictions_analyzed": len(predictions),
                    "explanation_analysis": explanation_analysis,
                    "insights": insights,
                    "generated_at": datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to generate explanation report: {e}")
            return {"error": str(e)}
    
    def cleanup_old_predictions(self) -> int:
        """
        Clean up old prediction logs
        
        Returns:
            Number of records cleaned up
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            with db_manager.get_session() as session:
                deleted_count = session.query(MLPredictionLog).filter(
                    MLPredictionLog.timestamp < cutoff_date
                ).delete()
                
                session.commit()
                
                logger.info(f"Cleaned up {deleted_count} old ML prediction logs")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old predictions: {e}")
            return 0
    
    def _generate_prediction_id(self, model_name: str, input_data: Any) -> str:
        """Generate unique prediction ID"""
        timestamp = datetime.now().isoformat()
        data_str = f"{model_name}:{timestamp}:{str(input_data)}"
        return hashlib.md5(data_str.encode()).hexdigest()
    
    def _determine_outcome(self, prediction: Dict[str, Any]) -> PredictionOutcome:
        """Determine prediction outcome from prediction results"""
        if 'error' in prediction:
            return PredictionOutcome.ERROR
        
        confidence = prediction.get('confidence', 0.0)
        has_vulnerability = prediction.get('has_vulnerability', False)
        
        if confidence < 0.5:
            return PredictionOutcome.UNCERTAIN
        elif has_vulnerability:
            return PredictionOutcome.VULNERABILITY_DETECTED
        else:
            return PredictionOutcome.NO_VULNERABILITY
    
    def _store_prediction_record(self, record: MLPredictionRecord):
        """Store prediction record in database"""
        with db_manager.get_session() as session:
            log_entry = MLPredictionLog(
                prediction_id=record.prediction_id,
                model_name=record.model_name,
                model_version=record.model_version,
                input_hash=record.input_hash,
                input_snippet=record.input_snippet,
                prediction_outcome=record.prediction_outcome.value,
                confidence_score=record.confidence_score,
                explanation_data=json.dumps(asdict(record.explanation)),
                processing_time_ms=record.processing_time_ms,
                timestamp=record.timestamp,
                metadata=json.dumps(record.metadata)
            )
            
            session.add(log_entry)
            session.commit()
    
    def _serialize_explanation(self, explanation: MLExplanation) -> Dict[str, Any]:
        """Serialize explanation for storage"""
        return asdict(explanation)
    
    def _deserialize_explanation(self, data: Dict[str, Any]) -> MLExplanation:
        """Deserialize explanation from storage"""
        # Convert feature importances
        feature_importances = [
            FeatureImportance(**fi) for fi in data.get('feature_importances', [])
        ]
        
        return MLExplanation(
            explanation_type=ExplanationType(data['explanation_type']),
            confidence_score=data['confidence_score'],
            feature_importances=feature_importances,
            reasoning_text=data['reasoning_text'],
            supporting_evidence=data['supporting_evidence'],
            uncertainty_factors=data['uncertainty_factors'],
            alternative_predictions=data['alternative_predictions']
        )
    
    def _log_detailed_prediction(self, record: MLPredictionRecord):
        """Log detailed prediction for audit"""
        logger.info(f"ML Prediction Details - ID: {record.prediction_id}, "
                   f"Model: {record.model_name}@{record.model_version}, "
                   f"Outcome: {record.prediction_outcome.value}, "
                   f"Confidence: {record.confidence_score:.3f}, "
                   f"Processing: {record.processing_time_ms:.1f}ms")
    
    def _calculate_performance_trends(self, predictions: List) -> Dict[str, Any]:
        """Calculate performance trends from predictions"""
        # Simple trend analysis
        if len(predictions) < 2:
            return {"trend": "insufficient_data"}
        
        # Sort by timestamp
        sorted_predictions = sorted(predictions, key=lambda p: p.timestamp)
        
        # Calculate confidence trend
        first_half = sorted_predictions[:len(sorted_predictions)//2]
        second_half = sorted_predictions[len(sorted_predictions)//2:]
        
        first_avg_confidence = sum(p.confidence_score for p in first_half) / len(first_half)
        second_avg_confidence = sum(p.confidence_score for p in second_half) / len(second_half)
        
        confidence_trend = "improving" if second_avg_confidence > first_avg_confidence else "declining"
        
        return {
            "confidence_trend": confidence_trend,
            "confidence_change": second_avg_confidence - first_avg_confidence
        }
    
    def _analyze_explanations(self, predictions: List) -> Dict[str, Any]:
        """Analyze explanations from predictions"""
        explanation_types = {}
        avg_confidence = 0
        feature_frequency = {}
        
        for prediction in predictions:
            explanation_data = json.loads(prediction.explanation_data)
            
            # Count explanation types
            exp_type = explanation_data.get('explanation_type', 'unknown')
            explanation_types[exp_type] = explanation_types.get(exp_type, 0) + 1
            
            # Track feature importance
            for fi in explanation_data.get('feature_importances', []):
                feature_name = fi.get('feature_name', 'unknown')
                feature_frequency[feature_name] = feature_frequency.get(feature_name, 0) + 1
            
            avg_confidence += explanation_data.get('confidence_score', 0)
        
        avg_confidence /= len(predictions)
        
        return {
            "explanation_types": explanation_types,
            "average_explanation_confidence": avg_confidence,
            "most_important_features": sorted(feature_frequency.items(), 
                                            key=lambda x: x[1], reverse=True)[:10]
        }
    
    def _generate_explanation_insights(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate insights from explanation analysis"""
        insights = []
        
        # Most common explanation type
        exp_types = analysis.get('explanation_types', {})
        if exp_types:
            most_common = max(exp_types.items(), key=lambda x: x[1])
            insights.append(f"Most common explanation type: {most_common[0]} ({most_common[1]} occurrences)")
        
        # Feature importance insights
        important_features = analysis.get('most_important_features', [])
        if important_features:
            top_feature = important_features[0]
            insights.append(f"Most influential feature: {top_feature[0]} (appeared in {top_feature[1]} predictions)")
        
        # Confidence insights
        avg_confidence = analysis.get('average_explanation_confidence', 0)
        if avg_confidence > 0.8:
            insights.append("Model explanations show high confidence overall")
        elif avg_confidence < 0.5:
            insights.append("Model explanations show low confidence - consider model retraining")
        
        return insights

# Global instance
explainability_logger = ExplainabilityLogger()
