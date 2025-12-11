"""
Ensemble Anomaly Detection System
Secondary ML model for detecting anomalies in plugin behavior, scan logs, and user metadata
"""

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class AnomalyType(Enum):
    """Types of anomalies detected"""
    PLUGIN_BEHAVIOR = "plugin_behavior"
    USER_ACTIVITY = "user_activity"
    SCAN_PATTERN = "scan_pattern"
    SYSTEM_PERFORMANCE = "system_performance"
    SECURITY_INCIDENT = "security_incident"

class AnomalySeverity(Enum):
    """Severity levels for anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AnomalyFeatures:
    """Feature set for anomaly detection"""
    timestamp: datetime
    user_id: str
    plugin_id: Optional[str] = None
    
    # User behavior features
    requests_per_hour: float = 0.0
    unique_endpoints: int = 0
    error_rate: float = 0.0
    session_duration: float = 0.0
    
    # Plugin behavior features
    plugin_execution_time: float = 0.0
    plugin_memory_usage: float = 0.0
    plugin_api_calls: int = 0
    plugin_error_count: int = 0
    
    # Scan pattern features
    scan_frequency: float = 0.0
    scan_size_mb: float = 0.0
    scan_duration: float = 0.0
    vulnerabilities_found: int = 0
    
    # System performance features
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_io: float = 0.0
    network_io: float = 0.0
    
    # Security features
    failed_auth_attempts: int = 0
    suspicious_patterns: int = 0
    geo_location_changes: int = 0

@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    detection_id: str
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence_score: float
    description: str
    features: AnomalyFeatures
    detected_at: datetime
    recommendations: List[str] = field(default_factory=list)
    additional_context: Dict[str, Any] = field(default_factory=dict)

class EnsembleAnomalyDetector:
    """
    Ensemble-based anomaly detection system using multiple ML models
    """
    
    def __init__(self, model_path: str = None):
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_columns = []
        self.is_trained = False
        self.model_path = model_path
        
        # Anomaly thresholds
        self.thresholds = {
            AnomalyType.PLUGIN_BEHAVIOR: {
                'isolation_forest': -0.1,
                'random_forest': 0.7
            },
            AnomalyType.USER_ACTIVITY: {
                'isolation_forest': -0.05,
                'random_forest': 0.8
            },
            AnomalyType.SCAN_PATTERN: {
                'isolation_forest': -0.15,
                'random_forest': 0.6
            },
            AnomalyType.SYSTEM_PERFORMANCE: {
                'isolation_forest': -0.2,
                'random_forest': 0.5
            },
            AnomalyType.SECURITY_INCIDENT: {
                'isolation_forest': -0.05,
                'random_forest': 0.9
            }
        }
        
        # Initialize models
        self._initialize_models()
        
        # Load pre-trained models if available
        if model_path:
            self._load_models()
    
    def _initialize_models(self):
        """Initialize ensemble models for each anomaly type"""
        for anomaly_type in AnomalyType:
            self.models[anomaly_type] = {
                'isolation_forest': IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                ),
                'random_forest': RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    class_weight='balanced'
                )
            }
            self.scalers[anomaly_type] = StandardScaler()
            self.encoders[anomaly_type] = {}
    
    def prepare_features(self, features: AnomalyFeatures) -> pd.DataFrame:
        """Prepare features for model input"""
        feature_dict = {
            'hour_of_day': features.timestamp.hour,
            'day_of_week': features.timestamp.weekday(),
            'requests_per_hour': features.requests_per_hour,
            'unique_endpoints': features.unique_endpoints,
            'error_rate': features.error_rate,
            'session_duration': features.session_duration,
            'plugin_execution_time': features.plugin_execution_time,
            'plugin_memory_usage': features.plugin_memory_usage,
            'plugin_api_calls': features.plugin_api_calls,
            'plugin_error_count': features.plugin_error_count,
            'scan_frequency': features.scan_frequency,
            'scan_size_mb': features.scan_size_mb,
            'scan_duration': features.scan_duration,
            'vulnerabilities_found': features.vulnerabilities_found,
            'cpu_usage': features.cpu_usage,
            'memory_usage': features.memory_usage,
            'disk_io': features.disk_io,
            'network_io': features.network_io,
            'failed_auth_attempts': features.failed_auth_attempts,
            'suspicious_patterns': features.suspicious_patterns,
            'geo_location_changes': features.geo_location_changes
        }
        
        return pd.DataFrame([feature_dict])
    
    def train_models(self, training_data: List[Tuple[AnomalyFeatures, AnomalyType, bool]]):
        """Train ensemble models with labeled data"""
        logger.info("Starting ensemble anomaly detector training...")
        
        # Prepare training data by anomaly type
        for anomaly_type in AnomalyType:
            type_data = [
                (features, is_anomaly) for features, atype, is_anomaly in training_data
                if atype == anomaly_type
            ]
            
            if len(type_data) < 10:  # Need minimum samples
                logger.warning(f"Insufficient training data for {anomaly_type.value}")
                continue
            
            # Convert to DataFrame
            X_list = []
            y_list = []
            
            for features, is_anomaly in type_data:
                feature_df = self.prepare_features(features)
                X_list.append(feature_df.iloc[0])
                y_list.append(1 if is_anomaly else 0)
            
            X = pd.DataFrame(X_list)
            y = np.array(y_list)
            
            # Store feature columns
            if not self.feature_columns:
                self.feature_columns = X.columns.tolist()
            
            # Scale features
            X_scaled = self.scalers[anomaly_type].fit_transform(X)
            
            # Train Isolation Forest (unsupervised)
            self.models[anomaly_type]['isolation_forest'].fit(X_scaled)
            
            # Train Random Forest (supervised)
            if len(np.unique(y)) > 1:  # Need both classes
                X_train, X_test, y_train, y_test = train_test_split(
                    X_scaled, y, test_size=0.2, random_state=42, stratify=y
                )
                
                self.models[anomaly_type]['random_forest'].fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.models[anomaly_type]['random_forest'].predict(X_test)
                logger.info(f"Random Forest performance for {anomaly_type.value}:")
                logger.info(f"\n{classification_report(y_test, y_pred)}")
        
        self.is_trained = True
        logger.info("Ensemble anomaly detector training completed")
        
        # Save models
        if self.model_path:
            self._save_models()
    
    def detect_anomaly(self, features: AnomalyFeatures, 
                      anomaly_type: AnomalyType) -> Optional[AnomalyDetection]:
        """Detect anomaly using ensemble approach"""
        if not self.is_trained:
            logger.warning("Models not trained yet")
            return None
        
        try:
            # Prepare features
            feature_df = self.prepare_features(features)
            
            # Ensure all required columns are present
            for col in self.feature_columns:
                if col not in feature_df.columns:
                    feature_df[col] = 0.0
            
            feature_df = feature_df[self.feature_columns]
            
            # Scale features
            X_scaled = self.scalers[anomaly_type].transform(feature_df)
            
            # Get predictions from ensemble
            isolation_score = self.models[anomaly_type]['isolation_forest'].decision_function(X_scaled)[0]
            isolation_pred = self.models[anomaly_type]['isolation_forest'].predict(X_scaled)[0]
            
            rf_proba = self.models[anomaly_type]['random_forest'].predict_proba(X_scaled)[0]
            rf_anomaly_proba = rf_proba[1] if len(rf_proba) > 1 else 0.0
            
            # Ensemble decision
            thresholds = self.thresholds[anomaly_type]
            
            is_anomaly_isolation = isolation_score < thresholds['isolation_forest']
            is_anomaly_rf = rf_anomaly_proba > thresholds['random_forest']
            
            # Combine predictions (both models must agree for high confidence)
            if is_anomaly_isolation and is_anomaly_rf:
                confidence = (abs(isolation_score) + rf_anomaly_proba) / 2
                severity = self._determine_severity(confidence, anomaly_type)
            elif is_anomaly_isolation or is_anomaly_rf:
                confidence = max(abs(isolation_score), rf_anomaly_proba) * 0.7
                severity = AnomalySeverity.LOW
            else:
                return None  # No anomaly detected
            
            # Generate detection
            detection_id = f"anomaly_{int(datetime.now().timestamp())}_{anomaly_type.value}"
            
            description = self._generate_anomaly_description(
                anomaly_type, features, confidence, 
                isolation_score, rf_anomaly_proba
            )
            
            recommendations = self._generate_recommendations(anomaly_type, features, severity)
            
            detection = AnomalyDetection(
                detection_id=detection_id,
                anomaly_type=anomaly_type,
                severity=severity,
                confidence_score=confidence,
                description=description,
                features=features,
                detected_at=datetime.now(),
                recommendations=recommendations,
                additional_context={
                    'isolation_score': isolation_score,
                    'rf_probability': rf_anomaly_proba,
                    'ensemble_agreement': is_anomaly_isolation and is_anomaly_rf
                }
            )
            
            logger.info(f"Anomaly detected: {detection.description}")
            return detection
            
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return None
    
    def _determine_severity(self, confidence: float, anomaly_type: AnomalyType) -> AnomalySeverity:
        """Determine anomaly severity based on confidence and type"""
        if anomaly_type == AnomalyType.SECURITY_INCIDENT:
            if confidence > 0.9:
                return AnomalySeverity.CRITICAL
            elif confidence > 0.7:
                return AnomalySeverity.HIGH
            elif confidence > 0.5:
                return AnomalySeverity.MEDIUM
            else:
                return AnomalySeverity.LOW
        else:
            if confidence > 0.8:
                return AnomalySeverity.HIGH
            elif confidence > 0.6:
                return AnomalySeverity.MEDIUM
            else:
                return AnomalySeverity.LOW
    
    def _generate_anomaly_description(self, anomaly_type: AnomalyType, 
                                    features: AnomalyFeatures, confidence: float,
                                    isolation_score: float, rf_proba: float) -> str:
        """Generate human-readable anomaly description"""
        base_desc = f"{anomaly_type.value.replace('_', ' ').title()} anomaly detected"
        
        if anomaly_type == AnomalyType.PLUGIN_BEHAVIOR:
            return f"{base_desc}: Plugin execution time {features.plugin_execution_time:.1f}s exceeds normal patterns"
        elif anomaly_type == AnomalyType.USER_ACTIVITY:
            return f"{base_desc}: User activity pattern unusual with {features.requests_per_hour:.0f} requests/hour"
        elif anomaly_type == AnomalyType.SCAN_PATTERN:
            return f"{base_desc}: Scan pattern irregular with {features.scan_frequency:.1f} scans/hour"
        elif anomaly_type == AnomalyType.SYSTEM_PERFORMANCE:
            return f"{base_desc}: System performance anomaly with {features.cpu_usage:.1f}% CPU usage"
        elif anomaly_type == AnomalyType.SECURITY_INCIDENT:
            return f"{base_desc}: Security incident indicators with {features.failed_auth_attempts} failed auth attempts"
        else:
            return f"{base_desc} with confidence {confidence:.2f}"
    
    def _generate_recommendations(self, anomaly_type: AnomalyType, 
                                features: AnomalyFeatures, 
                                severity: AnomalySeverity) -> List[str]:
        """Generate recommendations based on anomaly type and severity"""
        recommendations = []
        
        if anomaly_type == AnomalyType.PLUGIN_BEHAVIOR:
            recommendations.extend([
                "Review plugin execution logs for errors or performance issues",
                "Consider plugin resource limits or optimization",
                "Monitor plugin behavior for continued anomalies"
            ])
        elif anomaly_type == AnomalyType.USER_ACTIVITY:
            recommendations.extend([
                "Investigate user account for potential compromise",
                "Review user access patterns and permissions",
                "Consider implementing additional authentication factors"
            ])
        elif anomaly_type == AnomalyType.SECURITY_INCIDENT:
            recommendations.extend([
                "Immediately investigate potential security breach",
                "Review authentication logs and access patterns",
                "Consider temporary account restrictions"
            ])
        
        if severity in [AnomalySeverity.HIGH, AnomalySeverity.CRITICAL]:
            recommendations.insert(0, "Immediate attention required - escalate to security team")
        
        return recommendations
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'encoders': self.encoders,
                'feature_columns': self.feature_columns,
                'thresholds': self.thresholds,
                'is_trained': self.is_trained
            }
            joblib.dump(model_data, self.model_path)
            logger.info(f"Models saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            model_data = joblib.load(self.model_path)
            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.encoders = model_data['encoders']
            self.feature_columns = model_data['feature_columns']
            self.thresholds = model_data['thresholds']
            self.is_trained = model_data['is_trained']
            logger.info(f"Models loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Failed to load models: {e}")

# Global instance
ensemble_anomaly_detector = EnsembleAnomalyDetector()
