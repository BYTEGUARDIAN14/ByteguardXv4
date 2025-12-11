#!/usr/bin/env python3
"""
AI-Powered Security Analytics for ByteGuardX
Implements machine learning for advanced threat detection and prediction
"""

import logging
import numpy as np
import json
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import hashlib
import statistics

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Security event for ML analysis"""
    event_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    user_id: Optional[str]
    features: Dict[str, float]
    is_malicious: Optional[bool]
    confidence: float
    risk_score: float

@dataclass
class ThreatPrediction:
    """AI threat prediction"""
    prediction_id: str
    predicted_threat_type: str
    probability: float
    confidence_interval: Tuple[float, float]
    contributing_factors: List[str]
    recommended_actions: List[str]
    prediction_time: datetime
    validity_period: timedelta

@dataclass
class AnomalyCluster:
    """Detected anomaly cluster"""
    cluster_id: str
    cluster_type: str
    events: List[SecurityEvent]
    centroid_features: Dict[str, float]
    anomaly_score: float
    detected_at: datetime
    affected_users: List[str]
    affected_ips: List[str]

class AISecurityAnalytics:
    """
    AI-powered security analytics engine
    """
    
    def __init__(self):
        if not SKLEARN_AVAILABLE:
            logger.warning("Scikit-learn not available - install sklearn for AI analytics")
            return
        
        # ML models
        self.anomaly_detector = None
        self.threat_classifier = None
        self.behavior_clusterer = None
        self.feature_scaler = StandardScaler()
        
        # Training data
        self.security_events: deque = deque(maxlen=10000)
        self.labeled_events: List[SecurityEvent] = []
        
        # Predictions and clusters
        self.threat_predictions: List[ThreatPrediction] = []
        self.anomaly_clusters: List[AnomalyCluster] = []
        
        # Feature extractors
        self.feature_extractors = {
            'temporal': self._extract_temporal_features,
            'behavioral': self._extract_behavioral_features,
            'network': self._extract_network_features,
            'statistical': self._extract_statistical_features
        }
        
        # Model configuration with versioning
        self.model_config = {
            'anomaly_contamination': 0.1,  # 10% expected anomalies
            'clustering_eps': 0.5,
            'clustering_min_samples': 5,
            'retrain_interval': timedelta(hours=24),
            'prediction_horizon': timedelta(hours=6)
        }

        # Model versioning and drift detection
        self.model_versions = {}
        self.current_model_version = '1.0.0'
        self.drift_detection_enabled = True
        self.drift_threshold = 0.1  # 10% drift threshold
        self.baseline_distributions = {}
        self.drift_alerts = []
        
        # Initialize models
        self._initialize_models()

        # Initialize baseline distributions for drift detection
        self._initialize_baseline_distributions()

        logger.info("AI Security Analytics engine initialized with model versioning")
    
    def _initialize_models(self):
        """Initialize ML models"""
        try:
            # Anomaly detection model
            self.anomaly_detector = IsolationForest(
                contamination=self.model_config['anomaly_contamination'],
                random_state=42,
                n_estimators=100
            )
            
            # Threat classification model
            self.threat_classifier = RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                class_weight='balanced'
            )
            
            # Behavioral clustering model
            self.behavior_clusterer = DBSCAN(
                eps=self.model_config['clustering_eps'],
                min_samples=self.model_config['clustering_min_samples']
            )
            
            # Store initial model version
            self._save_model_version('1.0.0', {
                'anomaly_detector': self.anomaly_detector,
                'threat_classifier': self.threat_classifier,
                'behavior_clusterer': self.behavior_clusterer,
                'feature_scaler': self.feature_scaler
            })

            logger.info("ML models initialized successfully with versioning")

        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")

    def _initialize_baseline_distributions(self):
        """Initialize baseline feature distributions for drift detection"""
        try:
            # Initialize empty baseline distributions
            self.baseline_distributions = {
                'temporal_features': {},
                'behavioral_features': {},
                'network_features': {},
                'statistical_features': {}
            }

            logger.info("Baseline distributions initialized for drift detection")

        except Exception as e:
            logger.error(f"Failed to initialize baseline distributions: {e}")

    def _save_model_version(self, version: str, models: Dict[str, Any]):
        """Save model version for rollback capability"""
        try:
            import pickle
            import os

            # Create models directory
            models_dir = os.path.join('data', 'models')
            os.makedirs(models_dir, exist_ok=True)

            # Save models
            version_data = {
                'version': version,
                'created_at': datetime.now(),
                'models': models,
                'config': self.model_config.copy()
            }

            version_file = os.path.join(models_dir, f'model_v{version}.pkl')
            with open(version_file, 'wb') as f:
                pickle.dump(version_data, f)

            self.model_versions[version] = {
                'file_path': version_file,
                'created_at': datetime.now(),
                'is_active': version == self.current_model_version
            }

            logger.info(f"Saved model version {version}")

        except Exception as e:
            logger.error(f"Failed to save model version {version}: {e}")

    def load_model_version(self, version: str) -> bool:
        """Load specific model version"""
        try:
            if version not in self.model_versions:
                logger.error(f"Model version {version} not found")
                return False

            import pickle

            version_file = self.model_versions[version]['file_path']
            with open(version_file, 'rb') as f:
                version_data = pickle.load(f)

            # Load models
            models = version_data['models']
            self.anomaly_detector = models['anomaly_detector']
            self.threat_classifier = models['threat_classifier']
            self.behavior_clusterer = models['behavior_clusterer']
            self.feature_scaler = models['feature_scaler']

            # Update configuration
            self.model_config = version_data['config']
            self.current_model_version = version

            # Update version status
            for v in self.model_versions:
                self.model_versions[v]['is_active'] = (v == version)

            logger.info(f"Loaded model version {version}")
            return True

        except Exception as e:
            logger.error(f"Failed to load model version {version}: {e}")
            return False
    
    def analyze_security_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        """
        Analyze a security event using AI
        """
        try:
            # Extract features from event
            features = self._extract_all_features(event_data)
            
            # Create security event
            event = SecurityEvent(
                event_id=event_data.get('event_id', f"evt_{datetime.now().timestamp()}"),
                timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat())),
                event_type=event_data.get('event_type', 'unknown'),
                source_ip=event_data.get('source_ip', 'unknown'),
                user_id=event_data.get('user_id'),
                features=features,
                is_malicious=event_data.get('is_malicious'),
                confidence=0.0,
                risk_score=0.0
            )
            
            # Perform anomaly detection
            if self.anomaly_detector and len(self.security_events) > 100:
                anomaly_score = self._detect_anomaly(features)
                event.risk_score = max(event.risk_score, anomaly_score)
            
            # Perform threat classification
            if self.threat_classifier and len(self.labeled_events) > 50:
                threat_probability = self._classify_threat(features)
                event.confidence = threat_probability
                event.risk_score = max(event.risk_score, threat_probability)
            
            # Store event
            self.security_events.append(event)
            
            # Update models periodically and check for drift
            if len(self.security_events) % 100 == 0:
                self._update_models()

                # Check for model drift
                if self.drift_detection_enabled:
                    self._check_model_drift(features)
            
            logger.debug(f"Analyzed security event: {event.event_id} (risk: {event.risk_score:.3f})")
            
            return event
            
        except Exception as e:
            logger.error(f"Security event analysis failed: {e}")
            # Return basic event without AI analysis
            return SecurityEvent(
                event_id=event_data.get('event_id', 'error'),
                timestamp=datetime.now(),
                event_type=event_data.get('event_type', 'error'),
                source_ip=event_data.get('source_ip', 'unknown'),
                user_id=event_data.get('user_id'),
                features={},
                is_malicious=None,
                confidence=0.0,
                risk_score=0.5  # Medium risk for errors
            )
    
    def _extract_all_features(self, event_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract all features from event data"""
        features = {}
        
        for extractor_name, extractor_func in self.feature_extractors.items():
            try:
                extracted_features = extractor_func(event_data)
                features.update(extracted_features)
            except Exception as e:
                logger.warning(f"Feature extraction failed for {extractor_name}: {e}")
        
        return features
    
    def _extract_temporal_features(self, event_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract temporal features"""
        timestamp = datetime.fromisoformat(event_data.get('timestamp', datetime.now().isoformat()))
        
        return {
            'hour_of_day': timestamp.hour / 24.0,
            'day_of_week': timestamp.weekday() / 7.0,
            'is_weekend': float(timestamp.weekday() >= 5),
            'is_business_hours': float(9 <= timestamp.hour <= 17),
            'time_since_midnight': (timestamp.hour * 3600 + timestamp.minute * 60 + timestamp.second) / 86400.0
        }
    
    def _extract_behavioral_features(self, event_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract behavioral features"""
        user_id = event_data.get('user_id')
        source_ip = event_data.get('source_ip', '')
        
        # Calculate user behavior patterns
        user_events = [e for e in self.security_events if e.user_id == user_id] if user_id else []
        ip_events = [e for e in self.security_events if e.source_ip == source_ip]
        
        return {
            'user_event_frequency': len(user_events) / max(len(self.security_events), 1),
            'ip_event_frequency': len(ip_events) / max(len(self.security_events), 1),
            'user_risk_history': statistics.mean([e.risk_score for e in user_events]) if user_events else 0.0,
            'ip_risk_history': statistics.mean([e.risk_score for e in ip_events]) if ip_events else 0.0,
            'user_event_diversity': len(set(e.event_type for e in user_events)) / max(len(user_events), 1) if user_events else 0.0
        }
    
    def _extract_network_features(self, event_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract network-related features"""
        source_ip = event_data.get('source_ip', '')
        
        # IP address analysis
        ip_parts = source_ip.split('.')
        if len(ip_parts) == 4:
            try:
                ip_numeric = sum(int(part) * (256 ** (3-i)) for i, part in enumerate(ip_parts))
                is_private = (
                    source_ip.startswith('10.') or
                    source_ip.startswith('192.168.') or
                    source_ip.startswith('172.')
                )
            except ValueError:
                ip_numeric = 0
                is_private = False
        else:
            ip_numeric = 0
            is_private = False
        
        return {
            'ip_numeric': ip_numeric / (256**4),  # Normalize
            'is_private_ip': float(is_private),
            'ip_entropy': self._calculate_string_entropy(source_ip),
            'has_user_agent': float(bool(event_data.get('user_agent'))),
            'user_agent_entropy': self._calculate_string_entropy(event_data.get('user_agent', ''))
        }
    
    def _extract_statistical_features(self, event_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract statistical features"""
        payload = event_data.get('payload', {})
        
        return {
            'payload_size': len(str(payload)) / 10000.0,  # Normalize to ~1.0 max
            'payload_entropy': self._calculate_string_entropy(str(payload)),
            'num_fields': len(payload) / 50.0 if isinstance(payload, dict) else 0.0,
            'has_suspicious_patterns': float(self._has_suspicious_patterns(str(payload))),
            'request_complexity': self._calculate_request_complexity(event_data)
        }
    
    def _calculate_string_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy / 8.0  # Normalize to ~1.0 max
    
    def _has_suspicious_patterns(self, text: str) -> bool:
        """Check for suspicious patterns in text"""
        suspicious_patterns = [
            'union select', 'drop table', '<script', 'javascript:',
            '../', '..\\', 'cmd.exe', '/bin/sh', 'eval(',
            'base64_decode', 'system(', 'exec('
        ]
        
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in suspicious_patterns)
    
    def _calculate_request_complexity(self, event_data: Dict[str, Any]) -> float:
        """Calculate request complexity score"""
        complexity = 0.0
        
        # URL complexity
        url = event_data.get('url', '')
        complexity += len(url.split('/')) / 20.0
        complexity += len(url.split('?')) / 10.0
        complexity += len(url.split('&')) / 20.0
        
        # Headers complexity
        headers = event_data.get('headers', {})
        complexity += len(headers) / 30.0
        
        # Method complexity
        method = event_data.get('method', 'GET')
        method_weights = {'GET': 0.1, 'POST': 0.3, 'PUT': 0.4, 'DELETE': 0.5, 'PATCH': 0.4}
        complexity += method_weights.get(method, 0.2)
        
        return min(complexity, 1.0)
    
    def _detect_anomaly(self, features: Dict[str, float]) -> float:
        """Detect anomalies using trained model"""
        try:
            # Convert features to array
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features
            feature_vector_scaled = self.feature_scaler.transform(feature_vector)
            
            # Get anomaly score
            anomaly_score = self.anomaly_detector.decision_function(feature_vector_scaled)[0]
            
            # Convert to 0-1 range (higher = more anomalous)
            normalized_score = max(0.0, min(1.0, (0.5 - anomaly_score) * 2))
            
            return normalized_score
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return 0.0
    
    def _classify_threat(self, features: Dict[str, float]) -> float:
        """Classify threat using trained model"""
        try:
            # Convert features to array
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Scale features
            feature_vector_scaled = self.feature_scaler.transform(feature_vector)
            
            # Get threat probability
            threat_probabilities = self.threat_classifier.predict_proba(feature_vector_scaled)[0]
            
            # Return probability of malicious class (assuming binary classification)
            return threat_probabilities[1] if len(threat_probabilities) > 1 else 0.0
            
        except Exception as e:
            logger.error(f"Threat classification failed: {e}")
            return 0.0
    
    def _update_models(self):
        """Update ML models with new data"""
        try:
            if len(self.security_events) < 100:
                return
            
            # Prepare training data
            recent_events = list(self.security_events)[-1000:]  # Last 1000 events
            
            # Extract features
            X = []
            for event in recent_events:
                if event.features:
                    X.append(list(event.features.values()))
            
            if not X:
                return
            
            X = np.array(X)
            
            # Update feature scaler
            self.feature_scaler.fit(X)
            X_scaled = self.feature_scaler.transform(X)
            
            # Update anomaly detector
            self.anomaly_detector.fit(X_scaled)
            
            # Update threat classifier if we have labeled data
            labeled_events = [e for e in recent_events if e.is_malicious is not None]
            if len(labeled_events) > 20:
                X_labeled = []
                y_labeled = []
                
                for event in labeled_events:
                    if event.features:
                        X_labeled.append(list(event.features.values()))
                        y_labeled.append(int(event.is_malicious))
                
                if X_labeled:
                    X_labeled = np.array(X_labeled)
                    X_labeled_scaled = self.feature_scaler.transform(X_labeled)
                    
                    self.threat_classifier.fit(X_labeled_scaled, y_labeled)
            
            logger.info("ML models updated successfully")
            
        except Exception as e:
            logger.error(f"Model update failed: {e}")

    def _check_model_drift(self, current_features: Dict[str, float]):
        """Check for model drift using feature distribution comparison"""
        try:
            if not self.baseline_distributions:
                # Initialize baseline with current features
                self._update_baseline_distributions(current_features)
                return

            drift_detected = False
            drift_details = {}

            # Check each feature category for drift
            for category, extractor_func in self.feature_extractors.items():
                category_features = {}

                # Extract features for this category
                try:
                    category_features = extractor_func({'timestamp': datetime.now().isoformat()})
                except:
                    continue

                # Compare with baseline
                for feature_name, current_value in category_features.items():
                    baseline_key = f"{category}_{feature_name}"

                    if baseline_key in self.baseline_distributions:
                        baseline_stats = self.baseline_distributions[baseline_key]

                        # Calculate drift using statistical distance
                        drift_score = self._calculate_drift_score(
                            current_value,
                            baseline_stats['mean'],
                            baseline_stats['std']
                        )

                        if drift_score > self.drift_threshold:
                            drift_detected = True
                            drift_details[baseline_key] = {
                                'drift_score': drift_score,
                                'current_value': current_value,
                                'baseline_mean': baseline_stats['mean'],
                                'baseline_std': baseline_stats['std']
                            }

            # Handle drift detection
            if drift_detected:
                self._handle_model_drift(drift_details)

        except Exception as e:
            logger.error(f"Drift detection failed: {e}")

    def _calculate_drift_score(self, current_value: float, baseline_mean: float, baseline_std: float) -> float:
        """Calculate drift score using z-score"""
        try:
            if baseline_std == 0:
                return 0.0

            z_score = abs(current_value - baseline_mean) / baseline_std
            # Normalize to 0-1 range
            drift_score = min(1.0, z_score / 3.0)  # 3-sigma rule

            return drift_score

        except Exception:
            return 0.0

    def _update_baseline_distributions(self, features: Dict[str, float]):
        """Update baseline feature distributions"""
        try:
            # Update baseline statistics
            for feature_name, value in features.items():
                if feature_name not in self.baseline_distributions:
                    self.baseline_distributions[feature_name] = {
                        'values': [],
                        'mean': 0.0,
                        'std': 0.0,
                        'count': 0
                    }

                baseline = self.baseline_distributions[feature_name]
                baseline['values'].append(value)
                baseline['count'] += 1

                # Keep only recent values (sliding window)
                if len(baseline['values']) > 1000:
                    baseline['values'] = baseline['values'][-1000:]

                # Update statistics
                if len(baseline['values']) > 1:
                    baseline['mean'] = statistics.mean(baseline['values'])
                    baseline['std'] = statistics.stdev(baseline['values'])
                else:
                    baseline['mean'] = value
                    baseline['std'] = 0.0

        except Exception as e:
            logger.error(f"Failed to update baseline distributions: {e}")

    def _handle_model_drift(self, drift_details: Dict[str, Any]):
        """Handle detected model drift"""
        try:
            drift_alert = {
                'timestamp': datetime.now(),
                'drift_details': drift_details,
                'severity': 'HIGH' if len(drift_details) > 5 else 'MEDIUM',
                'recommended_action': 'retrain_model' if len(drift_details) > 10 else 'monitor'
            }

            self.drift_alerts.append(drift_alert)

            # Keep only recent alerts
            if len(self.drift_alerts) > 100:
                self.drift_alerts = self.drift_alerts[-100:]

            logger.warning(f"Model drift detected: {len(drift_details)} features affected")

            # Auto-retrain if severe drift
            if len(drift_details) > 10:
                logger.info("Severe drift detected - triggering model retraining")
                self._retrain_models_with_versioning()

        except Exception as e:
            logger.error(f"Failed to handle model drift: {e}")

    def _retrain_models_with_versioning(self):
        """Retrain models with version increment"""
        try:
            # Increment version
            version_parts = self.current_model_version.split('.')
            minor_version = int(version_parts[1]) + 1
            new_version = f"{version_parts[0]}.{minor_version}.0"

            # Retrain models
            self._update_models()

            # Save new version
            self._save_model_version(new_version, {
                'anomaly_detector': self.anomaly_detector,
                'threat_classifier': self.threat_classifier,
                'behavior_clusterer': self.behavior_clusterer,
                'feature_scaler': self.feature_scaler
            })

            self.current_model_version = new_version

            logger.info(f"Models retrained and saved as version {new_version}")

        except Exception as e:
            logger.error(f"Model retraining with versioning failed: {e}")
    
    def predict_threats(self, time_horizon: timedelta = None) -> List[ThreatPrediction]:
        """Predict future threats using AI"""
        try:
            time_horizon = time_horizon or self.model_config['prediction_horizon']
            
            # Analyze recent patterns
            recent_events = [e for e in self.security_events 
                           if (datetime.now() - e.timestamp) < timedelta(hours=24)]
            
            if len(recent_events) < 10:
                return []
            
            # Identify trending threat patterns
            threat_types = defaultdict(list)
            for event in recent_events:
                threat_types[event.event_type].append(event)
            
            predictions = []
            
            for threat_type, events in threat_types.items():
                if len(events) < 3:
                    continue
                
                # Calculate trend
                risk_scores = [e.risk_score for e in sorted(events, key=lambda x: x.timestamp)]
                if len(risk_scores) > 1:
                    trend = (risk_scores[-1] - risk_scores[0]) / len(risk_scores)
                    
                    if trend > 0.1:  # Increasing threat
                        probability = min(0.9, 0.5 + trend)
                        
                        prediction = ThreatPrediction(
                            prediction_id=f"pred_{datetime.now().timestamp()}",
                            predicted_threat_type=threat_type,
                            probability=probability,
                            confidence_interval=(probability - 0.1, probability + 0.1),
                            contributing_factors=[
                                f"Increasing trend: {trend:.3f}",
                                f"Recent events: {len(events)}",
                                f"Average risk: {statistics.mean(risk_scores):.3f}"
                            ],
                            recommended_actions=[
                                "Increase monitoring",
                                "Review security policies",
                                "Alert security team"
                            ],
                            prediction_time=datetime.now(),
                            validity_period=time_horizon
                        )
                        
                        predictions.append(prediction)
            
            # Store predictions
            self.threat_predictions.extend(predictions)
            
            # Clean up old predictions
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.threat_predictions = [
                p for p in self.threat_predictions
                if p.prediction_time > cutoff_time
            ]
            
            logger.info(f"Generated {len(predictions)} threat predictions")
            
            return predictions
            
        except Exception as e:
            logger.error(f"Threat prediction failed: {e}")
            return []
    
    def detect_anomaly_clusters(self) -> List[AnomalyCluster]:
        """Detect clusters of anomalous events"""
        try:
            if not SKLEARN_AVAILABLE or len(self.security_events) < 20:
                return []
            
            # Get recent high-risk events
            recent_events = [
                e for e in self.security_events
                if (datetime.now() - e.timestamp) < timedelta(hours=6) and e.risk_score > 0.6
            ]
            
            if len(recent_events) < 5:
                return []
            
            # Prepare features for clustering
            X = []
            for event in recent_events:
                if event.features:
                    X.append(list(event.features.values()))
            
            if not X:
                return []
            
            X = np.array(X)
            X_scaled = self.feature_scaler.transform(X)
            
            # Perform clustering
            cluster_labels = self.behavior_clusterer.fit_predict(X_scaled)
            
            # Group events by cluster
            clusters = defaultdict(list)
            for i, label in enumerate(cluster_labels):
                if label != -1:  # Ignore noise points
                    clusters[label].append(recent_events[i])
            
            # Create anomaly clusters
            anomaly_clusters = []
            for cluster_id, events in clusters.items():
                if len(events) >= 3:  # Minimum cluster size
                    # Calculate cluster statistics
                    avg_risk = statistics.mean(e.risk_score for e in events)
                    affected_users = list(set(e.user_id for e in events if e.user_id))
                    affected_ips = list(set(e.source_ip for e in events))
                    
                    # Determine cluster type
                    event_types = [e.event_type for e in events]
                    most_common_type = max(set(event_types), key=event_types.count)
                    
                    cluster = AnomalyCluster(
                        cluster_id=f"cluster_{cluster_id}_{datetime.now().timestamp()}",
                        cluster_type=most_common_type,
                        events=events,
                        centroid_features={},  # Would calculate actual centroid
                        anomaly_score=avg_risk,
                        detected_at=datetime.now(),
                        affected_users=affected_users,
                        affected_ips=affected_ips
                    )
                    
                    anomaly_clusters.append(cluster)
            
            # Store clusters
            self.anomaly_clusters.extend(anomaly_clusters)
            
            # Clean up old clusters
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.anomaly_clusters = [
                c for c in self.anomaly_clusters
                if c.detected_at > cutoff_time
            ]
            
            logger.info(f"Detected {len(anomaly_clusters)} anomaly clusters")
            
            return anomaly_clusters
            
        except Exception as e:
            logger.error(f"Anomaly clustering failed: {e}")
            return []
    
    def get_ai_analytics_status(self) -> Dict[str, Any]:
        """Get AI analytics system status"""
        if not SKLEARN_AVAILABLE:
            return {'available': False, 'reason': 'Scikit-learn not installed'}
        
        return {
            'available': True,
            'total_events_analyzed': len(self.security_events),
            'labeled_events': len(self.labeled_events),
            'active_predictions': len([p for p in self.threat_predictions 
                                     if (datetime.now() - p.prediction_time) < p.validity_period]),
            'anomaly_clusters': len(self.anomaly_clusters),
            'models_trained': {
                'anomaly_detector': self.anomaly_detector is not None,
                'threat_classifier': self.threat_classifier is not None,
                'behavior_clusterer': self.behavior_clusterer is not None
            },
            'last_model_update': datetime.now().isoformat(),
            'feature_extractors': list(self.feature_extractors.keys())
        }

# Global AI security analytics engine
ai_security_analytics = AISecurityAnalytics() if SKLEARN_AVAILABLE else None
