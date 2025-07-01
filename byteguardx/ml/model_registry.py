"""
ML Model Registry and Experiment Tracking for ByteGuardX
Manages model versions, experiments, and performance tracking
"""

import os
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import hashlib
import shutil
import threading

logger = logging.getLogger(__name__)

class ModelStatus(Enum):
    """Model status in registry"""
    TRAINING = "training"
    TRAINED = "trained"
    VALIDATED = "validated"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"
    FAILED = "failed"

class ModelType(Enum):
    """Types of ML models"""
    VULNERABILITY_CLASSIFIER = "vulnerability_classifier"
    FALSE_POSITIVE_DETECTOR = "false_positive_detector"
    PATTERN_MATCHER = "pattern_matcher"
    RISK_PREDICTOR = "risk_predictor"
    CODE_ANALYZER = "code_analyzer"

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_roc: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=list)
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    training_loss: float = 0.0
    validation_loss: float = 0.0
    training_time_seconds: float = 0.0
    inference_time_ms: float = 0.0
    model_size_mb: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class ModelVersion:
    """Model version information"""
    model_id: str
    version: str
    model_type: ModelType
    status: ModelStatus
    created_at: datetime
    created_by: str
    description: str
    
    # Model artifacts
    model_path: str
    config_path: str
    metadata_path: str
    
    # Training information
    training_dataset: str
    training_config: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    
    # Performance metrics
    metrics: ModelMetrics
    
    # Validation information
    validation_dataset: str = ""
    validation_results: Dict[str, Any] = field(default_factory=dict)
    
    # Deployment information
    deployment_config: Dict[str, Any] = field(default_factory=dict)
    deployment_date: Optional[datetime] = None
    
    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['model_type'] = self.model_type.value
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        if self.deployment_date:
            data['deployment_date'] = self.deployment_date.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelVersion':
        """Create from dictionary"""
        data['model_type'] = ModelType(data['model_type'])
        data['status'] = ModelStatus(data['status'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('deployment_date'):
            data['deployment_date'] = datetime.fromisoformat(data['deployment_date'])
        
        # Handle metrics
        if 'metrics' in data and isinstance(data['metrics'], dict):
            data['metrics'] = ModelMetrics(**data['metrics'])
        
        return cls(**data)

@dataclass
class Experiment:
    """ML experiment tracking"""
    experiment_id: str
    name: str
    description: str
    created_at: datetime
    created_by: str
    
    # Experiment configuration
    model_type: ModelType
    dataset_config: Dict[str, Any]
    training_config: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    
    # Results
    status: str  # 'running', 'completed', 'failed'
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    
    # Model versions created
    model_versions: List[str] = field(default_factory=list)
    
    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['model_type'] = self.model_type.value
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Experiment':
        """Create from dictionary"""
        data['model_type'] = ModelType(data['model_type'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

class ModelRegistry:
    """
    ML Model Registry for managing model versions, experiments, and deployments
    Provides model versioning, experiment tracking, and performance monitoring
    """
    
    def __init__(self, registry_dir: str = "data/ml_registry"):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        
        # Registry structure
        self.models_dir = self.registry_dir / "models"
        self.experiments_dir = self.registry_dir / "experiments"
        self.artifacts_dir = self.registry_dir / "artifacts"
        
        for dir_path in [self.models_dir, self.experiments_dir, self.artifacts_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # In-memory storage
        self.model_versions: Dict[str, ModelVersion] = {}
        self.experiments: Dict[str, Experiment] = {}
        self.deployed_models: Dict[ModelType, str] = {}  # model_type -> model_id
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Load existing data
        self._load_registry()
    
    def register_model(self, model_id: str, version: str, model_type: ModelType,
                      model_artifact: Any, training_config: Dict[str, Any],
                      metrics: ModelMetrics, created_by: str = "system",
                      description: str = "") -> bool:
        """Register new model version"""
        try:
            with self._lock:
                # Create model version
                model_version = ModelVersion(
                    model_id=model_id,
                    version=version,
                    model_type=model_type,
                    status=ModelStatus.TRAINED,
                    created_at=datetime.now(),
                    created_by=created_by,
                    description=description,
                    model_path="",
                    config_path="",
                    metadata_path="",
                    training_dataset="",
                    training_config=training_config,
                    hyperparameters=training_config.get("hyperparameters", {}),
                    metrics=metrics
                )
                
                # Save model artifacts
                model_dir = self.models_dir / model_id / version
                model_dir.mkdir(parents=True, exist_ok=True)
                
                # Save model
                model_file = model_dir / "model.pkl"
                with open(model_file, 'wb') as f:
                    pickle.dump(model_artifact, f)
                model_version.model_path = str(model_file)
                
                # Save config
                config_file = model_dir / "config.json"
                with open(config_file, 'w') as f:
                    json.dump(training_config, f, indent=2)
                model_version.config_path = str(config_file)
                
                # Save metadata
                metadata_file = model_dir / "metadata.json"
                with open(metadata_file, 'w') as f:
                    json.dump(model_version.to_dict(), f, indent=2)
                model_version.metadata_path = str(metadata_file)
                
                # Calculate model size
                model_version.metrics.model_size_mb = model_file.stat().st_size / (1024 * 1024)
                
                # Store in registry
                version_key = f"{model_id}:{version}"
                self.model_versions[version_key] = model_version
                
                # Save registry
                self._save_registry()
                
                logger.info(f"Registered model {model_id} version {version}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to register model: {e}")
            return False
    
    def load_model(self, model_id: str, version: str = "latest") -> Optional[Any]:
        """Load model artifact"""
        try:
            model_version = self.get_model_version(model_id, version)
            if not model_version:
                return None
            
            with open(model_version.model_path, 'rb') as f:
                return pickle.load(f)
                
        except Exception as e:
            logger.error(f"Failed to load model {model_id}:{version}: {e}")
            return None
    
    def get_model_version(self, model_id: str, version: str = "latest") -> Optional[ModelVersion]:
        """Get specific model version"""
        with self._lock:
            if version == "latest":
                # Find latest version for model
                model_versions = [
                    mv for mv in self.model_versions.values()
                    if mv.model_id == model_id
                ]
                if not model_versions:
                    return None
                
                # Sort by creation date
                model_versions.sort(key=lambda mv: mv.created_at, reverse=True)
                return model_versions[0]
            else:
                version_key = f"{model_id}:{version}"
                return self.model_versions.get(version_key)
    
    def list_models(self, model_type: Optional[ModelType] = None,
                   status: Optional[ModelStatus] = None) -> List[ModelVersion]:
        """List models with optional filtering"""
        with self._lock:
            models = list(self.model_versions.values())
            
            if model_type:
                models = [m for m in models if m.model_type == model_type]
            
            if status:
                models = [m for m in models if m.status == status]
            
            # Sort by creation date (newest first)
            models.sort(key=lambda m: m.created_at, reverse=True)
            return models
    
    def deploy_model(self, model_id: str, version: str = "latest",
                    deployment_config: Dict[str, Any] = None) -> bool:
        """Deploy model version"""
        try:
            with self._lock:
                model_version = self.get_model_version(model_id, version)
                if not model_version:
                    raise ValueError(f"Model {model_id}:{version} not found")
                
                # Update model status
                model_version.status = ModelStatus.DEPLOYED
                model_version.deployment_date = datetime.now()
                model_version.deployment_config = deployment_config or {}
                
                # Update deployed models mapping
                self.deployed_models[model_version.model_type] = f"{model_id}:{version}"
                
                # Save registry
                self._save_registry()
                
                logger.info(f"Deployed model {model_id}:{version}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to deploy model: {e}")
            return False
    
    def get_deployed_model(self, model_type: ModelType) -> Optional[ModelVersion]:
        """Get currently deployed model for type"""
        with self._lock:
            deployed_key = self.deployed_models.get(model_type)
            if deployed_key:
                return self.model_versions.get(deployed_key)
            return None
    
    def create_experiment(self, name: str, description: str, model_type: ModelType,
                         dataset_config: Dict[str, Any], training_config: Dict[str, Any],
                         created_by: str = "system") -> str:
        """Create new experiment"""
        try:
            with self._lock:
                experiment_id = self._generate_experiment_id(name)
                
                experiment = Experiment(
                    experiment_id=experiment_id,
                    name=name,
                    description=description,
                    created_at=datetime.now(),
                    created_by=created_by,
                    model_type=model_type,
                    dataset_config=dataset_config,
                    training_config=training_config,
                    hyperparameters=training_config.get("hyperparameters", {}),
                    status="running"
                )
                
                # Create experiment directory
                exp_dir = self.experiments_dir / experiment_id
                exp_dir.mkdir(exist_ok=True)
                
                # Save experiment
                self.experiments[experiment_id] = experiment
                self._save_experiment(experiment)
                
                logger.info(f"Created experiment {experiment_id}: {name}")
                return experiment_id
                
        except Exception as e:
            logger.error(f"Failed to create experiment: {e}")
            raise
    
    def log_experiment_metric(self, experiment_id: str, metric_name: str, value: Any):
        """Log metric for experiment"""
        with self._lock:
            if experiment_id in self.experiments:
                experiment = self.experiments[experiment_id]
                experiment.metrics[metric_name] = value
                self._save_experiment(experiment)
    
    def log_experiment_artifact(self, experiment_id: str, artifact_path: str):
        """Log artifact for experiment"""
        with self._lock:
            if experiment_id in self.experiments:
                experiment = self.experiments[experiment_id]
                experiment.artifacts.append(artifact_path)
                self._save_experiment(experiment)
    
    def complete_experiment(self, experiment_id: str, final_metrics: Dict[str, Any] = None):
        """Mark experiment as completed"""
        with self._lock:
            if experiment_id in self.experiments:
                experiment = self.experiments[experiment_id]
                experiment.status = "completed"
                if final_metrics:
                    experiment.metrics.update(final_metrics)
                self._save_experiment(experiment)
                logger.info(f"Completed experiment {experiment_id}")
    
    def compare_models(self, model_ids: List[str], metric: str = "accuracy") -> Dict[str, Any]:
        """Compare models by specific metric"""
        comparison = {}
        
        for model_id in model_ids:
            model_version = self.get_model_version(model_id)
            if model_version:
                metric_value = getattr(model_version.metrics, metric, 0.0)
                comparison[model_id] = {
                    "version": model_version.version,
                    "metric_value": metric_value,
                    "status": model_version.status.value,
                    "created_at": model_version.created_at.isoformat()
                }
        
        # Sort by metric value
        sorted_models = sorted(
            comparison.items(),
            key=lambda x: x[1]["metric_value"],
            reverse=True
        )
        
        return {
            "metric": metric,
            "models": dict(sorted_models),
            "best_model": sorted_models[0][0] if sorted_models else None
        }
    
    def get_model_lineage(self, model_id: str) -> List[ModelVersion]:
        """Get all versions of a model"""
        with self._lock:
            versions = [
                mv for mv in self.model_versions.values()
                if mv.model_id == model_id
            ]
            versions.sort(key=lambda mv: mv.created_at)
            return versions
    
    def archive_model(self, model_id: str, version: str):
        """Archive model version"""
        with self._lock:
            version_key = f"{model_id}:{version}"
            if version_key in self.model_versions:
                model_version = self.model_versions[version_key]
                model_version.status = ModelStatus.DEPRECATED
                self._save_registry()
                logger.info(f"Archived model {model_id}:{version}")
    
    def _generate_experiment_id(self, name: str) -> str:
        """Generate unique experiment ID"""
        timestamp = int(datetime.now().timestamp())
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        return f"exp_{name_hash}_{timestamp}"
    
    def _save_experiment(self, experiment: Experiment):
        """Save experiment to disk"""
        try:
            exp_file = self.experiments_dir / f"{experiment.experiment_id}.json"
            with open(exp_file, 'w') as f:
                json.dump(experiment.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save experiment: {e}")
    
    def _load_registry(self):
        """Load registry from disk"""
        try:
            # Load model versions
            for model_dir in self.models_dir.rglob("metadata.json"):
                try:
                    with open(model_dir, 'r') as f:
                        data = json.load(f)
                    
                    model_version = ModelVersion.from_dict(data)
                    version_key = f"{model_version.model_id}:{model_version.version}"
                    self.model_versions[version_key] = model_version
                    
                except Exception as e:
                    logger.error(f"Failed to load model metadata {model_dir}: {e}")
            
            # Load experiments
            for exp_file in self.experiments_dir.glob("exp_*.json"):
                try:
                    with open(exp_file, 'r') as f:
                        data = json.load(f)
                    
                    experiment = Experiment.from_dict(data)
                    self.experiments[experiment.experiment_id] = experiment
                    
                except Exception as e:
                    logger.error(f"Failed to load experiment {exp_file}: {e}")
            
            # Load deployed models mapping
            deployed_file = self.registry_dir / "deployed_models.json"
            if deployed_file.exists():
                with open(deployed_file, 'r') as f:
                    data = json.load(f)
                    self.deployed_models = {
                        ModelType(k): v for k, v in data.items()
                    }
            
            logger.info(f"Loaded {len(self.model_versions)} model versions and {len(self.experiments)} experiments")
            
        except Exception as e:
            logger.error(f"Failed to load registry: {e}")
    
    def _save_registry(self):
        """Save registry metadata"""
        try:
            # Save deployed models mapping
            deployed_file = self.registry_dir / "deployed_models.json"
            with open(deployed_file, 'w') as f:
                data = {k.value: v for k, v in self.deployed_models.items()}
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")

# Global model registry instance
model_registry = ModelRegistry()
