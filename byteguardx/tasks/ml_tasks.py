"""
ML/AI Tasks for ByteGuardX
Isolated AI workload processing with GPU support and ONNX runtime
"""

import os
import logging
import tempfile
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from celery import current_task
from pathlib import Path

from .celery_app import celery_app

logger = logging.getLogger(__name__)

# GPU availability check
def _check_gpu_availability() -> bool:
    """Check if GPU is available for ML inference"""
    try:
        import onnxruntime as ort
        providers = ort.get_available_providers()
        return 'CUDAExecutionProvider' in providers or 'ROCMExecutionProvider' in providers
    except ImportError:
        return False

GPU_AVAILABLE = _check_gpu_availability()
logger.info(f"GPU availability: {GPU_AVAILABLE}")

@celery_app.task(bind=True, name='byteguardx.tasks.ml_tasks.run_isolated_inference', queue='ml_inference')
def run_isolated_inference(self, model_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run ML inference in isolated container with GPU support
    
    Args:
        model_config: Configuration including:
            - model_path: Path to ONNX model
            - input_data: Input data for inference
            - use_gpu: Whether to use GPU if available
            - timeout: Inference timeout in seconds
    
    Returns:
        Dict containing inference results and metadata
    """
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Initializing ML inference...'})
        
        model_path = model_config['model_path']
        input_data = model_config['input_data']
        use_gpu = model_config.get('use_gpu', True) and GPU_AVAILABLE
        timeout = model_config.get('timeout', 30)
        
        # Import ONNX runtime
        try:
            import onnxruntime as ort
        except ImportError:
            logger.warning("ONNX Runtime not available, falling back to CPU inference")
            return _fallback_cpu_inference(input_data)
        
        # Configure providers
        providers = []
        if use_gpu:
            if 'CUDAExecutionProvider' in ort.get_available_providers():
                providers.append('CUDAExecutionProvider')
            elif 'ROCMExecutionProvider' in ort.get_available_providers():
                providers.append('ROCMExecutionProvider')
        
        providers.append('CPUExecutionProvider')  # Always include CPU as fallback
        
        self.update_state(state='PROGRESS', meta={'status': 'Loading model...'})
        
        # Create inference session
        session_options = ort.SessionOptions()
        session_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        
        # Set thread count for CPU
        if not use_gpu:
            session_options.intra_op_num_threads = min(4, os.cpu_count() or 1)
            session_options.inter_op_num_threads = min(2, os.cpu_count() or 1)
        
        session = ort.InferenceSession(
            model_path,
            sess_options=session_options,
            providers=providers
        )
        
        self.update_state(state='PROGRESS', meta={'status': 'Running inference...'})
        
        # Prepare input
        input_name = session.get_inputs()[0].name
        input_tensor = np.array(input_data, dtype=np.float32)
        
        # Run inference with timeout
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Inference timeout after {timeout} seconds")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            start_time = datetime.now()
            outputs = session.run(None, {input_name: input_tensor})
            inference_time = (datetime.now() - start_time).total_seconds()
        finally:
            signal.alarm(0)  # Cancel timeout
        
        # Process outputs
        prediction = outputs[0] if outputs else None
        confidence = float(np.max(prediction)) if prediction is not None else 0.0
        
        # Generate explanation
        explanation = _generate_model_explanation(input_data, prediction, model_config)
        
        result = {
            'prediction': prediction.tolist() if prediction is not None else None,
            'confidence': confidence,
            'explanation': explanation,
            'inference_time': inference_time,
            'provider_used': session.get_providers()[0],
            'gpu_used': use_gpu and 'CUDA' in session.get_providers()[0],
            'model_metadata': {
                'model_path': model_path,
                'input_shape': input_tensor.shape,
                'task_id': self.request.id
            }
        }
        
        # Log inference for audit
        from ..security.ai_audit_system import ai_audit_system
        ai_audit_system.log_prediction(
            model_name=Path(model_path).stem,
            model_version='1.0.0',
            input_data=input_data,
            prediction=result,
            metadata={
                'task_id': self.request.id,
                'provider': session.get_providers()[0],
                'inference_time': inference_time
            }
        )
        
        return result
        
    except TimeoutError as e:
        logger.error(f"ML inference timeout: {e}")
        # Fallback to rule-based scanning
        return _fallback_rule_based_scan(input_data)
        
    except Exception as e:
        logger.error(f"ML inference failed: {e}")
        # Fallback to rule-based scanning
        return _fallback_rule_based_scan(input_data)

@celery_app.task(bind=True, name='byteguardx.tasks.ml_tasks.train_model_task', queue='ml_inference')
def train_model_task(self, training_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Train ML model with adversarial samples
    
    Args:
        training_config: Training configuration
    
    Returns:
        Dict containing training results
    """
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Preparing training data...'})
        
        from ..ml.model_trainer import ModelTrainer
        from ..ml.adversarial_training import AdversarialTrainer
        
        trainer = ModelTrainer()
        adv_trainer = AdversarialTrainer()
        
        # Load training data
        training_data = training_config['training_data']
        validation_data = training_config.get('validation_data')
        
        self.update_state(state='PROGRESS', meta={'status': 'Generating adversarial samples...'})
        
        # Generate adversarial samples
        adversarial_samples = adv_trainer.generate_adversarial_samples(
            training_data,
            attack_types=['fgsm', 'pgd', 'c_w']
        )
        
        # Combine original and adversarial data
        augmented_data = training_data + adversarial_samples
        
        self.update_state(state='PROGRESS', meta={'status': 'Training model...'})
        
        # Train model
        model_path, metrics = trainer.train(
            training_data=augmented_data,
            validation_data=validation_data,
            config=training_config
        )
        
        # Run robustness benchmark
        self.update_state(state='PROGRESS', meta={'status': 'Running robustness tests...'})
        
        robustness_score = adv_trainer.evaluate_robustness(model_path, validation_data)
        
        return {
            'model_path': model_path,
            'training_metrics': metrics,
            'robustness_score': robustness_score,
            'adversarial_samples_count': len(adversarial_samples),
            'training_completed_at': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        raise

@celery_app.task(name='byteguardx.tasks.ml_tasks.detect_model_drift')
def detect_model_drift() -> Dict[str, Any]:
    """Detect model drift and performance degradation"""
    try:
        from ..ml.drift_detector import ModelDriftDetector
        
        drift_detector = ModelDriftDetector()
        
        # Check for data drift
        data_drift = drift_detector.detect_data_drift()
        
        # Check for concept drift
        concept_drift = drift_detector.detect_concept_drift()
        
        # Check performance metrics
        performance_drift = drift_detector.detect_performance_drift()
        
        drift_detected = any([data_drift['drift_detected'], 
                             concept_drift['drift_detected'],
                             performance_drift['drift_detected']])
        
        if drift_detected:
            # Send alert
            from ..alerts.alert_engine import alert_engine, AlertType, AlertSeverity
            
            alert_engine.create_alert(
                alert_type=AlertType.MODEL_DRIFT,
                severity=AlertSeverity.HIGH,
                title="Model Drift Detected",
                message="ML model performance drift detected - retraining recommended",
                metadata={
                    'data_drift': data_drift,
                    'concept_drift': concept_drift,
                    'performance_drift': performance_drift
                }
            )
        
        return {
            'drift_detected': drift_detected,
            'data_drift': data_drift,
            'concept_drift': concept_drift,
            'performance_drift': performance_drift,
            'check_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Model drift detection failed: {e}")
        raise

@celery_app.task(bind=True, name='byteguardx.tasks.ml_tasks.run_adversarial_testing')
def run_adversarial_testing(self, test_config: Dict[str, Any]) -> Dict[str, Any]:
    """Run adversarial testing on ML models"""
    try:
        self.update_state(state='PROGRESS', meta={'status': 'Initializing adversarial testing...'})
        
        from ..ml.adversarial_testing import AdversarialTester
        
        tester = AdversarialTester()
        model_path = test_config['model_path']
        test_data = test_config['test_data']
        
        # Run different attack types
        attack_results = {}
        
        for attack_type in ['fgsm', 'pgd', 'c_w', 'deepfool']:
            self.update_state(
                state='PROGRESS', 
                meta={'status': f'Running {attack_type.upper()} attack...'}
            )
            
            attack_results[attack_type] = tester.run_attack(
                model_path=model_path,
                test_data=test_data,
                attack_type=attack_type
            )
        
        # Calculate overall robustness score
        robustness_score = tester.calculate_robustness_score(attack_results)
        
        return {
            'robustness_score': robustness_score,
            'attack_results': attack_results,
            'test_completed_at': datetime.now().isoformat(),
            'recommendations': tester.generate_recommendations(attack_results)
        }
        
    except Exception as e:
        logger.error(f"Adversarial testing failed: {e}")
        raise

def _fallback_cpu_inference(input_data: Any) -> Dict[str, Any]:
    """Fallback CPU-based inference when GPU is unavailable"""
    logger.info("Using CPU fallback for ML inference")
    
    try:
        # Simple rule-based classification as fallback
        from ..scanners.rule_based_scanner import RuleBasedScanner
        
        scanner = RuleBasedScanner()
        result = scanner.scan_content(str(input_data))
        
        return {
            'prediction': result.get('findings', []),
            'confidence': 0.8,  # Rule-based has high confidence
            'explanation': 'Rule-based fallback used due to ML unavailability',
            'fallback_used': True,
            'provider_used': 'RuleBasedFallback'
        }
        
    except Exception as e:
        logger.error(f"CPU fallback failed: {e}")
        return {
            'prediction': None,
            'confidence': 0.0,
            'explanation': f'All inference methods failed: {e}',
            'error': str(e)
        }

def _fallback_rule_based_scan(input_data: Any) -> Dict[str, Any]:
    """Fallback to rule-based scanning when ML fails"""
    logger.info("Falling back to rule-based scanning")
    return _fallback_cpu_inference(input_data)

def _generate_model_explanation(input_data: Any, prediction: Any, config: Dict[str, Any]) -> str:
    """Generate explanation for model prediction"""
    try:
        if prediction is None:
            return "No prediction generated"
        
        # Simple explanation based on prediction confidence
        confidence = float(np.max(prediction)) if hasattr(prediction, '__iter__') else 0.0
        
        if confidence > 0.8:
            return f"High confidence ({confidence:.2f}) vulnerability detected based on code patterns"
        elif confidence > 0.5:
            return f"Medium confidence ({confidence:.2f}) potential vulnerability identified"
        else:
            return f"Low confidence ({confidence:.2f}) - code appears safe"
            
    except Exception as e:
        logger.error(f"Failed to generate explanation: {e}")
        return "Explanation generation failed"
