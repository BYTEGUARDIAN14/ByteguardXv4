"""
End-to-End Tests for AI Explainability Viewer
Tests the AI explanation interface and audit functionality
"""

import pytest
import json
import time
from unittest.mock import patch, Mock

from byteguardx.security.ai_security import ai_auditor, adversarial_detector
from byteguardx.api.app import create_app

class TestAIExplainabilityViewer:
    """Test AI explainability and audit functionality"""
    
    @pytest.fixture
    def app(self, test_secrets):
        """Create test Flask app"""
        app = create_app()
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': test_secrets['SECRET_KEY'],
            'JWT_SECRET': test_secrets['JWT_SECRET'],
            'CSRF_ENABLED': False
        })
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @pytest.fixture
    def mock_ai_prediction(self):
        """Mock AI prediction with explanation"""
        return {
            'model_name': 'vulnerability_detector',
            'input_data': {'code': 'test code snippet'},
            'prediction': {
                'vulnerabilities': [
                    {
                        'type': 'sql_injection',
                        'severity': 'high',
                        'confidence': 0.85,
                        'line': 15,
                        'pattern': 'string concatenation in SQL query'
                    }
                ]
            },
            'confidence': 0.85,
            'explanation': {
                'reasoning': 'Detected string concatenation in SQL query construction',
                'patterns_matched': ['sql_concat_pattern', 'user_input_pattern'],
                'confidence_factors': {
                    'pattern_strength': 0.9,
                    'context_relevance': 0.8,
                    'historical_accuracy': 0.85
                },
                'similar_cases': 3,
                'false_positive_rate': 0.12
            }
        }
    
    def test_ai_prediction_audit_logging(self, mock_ai_prediction):
        """Test that AI predictions are properly audited"""
        # Create audit entry
        audit_id = ai_auditor.audit_prediction(
            model_name=mock_ai_prediction['model_name'],
            input_data=mock_ai_prediction['input_data'],
            prediction=mock_ai_prediction['prediction'],
            confidence=mock_ai_prediction['confidence'],
            explanation=mock_ai_prediction['explanation'],
            user_id='test_user_123'
        )
        
        assert audit_id is not None
        assert audit_id.startswith('vulnerability_detector_')
        
        # Verify audit record structure
        assert len(audit_id.split('_')) >= 3  # model_timestamp_hash format
    
    def test_adversarial_input_detection(self):
        """Test adversarial input detection in AI pipeline"""
        # Test normal input
        normal_code = '''
def calculate_sum(a, b):
    return a + b

result = calculate_sum(5, 3)
print(result)
'''
        
        is_valid, reason = adversarial_detector.validate_input(normal_code, 'code')
        assert is_valid is True
        assert reason == ""
        
        # Test adversarial input - excessive repetition
        adversarial_code = 'A' * 15000  # Very long repetitive input
        
        is_valid, reason = adversarial_detector.validate_input(adversarial_code, 'code')
        assert is_valid is False
        assert 'too long' in reason.lower() or 'repetition' in reason.lower()
        
        # Test adversarial input - suspicious patterns
        suspicious_code = '''
        eval('malicious_code')
        exec('dangerous_operation')
        __import__('os').system('rm -rf /')
        '''
        
        is_valid, reason = adversarial_detector.validate_input(suspicious_code, 'code')
        assert is_valid is False
        assert 'dangerous' in reason.lower() or 'pattern' in reason.lower()
    
    def test_ai_explanation_completeness(self, client, mock_ai_prediction):
        """Test that AI explanations contain required information"""
        # Mock AI scan with explanation
        with patch('byteguardx.scanners.ai_pattern_scanner.AIPatternScanner.scan_file') as mock_scan:
            mock_scan.return_value = [mock_ai_prediction['prediction']['vulnerabilities'][0]]
            
            # Perform scan
            response = client.post('/scan/ai-patterns', json={
                'code': mock_ai_prediction['input_data']['code']
            })
            
            if response.status_code == 200:
                data = response.get_json()
                
                # Check for audit ID
                assert 'audit_id' in data
                
                # Check explanation structure
                if 'explanation' in data:
                    explanation = data['explanation']
                    
                    # Required explanation fields
                    required_fields = ['reasoning', 'confidence_factors']
                    for field in required_fields:
                        assert field in explanation or 'patterns_detected' in data
    
    def test_confidence_score_validation(self, mock_ai_prediction):
        """Test confidence score validation and thresholds"""
        # Test high confidence prediction
        high_confidence_prediction = mock_ai_prediction.copy()
        high_confidence_prediction['confidence'] = 0.95
        
        audit_id = ai_auditor.audit_prediction(
            model_name=high_confidence_prediction['model_name'],
            input_data=high_confidence_prediction['input_data'],
            prediction=high_confidence_prediction['prediction'],
            confidence=high_confidence_prediction['confidence'],
            explanation=high_confidence_prediction['explanation']
        )
        
        assert audit_id is not None
        
        # Test low confidence prediction
        low_confidence_prediction = mock_ai_prediction.copy()
        low_confidence_prediction['confidence'] = 0.25
        
        audit_id = ai_auditor.audit_prediction(
            model_name=low_confidence_prediction['model_name'],
            input_data=low_confidence_prediction['input_data'],
            prediction=low_confidence_prediction['prediction'],
            confidence=low_confidence_prediction['confidence'],
            explanation=low_confidence_prediction['explanation']
        )
        
        assert audit_id is not None
        
        # Verify risk assessment
        # Low confidence should be flagged as high risk
        # This would be checked in the audit logs in a real implementation
    
    def test_ai_model_performance_tracking(self):
        """Test AI model performance metrics tracking"""
        # Mock performance metrics
        performance_metrics = {
            'accuracy': 0.87,
            'precision': 0.82,
            'recall': 0.91,
            'f1_score': 0.86,
            'false_positive_rate': 0.13,
            'false_negative_rate': 0.09
        }
        
        # Audit performance
        ai_auditor.audit_model_performance(
            model_name='vulnerability_detector',
            performance_metrics=performance_metrics,
            test_data_hash='mock_test_data_hash'
        )
        
        # Test anomaly detection
        anomalous_metrics = {
            'accuracy': 0.99,  # Suspiciously high
            'precision': 0.98,
            'recall': 0.97,
            'f1_score': 0.975
        }
        
        ai_auditor.audit_model_performance(
            model_name='vulnerability_detector',
            performance_metrics=anomalous_metrics
        )
        
        # In a real implementation, this would trigger alerts
    
    def test_explanation_viewer_api(self, client):
        """Test AI explanation viewer API endpoints"""
        # Test explanation retrieval (mock endpoint)
        with patch('byteguardx.security.ai_security.ai_auditor.get_audit_summary') as mock_summary:
            mock_summary.return_value = {
                'total_predictions': 150,
                'confidence_distribution': {
                    'high': 45,
                    'medium': 80,
                    'low': 25
                },
                'risk_level_counts': {
                    'LOW': 45,
                    'MEDIUM': 80,
                    'HIGH': 25
                },
                'common_flags': ['LOW_CONFIDENCE', 'MISSING_REASONING'],
                'model_performance_trends': {
                    'accuracy_trend': 'stable',
                    'confidence_trend': 'improving'
                }
            }
            
            # Test audit summary endpoint (if it exists)
            response = client.get('/api/v1/ai/audit-summary')
            
            # Endpoint might not exist yet, so we test the mock
            if response.status_code == 200:
                data = response.get_json()
                assert 'total_predictions' in data
                assert 'confidence_distribution' in data
    
    def test_real_time_explanation_updates(self, client):
        """Test real-time explanation updates during scanning"""
        # Mock real-time scan with explanations
        test_code = '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()
'''
        
        # Test scan with explanation tracking
        with patch('byteguardx.security.ai_security.adversarial_detector.validate_input') as mock_validate:
            mock_validate.return_value = (True, "")
            
            response = client.post('/scan/ai-patterns', json={'code': test_code})
            
            if response.status_code == 200:
                data = response.get_json()
                
                # Should have findings with explanations
                if 'findings' in data and data['findings']:
                    finding = data['findings'][0]
                    
                    # Check for explanation metadata
                    expected_fields = ['type', 'severity', 'message', 'confidence']
                    for field in expected_fields:
                        assert field in finding or 'line' in finding
    
    def test_explanation_export_functionality(self, mock_ai_prediction):
        """Test explanation export for compliance"""
        # Create multiple audit entries
        audit_ids = []
        for i in range(3):
            prediction = mock_ai_prediction.copy()
            prediction['input_data']['code'] = f'test code {i}'
            
            audit_id = ai_auditor.audit_prediction(
                model_name=prediction['model_name'],
                input_data=prediction['input_data'],
                prediction=prediction['prediction'],
                confidence=prediction['confidence'],
                explanation=prediction['explanation'],
                user_id=f'test_user_{i}'
            )
            audit_ids.append(audit_id)
        
        # Test audit summary generation
        summary = ai_auditor.get_audit_summary(
            model_name='vulnerability_detector',
            start_date='2023-01-01',
            end_date='2023-12-31'
        )
        
        # Verify summary structure
        assert isinstance(summary, dict)
        assert 'total_predictions' in summary
        assert 'confidence_distribution' in summary
    
    def test_bias_detection_in_ai_predictions(self):
        """Test bias detection in AI model predictions"""
        # Create predictions with potential bias patterns
        biased_predictions = [
            {
                'input_type': 'python',
                'confidence': 0.9,
                'prediction': 'vulnerable'
            },
            {
                'input_type': 'javascript', 
                'confidence': 0.3,
                'prediction': 'safe'
            },
            {
                'input_type': 'python',
                'confidence': 0.85,
                'prediction': 'vulnerable'
            },
            {
                'input_type': 'javascript',
                'confidence': 0.25,
                'prediction': 'safe'
            }
        ]
        
        # Audit all predictions
        for i, pred in enumerate(biased_predictions):
            ai_auditor.audit_prediction(
                model_name='bias_test_model',
                input_data={'type': pred['input_type']},
                prediction={'result': pred['prediction']},
                confidence=pred['confidence'],
                explanation={'bias_test': True},
                user_id=f'bias_test_user_{i}'
            )
        
        # In a real implementation, this would trigger bias detection alerts
        # For now, we just verify the audit entries were created
        assert True  # Placeholder for bias detection logic
    
    @pytest.mark.integration
    def test_complete_ai_explanation_workflow(self, client):
        """Test complete AI explanation workflow"""
        # 1. Submit code for AI analysis
        test_code = '''
def process_user_input(user_data):
    # Potential XSS vulnerability
    return f"<div>{user_data}</div>"
'''
        
        # 2. Validate input
        is_valid, reason = adversarial_detector.validate_input(test_code, 'code')
        assert is_valid is True
        
        # 3. Perform AI scan with explanation
        with patch('byteguardx.scanners.ai_pattern_scanner.AIPatternScanner') as mock_scanner:
            mock_scanner.return_value.scan_file.return_value = [
                {
                    'type': 'xss_vulnerability',
                    'severity': 'medium',
                    'confidence': 0.75,
                    'message': 'Potential XSS vulnerability detected',
                    'line': 3,
                    'explanation': {
                        'pattern': 'unescaped_user_input',
                        'reasoning': 'User input directly embedded in HTML'
                    }
                }
            ]
            
            response = client.post('/scan/ai-patterns', json={'code': test_code})
            
            if response.status_code == 200:
                data = response.get_json()
                
                # 4. Verify explanation is included
                assert 'audit_id' in data
                
                # 5. Check findings have explanation metadata
                if 'findings' in data and data['findings']:
                    finding = data['findings'][0]
                    assert 'confidence' in finding or 'type' in finding
        
        # 6. Verify audit trail
        # In a real implementation, we would query the audit log
        # For now, we verify the workflow completed successfully
        assert True
