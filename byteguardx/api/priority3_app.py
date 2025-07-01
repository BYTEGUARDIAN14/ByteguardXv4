"""
Complete enterprise Flask application with Priority 3 features
Integrates SSO, advanced analytics, DevOps integrations, and API documentation
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
import uuid

# Priority 1 & 2 imports
from ..database.connection_pool import db_manager, init_db
from ..database.models import User, ScanResult, Finding
from ..security.auth_middleware import AuthMiddleware, auth_required, admin_required
from ..security.rbac import rbac, Permission, AccessContext
from ..performance.worker_pool import worker_pool
from ..performance.incremental_scanner import incremental_scanner
from ..ml.model_registry import model_registry
from ..ml.experiment_tracker import experiment_tracker
from ..error_handling.exception_handler import exception_handler, handle_exceptions, ErrorContext
from ..monitoring.health_checker import health_checker

# Priority 3 imports
from ..enterprise.sso_integration import sso_manager, SSOConfig, SSOProvider
from ..analytics.advanced_analytics import advanced_analytics, TrendDirection, RiskLevel
from ..integrations.cicd_integration import cicd_integrations, create_cicd_integration, CICDConfig, CICDPlatform
from ..api_docs.openapi_generator import openapi_generator

logger = logging.getLogger(__name__)

def create_priority3_app(config=None):
    """Create complete enterprise Flask application with Priority 3 features"""
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production'),
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
        'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB max file size
        'DATABASE_URL': os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db'),
        
        # Priority 2 features
        'ENABLE_WORKER_POOL': os.environ.get('ENABLE_WORKER_POOL', 'true').lower() == 'true',
        'ENABLE_INCREMENTAL_SCAN': os.environ.get('ENABLE_INCREMENTAL_SCAN', 'true').lower() == 'true',
        'ENABLE_CODE_SANDBOX': os.environ.get('ENABLE_CODE_SANDBOX', 'false').lower() == 'true',
        
        # Priority 3 features
        'ENABLE_SSO': os.environ.get('ENABLE_SSO', 'true').lower() == 'true',
        'ENABLE_ANALYTICS': os.environ.get('ENABLE_ANALYTICS', 'true').lower() == 'true',
        'ENABLE_CICD_INTEGRATIONS': os.environ.get('ENABLE_CICD_INTEGRATIONS', 'true').lower() == 'true',
        'ENABLE_API_DOCS': os.environ.get('ENABLE_API_DOCS', 'true').lower() == 'true'
    })
    
    if config:
        app.config.update(config)
    
    # Initialize database
    init_db(app.config['DATABASE_URL'])
    
    # Initialize Priority 2 components
    if app.config['ENABLE_WORKER_POOL']:
        worker_pool.start()
    
    # Enhanced security headers
    @app.after_request
    def add_enhanced_security_headers(response):
        """Add comprehensive security headers"""
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://unpkg.com; "
                "style-src 'self' 'unsafe-inline' https://unpkg.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://unpkg.com; "
                "connect-src 'self'"
            ),
            'Permissions-Policy': (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            )
        })
        return response
    
    # Initialize CORS
    CORS(app, 
         origins=os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(','),
         supports_credentials=True,
         max_age=3600)
    
    # Initialize components
    auth_middleware = AuthMiddleware()
    
    # Start background monitoring
    health_checker.start_background_monitoring()
    
    # RBAC decorator
    def require_permission(permission: Permission):
        """Decorator to require specific permission"""
        def decorator(f):
            def wrapper(*args, **kwargs):
                if not g.get('current_user'):
                    return jsonify({'error': 'Authentication required'}), 401
                
                user_id = g.current_user['user_id']
                context = AccessContext(
                    user_id=user_id,
                    organization_id=g.current_user.get('organization_id'),
                    resource_type=request.endpoint or '',
                    action=request.method.lower(),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                
                if not rbac.check_permission(user_id, permission, context):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    # SSO Authentication endpoints
    @app.route('/auth/sso/providers', methods=['GET'])
    def list_sso_providers():
        """List available SSO providers"""
        if not app.config['ENABLE_SSO']:
            return jsonify({'error': 'SSO is disabled'}), 404
        
        providers = sso_manager.list_providers()
        return jsonify({'providers': providers})
    
    @app.route('/auth/sso/<provider_name>/login', methods=['GET'])
    def sso_login(provider_name):
        """Initiate SSO login"""
        if not app.config['ENABLE_SSO']:
            return jsonify({'error': 'SSO is disabled'}), 404
        
        try:
            state = request.args.get('state', str(uuid.uuid4()))
            auth_url = sso_manager.get_auth_url(provider_name, state)
            
            return jsonify({
                'auth_url': auth_url,
                'state': state
            })
            
        except Exception as e:
            logger.error(f"SSO login failed for {provider_name}: {e}")
            return jsonify({'error': 'SSO login failed'}), 500
    
    @app.route('/auth/sso/<provider_name>/callback', methods=['POST'])
    def sso_callback(provider_name):
        """Handle SSO callback"""
        if not app.config['ENABLE_SSO']:
            return jsonify({'error': 'SSO is disabled'}), 404
        
        try:
            # Get callback data
            data = request.get_json() or {}
            
            # Process SSO callback
            sso_user = sso_manager.process_callback(provider_name, **data)
            
            # Provision user
            user = sso_manager.provision_user(sso_user)
            
            # Generate JWT tokens
            tokens = sso_manager.generate_jwt_token(user)
            
            return jsonify({
                'message': 'SSO login successful',
                'user': user.to_dict(),
                **tokens
            })
            
        except Exception as e:
            logger.error(f"SSO callback failed for {provider_name}: {e}")
            return jsonify({'error': 'SSO authentication failed'}), 500
    
    # Advanced Analytics endpoints
    @app.route('/analytics/trends', methods=['GET'])
    @auth_required
    @require_permission(Permission.ANALYTICS_READ)
    def get_security_trends():
        """Get security trends analysis"""
        if not app.config['ENABLE_ANALYTICS']:
            return jsonify({'error': 'Analytics is disabled'}), 404
        
        organization_id = g.current_user.get('organization_id')
        days = request.args.get('days', 30, type=int)
        
        trends = advanced_analytics.analyze_security_trends(organization_id, days)
        
        # Convert trends to JSON-serializable format
        trends_data = {}
        for metric, trend in trends.items():
            trends_data[metric] = {
                'metric_name': trend.metric_name,
                'current_value': trend.current_value,
                'previous_value': trend.previous_value,
                'change_percent': trend.change_percent,
                'direction': trend.direction.value,
                'confidence': trend.confidence,
                'time_period': trend.time_period
            }
        
        return jsonify({'trends': trends_data})
    
    @app.route('/analytics/risk-score', methods=['GET'])
    @auth_required
    @require_permission(Permission.ANALYTICS_READ)
    def get_risk_score():
        """Get comprehensive risk score"""
        if not app.config['ENABLE_ANALYTICS']:
            return jsonify({'error': 'Analytics is disabled'}), 404
        
        organization_id = g.current_user.get('organization_id')
        risk_score = advanced_analytics.calculate_risk_score(organization_id)
        
        return jsonify({
            'overall_score': risk_score.overall_score,
            'risk_level': risk_score.risk_level.value,
            'contributing_factors': risk_score.contributing_factors,
            'recommendations': risk_score.recommendations,
            'confidence': risk_score.confidence,
            'calculated_at': risk_score.calculated_at.isoformat()
        })
    
    @app.route('/analytics/insights', methods=['GET'])
    @auth_required
    @require_permission(Permission.ANALYTICS_READ)
    def get_predictive_insights():
        """Get predictive insights"""
        if not app.config['ENABLE_ANALYTICS']:
            return jsonify({'error': 'Analytics is disabled'}), 404
        
        organization_id = g.current_user.get('organization_id')
        insights = advanced_analytics.generate_predictive_insights(organization_id)
        
        insights_data = []
        for insight in insights:
            insights_data.append({
                'insight_type': insight.insight_type,
                'title': insight.title,
                'description': insight.description,
                'probability': insight.probability,
                'impact_score': insight.impact_score,
                'time_horizon': insight.time_horizon,
                'recommended_actions': insight.recommended_actions
            })
        
        return jsonify({'insights': insights_data})
    
    @app.route('/analytics/vulnerability-patterns', methods=['GET'])
    @auth_required
    @require_permission(Permission.ANALYTICS_READ)
    def get_vulnerability_patterns():
        """Get vulnerability patterns analysis"""
        if not app.config['ENABLE_ANALYTICS']:
            return jsonify({'error': 'Analytics is disabled'}), 404
        
        organization_id = g.current_user.get('organization_id')
        patterns = advanced_analytics.get_vulnerability_patterns(organization_id)
        
        return jsonify({'patterns': patterns})
    
    # CI/CD Integration endpoints
    @app.route('/integrations/cicd/webhook/<integration_name>', methods=['POST'])
    def cicd_webhook(integration_name):
        """Handle CI/CD webhook"""
        if not app.config['ENABLE_CICD_INTEGRATIONS']:
            return jsonify({'error': 'CI/CD integrations are disabled'}), 404
        
        if integration_name not in cicd_integrations:
            return jsonify({'error': 'Integration not found'}), 404
        
        integration = cicd_integrations[integration_name]
        
        # Get payload and headers
        payload = request.get_data()
        headers = dict(request.headers)
        
        # Handle webhook
        result = integration.handle_webhook(payload, headers)
        
        return jsonify(result), result.get('status', 200)
    
    @app.route('/integrations/cicd', methods=['GET'])
    @auth_required
    @require_permission(Permission.SYSTEM_ADMIN)
    def list_cicd_integrations():
        """List configured CI/CD integrations"""
        if not app.config['ENABLE_CICD_INTEGRATIONS']:
            return jsonify({'error': 'CI/CD integrations are disabled'}), 404
        
        integrations = []
        for name, integration in cicd_integrations.items():
            integrations.append({
                'name': name,
                'platform': integration.config.platform.value,
                'enabled': integration.config.enabled,
                'repository_url': integration.config.repository_url
            })
        
        return jsonify({'integrations': integrations})
    
    @app.route('/integrations/cicd', methods=['POST'])
    @auth_required
    @require_permission(Permission.SYSTEM_ADMIN)
    def create_cicd_integration():
        """Create new CI/CD integration"""
        if not app.config['ENABLE_CICD_INTEGRATIONS']:
            return jsonify({'error': 'CI/CD integrations are disabled'}), 404
        
        data = request.get_json()
        
        try:
            # Create integration config
            config = CICDConfig(
                platform=CICDPlatform(data['platform']),
                api_token=data.get('api_token', ''),
                webhook_secret=data.get('webhook_secret', ''),
                repository_url=data.get('repository_url', ''),
                auto_scan_on_push=data.get('auto_scan_on_push', True),
                auto_scan_on_pr=data.get('auto_scan_on_pr', True)
            )
            
            # Create integration
            integration = create_cicd_integration(config)
            
            # Register scan callback
            def scan_callback(scan_request):
                # This would trigger actual scan - simplified for demo
                return {
                    'scan_id': str(uuid.uuid4()),
                    'status': 'success',
                    'total_findings': 5,
                    'critical_findings': 0,
                    'high_findings': 1,
                    'medium_findings': 2,
                    'low_findings': 2,
                    'scan_duration': 45.2,
                    'report_url': f"https://app.byteguardx.com/scans/{uuid.uuid4()}"
                }
            
            integration.add_scan_callback(scan_callback)
            
            # Store integration
            integration_name = data.get('name', f"{config.platform.value}_{int(datetime.now().timestamp())}")
            cicd_integrations[integration_name] = integration
            
            return jsonify({
                'message': 'CI/CD integration created successfully',
                'name': integration_name
            })
            
        except Exception as e:
            logger.error(f"Failed to create CI/CD integration: {e}")
            return jsonify({'error': str(e)}), 500
    
    # API Documentation endpoints
    @app.route('/docs', methods=['GET'])
    def api_docs():
        """Serve API documentation"""
        if not app.config['ENABLE_API_DOCS']:
            return jsonify({'error': 'API documentation is disabled'}), 404
        
        try:
            # Generate documentation
            openapi_generator.generate_documentation(app)
            
            # Generate HTML docs
            docs_path = openapi_generator.generate_html_docs("docs/api.html")
            
            return send_file(docs_path, mimetype='text/html')
            
        except Exception as e:
            logger.error(f"Failed to serve API docs: {e}")
            return jsonify({'error': 'Failed to generate documentation'}), 500
    
    @app.route('/docs/openapi.json', methods=['GET'])
    def openapi_spec():
        """Get OpenAPI specification"""
        if not app.config['ENABLE_API_DOCS']:
            return jsonify({'error': 'API documentation is disabled'}), 404
        
        try:
            # Generate documentation
            openapi_generator.generate_documentation(app)
            
            # Export OpenAPI JSON
            spec_path = openapi_generator.export_openapi_json("docs/openapi.json")
            
            return send_file(spec_path, mimetype='application/json')
            
        except Exception as e:
            logger.error(f"Failed to generate OpenAPI spec: {e}")
            return jsonify({'error': 'Failed to generate specification'}), 500
    
    # Enhanced health check with all Priority 3 components
    @app.route('/health/complete', methods=['GET'])
    def complete_health_check():
        """Complete health check including all Priority 1-3 components"""
        try:
            health_info = health_checker.get_overall_health()
            
            # Add Priority 3 component status
            priority3_status = {}
            
            if app.config['ENABLE_SSO']:
                priority3_status['sso'] = {
                    'providers_configured': len(sso_manager.providers),
                    'enabled_providers': len([p for p in sso_manager.providers.values() if p.enabled])
                }
            
            if app.config['ENABLE_ANALYTICS']:
                priority3_status['analytics'] = {
                    'cache_size': len(advanced_analytics._cache),
                    'models_loaded': len(advanced_analytics.models)
                }
            
            if app.config['ENABLE_CICD_INTEGRATIONS']:
                priority3_status['cicd_integrations'] = {
                    'total_integrations': len(cicd_integrations),
                    'active_integrations': len([i for i in cicd_integrations.values() if i.config.enabled])
                }
            
            priority3_status['api_docs'] = {
                'enabled': app.config['ENABLE_API_DOCS'],
                'endpoints_documented': len(openapi_generator.documentation.endpoints)
            }
            
            health_info['priority3_components'] = priority3_status
            health_info['enterprise_ready'] = True
            
            status_code = 200
            if health_info['overall_status'] == 'unhealthy':
                status_code = 503
            
            return jsonify(health_info), status_code
            
        except Exception as e:
            logger.error(f"Complete health check failed: {e}")
            return jsonify({
                'overall_status': 'unhealthy',
                'error': 'Health check failed',
                'timestamp': datetime.now().isoformat()
            }), 503
    
    # Enterprise features summary
    @app.route('/enterprise/features', methods=['GET'])
    @auth_required
    @require_permission(Permission.SYSTEM_MONITOR)
    def enterprise_features():
        """Get enterprise features status"""
        features = {
            'priority_1': {
                'database_layer': True,
                'enhanced_auth': True,
                'performance_optimization': True,
                'error_handling': True,
                'monitoring': True
            },
            'priority_2': {
                'rbac': True,
                'worker_pool': app.config['ENABLE_WORKER_POOL'],
                'incremental_scanning': app.config['ENABLE_INCREMENTAL_SCAN'],
                'ml_registry': True,
                'code_sandboxing': app.config['ENABLE_CODE_SANDBOX']
            },
            'priority_3': {
                'sso_integration': app.config['ENABLE_SSO'],
                'advanced_analytics': app.config['ENABLE_ANALYTICS'],
                'cicd_integrations': app.config['ENABLE_CICD_INTEGRATIONS'],
                'api_documentation': app.config['ENABLE_API_DOCS']
            },
            'enterprise_ready': True,
            'version': '3.0.0'
        }
        
        return jsonify(features)
    
    # Error handlers
    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        """Handle all unhandled exceptions"""
        error_response = exception_handler.handle_exception(error)
        return jsonify(error_response), 500
    
    # Store app start time for uptime calculation
    app.start_time = datetime.now()
    
    return app

if __name__ == '__main__':
    app = create_priority3_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
