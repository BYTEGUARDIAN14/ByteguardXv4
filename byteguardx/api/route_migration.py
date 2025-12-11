"""
Route Migration Script for ByteGuardX API v1
Updates existing routes to use /api/v1/ namespace while maintaining backward compatibility
"""

import logging
from flask import Blueprint, request, jsonify, redirect, url_for
from functools import wraps

logger = logging.getLogger(__name__)

# Create backward compatibility blueprint
legacy_bp = Blueprint('legacy_api', __name__)

def create_legacy_redirect(new_endpoint):
    """Create a redirect from legacy endpoint to v1 endpoint"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Log the legacy usage
            logger.warning(f"Legacy API endpoint accessed: {request.path} -> /api/v1{request.path}")
            
            # Return deprecation notice with redirect
            return jsonify({
                'deprecated': True,
                'message': f'This endpoint is deprecated. Please use /api/v1{request.path}',
                'new_endpoint': f'/api/v1{request.path}',
                'migration_guide': 'https://docs.byteguardx.com/api/migration',
                'deprecation_date': '2024-06-01',
                'removal_date': '2024-12-01'
            }), 301, {'Location': f'/api/v1{request.path}'}
        return wrapper
    return decorator

# Legacy route redirects
@legacy_bp.route('/health', methods=['GET'])
@create_legacy_redirect('/api/v1/health')
def legacy_health():
    pass

@legacy_bp.route('/scan', methods=['POST'])
@create_legacy_redirect('/api/v1/scan')
def legacy_scan():
    pass

@legacy_bp.route('/scan/results/<scan_id>', methods=['GET'])
@create_legacy_redirect('/api/v1/scan/results')
def legacy_scan_results(scan_id):
    pass

@legacy_bp.route('/scan/list', methods=['GET'])
@create_legacy_redirect('/api/v1/scan/list')
def legacy_scan_list():
    pass

@legacy_bp.route('/api/admin/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@create_legacy_redirect('/api/v1/admin')
def legacy_admin(path):
    pass

@legacy_bp.route('/api/plugins/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@create_legacy_redirect('/api/v1/plugins')
def legacy_plugins(path):
    pass

@legacy_bp.route('/api/scheduler/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@create_legacy_redirect('/api/v1/scheduler')
def legacy_scheduler(path):
    pass

@legacy_bp.route('/api/deploy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@create_legacy_redirect('/api/v1/deploy')
def legacy_deploy(path):
    pass

def update_route_blueprints(app):
    """Update existing route blueprints to use v1 namespace"""
    
    # Import v1 API blueprint
    from .v1 import api_v1
    from .v1.security_routes import security_bp
    
    # Register v1 API
    app.register_blueprint(api_v1)
    
    # Update existing blueprints to use v1 namespace
    update_admin_routes(app)
    update_plugin_routes(app)
    update_scheduler_routes(app)
    update_deploy_routes(app)
    update_main_routes(app)
    
    # Register legacy redirects
    app.register_blueprint(legacy_bp)
    
    logger.info("API routes migrated to v1 namespace with backward compatibility")

def update_admin_routes(app):
    """Update admin routes to v1"""
    try:
        from .admin_routes import admin_bp
        
        # Update blueprint URL prefix
        admin_bp.url_prefix = '/api/v1/admin'
        
        # Apply zero trust to all admin routes
        from ..security.zero_trust_enforcement import deny_by_default
        
        # Wrap all admin route functions with zero trust
        for rule in admin_bp.url_map.iter_rules():
            if rule.endpoint.startswith('admin.'):
                endpoint_func = app.view_functions.get(rule.endpoint)
                if endpoint_func:
                    app.view_functions[rule.endpoint] = deny_by_default(endpoint_func)
        
        app.register_blueprint(admin_bp)
        logger.info("Admin routes updated to v1 with zero trust")
        
    except ImportError as e:
        logger.warning(f"Admin routes not found: {e}")

def update_plugin_routes(app):
    """Update plugin routes to v1"""
    try:
        from .plugin_routes import plugin_bp
        
        # Update blueprint URL prefix
        plugin_bp.url_prefix = '/api/v1/plugins'
        
        # Apply zero trust
        from ..security.zero_trust_enforcement import deny_by_default
        
        for rule in plugin_bp.url_map.iter_rules():
            if rule.endpoint.startswith('plugin.'):
                endpoint_func = app.view_functions.get(rule.endpoint)
                if endpoint_func:
                    app.view_functions[rule.endpoint] = deny_by_default(endpoint_func)
        
        app.register_blueprint(plugin_bp)
        logger.info("Plugin routes updated to v1 with zero trust")
        
    except ImportError as e:
        logger.warning(f"Plugin routes not found: {e}")

def update_scheduler_routes(app):
    """Update scheduler routes to v1"""
    try:
        from .scheduler_routes import scheduler_bp
        
        # Update blueprint URL prefix
        scheduler_bp.url_prefix = '/api/v1/scheduler'
        
        # Apply zero trust
        from ..security.zero_trust_enforcement import deny_by_default
        
        for rule in scheduler_bp.url_map.iter_rules():
            if rule.endpoint.startswith('scheduler.'):
                endpoint_func = app.view_functions.get(rule.endpoint)
                if endpoint_func:
                    app.view_functions[rule.endpoint] = deny_by_default(endpoint_func)
        
        app.register_blueprint(scheduler_bp)
        logger.info("Scheduler routes updated to v1 with zero trust")
        
    except ImportError as e:
        logger.warning(f"Scheduler routes not found: {e}")

def update_deploy_routes(app):
    """Update deploy routes to v1"""
    try:
        from .deploy_routes import deploy_bp
        
        # Update blueprint URL prefix
        deploy_bp.url_prefix = '/api/v1/deploy'
        
        # Apply zero trust
        from ..security.zero_trust_enforcement import deny_by_default
        
        for rule in deploy_bp.url_map.iter_rules():
            if rule.endpoint.startswith('deploy.'):
                endpoint_func = app.view_functions.get(rule.endpoint)
                if endpoint_func:
                    app.view_functions[rule.endpoint] = deny_by_default(endpoint_func)
        
        app.register_blueprint(deploy_bp)
        logger.info("Deploy routes updated to v1 with zero trust")
        
    except ImportError as e:
        logger.warning(f"Deploy routes not found: {e}")

def update_main_routes(app):
    """Update main app routes to v1"""
    try:
        # Create v1 scan routes
        from .v1 import api_v1, api_response, validate_schema, ScanRequestSchema
        from ..security.zero_trust_enforcement import deny_by_default
        
        @api_v1.route('/scan', methods=['POST'])
        @deny_by_default
        @validate_schema(ScanRequestSchema)
        def scan_v1(validated_data):
            """V1 scan endpoint with validation"""
            # Import scan logic from main app
            from .app import create_app
            
            # This would contain the actual scan logic
            # For now, return a placeholder response
            return api_response({
                'scan_id': 'scan_' + str(hash(str(validated_data))),
                'status': 'started',
                'message': 'Scan initiated successfully'
            })
        
        @api_v1.route('/scan/results/<scan_id>', methods=['GET'])
        @deny_by_default
        def get_scan_results_v1(scan_id):
            """V1 get scan results endpoint"""
            # This would contain the actual results logic
            return api_response({
                'scan_id': scan_id,
                'status': 'completed',
                'results': []
            })
        
        @api_v1.route('/scan/list', methods=['GET'])
        @deny_by_default
        def list_scans_v1():
            """V1 list scans endpoint"""
            return api_response({
                'scans': [],
                'total': 0
            })
        
        logger.info("Main scan routes updated to v1 with zero trust")
        
    except Exception as e:
        logger.error(f"Failed to update main routes: {e}")

def create_api_documentation():
    """Generate API documentation for v1"""
    documentation = {
        'openapi': '3.0.0',
        'info': {
            'title': 'ByteGuardX API',
            'version': '1.0.0',
            'description': 'Enterprise Security Scanning API',
            'contact': {
                'name': 'ByteGuardX Support',
                'url': 'https://byteguardx.com/support',
                'email': 'support@byteguardx.com'
            }
        },
        'servers': [
            {
                'url': '/api/v1',
                'description': 'Production API v1'
            }
        ],
        'paths': {
            '/info': {
                'get': {
                    'summary': 'API Information',
                    'description': 'Get API version and capabilities',
                    'responses': {
                        '200': {
                            'description': 'API information',
                            'content': {
                                'application/json': {
                                    'schema': {
                                        'type': 'object',
                                        'properties': {
                                            'success': {'type': 'boolean'},
                                            'data': {
                                                'type': 'object',
                                                'properties': {
                                                    'version': {'type': 'string'},
                                                    'name': {'type': 'string'},
                                                    'description': {'type': 'string'}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            '/scan': {
                'post': {
                    'summary': 'Start Security Scan',
                    'description': 'Initiate a security scan on specified directory',
                    'security': [{'BearerAuth': []}],
                    'requestBody': {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'required': ['directory_path'],
                                    'properties': {
                                        'directory_path': {'type': 'string'},
                                        'recursive': {'type': 'boolean', 'default': True},
                                        'include_secrets': {'type': 'boolean', 'default': True},
                                        'include_dependencies': {'type': 'boolean', 'default': True},
                                        'include_ai_patterns': {'type': 'boolean', 'default': True}
                                    }
                                }
                            }
                        }
                    },
                    'responses': {
                        '200': {
                            'description': 'Scan started successfully'
                        },
                        '400': {
                            'description': 'Invalid request'
                        },
                        '401': {
                            'description': 'Authentication required'
                        }
                    }
                }
            }
        },
        'components': {
            'securitySchemes': {
                'BearerAuth': {
                    'type': 'http',
                    'scheme': 'bearer',
                    'bearerFormat': 'JWT'
                }
            }
        }
    }
    
    return documentation
