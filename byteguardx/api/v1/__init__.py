"""
ByteGuardX API v1
Versioned API endpoints with schema validation and backward compatibility
"""

from flask import Blueprint, jsonify
from marshmallow import Schema, fields, ValidationError
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Create v1 API blueprint
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

class APIResponse(Schema):
    """Standard API response schema"""
    success = fields.Boolean(required=True)
    data = fields.Raw(allow_none=True)
    error = fields.String(allow_none=True)
    version = fields.String(default="1.0")
    timestamp = fields.DateTime(dump_default=lambda: __import__('datetime').datetime.now())

class ScanRequestSchema(Schema):
    """Scan request validation schema"""
    directory_path = fields.String(required=True)
    recursive = fields.Boolean(default=True)
    include_secrets = fields.Boolean(default=True)
    include_dependencies = fields.Boolean(default=True)
    include_ai_patterns = fields.Boolean(default=True)
    generate_fixes = fields.Boolean(default=False)
    output_format = fields.String(validate=lambda x: x in ['json', 'pdf'], default='json')

class UserCreateSchema(Schema):
    """User creation validation schema"""
    email = fields.Email(required=True)
    username = fields.String(required=True, validate=lambda x: len(x) >= 3)
    password = fields.String(required=True, validate=lambda x: len(x) >= 8)
    role = fields.String(validate=lambda x: x in ['admin', 'manager', 'developer', 'viewer'], default='developer')

def validate_schema(schema_class):
    """Decorator for request schema validation"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                from flask import request
                schema = schema_class()
                
                if request.is_json:
                    data = schema.load(request.get_json() or {})
                else:
                    data = schema.load(request.form.to_dict())
                
                # Add validated data to kwargs
                kwargs['validated_data'] = data
                return f(*args, **kwargs)
                
            except ValidationError as e:
                return jsonify({
                    'success': False,
                    'error': 'Validation failed',
                    'details': e.messages,
                    'version': '1.0'
                }), 400
            except Exception as e:
                logger.error(f"Schema validation error: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Invalid request format',
                    'version': '1.0'
                }), 400
        
        return decorated
    return decorator

def api_response(data=None, error=None, status_code=200):
    """Standard API response formatter"""
    response_data = {
        'success': error is None,
        'data': data,
        'error': error,
        'version': '1.0',
        'timestamp': __import__('datetime').datetime.now().isoformat()
    }
    return jsonify(response_data), status_code

# API versioning info endpoint
@api_v1.route('/info', methods=['GET'])
def api_info():
    """API version information"""
    return api_response({
        'version': '1.0',
        'name': 'ByteGuardX API',
        'description': 'Enterprise security scanning API',
        'supported_formats': ['json', 'pdf'],
        'authentication': 'JWT Bearer Token',
        'rate_limits': {
            'default': '1000/hour',
            'admin': '5000/hour'
        },
        'deprecation_notice': None,
        'migration_guide': None
    })

# Health check for v1
@api_v1.route('/health', methods=['GET'])
def health_check():
    """API v1 health check"""
    return api_response({
        'status': 'healthy',
        'version': '1.0',
        'components': {
            'database': 'healthy',
            'cache': 'healthy',
            'plugins': 'healthy'
        }
    })

# Error handlers for v1
@api_v1.errorhandler(404)
def not_found(error):
    return api_response(error="Endpoint not found in API v1", status_code=404)

@api_v1.errorhandler(405)
def method_not_allowed(error):
    return api_response(error="Method not allowed", status_code=405)

@api_v1.errorhandler(500)
def internal_error(error):
    return api_response(error="Internal server error", status_code=500)
