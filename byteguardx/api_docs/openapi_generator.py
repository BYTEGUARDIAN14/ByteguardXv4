"""
OpenAPI/Swagger documentation generator for ByteGuardX API
Automatically generates comprehensive API documentation
"""

import logging
import json
import yaml
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import inspect
from flask import Flask
import re

logger = logging.getLogger(__name__)

@dataclass
class APIEndpoint:
    """API endpoint information"""
    path: str
    method: str
    function_name: str
    summary: str
    description: str
    tags: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    security: List[Dict[str, Any]] = field(default_factory=list)
    deprecated: bool = False

@dataclass
class APIDocumentation:
    """Complete API documentation"""
    title: str
    version: str
    description: str
    base_url: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    schemas: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    security_schemes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tags: List[Dict[str, str]] = field(default_factory=list)

class OpenAPIGenerator:
    """
    OpenAPI 3.0 documentation generator for ByteGuardX API
    Automatically extracts API information from Flask routes and generates documentation
    """
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.documentation = APIDocumentation(
            title="ByteGuardX API",
            version="3.0.0",
            description="Enterprise-grade vulnerability scanning platform API",
            base_url="https://api.byteguardx.com"
        )
        
        # Initialize default schemas and security
        self._init_default_schemas()
        self._init_security_schemes()
        self._init_tags()
    
    def generate_documentation(self, app: Flask = None) -> APIDocumentation:
        """Generate complete API documentation from Flask app"""
        if app:
            self.app = app
        
        if not self.app:
            raise ValueError("Flask app is required")
        
        # Extract endpoints from Flask routes
        self._extract_endpoints()
        
        return self.documentation
    
    def export_openapi_json(self, output_path: str = "docs/openapi.json") -> str:
        """Export documentation as OpenAPI JSON"""
        try:
            openapi_spec = self._build_openapi_spec()
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(openapi_spec, f, indent=2)
            
            logger.info(f"Exported OpenAPI JSON to {output_path}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to export OpenAPI JSON: {e}")
            raise
    
    def export_openapi_yaml(self, output_path: str = "docs/openapi.yaml") -> str:
        """Export documentation as OpenAPI YAML"""
        try:
            openapi_spec = self._build_openapi_spec()
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                yaml.dump(openapi_spec, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Exported OpenAPI YAML to {output_path}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to export OpenAPI YAML: {e}")
            raise
    
    def generate_html_docs(self, output_path: str = "docs/api.html") -> str:
        """Generate HTML documentation using Swagger UI"""
        try:
            # Generate OpenAPI spec
            openapi_spec = self._build_openapi_spec()
            
            # Create HTML with embedded Swagger UI
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.documentation.title} - API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {{
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }}
        *, *:before, *:after {{
            box-sizing: inherit;
        }}
        body {{
            margin:0;
            background: #fafafa;
        }}
        .swagger-ui .topbar {{
            background-color: #1a1a1a;
        }}
        .swagger-ui .topbar .download-url-wrapper .download-url-button {{
            background-color: #00d4aa;
            border-color: #00d4aa;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                spec: {json.dumps(openapi_spec)},
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                theme: "dark"
            }});
        }};
    </script>
</body>
</html>"""
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Generated HTML documentation at {output_path}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to generate HTML docs: {e}")
            raise
    
    def _extract_endpoints(self):
        """Extract API endpoints from Flask routes"""
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint == 'static':
                continue
            
            # Get view function
            view_func = self.app.view_functions.get(rule.endpoint)
            if not view_func:
                continue
            
            # Extract endpoint information
            for method in rule.methods:
                if method in ['HEAD', 'OPTIONS']:
                    continue
                
                endpoint = self._analyze_endpoint(rule, method, view_func)
                if endpoint:
                    self.documentation.endpoints.append(endpoint)
    
    def _analyze_endpoint(self, rule, method: str, view_func) -> Optional[APIEndpoint]:
        """Analyze individual endpoint"""
        try:
            # Get function info
            func_name = view_func.__name__
            docstring = inspect.getdoc(view_func) or ""
            
            # Parse path parameters
            parameters = []
            path = str(rule.rule)
            
            # Extract path parameters
            path_params = re.findall(r'<([^>]+)>', path)
            for param in path_params:
                param_name = param.split(':')[-1]  # Remove type hint if present
                parameters.append({
                    'name': param_name,
                    'in': 'path',
                    'required': True,
                    'schema': {'type': 'string'},
                    'description': f'Path parameter: {param_name}'
                })
                # Convert to OpenAPI format
                path = path.replace(f'<{param}>', f'{{{param_name}}}')
            
            # Determine tags based on path
            tags = self._determine_tags(path)
            
            # Parse docstring for summary and description
            summary, description = self._parse_docstring(docstring)
            
            # Determine security requirements
            security = []
            if hasattr(view_func, '__wrapped__'):  # Check for decorators
                # Look for auth decorators
                if any(decorator.__name__ in ['auth_required', 'admin_required'] 
                      for decorator in getattr(view_func, '__decorators__', [])):
                    security.append({'BearerAuth': []})
            
            # Add query parameters for GET requests
            if method == 'GET':
                parameters.extend(self._get_common_query_params(path))
            
            # Add request body for POST/PUT requests
            request_body = None
            if method in ['POST', 'PUT', 'PATCH']:
                request_body = self._get_request_body_schema(path, func_name)
            
            # Define responses
            responses = self._get_response_schemas(path, method)
            
            return APIEndpoint(
                path=path,
                method=method.lower(),
                function_name=func_name,
                summary=summary,
                description=description,
                tags=tags,
                parameters=parameters,
                request_body=request_body,
                responses=responses,
                security=security
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze endpoint {rule.rule} {method}: {e}")
            return None
    
    def _determine_tags(self, path: str) -> List[str]:
        """Determine API tags based on path"""
        if path.startswith('/auth'):
            return ['Authentication']
        elif path.startswith('/scan'):
            return ['Scanning']
        elif path.startswith('/ml'):
            return ['Machine Learning']
        elif path.startswith('/rbac'):
            return ['Access Control']
        elif path.startswith('/health'):
            return ['Monitoring']
        elif path.startswith('/analytics'):
            return ['Analytics']
        elif path.startswith('/integrations'):
            return ['Integrations']
        elif path.startswith('/enterprise'):
            return ['Enterprise']
        else:
            return ['General']
    
    def _parse_docstring(self, docstring: str) -> tuple[str, str]:
        """Parse docstring into summary and description"""
        if not docstring:
            return "API endpoint", "API endpoint description"
        
        lines = docstring.strip().split('\n')
        summary = lines[0].strip()
        
        # Get description from remaining lines
        description_lines = [line.strip() for line in lines[1:] if line.strip()]
        description = ' '.join(description_lines) if description_lines else summary
        
        return summary, description
    
    def _get_common_query_params(self, path: str) -> List[Dict[str, Any]]:
        """Get common query parameters for GET endpoints"""
        params = []
        
        # Pagination parameters
        if any(keyword in path for keyword in ['/list', '/search', '/history']):
            params.extend([
                {
                    'name': 'page',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'integer', 'minimum': 1, 'default': 1},
                    'description': 'Page number for pagination'
                },
                {
                    'name': 'limit',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 20},
                    'description': 'Number of items per page'
                }
            ])
        
        # Filtering parameters
        if '/scan' in path:
            params.extend([
                {
                    'name': 'status',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string', 'enum': ['pending', 'running', 'completed', 'failed']},
                    'description': 'Filter by scan status'
                },
                {
                    'name': 'severity',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                    'description': 'Filter by finding severity'
                }
            ])
        
        return params
    
    def _get_request_body_schema(self, path: str, func_name: str) -> Optional[Dict[str, Any]]:
        """Get request body schema for POST/PUT endpoints"""
        # Define schemas based on endpoint patterns
        if '/auth/login' in path:
            return {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/LoginRequest'}
                    }
                }
            }
        elif '/scan/directory' in path:
            return {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ScanRequest'}
                    }
                }
            }
        elif '/ml/experiments' in path:
            return {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ExperimentRequest'}
                    }
                }
            }
        else:
            # Generic request body
            return {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
    
    def _get_response_schemas(self, path: str, method: str) -> Dict[str, Dict[str, Any]]:
        """Get response schemas for endpoint"""
        responses = {
            '400': {
                'description': 'Bad Request',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            },
            '401': {
                'description': 'Unauthorized',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            },
            '500': {
                'description': 'Internal Server Error',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            }
        }
        
        # Add success responses based on endpoint
        if method == 'GET':
            if '/health' in path:
                responses['200'] = {
                    'description': 'Health check response',
                    'content': {
                        'application/json': {
                            'schema': {'$ref': '#/components/schemas/HealthResponse'}
                        }
                    }
                }
            elif '/scan' in path and 'results' in path:
                responses['200'] = {
                    'description': 'Scan results',
                    'content': {
                        'application/json': {
                            'schema': {'$ref': '#/components/schemas/ScanResults'}
                        }
                    }
                }
            else:
                responses['200'] = {
                    'description': 'Successful response',
                    'content': {
                        'application/json': {
                            'schema': {'type': 'object'}
                        }
                    }
                }
        elif method == 'POST':
            responses['201'] = {
                'description': 'Created successfully',
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
        
        return responses
    
    def _build_openapi_spec(self) -> Dict[str, Any]:
        """Build complete OpenAPI specification"""
        spec = {
            'openapi': '3.0.3',
            'info': {
                'title': self.documentation.title,
                'version': self.documentation.version,
                'description': self.documentation.description,
                'contact': {
                    'name': 'ByteGuardX Support',
                    'email': 'support@byteguardx.com',
                    'url': 'https://byteguardx.com/support'
                },
                'license': {
                    'name': 'Commercial License',
                    'url': 'https://byteguardx.com/license'
                }
            },
            'servers': [
                {
                    'url': self.documentation.base_url,
                    'description': 'Production server'
                },
                {
                    'url': 'http://localhost:5000',
                    'description': 'Development server'
                }
            ],
            'tags': self.documentation.tags,
            'paths': {},
            'components': {
                'schemas': self.documentation.schemas,
                'securitySchemes': self.documentation.security_schemes
            }
        }
        
        # Add paths
        for endpoint in self.documentation.endpoints:
            if endpoint.path not in spec['paths']:
                spec['paths'][endpoint.path] = {}
            
            spec['paths'][endpoint.path][endpoint.method] = {
                'summary': endpoint.summary,
                'description': endpoint.description,
                'tags': endpoint.tags,
                'operationId': f"{endpoint.method}_{endpoint.function_name}",
                'parameters': endpoint.parameters,
                'responses': endpoint.responses
            }
            
            if endpoint.request_body:
                spec['paths'][endpoint.path][endpoint.method]['requestBody'] = endpoint.request_body
            
            if endpoint.security:
                spec['paths'][endpoint.path][endpoint.method]['security'] = endpoint.security
            
            if endpoint.deprecated:
                spec['paths'][endpoint.path][endpoint.method]['deprecated'] = True
        
        return spec
    
    def _init_default_schemas(self):
        """Initialize default API schemas"""
        self.documentation.schemas.update({
            'ErrorResponse': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'boolean', 'example': True},
                    'error_code': {'type': 'string', 'example': 'VALIDATION_ERROR'},
                    'message': {'type': 'string', 'example': 'Invalid input data'},
                    'timestamp': {'type': 'string', 'format': 'date-time'}
                },
                'required': ['error', 'message']
            },
            'LoginRequest': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'format': 'email'},
                    'password': {'type': 'string', 'minLength': 8}
                },
                'required': ['email', 'password']
            },
            'ScanRequest': {
                'type': 'object',
                'properties': {
                    'directory_path': {'type': 'string'},
                    'recursive': {'type': 'boolean', 'default': True},
                    'use_cache': {'type': 'boolean', 'default': True},
                    'use_incremental': {'type': 'boolean', 'default': True},
                    'priority': {'type': 'string', 'enum': ['low', 'normal', 'high', 'critical'], 'default': 'normal'}
                },
                'required': ['directory_path']
            },
            'ScanResults': {
                'type': 'object',
                'properties': {
                    'scan_id': {'type': 'string'},
                    'status': {'type': 'string', 'enum': ['pending', 'running', 'completed', 'failed']},
                    'total_files': {'type': 'integer'},
                    'total_findings': {'type': 'integer'},
                    'critical_findings': {'type': 'integer'},
                    'high_findings': {'type': 'integer'},
                    'medium_findings': {'type': 'integer'},
                    'low_findings': {'type': 'integer'},
                    'scan_duration': {'type': 'number'},
                    'findings': {
                        'type': 'array',
                        'items': {'$ref': '#/components/schemas/Finding'}
                    }
                }
            },
            'Finding': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'vulnerability_type': {'type': 'string'},
                    'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
                    'title': {'type': 'string'},
                    'description': {'type': 'string'},
                    'file_path': {'type': 'string'},
                    'line_number': {'type': 'integer'},
                    'code_snippet': {'type': 'string'},
                    'confidence_score': {'type': 'number', 'minimum': 0, 'maximum': 1}
                }
            },
            'HealthResponse': {
                'type': 'object',
                'properties': {
                    'overall_status': {'type': 'string', 'enum': ['healthy', 'degraded', 'unhealthy']},
                    'timestamp': {'type': 'string', 'format': 'date-time'},
                    'components': {'type': 'object'},
                    'uptime_seconds': {'type': 'number'}
                }
            },
            'ExperimentRequest': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'description': {'type': 'string'},
                    'model_type': {'type': 'string'},
                    'dataset_config': {'type': 'object'},
                    'training_config': {'type': 'object'}
                },
                'required': ['name', 'description', 'model_type']
            }
        })
    
    def _init_security_schemes(self):
        """Initialize security schemes"""
        self.documentation.security_schemes.update({
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
                'description': 'JWT token obtained from /auth/login endpoint'
            },
            'ApiKeyAuth': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-API-Key',
                'description': 'API key for programmatic access'
            }
        })
    
    def _init_tags(self):
        """Initialize API tags"""
        self.documentation.tags.extend([
            {'name': 'Authentication', 'description': 'User authentication and authorization'},
            {'name': 'Scanning', 'description': 'Vulnerability scanning operations'},
            {'name': 'Machine Learning', 'description': 'ML model management and experiments'},
            {'name': 'Access Control', 'description': 'Role-based access control'},
            {'name': 'Monitoring', 'description': 'Health checks and system monitoring'},
            {'name': 'Analytics', 'description': 'Security analytics and insights'},
            {'name': 'Integrations', 'description': 'External service integrations'},
            {'name': 'Enterprise', 'description': 'Enterprise features and SSO'},
            {'name': 'General', 'description': 'General API operations'}
        ])

# Global documentation generator
openapi_generator = OpenAPIGenerator()
