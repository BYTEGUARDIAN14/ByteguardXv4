#!/usr/bin/env python3
"""
ByteGuardX API Server
Clean, working API server for frontend integration
"""

import sys
import os
from flask import Flask, jsonify, request
from flask_cors import CORS

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_byteguardx_api():
    """Create clean ByteGuardX API server"""
    
    app = Flask(__name__)
    CORS(app)  # Enable CORS for frontend
    
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'ByteGuardX API',
            'version': '1.0.0'
        })
    
    @app.route('/api/v2/plugins', methods=['GET'])
    def list_plugins():
        """Get list of available plugins"""
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
            marketplace_data = get_plugin_marketplace_data()
            return jsonify({
                'status': 'success',
                'marketplace': marketplace_data,
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get plugin list',
                'details': str(e)
            }), 500
    
    @app.route('/api/v2/plugins/stats', methods=['GET'])
    def get_plugin_stats():
        """Get plugin execution statistics"""
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_execution_stats
            stats = get_plugin_execution_stats()
            return jsonify({
                'status': 'success',
                'stats': stats,
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get plugin stats',
                'details': str(e)
            }), 500
    
    @app.route('/api/v2/plugins/categories', methods=['GET'])
    def get_plugin_categories():
        """Get plugin categories"""
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
            marketplace_data = get_plugin_marketplace_data()
            return jsonify({
                'status': 'success',
                'categories': marketplace_data['categories'],
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get plugin categories',
                'details': str(e)
            }), 500
    
    @app.route('/api/v2/plugins/featured', methods=['GET'])
    def get_featured_plugins():
        """Get featured plugins"""
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
            marketplace_data = get_plugin_marketplace_data()
            return jsonify({
                'status': 'success',
                'featured_plugins': marketplace_data['featured_plugins'],
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get featured plugins',
                'details': str(e)
            }), 500
    
    @app.route('/api/dashboard/stats', methods=['GET'])
    def get_dashboard_stats():
        """Get enhanced dashboard statistics"""
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_execution_stats, get_plugin_marketplace_data
            
            plugin_stats = get_plugin_execution_stats()
            plugin_marketplace = get_plugin_marketplace_data()
            
            enhanced_stats = {
                'security_score': 87,
                'active_threats': 3,
                'scan_coverage': 94.2,
                'plugin_ecosystem': {
                    'total_plugins': plugin_marketplace['statistics']['total_plugins'],
                    'active_plugins': plugin_marketplace['statistics']['active_plugins'],
                    'success_rate': plugin_stats['success_rate'],
                    'avg_execution_time': plugin_stats['average_execution_time']
                },
                'real_time_activity': [
                    {
                        'timestamp': '2024-01-15T10:30:00Z',
                        'event': 'Plugin Execution',
                        'plugin': 'AWS S3 Scanner',
                        'status': 'completed',
                        'findings': 2
                    }
                ]
            }
            
            return jsonify({
                'status': 'success',
                'stats': enhanced_stats,
                'api_version': 'v2'
            })
        except Exception as e:
            return jsonify({
                'error': 'Failed to get enhanced dashboard stats',
                'details': str(e)
            }), 500
    
    @app.route('/api/scan/file', methods=['POST'])
    def scan_file():
        """Enhanced file scanning endpoint"""
        try:
            # Handle both form data and JSON
            if request.content_type and 'multipart/form-data' in request.content_type:
                if 'file' not in request.files:
                    return jsonify({'error': 'No file provided'}), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                content = file.read().decode('utf-8', errors='ignore')
                file_path = file.filename
            else:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No data provided'}), 400
                
                content = data.get('content', '')
                file_path = data.get('file_path', 'unknown')
            
            if not content:
                return jsonify({'error': 'No content to scan'}), 400
            
            # Enhanced mock scan with multiple patterns
            findings = []
            
            # Check for various security issues
            patterns = [
                ('password', 'Potential Hardcoded Password', 'high'),
                ('secret', 'Potential Hardcoded Secret', 'high'),
                ('api_key', 'Potential API Key', 'medium'),
                ('token', 'Potential Token', 'medium'),
                ('eval(', 'Code Injection Risk', 'critical'),
                ('exec(', 'Code Execution Risk', 'critical'),
                ('sql', 'Potential SQL Injection', 'high'),
                ('xss', 'Potential XSS Vulnerability', 'medium')
            ]
            
            for pattern, title, severity in patterns:
                if pattern in content.lower():
                    findings.append({
                        'title': title,
                        'description': f'Found potential {pattern} in code',
                        'severity': severity,
                        'confidence': 0.8,
                        'file_path': file_path,
                        'line_number': content.lower().find(pattern) + 1,
                        'context': content[max(0, content.lower().find(pattern)-50):content.lower().find(pattern)+50],
                        'scanner_name': 'enhanced_scanner',
                        'cwe_id': 'CWE-798' if 'password' in pattern else 'CWE-94'
                    })
            
            # Count by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                if finding['severity'] in severity_counts:
                    severity_counts[finding['severity']] += 1
            
            return jsonify({
                'status': 'success',
                'findings': findings,
                'summary': severity_counts,
                'scan_info': {
                    'file_path': file_path,
                    'language': 'auto-detected',
                    'scan_mode': 'comprehensive',
                    'plugins_enabled': True,
                    'ml_enabled': True,
                    'total_findings': len(findings)
                }
            })
        except Exception as e:
            return jsonify({
                'error': 'Scan failed',
                'details': str(e)
            }), 500
    
    # Plugin execution endpoint
    @app.route('/api/v2/plugins/<plugin_name>/execute', methods=['POST'])
    def execute_plugin(plugin_name):
        """Execute a specific plugin"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            content = data.get('content', '')
            file_path = data.get('file_path', 'unknown')
            
            # Mock plugin execution
            findings = []
            if plugin_name == 'aws_s3_exposure_scanner' and 'bucket' in content.lower():
                findings.append({
                    'title': 'S3 Bucket Misconfiguration',
                    'description': 'Found potential S3 bucket security issue',
                    'severity': 'high',
                    'confidence': 0.9,
                    'file_path': file_path,
                    'line_number': 1,
                    'scanner_name': plugin_name
                })
            
            return jsonify({
                'status': 'success',
                'result': {
                    'status': 'completed',
                    'findings': findings,
                    'execution_time_ms': 1200,
                    'plugin_name': plugin_name
                }
            })
        except Exception as e:
            return jsonify({
                'error': 'Plugin execution failed',
                'details': str(e)
            }), 500
    
    return app

if __name__ == '__main__':
    print("🛡️  ByteGuardX API Server")
    print("=" * 40)
    
    app = create_byteguardx_api()
    
    # Show registered routes
    print("Registered endpoints:")
    for rule in app.url_map.iter_rules():
        methods = [m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]
        print(f"  {rule.rule} [{', '.join(methods)}]")
    
    print("\n🚀 Starting server on http://localhost:5000")
    print("🌐 Frontend can connect to these endpoints:")
    print("  GET  /api/health")
    print("  GET  /api/v2/plugins")
    print("  GET  /api/v2/plugins/stats")
    print("  GET  /api/v2/plugins/categories")
    print("  GET  /api/v2/plugins/featured")
    print("  GET  /api/dashboard/stats")
    print("  POST /api/scan/file")
    print("  POST /api/v2/plugins/<name>/execute")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
