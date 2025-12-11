#!/usr/bin/env python3
"""
Standalone Plugin API Server
Test the plugin endpoints in complete isolation
"""

import sys
import os
from flask import Flask, jsonify, request

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_standalone_app():
    """Create standalone Flask app with just plugin endpoints"""
    
    app = Flask(__name__)
    
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({'status': 'standalone healthy'})
    
    @app.route('/api/v2/plugins', methods=['GET'])
    def list_plugins():
        """Get list of available plugins"""
        print("DEBUG: Standalone list_plugins called!")
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
            
            marketplace_data = get_plugin_marketplace_data()
            print(f"DEBUG: Got marketplace data: {marketplace_data['statistics']}")
            
            return jsonify({
                'status': 'success',
                'marketplace': marketplace_data,
                'api_version': 'v2-standalone'
            })
            
        except Exception as e:
            print(f"DEBUG: Plugin list error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'error': 'Failed to get plugin list',
                'details': str(e)
            }), 500
    
    @app.route('/api/v2/plugins/stats', methods=['GET'])
    def get_plugin_stats():
        """Get plugin execution statistics"""
        print("DEBUG: Standalone get_plugin_stats called!")
        try:
            from byteguardx.plugins.plugin_registry import get_plugin_execution_stats
            
            stats = get_plugin_execution_stats()
            print(f"DEBUG: Got plugin stats: {stats['total_executions']} executions")
            
            return jsonify({
                'status': 'success',
                'stats': stats,
                'api_version': 'v2-standalone'
            })
            
        except Exception as e:
            print(f"DEBUG: Plugin stats error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'error': 'Failed to get plugin stats',
                'details': str(e)
            }), 500
    
    @app.route('/api/scan/file', methods=['POST'])
    def scan_file():
        """Enhanced file scanning endpoint"""
        print("DEBUG: Standalone scan_file called!")
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            content = data.get('content', '')
            file_path = data.get('file_path', 'unknown')
            
            if not content:
                return jsonify({'error': 'No content to scan'}), 400
            
            # Mock scan results for testing
            findings = [
                {
                    'title': 'Test Finding',
                    'description': 'This is a test finding from standalone API',
                    'severity': 'medium',
                    'confidence': 0.8,
                    'file_path': file_path,
                    'line_number': 1,
                    'context': content[:100],
                    'scanner_name': 'standalone_scanner'
                }
            ]
            
            return jsonify({
                'status': 'success',
                'findings': findings,
                'summary': {'critical': 0, 'high': 0, 'medium': 1, 'low': 0},
                'scan_info': {
                    'file_path': file_path,
                    'total_findings': len(findings)
                }
            })
            
        except Exception as e:
            print(f"DEBUG: Scan error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'error': 'Scan failed',
                'details': str(e)
            }), 500
    
    return app

if __name__ == '__main__':
    print("🔧 Starting Standalone Plugin API Server")
    print("=" * 50)
    
    app = create_standalone_app()
    
    # Show registered routes
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        methods = [m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]
        print(f"  {rule.rule} [{', '.join(methods)}]")
    
    print("\n🚀 Starting server on http://localhost:5002")
    print("Test endpoints:")
    print("  http://localhost:5002/api/health")
    print("  http://localhost:5002/api/v2/plugins")
    print("  http://localhost:5002/api/v2/plugins/stats")
    print("  http://localhost:5002/api/scan/file (POST)")
    
    app.run(host='0.0.0.0', port=5002, debug=True)
