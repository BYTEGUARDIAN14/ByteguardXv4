#!/usr/bin/env python3
"""
Minimal API Test
Test just the plugin endpoints in isolation
"""

import sys
import os
from flask import Flask, jsonify

# Add ByteGuardX to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_minimal_app():
    """Create minimal Flask app with just plugin endpoints"""
    
    app = Flask(__name__)
    
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({'status': 'healthy'})
    
    @app.route('/api/v2/plugins', methods=['GET'])
    def list_plugins():
        """Get list of available plugins"""
        try:
            print("DEBUG: list_plugins called")
            
            # Import plugin registry
            from byteguardx.plugins.plugin_registry import get_plugin_marketplace_data
            
            # Get marketplace data
            marketplace_data = get_plugin_marketplace_data()
            print(f"DEBUG: Got marketplace data: {marketplace_data['statistics']}")
            
            return jsonify({
                'status': 'success',
                'marketplace': marketplace_data,
                'api_version': 'v2'
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
        try:
            print("DEBUG: get_plugin_stats called")
            
            from byteguardx.plugins.plugin_registry import get_plugin_execution_stats
            
            stats = get_plugin_execution_stats()
            print(f"DEBUG: Got plugin stats: {stats['total_executions']} executions")
            
            return jsonify({
                'status': 'success',
                'stats': stats,
                'api_version': 'v2'
            })
            
        except Exception as e:
            print(f"DEBUG: Plugin stats error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'error': 'Failed to get plugin stats',
                'details': str(e)
            }), 500
    
    return app

if __name__ == '__main__':
    print("🔧 Starting Minimal API Test Server")
    print("=" * 40)
    
    app = create_minimal_app()
    
    # Show registered routes
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        methods = [m for m in rule.methods if m not in ['HEAD', 'OPTIONS']]
        print(f"  {rule.rule} [{', '.join(methods)}]")
    
    print("\n🚀 Starting server on http://localhost:5001")
    print("Test endpoints:")
    print("  http://localhost:5001/api/health")
    print("  http://localhost:5001/api/v2/plugins")
    print("  http://localhost:5001/api/v2/plugins/stats")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
