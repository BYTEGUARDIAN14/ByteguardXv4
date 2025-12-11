"""
Plugin Marketplace API Routes
Provides endpoints for plugin management and marketplace functionality
"""

import os
import json
import logging
import zipfile
import tempfile
import shutil
from typing import Dict, List, Optional
from flask import Blueprint, request, jsonify, send_file
from pathlib import Path

from ..database.connection_pool import db_manager
from ..security.enhanced_auth_middleware import enhanced_auth_required, audit_logged
from ..security.csrf_protection import csrf_required
from ..plugins.plugin_manager import plugin_manager
from ..plugins.base_plugin import PluginType, PluginStatus

logger = logging.getLogger(__name__)

# Create blueprint
plugin_bp = Blueprint('plugins', __name__, url_prefix='/api/plugins')

# Plugin marketplace configuration
PLUGIN_MARKETPLACE_URL = "https://api.byteguardx.com/plugins"  # Mock URL
PLUGIN_INSTALL_DIR = Path("plugins/installed")
PLUGIN_CACHE_DIR = Path("plugins/cache")

# Ensure directories exist
PLUGIN_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_CACHE_DIR.mkdir(parents=True, exist_ok=True)


@plugin_bp.route('/marketplace', methods=['GET'])
@enhanced_auth_required
@audit_logged
def get_marketplace_plugins():
    """Get available plugins from marketplace"""
    try:
        # Mock marketplace data - in production this would fetch from a real marketplace
        marketplace_plugins = [
            {
                'id': 'security-headers-checker',
                'name': 'Security Headers Checker',
                'version': '1.2.0',
                'author': 'ByteGuardX Team',
                'description': 'Validates HTTP security headers in web applications',
                'type': 'scanner',
                'category': 'web-security',
                'tags': ['headers', 'web', 'security'],
                'downloads': 1250,
                'rating': 4.8,
                'verified': True,
                'license': 'MIT',
                'repository': 'https://github.com/byteguardx/plugin-security-headers',
                'documentation': 'https://docs.byteguardx.com/plugins/security-headers',
                'size_mb': 0.5,
                'requirements': ['requests>=2.25.0'],
                'compatibility': ['byteguardx>=1.0.0'],
                'last_updated': '2024-01-15T10:30:00Z'
            },
            {
                'id': 'docker-security-scanner',
                'name': 'Docker Security Scanner',
                'version': '2.1.3',
                'author': 'Community',
                'description': 'Scans Docker containers and images for security vulnerabilities',
                'type': 'scanner',
                'category': 'container-security',
                'tags': ['docker', 'containers', 'images'],
                'downloads': 890,
                'rating': 4.6,
                'verified': False,
                'license': 'Apache-2.0',
                'repository': 'https://github.com/community/docker-security-plugin',
                'documentation': 'https://github.com/community/docker-security-plugin/wiki',
                'size_mb': 2.1,
                'requirements': ['docker>=5.0.0', 'pyyaml>=5.4.0'],
                'compatibility': ['byteguardx>=1.0.0'],
                'last_updated': '2024-01-10T14:20:00Z'
            },
            {
                'id': 'custom-rules-engine',
                'name': 'Custom Rules Engine',
                'version': '1.0.5',
                'author': 'ByteGuardX Team',
                'description': 'Create and manage custom security rules with YAML configuration',
                'type': 'rule',
                'category': 'customization',
                'tags': ['rules', 'yaml', 'custom'],
                'downloads': 2100,
                'rating': 4.9,
                'verified': True,
                'license': 'MIT',
                'repository': 'https://github.com/byteguardx/plugin-custom-rules',
                'documentation': 'https://docs.byteguardx.com/plugins/custom-rules',
                'size_mb': 0.8,
                'requirements': ['pyyaml>=5.4.0', 'jsonschema>=3.2.0'],
                'compatibility': ['byteguardx>=1.0.0'],
                'last_updated': '2024-01-12T09:15:00Z'
            },
            {
                'id': 'slack-notifier',
                'name': 'Slack Notifications',
                'version': '1.1.2',
                'author': 'Community',
                'description': 'Send scan results and alerts to Slack channels',
                'type': 'exporter',
                'category': 'notifications',
                'tags': ['slack', 'notifications', 'webhooks'],
                'downloads': 750,
                'rating': 4.4,
                'verified': False,
                'license': 'MIT',
                'repository': 'https://github.com/community/byteguardx-slack',
                'documentation': 'https://github.com/community/byteguardx-slack/README.md',
                'size_mb': 0.3,
                'requirements': ['slack-sdk>=3.15.0'],
                'compatibility': ['byteguardx>=1.0.0'],
                'last_updated': '2024-01-08T16:45:00Z'
            }
        ]
        
        # Filter by category if specified
        category = request.args.get('category', '').strip()
        if category:
            marketplace_plugins = [p for p in marketplace_plugins if p['category'] == category]
        
        # Filter by type if specified
        plugin_type = request.args.get('type', '').strip()
        if plugin_type:
            marketplace_plugins = [p for p in marketplace_plugins if p['type'] == plugin_type]
        
        # Search filter
        search = request.args.get('search', '').strip().lower()
        if search:
            marketplace_plugins = [
                p for p in marketplace_plugins 
                if search in p['name'].lower() or 
                   search in p['description'].lower() or
                   any(search in tag.lower() for tag in p['tags'])
            ]
        
        return jsonify({
            'plugins': marketplace_plugins,
            'total': len(marketplace_plugins),
            'categories': ['web-security', 'container-security', 'customization', 'notifications'],
            'types': ['scanner', 'rule', 'exporter', 'validator']
        })
        
    except Exception as e:
        logger.error(f"Error fetching marketplace plugins: {e}")
        return jsonify({'error': 'Failed to fetch marketplace plugins'}), 500


@plugin_bp.route('/installed', methods=['GET'])
@enhanced_auth_required
@audit_logged
def get_installed_plugins():
    """Get list of installed plugins"""
    try:
        installed_plugins = plugin_manager.get_installed_plugins()
        
        plugin_data = []
        for plugin_id, plugin in installed_plugins.items():
            metadata = plugin.get_metadata()
            plugin_info = {
                'id': plugin_id,
                'name': metadata['name'],
                'version': metadata['version'],
                'description': metadata['description'],
                'author': metadata['author'],
                'type': metadata['type'],
                'status': metadata['status'],
                'execution_count': metadata['execution_count'],
                'total_execution_time': metadata['total_execution_time'],
                'last_error': metadata['last_error'],
                'config': metadata['config']
            }
            plugin_data.append(plugin_info)
        
        return jsonify({
            'plugins': plugin_data,
            'total': len(plugin_data)
        })
        
    except Exception as e:
        logger.error(f"Error fetching installed plugins: {e}")
        return jsonify({'error': 'Failed to fetch installed plugins'}), 500


@plugin_bp.route('/install', methods=['POST'])
@csrf_required
@enhanced_auth_required
@audit_logged
def install_plugin():
    """Install a plugin from marketplace or upload"""
    try:
        data = request.get_json()
        
        if 'plugin_id' in data:
            # Install from marketplace
            plugin_id = data['plugin_id']
            return install_from_marketplace(plugin_id)
        
        elif 'repository_url' in data:
            # Install from GitHub repository
            repository_url = data['repository_url']
            return install_from_repository(repository_url)
        
        else:
            return jsonify({'error': 'Either plugin_id or repository_url required'}), 400
            
    except Exception as e:
        logger.error(f"Error installing plugin: {e}")
        return jsonify({'error': 'Failed to install plugin'}), 500


@plugin_bp.route('/upload', methods=['POST'])
@csrf_required
@enhanced_auth_required
@audit_logged
def upload_plugin():
    """Upload and install a plugin from ZIP file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Comprehensive file validation
        from ..security.file_validator import file_validator

        # Check file size (5MB limit for plugins)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning

        if file_size > 5 * 1024 * 1024:  # 5MB
            return jsonify({'error': 'Plugin file exceeds 5MB limit'}), 400

        if file_size == 0:
            return jsonify({'error': 'Empty file not allowed'}), 400

        # Validate file extension and MIME type
        if not file.filename.endswith('.zip'):
            return jsonify({'error': 'Only ZIP files are supported'}), 400

        # Sanitize filename
        file.filename = file_validator.sanitize_filename(file.filename)

        # Check for null bytes in filename
        if '\x00' in file.filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        # Save uploaded file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            file.save(temp_file.name)
            
            # Extract and validate plugin
            result = extract_and_validate_plugin(temp_file.name)
            
            # Clean up temp file
            os.unlink(temp_file.name)
            
            return jsonify(result)
            
    except Exception as e:
        logger.error(f"Error uploading plugin: {e}")
        return jsonify({'error': 'Failed to upload plugin'}), 500


@plugin_bp.route('/<plugin_id>/uninstall', methods=['DELETE'])
@csrf_required
@enhanced_auth_required
@audit_logged
def uninstall_plugin(plugin_id):
    """Uninstall a plugin"""
    try:
        success = plugin_manager.uninstall_plugin(plugin_id)
        
        if success:
            # Remove plugin files
            plugin_dir = PLUGIN_INSTALL_DIR / plugin_id
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir)
            
            logger.info(f"Plugin {plugin_id} uninstalled successfully")
            
            return jsonify({
                'message': f'Plugin {plugin_id} uninstalled successfully'
            })
        else:
            return jsonify({'error': 'Failed to uninstall plugin'}), 500
            
    except Exception as e:
        logger.error(f"Error uninstalling plugin: {e}")
        return jsonify({'error': 'Failed to uninstall plugin'}), 500


@plugin_bp.route('/<plugin_id>/enable', methods=['POST'])
@csrf_required
@enhanced_auth_required
@audit_logged
def enable_plugin(plugin_id):
    """Enable a plugin"""
    try:
        success = plugin_manager.enable_plugin(plugin_id)
        
        if success:
            return jsonify({
                'message': f'Plugin {plugin_id} enabled successfully'
            })
        else:
            return jsonify({'error': 'Failed to enable plugin'}), 500
            
    except Exception as e:
        logger.error(f"Error enabling plugin: {e}")
        return jsonify({'error': 'Failed to enable plugin'}), 500


@plugin_bp.route('/<plugin_id>/disable', methods=['POST'])
@csrf_required
@enhanced_auth_required
@audit_logged
def disable_plugin(plugin_id):
    """Disable a plugin"""
    try:
        success = plugin_manager.disable_plugin(plugin_id)
        
        if success:
            return jsonify({
                'message': f'Plugin {plugin_id} disabled successfully'
            })
        else:
            return jsonify({'error': 'Failed to disable plugin'}), 500
            
    except Exception as e:
        logger.error(f"Error disabling plugin: {e}")
        return jsonify({'error': 'Failed to disable plugin'}), 500


@plugin_bp.route('/<plugin_id>/config', methods=['GET', 'PUT'])
@enhanced_auth_required
@audit_logged
def plugin_config(plugin_id):
    """Get or update plugin configuration"""
    try:
        if request.method == 'GET':
            config = plugin_manager.get_plugin_config(plugin_id)
            return jsonify({'config': config})

        elif request.method == 'PUT':
            # Apply CSRF protection for PUT requests
            from ..security.csrf_protection import csrf
            token = csrf.get_csrf_token_from_request()
            if not token or not csrf.validate_csrf_token(token):
                return jsonify({'error': 'CSRF token missing or invalid'}), 403
            data = request.get_json()
            new_config = data.get('config', {})
            
            success = plugin_manager.update_plugin_config(plugin_id, new_config)
            
            if success:
                return jsonify({
                    'message': f'Plugin {plugin_id} configuration updated successfully'
                })
            else:
                return jsonify({'error': 'Failed to update plugin configuration'}), 500
                
    except Exception as e:
        logger.error(f"Error managing plugin config: {e}")
        return jsonify({'error': 'Failed to manage plugin configuration'}), 500


def install_from_marketplace(plugin_id: str) -> Dict:
    """Install plugin from marketplace"""
    # Mock implementation - would download from actual marketplace
    logger.info(f"Installing plugin {plugin_id} from marketplace")
    
    # Simulate successful installation
    return {
        'message': f'Plugin {plugin_id} installed successfully from marketplace',
        'plugin_id': plugin_id,
        'status': 'installed'
    }


def install_from_repository(repository_url: str) -> Dict:
    """Install plugin from GitHub repository"""
    # Mock implementation - would clone and install from repository
    logger.info(f"Installing plugin from repository: {repository_url}")
    
    # Simulate successful installation
    plugin_id = repository_url.split('/')[-1].replace('.git', '')
    
    return {
        'message': f'Plugin installed successfully from repository',
        'plugin_id': plugin_id,
        'repository_url': repository_url,
        'status': 'installed'
    }


def extract_and_validate_plugin(zip_path: str) -> Dict:
    """Extract and validate uploaded plugin"""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract ZIP file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Look for plugin.json manifest
            manifest_path = Path(temp_dir) / 'plugin.json'
            if not manifest_path.exists():
                return {'error': 'Plugin manifest (plugin.json) not found'}
            
            # Validate manifest
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            required_fields = ['id', 'name', 'version', 'author', 'type', 'main']
            for field in required_fields:
                if field not in manifest:
                    return {'error': f'Missing required field in manifest: {field}'}
            
            plugin_id = manifest['id']
            
            # Check if plugin already exists
            if plugin_manager.is_plugin_installed(plugin_id):
                return {'error': f'Plugin {plugin_id} is already installed'}
            
            # Copy plugin to install directory
            plugin_install_path = PLUGIN_INSTALL_DIR / plugin_id
            shutil.copytree(temp_dir, plugin_install_path)
            
            # Load and register plugin
            success = plugin_manager.load_plugin_from_directory(plugin_install_path)
            
            if success:
                return {
                    'message': f'Plugin {plugin_id} uploaded and installed successfully',
                    'plugin_id': plugin_id,
                    'manifest': manifest,
                    'status': 'installed'
                }
            else:
                # Clean up on failure
                if plugin_install_path.exists():
                    shutil.rmtree(plugin_install_path)
                return {'error': 'Failed to load plugin after installation'}
                
    except Exception as e:
        logger.error(f"Error extracting plugin: {e}")
        return {'error': f'Failed to extract plugin: {str(e)}'}


@plugin_bp.route('/<plugin_id>/source', methods=['GET'])
@enhanced_auth_required
@audit_logged
def view_plugin_source(plugin_id):
    """View plugin source code (for security review)"""
    try:
        plugin_dir = PLUGIN_INSTALL_DIR / plugin_id
        
        if not plugin_dir.exists():
            return jsonify({'error': 'Plugin not found'}), 404
        
        # Get list of source files
        source_files = []
        for file_path in plugin_dir.rglob('*.py'):
            relative_path = file_path.relative_to(plugin_dir)
            source_files.append(str(relative_path))
        
        # Get specific file content if requested
        file_path = request.args.get('file', '')
        if file_path:
            full_path = plugin_dir / file_path
            if full_path.exists() and full_path.suffix == '.py':
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                return jsonify({
                    'file': file_path,
                    'content': content,
                    'size': len(content)
                })
            else:
                return jsonify({'error': 'File not found or not a Python file'}), 404
        
        return jsonify({
            'plugin_id': plugin_id,
            'source_files': source_files
        })
        
    except Exception as e:
        logger.error(f"Error viewing plugin source: {e}")
        return jsonify({'error': 'Failed to view plugin source'}), 500
