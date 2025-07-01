"""
Enhanced Flask application with Priority 2 features
Integrates RBAC, worker pools, incremental scanning, ML registry, and code sandboxing
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Priority 1 imports
from ..database.connection_pool import db_manager, init_db
from ..database.models import User, ScanResult, Finding
from ..security.auth_middleware import AuthMiddleware, auth_required, admin_required
from ..security.jwt_utils import jwt_manager, token_blacklist
from ..performance.cache_manager import cache_manager
from ..error_handling.exception_handler import exception_handler, handle_exceptions, ErrorContext
from ..monitoring.health_checker import health_checker

# Priority 2 imports
from ..security.rbac import rbac, Permission, AccessContext
from ..performance.worker_pool import worker_pool, ScanTask, TaskPriority
from ..performance.incremental_scanner import incremental_scanner
from ..ml.model_registry import model_registry, ModelType, ModelMetrics
from ..ml.experiment_tracker import experiment_tracker
from ..security.code_sandbox import code_sandbox, SandboxConfig

# Original components
from ..core.file_processor import FileProcessor
from ..core.event_bus import event_bus, EventTypes
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner

logger = logging.getLogger(__name__)

def create_priority2_app(config=None):
    """Create enhanced Flask application with Priority 2 features"""
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production'),
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
        'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB max file size
        'DATABASE_URL': os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db'),
        'ENABLE_WORKER_POOL': os.environ.get('ENABLE_WORKER_POOL', 'true').lower() == 'true',
        'ENABLE_INCREMENTAL_SCAN': os.environ.get('ENABLE_INCREMENTAL_SCAN', 'true').lower() == 'true',
        'ENABLE_CODE_SANDBOX': os.environ.get('ENABLE_CODE_SANDBOX', 'false').lower() == 'true'
    })
    
    if config:
        app.config.update(config)
    
    # Initialize database
    init_db(app.config['DATABASE_URL'])
    
    # Initialize Priority 2 components
    if app.config['ENABLE_WORKER_POOL']:
        worker_pool.start()
    
    # Enhanced security headers (from Priority 1)
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
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
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
    
    # Enhanced scan endpoint with worker pool and incremental scanning
    @app.route('/scan/directory/enhanced', methods=['POST'])
    @auth_required
    @require_permission(Permission.SCAN_CREATE)
    @handle_exceptions(ErrorContext(component='scanner', operation='enhanced_directory_scan'))
    def enhanced_scan_directory():
        """Enhanced directory scanning with worker pool and incremental scanning"""
        data = request.get_json()
        
        if not data or 'directory_path' not in data:
            return jsonify({'error': 'Directory path is required'}), 400
        
        directory_path = data['directory_path']
        recursive = data.get('recursive', True)
        use_cache = data.get('use_cache', True)
        use_incremental = data.get('use_incremental', app.config['ENABLE_INCREMENTAL_SCAN'])
        use_worker_pool = data.get('use_worker_pool', app.config['ENABLE_WORKER_POOL'])
        priority = data.get('priority', 'normal')
        
        # Validate directory path
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            return jsonify({'error': 'Directory does not exist'}), 400
        
        try:
            scan_id = str(uuid.uuid4())
            user_id = g.current_user['user_id']
            
            # Create scan record in database
            with db_manager.get_session() as session:
                scan_record = ScanResult(
                    scan_id=scan_id,
                    directory_path=directory_path,
                    user_id=user_id,
                    status='running',
                    started_at=datetime.now(),
                    scan_config={
                        'recursive': recursive,
                        'use_cache': use_cache,
                        'use_incremental': use_incremental,
                        'use_worker_pool': use_worker_pool,
                        'priority': priority
                    }
                )
                session.add(scan_record)
                session.commit()
            
            # Determine files to scan
            if use_incremental:
                # Create snapshot if needed
                if not incremental_scanner.directory_snapshots.get(directory_path):
                    incremental_scanner.create_snapshot(directory_path, {
                        'recursive': recursive,
                        'scan_type': 'full'
                    })
                
                # Get files to scan incrementally
                files_to_scan, is_incremental = incremental_scanner.get_files_to_scan(
                    directory_path, force_full_scan=False
                )
                
                logger.info(f"Incremental scan: {len(files_to_scan)} files to scan "
                           f"(incremental: {is_incremental})")
            else:
                # Full scan
                file_processor = FileProcessor()
                processed_files = file_processor.process_directory(directory_path, recursive)
                files_to_scan = [f['file_path'] for f in processed_files if 'error' not in f]
                is_incremental = False
            
            # Submit to worker pool if enabled
            if use_worker_pool and app.config['ENABLE_WORKER_POOL']:
                task_priority = {
                    'low': TaskPriority.LOW,
                    'normal': TaskPriority.NORMAL,
                    'high': TaskPriority.HIGH,
                    'critical': TaskPriority.CRITICAL
                }.get(priority, TaskPriority.NORMAL)
                
                # Submit directory scan task
                worker_task_id = worker_pool.submit_directory_scan(
                    directory_path=directory_path,
                    recursive=recursive,
                    scanner_types=['secret', 'dependency', 'ai_pattern'],
                    priority=task_priority
                )
                
                # Update scan record with worker task ID
                with db_manager.get_session() as session:
                    scan_record = session.query(ScanResult).filter(
                        ScanResult.scan_id == scan_id
                    ).first()
                    if scan_record:
                        scan_record.scan_config['worker_task_id'] = worker_task_id
                        session.commit()
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'submitted_to_worker_pool',
                    'worker_task_id': worker_task_id,
                    'files_to_scan': len(files_to_scan),
                    'is_incremental': is_incremental,
                    'estimated_time': len(files_to_scan) * 0.1  # Rough estimate
                })
            
            else:
                # Process synchronously (fallback)
                # This would be the same as Priority 1 implementation
                # but with incremental file list
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'processing_synchronously',
                    'files_to_scan': len(files_to_scan),
                    'is_incremental': is_incremental
                })
                
        except Exception as e:
            # Update scan record with error
            try:
                with db_manager.get_session() as session:
                    scan_record = session.query(ScanResult).filter(
                        ScanResult.scan_id == scan_id
                    ).first()
                    if scan_record:
                        scan_record.status = 'failed'
                        scan_record.completed_at = datetime.now()
                        session.commit()
            except:
                pass
            
            raise  # Re-raise for exception handler
    
    # Worker pool status endpoint
    @app.route('/worker-pool/status', methods=['GET'])
    @auth_required
    @require_permission(Permission.SYSTEM_MONITOR)
    def worker_pool_status():
        """Get worker pool status and statistics"""
        if not app.config['ENABLE_WORKER_POOL']:
            return jsonify({'error': 'Worker pool is disabled'}), 404
        
        stats = worker_pool.get_pool_stats()
        return jsonify(stats)
    
    # ML Model Registry endpoints
    @app.route('/ml/models', methods=['GET'])
    @auth_required
    @require_permission(Permission.PATTERN_CREATE)
    def list_ml_models():
        """List ML models in registry"""
        model_type = request.args.get('type')
        status = request.args.get('status')
        
        try:
            model_type_enum = ModelType(model_type) if model_type else None
        except ValueError:
            model_type_enum = None
        
        models = model_registry.list_models(model_type_enum, status)
        
        return jsonify({
            'models': [
                {
                    'model_id': model.model_id,
                    'version': model.version,
                    'model_type': model.model_type.value,
                    'status': model.status.value,
                    'created_at': model.created_at.isoformat(),
                    'metrics': model.metrics.to_dict(),
                    'description': model.description
                }
                for model in models
            ]
        })
    
    @app.route('/ml/models/<model_id>/deploy', methods=['POST'])
    @auth_required
    @require_permission(Permission.PATTERN_UPDATE)
    def deploy_ml_model(model_id):
        """Deploy ML model"""
        data = request.get_json() or {}
        version = data.get('version', 'latest')
        deployment_config = data.get('deployment_config', {})
        
        success = model_registry.deploy_model(model_id, version, deployment_config)
        
        if success:
            return jsonify({'message': f'Model {model_id}:{version} deployed successfully'})
        else:
            return jsonify({'error': 'Failed to deploy model'}), 500
    
    # Experiment tracking endpoints
    @app.route('/ml/experiments', methods=['POST'])
    @auth_required
    @require_permission(Permission.PATTERN_TRAIN)
    def create_experiment():
        """Create new ML experiment"""
        data = request.get_json()
        
        required_fields = ['name', 'description', 'model_type', 'dataset_config', 'training_config']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        try:
            model_type = ModelType(data['model_type'])
        except ValueError:
            return jsonify({'error': 'Invalid model type'}), 400
        
        experiment_id = experiment_tracker.create_experiment(
            name=data['name'],
            description=data['description'],
            model_type=model_type,
            dataset_config=data['dataset_config'],
            training_config=data['training_config'],
            created_by=g.current_user['user_id']
        )
        
        return jsonify({
            'experiment_id': experiment_id,
            'message': 'Experiment created successfully'
        })
    
    @app.route('/ml/experiments/<experiment_id>/runs', methods=['POST'])
    @auth_required
    @require_permission(Permission.PATTERN_TRAIN)
    def start_experiment_run(experiment_id):
        """Start new experiment run"""
        data = request.get_json() or {}
        
        run_id = experiment_tracker.start_run(
            experiment_id=experiment_id,
            run_name=data.get('run_name', f'run_{int(datetime.now().timestamp())}'),
            config=data.get('config', {}),
            hyperparameters=data.get('hyperparameters', {}),
            tags=data.get('tags', [])
        )
        
        return jsonify({
            'run_id': run_id,
            'message': 'Experiment run started'
        })
    
    # Code sandboxing endpoint
    @app.route('/security/sandbox/scan', methods=['POST'])
    @auth_required
    @require_permission(Permission.SCAN_CREATE)
    def sandbox_scan():
        """Scan code in secure sandbox"""
        if not app.config['ENABLE_CODE_SANDBOX']:
            return jsonify({'error': 'Code sandboxing is disabled'}), 404
        
        data = request.get_json()
        
        if not data or 'code_content' not in data:
            return jsonify({'error': 'Code content is required'}), 400
        
        code_content = data['code_content']
        scanner_type = data.get('scanner_type', 'all')
        
        # Validate code size
        if len(code_content) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'Code content too large'}), 400
        
        try:
            result = code_sandbox.scan_code_safely(code_content, scanner_type)
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Sandbox scan failed: {e}")
            return jsonify({
                'success': False,
                'error': 'Sandbox execution failed'
            }), 500
    
    # RBAC management endpoints
    @app.route('/rbac/roles', methods=['GET'])
    @auth_required
    @require_permission(Permission.USER_READ)
    def list_roles():
        """List available roles"""
        roles = []
        
        # System roles
        for role_name, role_def in rbac.roles.items():
            roles.append({
                'name': role_name,
                'display_name': role_def.display_name,
                'description': role_def.description,
                'is_system_role': role_def.is_system_role,
                'permissions': [p.value for p in role_def.permissions]
            })
        
        # Custom roles
        for role_name, role_def in rbac.custom_roles.items():
            roles.append({
                'name': role_name,
                'display_name': role_def.display_name,
                'description': role_def.description,
                'is_system_role': role_def.is_system_role,
                'permissions': [p.value for p in role_def.permissions]
            })
        
        return jsonify({'roles': roles})
    
    @app.route('/rbac/users/<user_id>/roles', methods=['POST'])
    @auth_required
    @require_permission(Permission.USER_UPDATE)
    def assign_user_role(user_id):
        """Assign role to user"""
        data = request.get_json()
        
        if not data or 'role_name' not in data:
            return jsonify({'error': 'Role name is required'}), 400
        
        role_name = data['role_name']
        organization_id = data.get('organization_id')
        
        success = rbac.assign_role(user_id, role_name, organization_id)
        
        if success:
            return jsonify({'message': f'Role {role_name} assigned to user {user_id}'})
        else:
            return jsonify({'error': 'Failed to assign role'}), 500
    
    # Enhanced health check with Priority 2 components
    @app.route('/health/enhanced', methods=['GET'])
    def enhanced_health_check():
        """Enhanced health check including Priority 2 components"""
        try:
            health_info = health_checker.get_overall_health()
            
            # Add Priority 2 component status
            priority2_status = {}
            
            if app.config['ENABLE_WORKER_POOL']:
                priority2_status['worker_pool'] = worker_pool.get_pool_stats()
            
            if app.config['ENABLE_INCREMENTAL_SCAN']:
                priority2_status['incremental_scanner'] = {
                    'watched_directories': len(incremental_scanner.watched_directories),
                    'snapshots': len(incremental_scanner.snapshots)
                }
            
            priority2_status['ml_registry'] = {
                'total_models': len(model_registry.model_versions),
                'deployed_models': len(model_registry.deployed_models)
            }
            
            priority2_status['experiment_tracker'] = {
                'active_runs': len(experiment_tracker.active_runs),
                'completed_runs': len(experiment_tracker.completed_runs)
            }
            
            health_info['priority2_components'] = priority2_status
            
            status_code = 200
            if health_info['overall_status'] == 'unhealthy':
                status_code = 503
            
            return jsonify(health_info), status_code
            
        except Exception as e:
            logger.error(f"Enhanced health check failed: {e}")
            return jsonify({
                'overall_status': 'unhealthy',
                'error': 'Health check failed',
                'timestamp': datetime.now().isoformat()
            }), 503
    
    # Error handlers
    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        """Handle all unhandled exceptions"""
        error_response = exception_handler.handle_exception(error)
        return jsonify(error_response), 500
    
    # Cleanup on shutdown
    @app.teardown_appcontext
    def cleanup_resources(error):
        """Cleanup resources on request end"""
        pass
    
    # Store app start time for uptime calculation
    app.start_time = datetime.now()
    
    return app

if __name__ == '__main__':
    app = create_priority2_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
