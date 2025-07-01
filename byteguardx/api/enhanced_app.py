"""
Enhanced Flask application with Priority 1 improvements
Integrates database layer, enhanced security, performance optimizations, and monitoring
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import uuid

# ByteGuardX imports - Enhanced components
from ..database.connection_pool import db_manager, init_db
from ..database.models import User, ScanResult, Finding
from ..security.auth_middleware import AuthMiddleware, auth_required, admin_required
from ..security.jwt_utils import jwt_manager, token_blacklist
from ..performance.async_scanner import AsyncScanner
from ..performance.cache_manager import cache_manager
from ..error_handling.exception_handler import exception_handler, handle_exceptions, ErrorContext
from ..monitoring.health_checker import health_checker

# Original components
from ..core.file_processor import FileProcessor
from ..core.event_bus import event_bus, EventTypes
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner
from ..ai_suggestions.fix_engine import FixEngine
from ..reports.pdf_report import PDFReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_enhanced_app(config=None):
    """Create enhanced Flask application with Priority 1 improvements"""
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production'),
        'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
        'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB max file size
        'DATABASE_URL': os.environ.get('DATABASE_URL', 'sqlite:///data/byteguardx.db')
    })
    
    if config:
        app.config.update(config)
    
    # Initialize database
    init_db(app.config['DATABASE_URL'])
    
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
    
    # Initialize CORS with enhanced settings
    CORS(app, 
         origins=os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(','),
         supports_credentials=True,
         max_age=3600)
    
    # Initialize components
    auth_middleware = AuthMiddleware()
    async_scanner = AsyncScanner()
    file_processor = FileProcessor()
    secret_scanner = SecretScanner()
    dependency_scanner = DependencyScanner()
    ai_pattern_scanner = AIPatternScanner()
    fix_engine = FixEngine()
    pdf_generator = PDFReportGenerator()
    
    # Start background monitoring
    health_checker.start_background_monitoring()
    
    # Enhanced health check endpoint
    @app.route('/health', methods=['GET'])
    def enhanced_health_check():
        """Comprehensive health check endpoint"""
        try:
            health_info = health_checker.get_overall_health()
            
            # Add application-specific metrics
            health_info['application'] = {
                'version': '2.0.0',
                'uptime_seconds': (datetime.now() - app.start_time).total_seconds(),
                'cache_stats': cache_manager.get_cache_stats(),
                'error_stats': exception_handler.get_error_stats()
            }
            
            status_code = 200
            if health_info['overall_status'] == 'unhealthy':
                status_code = 503
            elif health_info['overall_status'] == 'degraded':
                status_code = 200  # Still serving requests
            
            return jsonify(health_info), status_code
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'overall_status': 'unhealthy',
                'error': 'Health check failed',
                'timestamp': datetime.now().isoformat()
            }), 503
    
    # Enhanced authentication endpoints
    @app.route('/auth/login', methods=['POST'])
    @handle_exceptions(ErrorContext(component='auth', operation='login'))
    def enhanced_login():
        """Enhanced login with comprehensive security"""
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        with db_manager.get_session() as session:
            user = session.query(User).filter(User.email == email).first()
            
            if not user or not user.check_password(password):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            if not user.is_active:
                return jsonify({'error': 'Account is deactivated'}), 401
            
            # Update last login
            user.last_login = datetime.now()
            session.commit()
            
            # Generate tokens
            user_data = {
                'email': user.email,
                'username': user.username,
                'role': user.role,
                'subscription_tier': user.subscription_tier
            }
            
            tokens = jwt_manager.generate_tokens(str(user.id), user_data)
            
            return jsonify({
                'message': 'Login successful',
                'user': user.to_dict(),
                **tokens
            })
    
    @app.route('/auth/refresh', methods=['POST'])
    @handle_exceptions(ErrorContext(component='auth', operation='refresh'))
    def refresh_token():
        """Refresh access token"""
        data = request.get_json()
        refresh_token = data.get('refresh_token') if data else None
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token required'}), 400
        
        new_tokens = jwt_manager.refresh_access_token(refresh_token, token_blacklist)
        
        if not new_tokens:
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        return jsonify(new_tokens)
    
    @app.route('/auth/logout', methods=['POST'])
    @auth_required
    @handle_exceptions(ErrorContext(component='auth', operation='logout'))
    def logout():
        """Logout and blacklist tokens"""
        # Get current user's tokens and blacklist them
        user_id = g.current_user['user_id']
        jwt_manager.revoke_user_tokens(user_id, token_blacklist)
        
        return jsonify({'message': 'Logged out successfully'})
    
    # Enhanced scan endpoint with async processing
    @app.route('/scan/directory', methods=['POST'])
    @auth_required
    @handle_exceptions(ErrorContext(component='scanner', operation='directory_scan'))
    def enhanced_scan_directory():
        """Enhanced directory scanning with async processing and caching"""
        data = request.get_json()
        
        if not data or 'directory_path' not in data:
            return jsonify({'error': 'Directory path is required'}), 400
        
        directory_path = data['directory_path']
        recursive = data.get('recursive', True)
        use_cache = data.get('use_cache', True)
        
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
                        'use_cache': use_cache
                    }
                )
                session.add(scan_record)
                session.commit()
            
            # TODO: Implement async scanning with progress updates
            # For now, use synchronous scanning
            
            # Process files
            file_processor.reset()
            processed_files = file_processor.process_directory(directory_path, recursive)
            
            # Perform scans
            all_findings = []
            
            # Secret scanning
            secret_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = secret_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            
            # Dependency scanning
            dependency_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = dependency_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            
            # AI pattern scanning
            ai_pattern_scanner.reset()
            for file_info in processed_files:
                if 'error' not in file_info:
                    findings = ai_pattern_scanner.scan_file(file_info)
                    all_findings.extend(findings)
            
            # Generate fixes
            fix_engine.reset()
            fixes = fix_engine.generate_fixes(all_findings)
            
            # Update scan record with results
            with db_manager.get_session() as session:
                scan_record = session.query(ScanResult).filter(
                    ScanResult.scan_id == scan_id
                ).first()
                
                if scan_record:
                    scan_record.status = 'completed'
                    scan_record.completed_at = datetime.now()
                    scan_record.total_files = len(processed_files)
                    scan_record.total_findings = len(all_findings)
                    
                    # Count findings by severity
                    severity_counts = {}
                    for finding in all_findings:
                        severity = finding.get('severity', 'unknown')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    scan_record.critical_findings = severity_counts.get('critical', 0)
                    scan_record.high_findings = severity_counts.get('high', 0)
                    scan_record.medium_findings = severity_counts.get('medium', 0)
                    scan_record.low_findings = severity_counts.get('low', 0)
                    
                    # Calculate performance metrics
                    if scan_record.started_at:
                        duration = (scan_record.completed_at - scan_record.started_at).total_seconds()
                        scan_record.scan_duration_seconds = duration
                        scan_record.files_per_second = len(processed_files) / duration if duration > 0 else 0
                    
                    # Save findings to database
                    for finding_data in all_findings:
                        finding = Finding(
                            scan_result_id=scan_record.id,
                            vulnerability_type=finding_data.get('type', 'unknown'),
                            severity=finding_data.get('severity', 'medium'),
                            title=finding_data.get('description', 'Vulnerability found'),
                            description=finding_data.get('details', ''),
                            file_path=finding_data.get('file_path', ''),
                            line_number=finding_data.get('line_number'),
                            code_snippet=finding_data.get('code_snippet', ''),
                            matched_pattern=finding_data.get('pattern', ''),
                            confidence_score=finding_data.get('confidence', 0.5),
                            scanner_type=finding_data.get('scanner', 'unknown'),
                            metadata=finding_data
                        )
                        session.add(finding)
                    
                    session.commit()
            
            return jsonify({
                'scan_id': scan_id,
                'status': 'completed',
                'total_files': len(processed_files),
                'total_findings': len(all_findings),
                'total_fixes': len(fixes),
                'summary': {
                    'secrets': secret_scanner.get_summary(),
                    'dependencies': dependency_scanner.get_summary(),
                    'ai_patterns': ai_pattern_scanner.get_summary(),
                    'fixes': fix_engine.get_fix_summary()
                }
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
    
    # Get scan results from database
    @app.route('/scan/results/<scan_id>', methods=['GET'])
    @auth_required
    @handle_exceptions(ErrorContext(component='api', operation='get_scan_results'))
    def get_enhanced_scan_results(scan_id):
        """Get scan results from database"""
        user_id = g.current_user['user_id']
        
        with db_manager.get_session() as session:
            scan_result = session.query(ScanResult).filter(
                ScanResult.scan_id == scan_id,
                ScanResult.user_id == user_id
            ).first()
            
            if not scan_result:
                return jsonify({'error': 'Scan results not found'}), 404
            
            # Get findings
            findings = session.query(Finding).filter(
                Finding.scan_result_id == scan_result.id
            ).all()
            
            return jsonify({
                'scan_result': scan_result.to_dict(),
                'findings': [finding.to_dict() for finding in findings]
            })
    
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
    app = create_enhanced_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
