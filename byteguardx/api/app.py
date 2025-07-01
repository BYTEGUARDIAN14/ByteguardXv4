"""
ByteGuardX Flask API - REST endpoints for vulnerability scanning
"""

import os
import json
import uuid
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import zipfile
import io
import tempfile
import shutil

# ByteGuardX imports
from ..core.file_processor import FileProcessor
from ..core.event_bus import event_bus, EventTypes
from ..scanners.secret_scanner import SecretScanner
from ..scanners.dependency_scanner import DependencyScanner
from ..scanners.ai_pattern_scanner import AIPatternScanner
from ..ai_suggestions.fix_engine import FixEngine
from ..reports.pdf_report import PDFReportGenerator
from ..auth.models import UserManager, UserRole, SubscriptionTier, PermissionType
from ..auth.decorators import (
    auth_required, permission_required, subscription_required,
    rate_limit_check, admin_required, audit_log, organization_access
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_zip_file(file_obj) -> bool:
    """Validate ZIP file to prevent ZIP bombs and malicious content"""
    try:
        # Reset file pointer
        file_obj.seek(0)
        file_content = file_obj.read()
        file_obj.seek(0)

        # Check if it's actually a ZIP file
        if not zipfile.is_zipfile(io.BytesIO(file_content)):
            return False

        with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zip_ref:
            total_uncompressed_size = 0
            file_count = 0
            max_files = 1000  # Maximum number of files
            max_uncompressed_size = 100 * 1024 * 1024  # 100MB uncompressed
            max_compression_ratio = 100  # Maximum compression ratio

            for info in zip_ref.infolist():
                file_count += 1

                # Check file count limit
                if file_count > max_files:
                    logger.warning(f"ZIP file contains too many files: {file_count}")
                    return False

                # Check for path traversal
                if os.path.isabs(info.filename) or '..' in info.filename:
                    logger.warning(f"ZIP contains dangerous path: {info.filename}")
                    return False

                # Check uncompressed size
                total_uncompressed_size += info.file_size
                if total_uncompressed_size > max_uncompressed_size:
                    logger.warning(f"ZIP uncompressed size too large: {total_uncompressed_size}")
                    return False

                # Check compression ratio (potential ZIP bomb)
                if info.compress_size > 0:
                    compression_ratio = info.file_size / info.compress_size
                    if compression_ratio > max_compression_ratio:
                        logger.warning(f"Suspicious compression ratio: {compression_ratio}")
                        return False

        return True

    except Exception as e:
        logger.warning(f"ZIP validation failed: {e}")
        return False

def create_app(config=None):
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Configuration with secure defaults
    import secrets

    # Generate secure random keys if not provided
    default_secret_key = secrets.token_urlsafe(64)
    default_jwt_key = secrets.token_urlsafe(64)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', default_secret_key)
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', default_jwt_key)
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Reduced from 24h to 1h
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Reduced from 50MB to 10MB

    # Warn if using default keys
    if 'SECRET_KEY' not in os.environ:
        logger.warning("Using generated SECRET_KEY. Set SECRET_KEY environment variable for production.")
    if 'JWT_SECRET_KEY' not in os.environ:
        logger.warning("Using generated JWT_SECRET_KEY. Set JWT_SECRET_KEY environment variable for production.")
    
    # Comprehensive security headers
    @app.after_request
    def add_security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # XSS protection (legacy but still useful)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # HSTS for HTTPS connections
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

        # Content Security Policy
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers['Content-Security-Policy'] = csp_policy

        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions policy
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        return response
    
    # Initialize extensions with secure CORS configuration
    allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
    # Remove any wildcard origins for security
    allowed_origins = [origin.strip() for origin in allowed_origins if origin.strip() != '*']

    CORS(app,
         origins=allowed_origins,
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    jwt = JWTManager(app)
    
    # Initialize ByteGuardX components
    file_processor = FileProcessor()
    secret_scanner = SecretScanner()
    dependency_scanner = DependencyScanner()
    ai_pattern_scanner = AIPatternScanner()
    fix_engine = FixEngine()
    pdf_generator = PDFReportGenerator()
    user_manager = UserManager()

    # Temporary storage for scan results
    scan_results = {}
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        })
    
    @app.route('/auth/register', methods=['POST'])
    def register():
        """User registration endpoint"""
        data = request.get_json()

        if not data or not all(k in data for k in ['email', 'username', 'password']):
            return jsonify({'error': 'Email, username and password required'}), 400

        email = data['email']
        username = data['username']
        password = data['password']

        # Check if user already exists
        if user_manager.get_user_by_email(email):
            return jsonify({'error': 'User already exists'}), 409

        try:
            user = user_manager.create_user(email, username, password)
            access_token = create_access_token(identity=user.id)

            return jsonify({
                'access_token': access_token,
                'user': user.to_dict(),
                'message': 'Registration successful'
            })
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({'error': 'Registration failed'}), 500

    @app.route('/auth/login', methods=['POST'])
    def login():
        """User authentication endpoint"""
        data = request.get_json()

        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400

        email = data['email']
        password = data['password']

        user = user_manager.get_user_by_email(email)
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401

        # Update last login
        user.last_login = datetime.now()
        user_manager.update_user(user)

        # Log login
        user_manager.log_audit(
            user_id=user.id,
            action="login",
            resource_type="auth",
            resource_id=user.id,
            ip_address=request.remote_addr or "",
            user_agent=request.headers.get('User-Agent', '')
        )

        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict()
        })
    
    @app.route('/scan/upload', methods=['POST'])
    @auth_required
    @permission_required(PermissionType.SCAN_CREATE)
    @rate_limit_check
    @audit_log("file_upload", "scan")
    def upload_files():
        """Upload files for scanning"""
        try:
            if 'files' not in request.files:
                return jsonify({'error': 'No files provided'}), 400
            
            files = request.files.getlist('files')
            if not files or all(f.filename == '' for f in files):
                return jsonify({'error': 'No files selected'}), 400
            
            scan_id = str(uuid.uuid4())
            upload_dir = Path(f'/tmp/byteguardx_uploads/{scan_id}')
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            uploaded_files = []
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)

                    # Additional security validation
                    if not filename or filename in ('.', '..'):
                        continue

                    # Check for path traversal attempts
                    if '..' in filename or filename.startswith('/') or '\\' in filename:
                        logger.warning(f"Path traversal attempt detected: {filename}")
                        continue

                    # Validate file extension
                    allowed_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.h',
                                        '.php', '.rb', '.go', '.rs', '.json', '.xml', '.yml',
                                        '.yaml', '.txt', '.md', '.sql', '.sh', '.bat'}
                    file_ext = Path(filename).suffix.lower()
                    if file_ext not in allowed_extensions:
                        logger.warning(f"Disallowed file extension: {filename}")
                        continue

                    file_path = upload_dir / filename

                    # Ensure the resolved path is within upload directory
                    try:
                        resolved_path = file_path.resolve()
                        upload_dir_resolved = upload_dir.resolve()
                        if not str(resolved_path).startswith(str(upload_dir_resolved)):
                            logger.warning(f"Path traversal detected: {filename}")
                            continue
                    except Exception as e:
                        logger.warning(f"Path resolution failed for {filename}: {e}")
                        continue

                    # Check file size before saving
                    file.seek(0, 2)  # Seek to end
                    file_size = file.tell()
                    file.seek(0)  # Reset to beginning

                    if file_size > 10 * 1024 * 1024:  # 10MB limit
                        logger.warning(f"File too large: {filename} ({file_size} bytes)")
                        continue

                    # Check for ZIP bombs if it's a ZIP file
                    if filename.lower().endswith('.zip'):
                        if not validate_zip_file(file):
                            logger.warning(f"Potentially malicious ZIP file: {filename}")
                            continue

                    # Save file with secure permissions
                    file.save(str(file_path))
                    file_path.chmod(0o600)  # Owner read/write only
                    uploaded_files.append(str(file_path))
            
            return jsonify({
                'scan_id': scan_id,
                'uploaded_files': len(uploaded_files),
                'message': 'Files uploaded successfully'
            })
            
        except RequestEntityTooLarge:
            return jsonify({'error': 'File too large'}), 413
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return jsonify({'error': 'Upload failed'}), 500
    
    @app.route('/scan/directory', methods=['POST'])
    def scan_directory():
        """Scan a directory path"""
        data = request.get_json()
        
        if not data or 'path' not in data:
            return jsonify({'error': 'Directory path required'}), 400
        
        directory_path = data['path']
        
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            return jsonify({'error': 'Invalid directory path'}), 400
        
        try:
            scan_id = str(uuid.uuid4())
            
            # Process files
            file_processor.reset()
            processed_files = file_processor.process_directory(directory_path, recursive=True)
            
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
            
            # Store results
            scan_results[scan_id] = {
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'directory_path': directory_path,
                'total_files': len(processed_files),
                'findings': all_findings,
                'fixes': fix_engine.export_fixes_to_dict(),
                'summary': {
                    'secrets': secret_scanner.get_summary(),
                    'dependencies': dependency_scanner.get_summary(),
                    'ai_patterns': ai_pattern_scanner.get_summary(),
                    'fixes': fix_engine.get_fix_summary()
                }
            }
            
            return jsonify({
                'scan_id': scan_id,
                'total_files': len(processed_files),
                'total_findings': len(all_findings),
                'total_fixes': len(fixes),
                'summary': scan_results[scan_id]['summary']
            })
            
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
            return jsonify({'error': 'Scan failed'}), 500
    
    @app.route('/scan/secrets', methods=['POST'])
    def scan_secrets():
        """Scan uploaded files for secrets"""
        data = request.get_json()
        
        if not data or 'scan_id' not in data:
            return jsonify({'error': 'Scan ID required'}), 400
        
        scan_id = data['scan_id']
        upload_dir = Path(f'/tmp/byteguardx_uploads/{scan_id}')
        
        if not upload_dir.exists():
            return jsonify({'error': 'Invalid scan ID'}), 404
        
        try:
            # Process uploaded files
            file_processor.reset()
            processed_files = file_processor.process_directory(str(upload_dir))
            
            # Scan for secrets
            secret_scanner.reset()
            findings = []
            for file_info in processed_files:
                if 'error' not in file_info:
                    file_findings = secret_scanner.scan_file(file_info)
                    findings.extend(file_findings)
            
            return jsonify({
                'scan_id': scan_id,
                'type': 'secrets',
                'findings': findings,
                'summary': secret_scanner.get_summary()
            })
            
        except Exception as e:
            logger.error(f"Secret scan error: {e}")
            return jsonify({'error': 'Secret scan failed'}), 500
    
    @app.route('/scan/dependencies', methods=['POST'])
    def scan_dependencies():
        """Scan uploaded files for vulnerable dependencies"""
        data = request.get_json()
        
        if not data or 'scan_id' not in data:
            return jsonify({'error': 'Scan ID required'}), 400
        
        scan_id = data['scan_id']
        upload_dir = Path(f'/tmp/byteguardx_uploads/{scan_id}')
        
        if not upload_dir.exists():
            return jsonify({'error': 'Invalid scan ID'}), 404
        
        try:
            # Process uploaded files
            file_processor.reset()
            processed_files = file_processor.process_directory(str(upload_dir))
            
            # Scan for vulnerabilities
            dependency_scanner.reset()
            findings = []
            for file_info in processed_files:
                if 'error' not in file_info:
                    file_findings = dependency_scanner.scan_file(file_info)
                    findings.extend(file_findings)
            
            return jsonify({
                'scan_id': scan_id,
                'type': 'dependencies',
                'findings': findings,
                'summary': dependency_scanner.get_summary()
            })
            
        except Exception as e:
            logger.error(f"Dependency scan error: {e}")
            return jsonify({'error': 'Dependency scan failed'}), 500
    
    @app.route('/scan/ai-patterns', methods=['POST'])
    def scan_ai_patterns():
        """Scan uploaded files for AI-generated anti-patterns"""
        data = request.get_json()
        
        if not data or 'scan_id' not in data:
            return jsonify({'error': 'Scan ID required'}), 400
        
        scan_id = data['scan_id']
        upload_dir = Path(f'/tmp/byteguardx_uploads/{scan_id}')
        
        if not upload_dir.exists():
            return jsonify({'error': 'Invalid scan ID'}), 404
        
        try:
            # Process uploaded files
            file_processor.reset()
            processed_files = file_processor.process_directory(str(upload_dir))
            
            # Scan for AI patterns
            ai_pattern_scanner.reset()
            findings = []
            for file_info in processed_files:
                if 'error' not in file_info:
                    file_findings = ai_pattern_scanner.scan_file(file_info)
                    findings.extend(file_findings)
            
            return jsonify({
                'scan_id': scan_id,
                'type': 'ai_patterns',
                'findings': findings,
                'summary': ai_pattern_scanner.get_summary()
            })
            
        except Exception as e:
            logger.error(f"AI pattern scan error: {e}")
            return jsonify({'error': 'AI pattern scan failed'}), 500

    @app.route('/scan/all', methods=['POST'])
    def scan_all():
        """Perform comprehensive scan (all scanners)"""
        data = request.get_json()

        if not data or 'scan_id' not in data:
            return jsonify({'error': 'Scan ID required'}), 400

        scan_id = data['scan_id']
        upload_dir = Path(f'/tmp/byteguardx_uploads/{scan_id}')

        if not upload_dir.exists():
            return jsonify({'error': 'Invalid scan ID'}), 404

        try:
            # Process uploaded files
            file_processor.reset()
            processed_files = file_processor.process_directory(str(upload_dir))

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

            # Store results
            scan_results[scan_id] = {
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'total_files': len(processed_files),
                'findings': all_findings,
                'fixes': fix_engine.export_fixes_to_dict(),
                'summary': {
                    'secrets': secret_scanner.get_summary(),
                    'dependencies': dependency_scanner.get_summary(),
                    'ai_patterns': ai_pattern_scanner.get_summary(),
                    'fixes': fix_engine.get_fix_summary()
                }
            }

            return jsonify({
                'scan_id': scan_id,
                'total_files': len(processed_files),
                'total_findings': len(all_findings),
                'total_fixes': len(fixes),
                'findings': all_findings,
                'fixes': fix_engine.export_fixes_to_dict(),
                'summary': scan_results[scan_id]['summary']
            })

        except Exception as e:
            logger.error(f"Comprehensive scan error: {e}")
            return jsonify({'error': 'Comprehensive scan failed'}), 500

    @app.route('/fix/bulk', methods=['POST'])
    def generate_bulk_fixes():
        """Generate fixes for multiple findings"""
        data = request.get_json()

        if not data or 'findings' not in data:
            return jsonify({'error': 'Findings required'}), 400

        try:
            fix_engine.reset()
            fixes = fix_engine.generate_fixes(data['findings'])

            return jsonify({
                'total_fixes': len(fixes),
                'fixes': fix_engine.export_fixes_to_dict(),
                'summary': fix_engine.get_fix_summary()
            })

        except Exception as e:
            logger.error(f"Bulk fix generation error: {e}")
            return jsonify({'error': 'Fix generation failed'}), 500

    @app.route('/report/pdf', methods=['POST'])
    def generate_pdf_report():
        """Generate PDF report"""
        data = request.get_json()

        if not data or 'scan_id' not in data:
            return jsonify({'error': 'Scan ID required'}), 400

        scan_id = data['scan_id']

        if scan_id not in scan_results:
            return jsonify({'error': 'Scan results not found'}), 404

        try:
            scan_data = scan_results[scan_id]

            # Generate PDF report
            report_path = pdf_generator.generate_report(
                findings=scan_data['findings'],
                fixes=scan_data['fixes'],
                scan_metadata={
                    'scan_id': scan_id,
                    'total_files': scan_data['total_files']
                }
            )

            return jsonify({
                'report_path': report_path,
                'download_url': f'/report/download/{Path(report_path).name}'
            })

        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return jsonify({'error': 'PDF generation failed'}), 500

    @app.route('/report/download/<filename>', methods=['GET'])
    def download_report(filename):
        """Download generated report"""
        try:
            # Security: validate filename
            safe_filename = secure_filename(filename)
            if not safe_filename.endswith('.pdf'):
                abort(400)

            # Look for the file in current directory
            file_path = Path(safe_filename)
            if not file_path.exists():
                abort(404)

            return send_file(
                str(file_path),
                as_attachment=True,
                download_name=safe_filename,
                mimetype='application/pdf'
            )

        except Exception as e:
            logger.error(f"Download error: {e}")
            abort(500)

    @app.route('/scan/results/<scan_id>', methods=['GET'])
    def get_scan_results(scan_id):
        """Get scan results by ID"""
        if scan_id not in scan_results:
            return jsonify({'error': 'Scan results not found'}), 404

        return jsonify(scan_results[scan_id])

    @app.route('/scan/list', methods=['GET'])
    def list_scans():
        """List all scan results"""
        scans = []
        for scan_id, data in scan_results.items():
            scans.append({
                'scan_id': scan_id,
                'timestamp': data['timestamp'],
                'total_files': data['total_files'],
                'total_findings': len(data['findings']),
                'total_fixes': len(data['fixes'])
            })

        return jsonify({'scans': scans})

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    @app.errorhandler(RequestEntityTooLarge)
    def file_too_large(error):
        return jsonify({'error': 'File too large'}), 413

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
