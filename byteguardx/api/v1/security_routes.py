"""
ByteGuardX API v1 - Security Enhancement Routes
Provides endpoints for all 10 enterprise security improvements
"""

import logging
from flask import Blueprint, request, jsonify, g
from datetime import datetime

from . import api_v1, api_response, validate_schema
from ..security.zero_trust_enforcement import deny_by_default, RoutePolicy, zero_trust_enforcer
from ..security.dast_integration import dast_manager, DASTTool
from ..security.insider_threat_auditing import insider_threat_monitor, AccessType, ThreatLevel
from ..plugins.signature_verification import plugin_signature_verifier, PluginSignature
from ..cli.backup import backup_manager
from ..auth.models import UserRole, PermissionType
from ..security.rbac import Permission

logger = logging.getLogger(__name__)

# Register security routes with v1 API
security_bp = Blueprint('security', __name__)

# 1. Zero Trust API Enforcement - Admin route to manage policies
@security_bp.route('/zero-trust/policies', methods=['GET'])
@deny_by_default
def list_zero_trust_policies():
    """List all zero trust policies (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    policies = []
    for pattern, policy in zero_trust_enforcer.route_policies.items():
        policies.append({
            'route_pattern': pattern,
            'required_permissions': [p.value for p in policy.required_permissions],
            'required_roles': [r.value for r in policy.required_roles],
            'allow_anonymous': policy.allow_anonymous,
            'require_2fa': policy.require_2fa,
            'audit_level': policy.audit_level
        })
    
    return api_response(policies)

@security_bp.route('/zero-trust/policies', methods=['POST'])
@deny_by_default
def create_zero_trust_policy():
    """Create new zero trust policy (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    data = request.get_json()
    
    try:
        # Create new policy
        policy = RoutePolicy(
            route_pattern=data['route_pattern'],
            required_permissions=[Permission(p) for p in data.get('required_permissions', [])],
            required_roles=[UserRole(r) for r in data.get('required_roles', [])],
            allow_anonymous=data.get('allow_anonymous', False),
            require_2fa=data.get('require_2fa', False),
            audit_level=data.get('audit_level', 'info')
        )
        
        zero_trust_enforcer.register_route_policy(data['route_pattern'], policy)
        
        # Log the policy creation
        insider_threat_monitor.log_privileged_access(
            admin_user_id=g.user_id,
            target_user_id=None,
            access_type=AccessType.SYSTEM_CONFIG_CHANGE,
            resource_type="zero_trust_policy",
            resource_id=data['route_pattern'],
            action="create",
            justification=data.get('justification')
        )
        
        return api_response({'message': 'Policy created successfully'})
        
    except Exception as e:
        logger.error(f"Failed to create zero trust policy: {e}")
        return api_response(error=str(e), status_code=400)

# 2. Plugin Signature Verification
@security_bp.route('/plugins/verify-signature', methods=['POST'])
@deny_by_default
def verify_plugin_signature():
    """Verify plugin signature"""
    if g.user_role not in [UserRole.ADMIN, UserRole.MANAGER]:
        return api_response(error="Manager or Admin access required", status_code=403)
    
    data = request.get_json()
    
    try:
        signature = PluginSignature.from_dict(data['signature'])
        is_valid, message = plugin_signature_verifier.verify_plugin_signature(
            data['plugin_path'], signature
        )
        
        return api_response({
            'valid': is_valid,
            'message': message,
            'signature_details': signature.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Plugin signature verification failed: {e}")
        return api_response(error=str(e), status_code=400)

@security_bp.route('/plugins/trusted-signers', methods=['GET'])
@deny_by_default
def list_trusted_signers():
    """List trusted plugin signers"""
    if g.user_role not in [UserRole.ADMIN, UserRole.MANAGER]:
        return api_response(error="Manager or Admin access required", status_code=403)
    
    signers = plugin_signature_verifier.get_trusted_signers()
    return api_response([{
        'signer_id': signer.signer_id,
        'name': signer.name,
        'trusted_since': signer.trusted_since,
        'expires_at': signer.expires_at,
        'permissions': signer.permissions
    } for signer in signers])

# 3. DAST Integration
@security_bp.route('/tools/dast-scan', methods=['POST'])
@deny_by_default
def start_dast_scan():
    """Start DAST scan (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    data = request.get_json()
    
    try:
        tool = DASTTool(data.get('tool', 'internal_spider'))
        scan_id = dast_manager.start_dast_scan(
            target_url=data['target_url'],
            tool=tool,
            scan_config=data.get('scan_config', {})
        )
        
        # Log DAST scan initiation
        insider_threat_monitor.log_privileged_access(
            admin_user_id=g.user_id,
            target_user_id=None,
            access_type=AccessType.SYSTEM_CONFIG_CHANGE,
            resource_type="dast_scan",
            resource_id=scan_id,
            action="start",
            justification=data.get('justification', 'Security testing')
        )
        
        return api_response({
            'scan_id': scan_id,
            'tool': tool.value,
            'target_url': data['target_url'],
            'status': 'started'
        })
        
    except Exception as e:
        logger.error(f"DAST scan failed to start: {e}")
        return api_response(error=str(e), status_code=400)

@security_bp.route('/tools/dast-scan/<scan_id>', methods=['GET'])
@deny_by_default
def get_dast_scan_result(scan_id):
    """Get DAST scan results (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    scan_result = dast_manager.get_scan_result(scan_id)
    if not scan_result:
        return api_response(error="Scan not found", status_code=404)
    
    return api_response(scan_result.to_dict())

@security_bp.route('/tools/dast-scans', methods=['GET'])
@deny_by_default
def list_dast_scans():
    """List all DAST scans (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    scans = dast_manager.list_scans()
    return api_response([scan.to_dict() for scan in scans])

# 4. Insider Threat Auditing
@security_bp.route('/admin/activity', methods=['GET'])
@deny_by_default
def get_admin_activity():
    """Get admin activity logs (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    hours = request.args.get('hours', 24, type=int)
    threat_level = request.args.get('threat_level')
    
    threat_level_enum = None
    if threat_level:
        try:
            threat_level_enum = ThreatLevel(threat_level)
        except ValueError:
            return api_response(error="Invalid threat level", status_code=400)
    
    events = insider_threat_monitor.get_threat_events(
        threat_level=threat_level_enum,
        hours=hours
    )
    
    return api_response([event.to_dict() for event in events])

@security_bp.route('/admin/escalation-requests', methods=['GET'])
@deny_by_default
def get_escalation_requests():
    """Get JIT escalation requests (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    pending_only = request.args.get('pending_only', 'false').lower() == 'true'
    
    requests = insider_threat_monitor.get_escalation_requests(pending_only=pending_only)
    return api_response([{
        'request_id': req.request_id,
        'admin_user_id': req.admin_user_id,
        'requested_action': req.requested_action,
        'target_resource': req.target_resource,
        'justification': req.justification,
        'requested_at': req.requested_at,
        'expires_at': req.expires_at,
        'approved': req.approved,
        'approved_by': req.approved_by,
        'used': req.used
    } for req in requests])

@security_bp.route('/admin/escalation-requests/<request_id>/approve', methods=['POST'])
@deny_by_default
def approve_escalation_request(request_id):
    """Approve JIT escalation request (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    success = insider_threat_monitor.approve_jit_escalation(request_id, g.user_id)
    
    if success:
        return api_response({'message': 'Escalation request approved'})
    else:
        return api_response(error="Failed to approve request", status_code=400)

# 10. Disaster Recovery & Backups
@security_bp.route('/admin/backup/trigger', methods=['POST'])
@deny_by_default
def trigger_backup():
    """Trigger manual backup (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    data = request.get_json() or {}
    
    try:
        backup_path = backup_manager.create_backup(
            backup_name=data.get('backup_name'),
            include_database=data.get('include_database', True),
            include_files=data.get('include_files', True)
        )
        
        # Log backup creation
        insider_threat_monitor.log_privileged_access(
            admin_user_id=g.user_id,
            target_user_id=None,
            access_type=AccessType.SYSTEM_CONFIG_CHANGE,
            resource_type="backup",
            resource_id=backup_path,
            action="create",
            justification=data.get('justification', 'Manual backup')
        )
        
        return api_response({
            'message': 'Backup created successfully',
            'backup_path': backup_path
        })
        
    except Exception as e:
        logger.error(f"Manual backup failed: {e}")
        return api_response(error=str(e), status_code=500)

@security_bp.route('/admin/backups', methods=['GET'])
@deny_by_default
def list_backups():
    """List available backups (Admin only)"""
    if g.user_role != UserRole.ADMIN:
        return api_response(error="Admin access required", status_code=403)
    
    backups = backup_manager.list_backups()
    return api_response(backups)

# Security status endpoint
@security_bp.route('/status', methods=['GET'])
@deny_by_default
def security_status():
    """Get overall security status"""
    if g.user_role not in [UserRole.ADMIN, UserRole.MANAGER]:
        return api_response(error="Manager or Admin access required", status_code=403)
    
    # Get recent threat events
    recent_threats = insider_threat_monitor.get_threat_events(hours=24)
    high_threat_count = len([e for e in recent_threats if e.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]])
    
    # Get DAST scan status
    recent_scans = dast_manager.list_scans()
    active_scans = len([s for s in recent_scans if s.status.value == 'running'])
    
    # Get backup status
    backups = backup_manager.list_backups()
    latest_backup = backups[0] if backups else None
    
    status = {
        'overall_status': 'healthy',
        'components': {
            'zero_trust': {
                'status': 'active',
                'policies_count': len(zero_trust_enforcer.route_policies)
            },
            'plugin_security': {
                'status': 'active',
                'trusted_signers': len(plugin_signature_verifier.get_trusted_signers())
            },
            'dast_integration': {
                'status': 'active',
                'active_scans': active_scans
            },
            'insider_threat_monitoring': {
                'status': 'active',
                'high_threat_events_24h': high_threat_count
            },
            'backup_system': {
                'status': 'active',
                'latest_backup': latest_backup['created_at'] if latest_backup else None,
                'total_backups': len(backups)
            }
        },
        'alerts': []
    }
    
    # Add alerts for high threat events
    if high_threat_count > 0:
        status['alerts'].append({
            'type': 'warning',
            'message': f'{high_threat_count} high-threat events in the last 24 hours'
        })
    
    # Add alert if no recent backup
    if not latest_backup:
        status['alerts'].append({
            'type': 'error',
            'message': 'No backups found - consider creating a backup'
        })
    elif latest_backup:
        backup_age = datetime.now() - datetime.fromisoformat(latest_backup['created_at'])
        if backup_age.days > 7:
            status['alerts'].append({
                'type': 'warning',
                'message': f'Latest backup is {backup_age.days} days old'
            })
    
    return api_response(status)

# Register security blueprint with v1 API
api_v1.register_blueprint(security_bp, url_prefix='/security')
