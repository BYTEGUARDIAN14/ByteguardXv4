"""
CI/CD integration for ByteGuardX
Provides integration with GitHub, GitLab, Jenkins, and other CI/CD platforms
"""

import logging
import json
import base64
import hashlib
import hmac
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import requests
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class CICDPlatform(Enum):
    """Supported CI/CD platforms"""
    GITHUB = "github"
    GITLAB = "gitlab"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"
    CIRCLECI = "circleci"

class ScanTrigger(Enum):
    """Scan trigger events"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MERGE_REQUEST = "merge_request"
    SCHEDULED = "scheduled"
    MANUAL = "manual"

@dataclass
class CICDConfig:
    """CI/CD integration configuration"""
    platform: CICDPlatform
    enabled: bool = True
    
    # Authentication
    api_token: str = ""
    webhook_secret: str = ""
    
    # Repository settings
    repository_url: str = ""
    default_branch: str = "main"
    
    # Scan settings
    auto_scan_on_push: bool = True
    auto_scan_on_pr: bool = True
    scan_timeout_minutes: int = 30
    fail_on_critical: bool = True
    fail_on_high: bool = False
    
    # Notification settings
    post_comments: bool = True
    update_status: bool = True
    
    # Custom settings
    custom_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanRequest:
    """CI/CD scan request"""
    platform: CICDPlatform
    trigger: ScanTrigger
    repository_url: str
    branch: str
    commit_sha: str
    pull_request_id: Optional[str] = None
    triggered_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """CI/CD scan result"""
    scan_id: str
    status: str  # 'success', 'failure', 'error'
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    scan_duration: float
    report_url: str = ""
    summary: str = ""

class CICDIntegration(ABC):
    """Base class for CI/CD integrations"""
    
    def __init__(self, config: CICDConfig):
        self.config = config
        self.scan_callbacks: List[Callable] = []
    
    @abstractmethod
    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature"""
        pass
    
    @abstractmethod
    def parse_webhook(self, payload: Dict[str, Any]) -> Optional[ScanRequest]:
        """Parse webhook payload into scan request"""
        pass
    
    @abstractmethod
    def update_status(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Update commit/PR status"""
        pass
    
    @abstractmethod
    def post_comment(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Post scan results as comment"""
        pass
    
    def add_scan_callback(self, callback: Callable[[ScanRequest], ScanResult]):
        """Add callback for handling scan requests"""
        self.scan_callbacks.append(callback)
    
    def handle_webhook(self, payload: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        """Handle incoming webhook"""
        try:
            # Verify signature
            signature = headers.get('X-Hub-Signature-256') or headers.get('X-GitLab-Token') or ''
            if not self.verify_webhook(payload, signature):
                return {'error': 'Invalid webhook signature', 'status': 401}
            
            # Parse payload
            payload_dict = json.loads(payload.decode('utf-8'))
            scan_request = self.parse_webhook(payload_dict)
            
            if not scan_request:
                return {'message': 'No scan required for this event', 'status': 200}
            
            # Trigger scan
            scan_result = self._trigger_scan(scan_request)
            
            # Update status and post comments
            if self.config.update_status:
                self.update_status(scan_request, scan_result)
            
            if self.config.post_comments and scan_request.pull_request_id:
                self.post_comment(scan_request, scan_result)
            
            return {
                'message': 'Scan completed successfully',
                'scan_id': scan_result.scan_id,
                'status': 200
            }
            
        except Exception as e:
            logger.error(f"Failed to handle webhook: {e}")
            return {'error': str(e), 'status': 500}
    
    def _trigger_scan(self, scan_request: ScanRequest) -> ScanResult:
        """Trigger scan using registered callbacks"""
        if not self.scan_callbacks:
            raise ValueError("No scan callbacks registered")
        
        # Use the first callback (could be enhanced to support multiple)
        callback = self.scan_callbacks[0]
        return callback(scan_request)

class GitHubIntegration(CICDIntegration):
    """GitHub CI/CD integration"""
    
    def __init__(self, config: CICDConfig):
        super().__init__(config)
        self.api_base = "https://api.github.com"
    
    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature"""
        if not self.config.webhook_secret or not signature:
            return False
        
        expected_signature = 'sha256=' + hmac.new(
            self.config.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def parse_webhook(self, payload: Dict[str, Any]) -> Optional[ScanRequest]:
        """Parse GitHub webhook payload"""
        event_type = payload.get('action', '')
        
        # Handle push events
        if 'commits' in payload and payload.get('ref'):
            branch = payload['ref'].replace('refs/heads/', '')
            
            if not self.config.auto_scan_on_push:
                return None
            
            return ScanRequest(
                platform=CICDPlatform.GITHUB,
                trigger=ScanTrigger.PUSH,
                repository_url=payload['repository']['clone_url'],
                branch=branch,
                commit_sha=payload['after'],
                triggered_by=payload.get('pusher', {}).get('name', ''),
                metadata={
                    'repository': payload['repository']['full_name'],
                    'commits': payload['commits']
                }
            )
        
        # Handle pull request events
        elif 'pull_request' in payload:
            if not self.config.auto_scan_on_pr:
                return None
            
            pr = payload['pull_request']
            
            # Only scan on opened, synchronize, or reopened
            if event_type not in ['opened', 'synchronize', 'reopened']:
                return None
            
            return ScanRequest(
                platform=CICDPlatform.GITHUB,
                trigger=ScanTrigger.PULL_REQUEST,
                repository_url=pr['head']['repo']['clone_url'],
                branch=pr['head']['ref'],
                commit_sha=pr['head']['sha'],
                pull_request_id=str(pr['number']),
                triggered_by=pr['user']['login'],
                metadata={
                    'repository': payload['repository']['full_name'],
                    'pull_request': pr
                }
            )
        
        return None
    
    def update_status(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Update GitHub commit status"""
        try:
            repo_full_name = scan_request.metadata.get('repository', '')
            if not repo_full_name:
                return False
            
            # Determine status
            if scan_result.status == 'success':
                if (self.config.fail_on_critical and scan_result.critical_findings > 0) or \
                   (self.config.fail_on_high and scan_result.high_findings > 0):
                    state = 'failure'
                    description = f"Security scan failed: {scan_result.critical_findings} critical, {scan_result.high_findings} high findings"
                else:
                    state = 'success'
                    description = f"Security scan passed: {scan_result.total_findings} findings"
            else:
                state = 'error'
                description = "Security scan encountered an error"
            
            # Post status
            status_data = {
                'state': state,
                'target_url': scan_result.report_url,
                'description': description,
                'context': 'security/byteguardx'
            }
            
            url = f"{self.api_base}/repos/{repo_full_name}/statuses/{scan_request.commit_sha}"
            headers = {
                'Authorization': f'token {self.config.api_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            response = requests.post(url, json=status_data, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Updated GitHub status for {repo_full_name}#{scan_request.commit_sha}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update GitHub status: {e}")
            return False
    
    def post_comment(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Post scan results as GitHub PR comment"""
        try:
            repo_full_name = scan_request.metadata.get('repository', '')
            pr_number = scan_request.pull_request_id
            
            if not repo_full_name or not pr_number:
                return False
            
            # Generate comment
            comment = self._generate_comment(scan_result)
            
            # Post comment
            url = f"{self.api_base}/repos/{repo_full_name}/issues/{pr_number}/comments"
            headers = {
                'Authorization': f'token {self.config.api_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            response = requests.post(url, json={'body': comment}, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Posted GitHub comment for {repo_full_name}#{pr_number}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to post GitHub comment: {e}")
            return False
    
    def _generate_comment(self, scan_result: ScanResult) -> str:
        """Generate scan results comment"""
        if scan_result.status == 'success':
            emoji = "✅" if scan_result.critical_findings == 0 else "⚠️"
            status_text = "completed"
        else:
            emoji = "❌"
            status_text = "failed"
        
        comment = f"""## {emoji} ByteGuardX Security Scan {status_text.title()}

**Scan Results:**
- 🔴 Critical: {scan_result.critical_findings}
- 🟠 High: {scan_result.high_findings}
- 🟡 Medium: {scan_result.medium_findings}
- 🔵 Low: {scan_result.low_findings}
- **Total**: {scan_result.total_findings} findings

**Scan Duration:** {scan_result.scan_duration:.1f}s
"""
        
        if scan_result.report_url:
            comment += f"\n[📊 View Detailed Report]({scan_result.report_url})"
        
        if scan_result.summary:
            comment += f"\n\n**Summary:** {scan_result.summary}"
        
        return comment

class GitLabIntegration(CICDIntegration):
    """GitLab CI/CD integration"""
    
    def __init__(self, config: CICDConfig):
        super().__init__(config)
        # Extract GitLab instance URL from repository URL
        if config.repository_url:
            parts = config.repository_url.split('/')
            self.api_base = f"https://{parts[2]}/api/v4"
        else:
            self.api_base = "https://gitlab.com/api/v4"
    
    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        """Verify GitLab webhook token"""
        return signature == self.config.webhook_secret
    
    def parse_webhook(self, payload: Dict[str, Any]) -> Optional[ScanRequest]:
        """Parse GitLab webhook payload"""
        object_kind = payload.get('object_kind', '')
        
        # Handle push events
        if object_kind == 'push':
            if not self.config.auto_scan_on_push:
                return None
            
            branch = payload['ref'].replace('refs/heads/', '')
            
            return ScanRequest(
                platform=CICDPlatform.GITLAB,
                trigger=ScanTrigger.PUSH,
                repository_url=payload['project']['git_http_url'],
                branch=branch,
                commit_sha=payload['after'],
                triggered_by=payload.get('user_name', ''),
                metadata={
                    'project': payload['project'],
                    'commits': payload['commits']
                }
            )
        
        # Handle merge request events
        elif object_kind == 'merge_request':
            if not self.config.auto_scan_on_pr:
                return None
            
            mr = payload['object_attributes']
            
            # Only scan on opened or updated
            if mr['action'] not in ['open', 'update']:
                return None
            
            return ScanRequest(
                platform=CICDPlatform.GITLAB,
                trigger=ScanTrigger.MERGE_REQUEST,
                repository_url=payload['project']['git_http_url'],
                branch=mr['source_branch'],
                commit_sha=mr['last_commit']['id'],
                pull_request_id=str(mr['iid']),
                triggered_by=payload.get('user', {}).get('name', ''),
                metadata={
                    'project': payload['project'],
                    'merge_request': mr
                }
            )
        
        return None
    
    def update_status(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Update GitLab commit status"""
        try:
            project_id = scan_request.metadata.get('project', {}).get('id')
            if not project_id:
                return False
            
            # Determine status
            if scan_result.status == 'success':
                if (self.config.fail_on_critical and scan_result.critical_findings > 0) or \
                   (self.config.fail_on_high and scan_result.high_findings > 0):
                    state = 'failed'
                else:
                    state = 'success'
            else:
                state = 'failed'
            
            # Post status
            status_data = {
                'state': state,
                'target_url': scan_result.report_url,
                'description': f"ByteGuardX: {scan_result.total_findings} findings",
                'name': 'security/byteguardx'
            }
            
            url = f"{self.api_base}/projects/{project_id}/statuses/{scan_request.commit_sha}"
            headers = {
                'PRIVATE-TOKEN': self.config.api_token,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=status_data, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Updated GitLab status for project {project_id}#{scan_request.commit_sha}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update GitLab status: {e}")
            return False
    
    def post_comment(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Post scan results as GitLab MR comment"""
        try:
            project_id = scan_request.metadata.get('project', {}).get('id')
            mr_iid = scan_request.pull_request_id
            
            if not project_id or not mr_iid:
                return False
            
            # Generate comment
            comment = self._generate_comment(scan_result)
            
            # Post comment
            url = f"{self.api_base}/projects/{project_id}/merge_requests/{mr_iid}/notes"
            headers = {
                'PRIVATE-TOKEN': self.config.api_token,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json={'body': comment}, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Posted GitLab comment for project {project_id} MR {mr_iid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to post GitLab comment: {e}")
            return False
    
    def _generate_comment(self, scan_result: ScanResult) -> str:
        """Generate scan results comment for GitLab"""
        if scan_result.status == 'success':
            emoji = "✅" if scan_result.critical_findings == 0 else "⚠️"
            status_text = "completed"
        else:
            emoji = "❌"
            status_text = "failed"
        
        comment = f"""## {emoji} ByteGuardX Security Scan {status_text.title()}

| Severity | Count |
|----------|-------|
| 🔴 Critical | {scan_result.critical_findings} |
| 🟠 High | {scan_result.high_findings} |
| 🟡 Medium | {scan_result.medium_findings} |
| 🔵 Low | {scan_result.low_findings} |
| **Total** | **{scan_result.total_findings}** |

**Scan Duration:** {scan_result.scan_duration:.1f}s
"""
        
        if scan_result.report_url:
            comment += f"\n[📊 View Detailed Report]({scan_result.report_url})"
        
        return comment

class JenkinsIntegration(CICDIntegration):
    """Jenkins CI/CD integration"""
    
    def __init__(self, config: CICDConfig):
        super().__init__(config)
        self.jenkins_url = config.custom_config.get('jenkins_url', '')
    
    def verify_webhook(self, payload: bytes, signature: str) -> bool:
        """Jenkins webhook verification (basic token check)"""
        return signature == self.config.webhook_secret
    
    def parse_webhook(self, payload: Dict[str, Any]) -> Optional[ScanRequest]:
        """Parse Jenkins webhook payload"""
        # Jenkins webhook format varies, this is a basic implementation
        build_info = payload.get('build', {})
        scm_info = payload.get('scm', {})
        
        if not build_info or not scm_info:
            return None
        
        return ScanRequest(
            platform=CICDPlatform.JENKINS,
            trigger=ScanTrigger.PUSH,
            repository_url=scm_info.get('url', ''),
            branch=scm_info.get('branch', 'main'),
            commit_sha=scm_info.get('commit', ''),
            triggered_by=build_info.get('user', ''),
            metadata={
                'build': build_info,
                'job_name': payload.get('name', ''),
                'build_number': build_info.get('number', 0)
            }
        )
    
    def update_status(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Update Jenkins build status (if supported)"""
        # Jenkins status updates would depend on specific plugins
        logger.info(f"Jenkins scan completed: {scan_result.total_findings} findings")
        return True
    
    def post_comment(self, scan_request: ScanRequest, scan_result: ScanResult) -> bool:
        """Jenkins doesn't have native comment support"""
        return True

# Integration factory
def create_cicd_integration(config: CICDConfig) -> CICDIntegration:
    """Factory function to create CI/CD integration"""
    if config.platform == CICDPlatform.GITHUB:
        return GitHubIntegration(config)
    elif config.platform == CICDPlatform.GITLAB:
        return GitLabIntegration(config)
    elif config.platform == CICDPlatform.JENKINS:
        return JenkinsIntegration(config)
    else:
        raise ValueError(f"Unsupported CI/CD platform: {config.platform}")

# Global integrations registry
cicd_integrations: Dict[str, CICDIntegration] = {}
