"""
CI/CD Pipeline Integration for ByteGuardX
"""

import os
import sys
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CICDIntegration:
    """
    Base class for CI/CD integrations
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.scan_results = None
        
    def generate_config(self, pipeline_type: str, options: Dict = None) -> str:
        """Generate CI/CD configuration file"""
        options = options or {}
        
        if pipeline_type == "github":
            return self._generate_github_actions(options)
        elif pipeline_type == "gitlab":
            return self._generate_gitlab_ci(options)
        elif pipeline_type == "jenkins":
            return self._generate_jenkins_pipeline(options)
        elif pipeline_type == "azure":
            return self._generate_azure_pipelines(options)
        elif pipeline_type == "circleci":
            return self._generate_circleci_config(options)
        else:
            raise ValueError(f"Unsupported pipeline type: {pipeline_type}")
    
    def _generate_github_actions(self, options: Dict) -> str:
        """Generate GitHub Actions workflow"""
        config = {
            'name': 'ByteGuardX Security Scan',
            'on': {
                'push': {'branches': ['main', 'develop']},
                'pull_request': {'branches': ['main']}
            },
            'jobs': {
                'security-scan': {
                    'runs-on': 'ubuntu-latest',
                    'steps': [
                        {
                            'name': 'Checkout code',
                            'uses': 'actions/checkout@v4'
                        },
                        {
                            'name': 'Set up Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {'python-version': '3.11'}
                        },
                        {
                            'name': 'Install ByteGuardX',
                            'run': 'pip install byteguardx'
                        },
                        {
                            'name': 'Run Security Scan',
                            'run': 'byteguardx scan . --output security-report.json',
                            'env': {
                                'BYTEGUARDX_API_KEY': '${{ secrets.BYTEGUARDX_API_KEY }}'
                            }
                        },
                        {
                            'name': 'Upload Security Report',
                            'uses': 'actions/upload-artifact@v3',
                            'with': {
                                'name': 'security-report',
                                'path': 'security-report.json'
                            }
                        },
                        {
                            'name': 'Comment PR',
                            'if': 'github.event_name == \'pull_request\'',
                            'uses': 'actions/github-script@v6',
                            'with': {
                                'script': '''
                                const fs = require('fs');
                                const report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
                                const comment = `## 🔐 ByteGuardX Security Report
                                
                                **Total Issues Found:** ${report.total_findings}
                                **Critical:** ${report.findings.filter(f => f.severity === 'critical').length}
                                **High:** ${report.findings.filter(f => f.severity === 'high').length}
                                **Medium:** ${report.findings.filter(f => f.severity === 'medium').length}
                                **Low:** ${report.findings.filter(f => f.severity === 'low').length}
                                
                                ${report.total_findings > 0 ? '⚠️ Please review and fix security issues before merging.' : '✅ No security issues found!'}
                                `;
                                
                                github.rest.issues.createComment({
                                  issue_number: context.issue.number,
                                  owner: context.repo.owner,
                                  repo: context.repo.repo,
                                  body: comment
                                });
                                '''
                            }
                        }
                    ]
                }
            }
        }
        
        # Add failure conditions if specified
        if options.get('fail_on_critical', True):
            config['jobs']['security-scan']['steps'].append({
                'name': 'Fail on Critical Issues',
                'run': '''
                python -c "
                import json
                with open('security-report.json') as f:
                    report = json.load(f)
                critical_count = len([f for f in report['findings'] if f['severity'] == 'critical'])
                if critical_count > 0:
                    print(f'❌ Found {critical_count} critical security issues!')
                    exit(1)
                print('✅ No critical security issues found')
                "
                '''
            })
        
        return yaml.dump(config, default_flow_style=False)
    
    def _generate_gitlab_ci(self, options: Dict) -> str:
        """Generate GitLab CI configuration"""
        config = {
            'stages': ['security'],
            'variables': {
                'PIP_CACHE_DIR': '$CI_PROJECT_DIR/.cache/pip'
            },
            'cache': {
                'paths': ['.cache/pip']
            },
            'security_scan': {
                'stage': 'security',
                'image': 'python:3.11',
                'before_script': [
                    'pip install byteguardx'
                ],
                'script': [
                    'byteguardx scan . --output security-report.json',
                    'byteguardx scan . --pdf'
                ],
                'artifacts': {
                    'reports': {
                        'junit': 'security-report.xml'
                    },
                    'paths': [
                        'security-report.json',
                        '*.pdf'
                    ],
                    'expire_in': '1 week'
                },
                'rules': [
                    {'if': '$CI_PIPELINE_SOURCE == "merge_request_event"'},
                    {'if': '$CI_COMMIT_BRANCH == "main"'}
                ]
            }
        }
        
        if options.get('fail_on_critical', True):
            config['security_scan']['after_script'] = [
                '''
                python -c "
                import json
                with open('security-report.json') as f:
                    report = json.load(f)
                critical_count = len([f for f in report['findings'] if f['severity'] == 'critical'])
                if critical_count > 0:
                    exit(1)
                "
                '''
            ]
        
        return yaml.dump(config, default_flow_style=False)
    
    def _generate_jenkins_pipeline(self, options: Dict) -> str:
        """Generate Jenkins pipeline script"""
        script = '''
pipeline {
    agent any
    
    environment {
        BYTEGUARDX_API_KEY = credentials('byteguardx-api-key')
    }
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install byteguardx'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'byteguardx scan . --output security-report.json'
                sh 'byteguardx scan . --pdf'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json,*.pdf', fingerprint: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'security-report.html',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    def report = readJSON file: 'security-report.json'
                    def criticalCount = report.findings.count { it.severity == 'critical' }
                    
                    if (criticalCount > 0) {
                        error("Found ${criticalCount} critical security issues!")
                    }
                    
                    echo "✅ Security scan passed"
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security scan failed. Please check the build logs and security report.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
        '''
        
        return script.strip()
    
    def _generate_azure_pipelines(self, options: Dict) -> str:
        """Generate Azure Pipelines configuration"""
        config = {
            'trigger': ['main', 'develop'],
            'pr': ['main'],
            'pool': {
                'vmImage': 'ubuntu-latest'
            },
            'variables': {
                'pythonVersion': '3.11'
            },
            'steps': [
                {
                    'task': 'UsePythonVersion@0',
                    'inputs': {
                        'versionSpec': '$(pythonVersion)'
                    },
                    'displayName': 'Use Python $(pythonVersion)'
                },
                {
                    'script': 'pip install byteguardx',
                    'displayName': 'Install ByteGuardX'
                },
                {
                    'script': 'byteguardx scan . --output $(Agent.TempDirectory)/security-report.json',
                    'displayName': 'Run Security Scan',
                    'env': {
                        'BYTEGUARDX_API_KEY': '$(BYTEGUARDX_API_KEY)'
                    }
                },
                {
                    'task': 'PublishBuildArtifacts@1',
                    'inputs': {
                        'pathToPublish': '$(Agent.TempDirectory)/security-report.json',
                        'artifactName': 'SecurityReport'
                    },
                    'displayName': 'Publish Security Report'
                }
            ]
        }
        
        if options.get('fail_on_critical', True):
            config['steps'].append({
                'script': '''
                python -c "
                import json
                with open('$(Agent.TempDirectory)/security-report.json') as f:
                    report = json.load(f)
                critical_count = len([f for f in report['findings'] if f['severity'] == 'critical'])
                if critical_count > 0:
                    print(f'##vso[task.logissue type=error]Found {critical_count} critical security issues!')
                    exit(1)
                print('✅ No critical security issues found')
                "
                ''',
                'displayName': 'Security Gate Check'
            })
        
        return yaml.dump(config, default_flow_style=False)
    
    def _generate_circleci_config(self, options: Dict) -> str:
        """Generate CircleCI configuration"""
        config = {
            'version': 2.1,
            'jobs': {
                'security-scan': {
                    'docker': [{'image': 'python:3.11'}],
                    'steps': [
                        'checkout',
                        {
                            'run': {
                                'name': 'Install ByteGuardX',
                                'command': 'pip install byteguardx'
                            }
                        },
                        {
                            'run': {
                                'name': 'Run Security Scan',
                                'command': 'byteguardx scan . --output security-report.json'
                            }
                        },
                        {
                            'store_artifacts': {
                                'path': 'security-report.json',
                                'destination': 'security-report'
                            }
                        }
                    ]
                }
            },
            'workflows': {
                'version': 2,
                'security-workflow': {
                    'jobs': ['security-scan']
                }
            }
        }
        
        if options.get('fail_on_critical', True):
            config['jobs']['security-scan']['steps'].append({
                'run': {
                    'name': 'Security Gate Check',
                    'command': '''
                    python -c "
                    import json
                    with open('security-report.json') as f:
                        report = json.load(f)
                    critical_count = len([f for f in report['findings'] if f['severity'] == 'critical'])
                    if critical_count > 0:
                        print(f'Found {critical_count} critical security issues!')
                        exit(1)
                    print('✅ No critical security issues found')
                    "
                    '''
                }
            })
        
        return yaml.dump(config, default_flow_style=False)

class SlackNotifier:
    """Slack integration for security notifications"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_scan_results(self, scan_results: Dict):
        """Send scan results to Slack"""
        try:
            import requests
            
            total_findings = scan_results.get('total_findings', 0)
            critical_count = len([f for f in scan_results.get('findings', []) if f.get('severity') == 'critical'])
            
            color = 'danger' if critical_count > 0 else 'warning' if total_findings > 0 else 'good'
            
            message = {
                'attachments': [{
                    'color': color,
                    'title': '🔐 ByteGuardX Security Scan Results',
                    'fields': [
                        {'title': 'Total Issues', 'value': str(total_findings), 'short': True},
                        {'title': 'Critical', 'value': str(critical_count), 'short': True},
                        {'title': 'Repository', 'value': scan_results.get('repository', 'Unknown'), 'short': True},
                        {'title': 'Branch', 'value': scan_results.get('branch', 'Unknown'), 'short': True}
                    ],
                    'footer': 'ByteGuardX Security Scanner',
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(self.webhook_url, json=message)
            response.raise_for_status()
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

class JiraIntegration:
    """JIRA integration for creating security issues"""
    
    def __init__(self, server_url: str, username: str, api_token: str, project_key: str):
        self.server_url = server_url
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
    
    def create_security_issues(self, findings: List[Dict]) -> List[str]:
        """Create JIRA issues for critical/high severity findings"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            created_issues = []
            auth = HTTPBasicAuth(self.username, self.api_token)
            
            for finding in findings:
                if finding.get('severity') in ['critical', 'high']:
                    issue_data = {
                        'fields': {
                            'project': {'key': self.project_key},
                            'summary': f"Security Issue: {finding.get('description', 'Unknown')}",
                            'description': self._format_finding_description(finding),
                            'issuetype': {'name': 'Bug'},
                            'priority': {'name': 'High' if finding.get('severity') == 'critical' else 'Medium'},
                            'labels': ['security', 'byteguardx', finding.get('severity', 'unknown')]
                        }
                    }
                    
                    response = requests.post(
                        f"{self.server_url}/rest/api/2/issue",
                        json=issue_data,
                        auth=auth,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 201:
                        issue_key = response.json()['key']
                        created_issues.append(issue_key)
                        logger.info(f"Created JIRA issue: {issue_key}")
                    else:
                        logger.error(f"Failed to create JIRA issue: {response.text}")
            
            return created_issues
            
        except Exception as e:
            logger.error(f"Failed to create JIRA issues: {e}")
            return []
    
    def _format_finding_description(self, finding: Dict) -> str:
        """Format finding for JIRA description"""
        description = f"""
*Security Finding Details*

*Severity:* {finding.get('severity', 'Unknown').upper()}
*Type:* {finding.get('type', 'Unknown')}
*File:* {finding.get('file_path', 'Unknown')}
*Line:* {finding.get('line_number', 'Unknown')}

*Description:*
{finding.get('description', 'No description available')}

*Code Context:*
{{code}}
{finding.get('context', 'No context available')}
{{code}}

*Recommendation:*
{finding.get('recommendation', 'No recommendation available')}

---
_This issue was automatically created by ByteGuardX Security Scanner_
        """
        return description.strip()

def generate_integration_files(output_dir: str = "."):
    """Generate all CI/CD integration files"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    cicd = CICDIntegration()
    
    # Generate all pipeline configurations
    pipelines = {
        'github': ('.github/workflows/security.yml', 'github'),
        'gitlab': ('.gitlab-ci.yml', 'gitlab'),
        'jenkins': ('Jenkinsfile', 'jenkins'),
        'azure': ('azure-pipelines.yml', 'azure'),
        'circleci': ('.circleci/config.yml', 'circleci')
    }
    
    for name, (filename, pipeline_type) in pipelines.items():
        try:
            config_content = cicd.generate_config(pipeline_type, {'fail_on_critical': True})
            
            file_path = output_path / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(config_content)
            
            print(f"✅ Generated {filename}")
            
        except Exception as e:
            print(f"❌ Failed to generate {filename}: {e}")

if __name__ == "__main__":
    generate_integration_files()
