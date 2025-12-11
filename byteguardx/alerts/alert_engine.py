"""
Lightweight Alert Engine for ByteGuardX
Provides email, webhook, and other notification mechanisms
"""

import os
import json
import logging
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import threading
import queue
import time

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertType(Enum):
    """Types of alerts"""
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITIES_FOUND = "vulnerabilities_found"
    SECURITY_THRESHOLD_EXCEEDED = "security_threshold_exceeded"
    SYSTEM_ERROR = "system_error"
    AUTHENTICATION_FAILURE = "authentication_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

@dataclass
class AlertRule:
    """Configuration for alert rules"""
    name: str
    alert_type: AlertType
    severity_threshold: AlertSeverity
    conditions: Dict[str, Any]
    enabled: bool = True
    cooldown_minutes: int = 60
    notification_channels: List[str] = None
    
    def __post_init__(self):
        if self.notification_channels is None:
            self.notification_channels = ["email"]

@dataclass
class Alert:
    """Alert data structure"""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime
    source: str
    metadata: Dict[str, Any] = None
    resolved: bool = False
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, smtp_config: Dict[str, Any]):
        self.smtp_host = smtp_config.get('host', 'localhost')
        self.smtp_port = smtp_config.get('port', 587)
        self.smtp_username = smtp_config.get('username', '')
        self.smtp_password = smtp_config.get('password', '')
        self.smtp_use_tls = smtp_config.get('use_tls', True)
        self.from_email = smtp_config.get('from_email', 'noreply@byteguardx.com')
        self.to_emails = smtp_config.get('to_emails', [])
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert via email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[ByteGuardX] {alert.severity.value.upper()}: {alert.title}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"Email alert sent successfully: {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _create_email_body(self, alert: Alert) -> str:
        """Create HTML email body"""
        severity_colors = {
            AlertSeverity.LOW: "#28a745",
            AlertSeverity.MEDIUM: "#ffc107", 
            AlertSeverity.HIGH: "#fd7e14",
            AlertSeverity.CRITICAL: "#dc3545"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .metadata {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; margin-top: 10px; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🔒 ByteGuardX Security Alert</h2>
                <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
                <p><strong>Type:</strong> {alert.alert_type.value.replace('_', ' ').title()}</p>
            </div>
            
            <div class="content">
                <h3>{alert.title}</h3>
                <p>{alert.message}</p>
                
                <div class="metadata">
                    <h4>Alert Details:</h4>
                    <ul>
                        <li><strong>Alert ID:</strong> {alert.id}</li>
                        <li><strong>Timestamp:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                        <li><strong>Source:</strong> {alert.source}</li>
                    </ul>
                    
                    {self._format_metadata(alert.metadata)}
                </div>
            </div>
            
            <div class="footer">
                <p>This alert was generated by ByteGuardX Security Scanner.</p>
                <p>For more information, please check your ByteGuardX dashboard.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_metadata(self, metadata: Dict[str, Any]) -> str:
        """Format metadata for email display"""
        if not metadata:
            return ""
        
        html = "<h4>Additional Information:</h4><ul>"
        for key, value in metadata.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        html += "</ul>"
        
        return html

class WebhookNotifier:
    """Webhook notification handler"""
    
    def __init__(self, webhook_config: Dict[str, Any]):
        self.webhook_url = webhook_config.get('url', '')
        self.webhook_secret = webhook_config.get('secret', '')
        self.webhook_format = webhook_config.get('format', 'slack')  # slack, discord, teams, generic
        self.timeout = webhook_config.get('timeout', 10)
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert via webhook"""
        try:
            if not self.webhook_url:
                logger.warning("Webhook URL not configured")
                return False
            
            # Format payload based on webhook type
            payload = self._format_payload(alert)
            
            # Add authentication if secret is provided
            headers = {'Content-Type': 'application/json'}
            if self.webhook_secret:
                headers['Authorization'] = f"Bearer {self.webhook_secret}"
            
            # Send webhook
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            logger.info(f"Webhook alert sent successfully: {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    def _format_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format payload based on webhook type"""
        if self.webhook_format == 'slack':
            return self._format_slack_payload(alert)
        elif self.webhook_format == 'discord':
            return self._format_discord_payload(alert)
        elif self.webhook_format == 'teams':
            return self._format_teams_payload(alert)
        else:
            return self._format_generic_payload(alert)
    
    def _format_slack_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format payload for Slack"""
        severity_colors = {
            AlertSeverity.LOW: "good",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.HIGH: "danger",
            AlertSeverity.CRITICAL: "danger"
        }
        
        severity_emojis = {
            AlertSeverity.LOW: "🟢",
            AlertSeverity.MEDIUM: "🟡",
            AlertSeverity.HIGH: "🟠",
            AlertSeverity.CRITICAL: "🔴"
        }
        
        color = severity_colors.get(alert.severity, "good")
        emoji = severity_emojis.get(alert.severity, "🔒")
        
        return {
            "text": f"{emoji} ByteGuardX Security Alert",
            "attachments": [
                {
                    "color": color,
                    "title": alert.title,
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert.severity.value.upper(),
                            "short": True
                        },
                        {
                            "title": "Type",
                            "value": alert.alert_type.value.replace('_', ' ').title(),
                            "short": True
                        },
                        {
                            "title": "Source",
                            "value": alert.source,
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            "short": True
                        }
                    ],
                    "footer": "ByteGuardX",
                    "ts": int(alert.timestamp.timestamp())
                }
            ]
        }
    
    def _format_discord_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format payload for Discord"""
        severity_colors = {
            AlertSeverity.LOW: 0x28a745,
            AlertSeverity.MEDIUM: 0xffc107,
            AlertSeverity.HIGH: 0xfd7e14,
            AlertSeverity.CRITICAL: 0xdc3545
        }
        
        color = severity_colors.get(alert.severity, 0x6c757d)
        
        return {
            "embeds": [
                {
                    "title": "🔒 ByteGuardX Security Alert",
                    "description": alert.title,
                    "color": color,
                    "fields": [
                        {
                            "name": "Message",
                            "value": alert.message,
                            "inline": False
                        },
                        {
                            "name": "Severity",
                            "value": alert.severity.value.upper(),
                            "inline": True
                        },
                        {
                            "name": "Type",
                            "value": alert.alert_type.value.replace('_', ' ').title(),
                            "inline": True
                        },
                        {
                            "name": "Source",
                            "value": alert.source,
                            "inline": True
                        }
                    ],
                    "timestamp": alert.timestamp.isoformat(),
                    "footer": {
                        "text": "ByteGuardX Security Scanner"
                    }
                }
            ]
        }
    
    def _format_teams_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format payload for Microsoft Teams"""
        severity_colors = {
            AlertSeverity.LOW: "Good",
            AlertSeverity.MEDIUM: "Warning",
            AlertSeverity.HIGH: "Attention",
            AlertSeverity.CRITICAL: "Attention"
        }
        
        theme_color = severity_colors.get(alert.severity, "Good")
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"ByteGuardX Alert: {alert.title}",
            "sections": [
                {
                    "activityTitle": "🔒 ByteGuardX Security Alert",
                    "activitySubtitle": alert.title,
                    "activityImage": "https://byteguardx.com/logo.png",
                    "facts": [
                        {
                            "name": "Severity",
                            "value": alert.severity.value.upper()
                        },
                        {
                            "name": "Type",
                            "value": alert.alert_type.value.replace('_', ' ').title()
                        },
                        {
                            "name": "Source",
                            "value": alert.source
                        },
                        {
                            "name": "Timestamp",
                            "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
                        }
                    ],
                    "text": alert.message
                }
            ]
        }
    
    def _format_generic_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format generic payload"""
        return {
            "alert": asdict(alert),
            "timestamp": alert.timestamp.isoformat(),
            "source": "ByteGuardX"
        }

class AlertEngine:
    """Main alert engine"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.rules = []
        self.notifiers = {}
        self.alert_history = []
        self.alert_queue = queue.Queue()
        self.worker_thread = None
        self.running = False
        self.cooldown_tracker = {}
        
        self._setup_notifiers()
        self._load_default_rules()
    
    def _setup_notifiers(self):
        """Setup notification handlers"""
        # Email notifier
        email_config = self.config.get('email', {})
        if email_config.get('enabled', False):
            self.notifiers['email'] = EmailNotifier(email_config)
        
        # Webhook notifier
        webhook_config = self.config.get('webhook', {})
        if webhook_config.get('enabled', False):
            self.notifiers['webhook'] = WebhookNotifier(webhook_config)
    
    def _load_default_rules(self):
        """Load default alert rules"""
        default_rules = [
            AlertRule(
                name="Critical Vulnerabilities Found",
                alert_type=AlertType.VULNERABILITIES_FOUND,
                severity_threshold=AlertSeverity.CRITICAL,
                conditions={"min_critical_count": 1},
                cooldown_minutes=30
            ),
            AlertRule(
                name="High Severity Threshold",
                alert_type=AlertType.SECURITY_THRESHOLD_EXCEEDED,
                severity_threshold=AlertSeverity.HIGH,
                conditions={"min_high_count": 5},
                cooldown_minutes=60
            ),
            AlertRule(
                name="Authentication Failures",
                alert_type=AlertType.AUTHENTICATION_FAILURE,
                severity_threshold=AlertSeverity.MEDIUM,
                conditions={"failure_count": 10, "time_window_minutes": 15},
                cooldown_minutes=30
            )
        ]
        
        self.rules.extend(default_rules)
    
    def start(self):
        """Start the alert engine"""
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        logger.info("Alert engine started")
    
    def stop(self):
        """Stop the alert engine"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("Alert engine stopped")
    
    def _worker_loop(self):
        """Main worker loop for processing alerts"""
        while self.running:
            try:
                # Process alerts from queue
                alert = self.alert_queue.get(timeout=1)
                self._process_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    def trigger_alert(self, alert_type: AlertType, title: str, message: str,
                     severity: AlertSeverity = AlertSeverity.MEDIUM,
                     source: str = "ByteGuardX", metadata: Dict[str, Any] = None):
        """Trigger a new alert"""
        alert = Alert(
            id=f"alert_{int(time.time())}_{hash(title) % 10000}",
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            timestamp=datetime.utcnow(),
            source=source,
            metadata=metadata or {}
        )
        
        # Check if alert should be triggered based on rules
        if self._should_trigger_alert(alert):
            self.alert_queue.put(alert)
            logger.info(f"Alert triggered: {alert.id}")
    
    def _should_trigger_alert(self, alert: Alert) -> bool:
        """Check if alert should be triggered based on rules and cooldown"""
        # Find matching rules
        matching_rules = [
            rule for rule in self.rules
            if rule.enabled and rule.alert_type == alert.alert_type
        ]
        
        if not matching_rules:
            return True  # No rules, allow alert
        
        for rule in matching_rules:
            # Check severity threshold
            severity_levels = {
                AlertSeverity.LOW: 1,
                AlertSeverity.MEDIUM: 2,
                AlertSeverity.HIGH: 3,
                AlertSeverity.CRITICAL: 4
            }
            
            if severity_levels[alert.severity] < severity_levels[rule.severity_threshold]:
                continue
            
            # Check cooldown
            cooldown_key = f"{rule.name}_{alert.alert_type.value}"
            last_triggered = self.cooldown_tracker.get(cooldown_key)
            
            if last_triggered:
                time_since = datetime.utcnow() - last_triggered
                if time_since.total_seconds() < rule.cooldown_minutes * 60:
                    logger.debug(f"Alert {alert.id} suppressed due to cooldown")
                    continue
            
            # Check rule conditions
            if self._check_rule_conditions(rule, alert):
                self.cooldown_tracker[cooldown_key] = datetime.utcnow()
                return True
        
        return False
    
    def _check_rule_conditions(self, rule: AlertRule, alert: Alert) -> bool:
        """Check if rule conditions are met"""
        conditions = rule.conditions
        metadata = alert.metadata
        
        # Check minimum counts
        for key, min_value in conditions.items():
            if key.startswith("min_") and key.endswith("_count"):
                actual_value = metadata.get(key.replace("min_", "").replace("_count", "_count"), 0)
                if actual_value < min_value:
                    return False
        
        return True
    
    def _process_alert(self, alert: Alert):
        """Process and send alert through configured channels"""
        self.alert_history.append(alert)
        
        # Limit history size
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-500:]
        
        # Send through all configured notifiers
        for channel, notifier in self.notifiers.items():
            try:
                success = notifier.send_alert(alert)
                if success:
                    logger.info(f"Alert {alert.id} sent via {channel}")
                else:
                    logger.warning(f"Failed to send alert {alert.id} via {channel}")
            except Exception as e:
                logger.error(f"Error sending alert {alert.id} via {channel}: {e}")
    
    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get recent alert history"""
        return self.alert_history[-limit:]
    
    def add_rule(self, rule: AlertRule):
        """Add a new alert rule"""
        self.rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """Remove an alert rule"""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
        logger.info(f"Removed alert rule: {rule_name}")
    
    def get_rules(self) -> List[AlertRule]:
        """Get all alert rules"""
        return self.rules.copy()

# Global alert engine instance
alert_engine = AlertEngine()
