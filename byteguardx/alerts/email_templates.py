"""
Email Templates for ByteGuardX Notifications
Provides HTML and text templates for various notification types
"""

from typing import Dict, Any
from datetime import datetime


class EmailTemplates:
    """Email template generator for ByteGuardX notifications"""
    
    @staticmethod
    def get_base_template() -> str:
        """Base HTML template for all emails"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ByteGuardX Notification</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #0ea5e9;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 28px;
            font-weight: bold;
            color: #0ea5e9;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            font-size: 14px;
        }
        .content {
            margin-bottom: 30px;
        }
        .alert-box {
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .alert-critical {
            background-color: #fee2e2;
            border-left: 4px solid #dc2626;
            color: #991b1b;
        }
        .alert-high {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            color: #92400e;
        }
        .alert-medium {
            background-color: #dbeafe;
            border-left: 4px solid #3b82f6;
            color: #1e40af;
        }
        .alert-low {
            background-color: #d1fae5;
            border-left: 4px solid #10b981;
            color: #065f46;
        }
        .stats-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .stats-table th,
        .stats-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        .stats-table th {
            background-color: #f9fafb;
            font-weight: 600;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background-color: #0ea5e9;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: 600;
            margin: 10px 0;
        }
        .footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #666;
            font-size: 12px;
        }
        .timestamp {
            color: #666;
            font-size: 12px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ ByteGuardX</div>
            <div class="subtitle">AI-Powered Vulnerability Scanner</div>
        </div>
        
        <div class="content">
            {content}
        </div>
        
        <div class="footer">
            <p>This is an automated notification from ByteGuardX.</p>
            <p>If you no longer wish to receive these emails, you can update your preferences in your account settings.</p>
        </div>
    </div>
</body>
</html>
        """
    
    @staticmethod
    def scan_completed(data: Dict[str, Any]) -> Dict[str, str]:
        """Template for scan completion notification"""
        scan_id = data.get('scan_id', 'Unknown')
        directory_path = data.get('directory_path', 'Unknown')
        total_findings = data.get('total_findings', 0)
        critical_findings = data.get('critical_findings', 0)
        high_findings = data.get('high_findings', 0)
        medium_findings = data.get('medium_findings', 0)
        low_findings = data.get('low_findings', 0)
        scan_duration = data.get('scan_duration_seconds', 0)
        
        # Determine alert level
        if critical_findings > 0:
            alert_class = "alert-critical"
            alert_title = "🚨 Critical Vulnerabilities Found"
        elif high_findings > 0:
            alert_class = "alert-high"
            alert_title = "⚠️ High Severity Issues Detected"
        elif medium_findings > 0:
            alert_class = "alert-medium"
            alert_title = "ℹ️ Security Issues Found"
        else:
            alert_class = "alert-low"
            alert_title = "✅ Scan Completed Successfully"
        
        content = f"""
        <h2>Security Scan Completed</h2>
        
        <div class="{alert_class} alert-box">
            <strong>{alert_title}</strong><br>
            Your security scan has completed with {total_findings} total findings.
        </div>
        
        <h3>Scan Details</h3>
        <table class="stats-table">
            <tr>
                <th>Scan ID</th>
                <td>{scan_id}</td>
            </tr>
            <tr>
                <th>Directory</th>
                <td>{directory_path}</td>
            </tr>
            <tr>
                <th>Duration</th>
                <td>{scan_duration:.1f} seconds</td>
            </tr>
        </table>
        
        <h3>Findings Summary</h3>
        <table class="stats-table">
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>🔴 Critical</td>
                <td><strong>{critical_findings}</strong></td>
            </tr>
            <tr>
                <td>🟠 High</td>
                <td><strong>{high_findings}</strong></td>
            </tr>
            <tr>
                <td>🟡 Medium</td>
                <td><strong>{medium_findings}</strong></td>
            </tr>
            <tr>
                <td>🟢 Low</td>
                <td><strong>{low_findings}</strong></td>
            </tr>
        </table>
        
        <a href="{data.get('report_url', '#')}" class="button">View Detailed Report</a>
        
        <div class="timestamp">
            Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
        """
        
        base_template = EmailTemplates.get_base_template()
        html_content = base_template.format(content=content)
        
        # Text version
        text_content = f"""
ByteGuardX Security Scan Completed

{alert_title}
Your security scan has completed with {total_findings} total findings.

Scan Details:
- Scan ID: {scan_id}
- Directory: {directory_path}
- Duration: {scan_duration:.1f} seconds

Findings Summary:
- Critical: {critical_findings}
- High: {high_findings}
- Medium: {medium_findings}
- Low: {low_findings}

View your detailed report: {data.get('report_url', 'N/A')}

Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        return {
            'subject': f"ByteGuardX: Scan Completed - {total_findings} findings found",
            'html': html_content,
            'text': text_content.strip()
        }
    
    @staticmethod
    def login_alert(data: Dict[str, Any]) -> Dict[str, str]:
        """Template for login alert notification"""
        ip_address = data.get('ip_address', 'Unknown')
        user_agent = data.get('user_agent', 'Unknown')
        location = data.get('location', 'Unknown')
        timestamp = data.get('timestamp', datetime.now())
        
        content = f"""
        <h2>New Login Detected</h2>
        
        <div class="alert-medium alert-box">
            <strong>🔐 Account Access Alert</strong><br>
            A new login to your ByteGuardX account has been detected.
        </div>
        
        <h3>Login Details</h3>
        <table class="stats-table">
            <tr>
                <th>Time</th>
                <td>{timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
            </tr>
            <tr>
                <th>IP Address</th>
                <td>{ip_address}</td>
            </tr>
            <tr>
                <th>Location</th>
                <td>{location}</td>
            </tr>
            <tr>
                <th>Device/Browser</th>
                <td>{user_agent}</td>
            </tr>
        </table>
        
        <p>If this was you, no action is required. If you don't recognize this login, please:</p>
        <ul>
            <li>Change your password immediately</li>
            <li>Review your account activity</li>
            <li>Enable two-factor authentication if not already active</li>
        </ul>
        
        <a href="{data.get('security_url', '#')}" class="button">Review Account Security</a>
        """
        
        base_template = EmailTemplates.get_base_template()
        html_content = base_template.format(content=content)
        
        text_content = f"""
ByteGuardX Login Alert

A new login to your ByteGuardX account has been detected.

Login Details:
- Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
- IP Address: {ip_address}
- Location: {location}
- Device/Browser: {user_agent}

If this was you, no action is required. If you don't recognize this login, please:
- Change your password immediately
- Review your account activity
- Enable two-factor authentication if not already active

Review your account security: {data.get('security_url', 'N/A')}
        """
        
        return {
            'subject': "ByteGuardX: New login detected",
            'html': html_content,
            'text': text_content.strip()
        }
    
    @staticmethod
    def scheduled_scan_failed(data: Dict[str, Any]) -> Dict[str, str]:
        """Template for scheduled scan failure notification"""
        scan_name = data.get('scan_name', 'Unknown')
        error_message = data.get('error_message', 'Unknown error')
        next_run = data.get('next_run_at', 'Unknown')
        
        content = f"""
        <h2>Scheduled Scan Failed</h2>
        
        <div class="alert-high alert-box">
            <strong>⚠️ Scheduled Scan Error</strong><br>
            Your scheduled scan "{scan_name}" failed to complete.
        </div>
        
        <h3>Error Details</h3>
        <table class="stats-table">
            <tr>
                <th>Scan Name</th>
                <td>{scan_name}</td>
            </tr>
            <tr>
                <th>Error</th>
                <td>{error_message}</td>
            </tr>
            <tr>
                <th>Next Scheduled Run</th>
                <td>{next_run}</td>
            </tr>
        </table>
        
        <p>Please check your scan configuration and ensure the target directory is accessible.</p>
        
        <a href="{data.get('schedule_url', '#')}" class="button">Manage Scheduled Scans</a>
        """
        
        base_template = EmailTemplates.get_base_template()
        html_content = base_template.format(content=content)
        
        text_content = f"""
ByteGuardX Scheduled Scan Failed

Your scheduled scan "{scan_name}" failed to complete.

Error Details:
- Scan Name: {scan_name}
- Error: {error_message}
- Next Scheduled Run: {next_run}

Please check your scan configuration and ensure the target directory is accessible.

Manage your scheduled scans: {data.get('schedule_url', 'N/A')}
        """
        
        return {
            'subject': f"ByteGuardX: Scheduled scan '{scan_name}' failed",
            'html': html_content,
            'text': text_content.strip()
        }
    
    @staticmethod
    def weekly_summary(data: Dict[str, Any]) -> Dict[str, str]:
        """Template for weekly summary notification"""
        week_start = data.get('week_start', 'Unknown')
        week_end = data.get('week_end', 'Unknown')
        total_scans = data.get('total_scans', 0)
        total_findings = data.get('total_findings', 0)
        new_critical = data.get('new_critical', 0)
        resolved_issues = data.get('resolved_issues', 0)
        
        content = f"""
        <h2>Weekly Security Summary</h2>
        
        <div class="alert-low alert-box">
            <strong>📊 Week of {week_start} - {week_end}</strong><br>
            Here's your weekly security activity summary.
        </div>
        
        <h3>Activity Summary</h3>
        <table class="stats-table">
            <tr>
                <th>Total Scans</th>
                <td>{total_scans}</td>
            </tr>
            <tr>
                <th>Total Findings</th>
                <td>{total_findings}</td>
            </tr>
            <tr>
                <th>New Critical Issues</th>
                <td>{new_critical}</td>
            </tr>
            <tr>
                <th>Resolved Issues</th>
                <td>{resolved_issues}</td>
            </tr>
        </table>
        
        <a href="{data.get('dashboard_url', '#')}" class="button">View Dashboard</a>
        """
        
        base_template = EmailTemplates.get_base_template()
        html_content = base_template.format(content=content)
        
        text_content = f"""
ByteGuardX Weekly Security Summary

Week of {week_start} - {week_end}

Activity Summary:
- Total Scans: {total_scans}
- Total Findings: {total_findings}
- New Critical Issues: {new_critical}
- Resolved Issues: {resolved_issues}

View your dashboard: {data.get('dashboard_url', 'N/A')}
        """
        
        return {
            'subject': f"ByteGuardX: Weekly Summary ({week_start} - {week_end})",
            'html': html_content,
            'text': text_content.strip()
        }
