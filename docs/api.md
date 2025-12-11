# ByteGuardX API Documentation

## Overview

The ByteGuardX REST API provides programmatic access to security scanning capabilities. This API is designed for integration with CI/CD pipelines, development tools, and custom applications.

## Base URL

```
http://localhost:5000
```

## Authentication

ByteGuardX uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

### Getting a Token

**POST** `/auth/login`

```json
{
  "email": "user@example.com",
  "password": "your_password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "user-123",
    "email": "user@example.com",
    "username": "johndoe",
    "role": "developer",
    "subscription_tier": "pro"
  }
}
```

## Endpoints

### Health Check

**GET** `/health`

Check API health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### User Management

#### Register User

**POST** `/auth/register`

```json
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "secure_password"
}
```

#### Get Current User

**GET** `/auth/me`

*Requires authentication*

**Response:**
```json
{
  "id": "user-123",
  "email": "user@example.com",
  "username": "johndoe",
  "role": "developer",
  "subscription_tier": "pro",
  "scans_this_month": 15,
  "total_scans": 127
}
```

### File Upload

#### Upload Files for Scanning

**POST** `/scan/upload`

*Requires authentication and SCAN_CREATE permission*

Upload files for security scanning.

**Request:** `multipart/form-data`
- `files`: Multiple files to scan

**Response:**
```json
{
  "scan_id": "scan-abc123",
  "uploaded_files": 5,
  "message": "Files uploaded successfully"
}
```

### Scanning

#### Scan Directory

**POST** `/scan/directory`

*Requires authentication and SCAN_CREATE permission*

```json
{
  "path": "/path/to/your/project"
}
```

**Response:**
```json
{
  "scan_id": "scan-abc123",
  "total_files": 45,
  "total_findings": 12,
  "total_fixes": 8,
  "summary": {
    "secrets": {
      "total": 3,
      "by_severity": {
        "critical": 1,
        "high": 1,
        "medium": 1
      }
    },
    "dependencies": {
      "total": 7,
      "by_severity": {
        "high": 2,
        "medium": 3,
        "low": 2
      }
    },
    "ai_patterns": {
      "total": 2,
      "by_severity": {
        "medium": 1,
        "low": 1
      }
    }
  }
}
```

#### Comprehensive Scan

**POST** `/scan/all`

*Requires authentication and SCAN_CREATE permission*

```json
{
  "scan_id": "scan-abc123"
}
```

**Response:**
```json
{
  "scan_id": "scan-abc123",
  "total_files": 45,
  "total_findings": 12,
  "total_fixes": 8,
  "findings": [
    {
      "type": "secret",
      "subtype": "api_keys.github_token",
      "severity": "critical",
      "confidence": 0.95,
      "file_path": "src/config.py",
      "line_number": 12,
      "description": "GitHub Personal Access Token detected",
      "context": "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
      "recommendation": "Move token to environment variable"
    }
  ],
  "fixes": [
    {
      "vulnerability_type": "api_keys.github_token",
      "original_code": "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
      "fixed_code": "token = os.environ.get('GITHUB_TOKEN')",
      "explanation": "Store GitHub token in environment variable for security",
      "confidence": 0.95,
      "file_path": "src/config.py",
      "line_number": 12
    }
  ]
}
```

#### Specific Scanner Types

**POST** `/scan/secrets`
**POST** `/scan/dependencies`
**POST** `/scan/ai-patterns`

Each endpoint accepts:
```json
{
  "scan_id": "scan-abc123"
}
```

### Results

#### Get Scan Results

**GET** `/scan/results/{scan_id}`

*Requires authentication and SCAN_READ permission*

**Response:**
```json
{
  "scan_id": "scan-abc123",
  "timestamp": "2024-01-15T10:30:00Z",
  "total_files": 45,
  "total_findings": 12,
  "findings": [...],
  "fixes": [...],
  "summary": {...}
}
```

#### List All Scans

**GET** `/scan/list`

*Requires authentication*

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "scan-abc123",
      "timestamp": "2024-01-15T10:30:00Z",
      "total_files": 45,
      "total_findings": 12,
      "total_fixes": 8
    }
  ]
}
```

### Fix Generation

#### Generate Bulk Fixes

**POST** `/fix/bulk`

*Requires authentication*

```json
{
  "findings": [
    {
      "type": "secret",
      "subtype": "api_keys.github_token",
      "file_path": "src/config.py",
      "line_number": 12,
      "context": "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
    }
  ]
}
```

### Reports

#### Generate PDF Report

**POST** `/report/pdf`

*Requires authentication and REPORT_GENERATE permission*

```json
{
  "scan_id": "scan-abc123"
}
```

**Response:**
```json
{
  "report_path": "byteguardx_report_20240115_103000.pdf",
  "download_url": "/report/download/byteguardx_report_20240115_103000.pdf"
}
```

#### Download Report

**GET** `/report/download/{filename}`

*Requires authentication and REPORT_DOWNLOAD permission*

Downloads the generated PDF report.

### Analytics (Enterprise)

#### Executive Dashboard

**GET** `/analytics/dashboard`

*Requires authentication and ANALYTICS_VIEW permission*

**Query Parameters:**
- `days`: Number of days to analyze (default: 30)
- `organization_id`: Filter by organization (optional)

**Response:**
```json
{
  "period": "Last 30 days",
  "summary": {
    "total_scans": 156,
    "total_findings": 1247,
    "total_files_scanned": 5432,
    "security_score": 78.5,
    "avg_findings_per_scan": 8.0,
    "scan_frequency": 5.2
  },
  "severity_breakdown": {
    "critical": 23,
    "high": 89,
    "medium": 234,
    "low": 901
  },
  "trends": {
    "findings_trend": {
      "current_avg": 7.2,
      "previous_avg": 9.1,
      "change_percent": -20.9,
      "direction": "down"
    }
  },
  "recommendations": [
    "Good progress on reducing critical issues",
    "Focus on dependency management",
    "Implement automated scanning in CI/CD"
  ]
}
```

#### Compliance Report

**GET** `/analytics/compliance`

*Requires authentication and ANALYTICS_VIEW permission*

**Query Parameters:**
- `framework`: Compliance framework (owasp, pci, sox)
- `organization_id`: Filter by organization (optional)

**Response:**
```json
{
  "framework": "OWASP Top 10",
  "compliance_score": 85.2,
  "total_findings": 45,
  "categories": {
    "injection": 12,
    "broken_auth": 8,
    "sensitive_data": 15,
    "xxe": 2,
    "broken_access": 5,
    "security_misconfig": 3
  },
  "recommendations": [
    "Address injection vulnerabilities first",
    "Implement proper authentication mechanisms",
    "Encrypt sensitive data at rest and in transit"
  ]
}
```

## Error Handling

The API uses standard HTTP status codes:

- `200` - Success
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `413` - Payload Too Large
- `429` - Too Many Requests
- `500` - Internal Server Error

**Error Response Format:**
```json
{
  "error": "Error message description",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details"
  }
}
```

## Rate Limiting

Rate limits are based on subscription tier:

- **Free**: 5 scans per month
- **Pro**: Unlimited scans
- **Enterprise**: Unlimited scans + advanced features

When rate limit is exceeded:
```json
{
  "error": "Scan limit exceeded",
  "scans_this_month": 5,
  "subscription_tier": "free",
  "upgrade_message": "Upgrade to Pro for unlimited scans"
}
```

## Webhooks (Enterprise)

Configure webhooks to receive real-time notifications:

**POST** `/webhooks/configure`

```json
{
  "url": "https://your-app.com/webhook",
  "events": ["scan.completed", "scan.failed", "critical.found"],
  "secret": "webhook_secret_key"
}
```

**Webhook Payload:**
```json
{
  "event": "scan.completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "scan_id": "scan-abc123",
    "total_findings": 12,
    "critical_count": 2
  }
}
```

## SDKs and Libraries

### Python SDK

```bash
pip install byteguardx-sdk
```

```python
from byteguardx import ByteGuardXClient

client = ByteGuardXClient(api_key="your_api_key")

# Scan directory
result = client.scan_directory("/path/to/project")
print(f"Found {result.total_findings} issues")

# Generate report
report = client.generate_report(result.scan_id, format="pdf")
```

### JavaScript SDK

```bash
npm install @byteguardx/sdk
```

```javascript
import { ByteGuardXClient } from '@byteguardx/sdk';

const client = new ByteGuardXClient({ apiKey: 'your_api_key' });

// Scan files
const result = await client.scanFiles(['file1.js', 'file2.py']);
console.log(`Found ${result.totalFindings} issues`);
```

## Examples

### CI/CD Integration

```bash
# Install CLI
pip install byteguardx

# Scan current directory
byteguardx scan . --output security-report.json

# Check exit code
if [ $? -ne 0 ]; then
  echo "Security issues found!"
  exit 1
fi
```

### Custom Integration

```python
import requests

# Login
response = requests.post('http://localhost:5000/auth/login', json={
    'email': 'user@example.com',
    'password': 'password'
})
token = response.json()['access_token']

# Upload files
files = {'files': open('app.py', 'rb')}
headers = {'Authorization': f'Bearer {token}'}

upload_response = requests.post(
    'http://localhost:5000/scan/upload',
    files=files,
    headers=headers
)
scan_id = upload_response.json()['scan_id']

# Run scan
scan_response = requests.post(
    'http://localhost:5000/scan/all',
    json={'scan_id': scan_id},
    headers=headers
)

results = scan_response.json()
print(f"Found {results['total_findings']} security issues")
```
