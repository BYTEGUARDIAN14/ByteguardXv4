"""
SDK generator for ByteGuardX API
Generates client SDKs in multiple programming languages
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SDKConfig:
    """SDK generation configuration"""
    language: str
    package_name: str
    version: str
    author: str = "ByteGuardX Team"
    description: str = "ByteGuardX API Client SDK"
    license: str = "Commercial"

class SDKGenerator:
    """
    SDK generator for multiple programming languages
    """
    
    def __init__(self, output_dir: str = "sdks"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_python_sdk(self, openapi_spec: Dict[str, Any], 
                           config: SDKConfig) -> str:
        """Generate Python SDK"""
        try:
            sdk_dir = self.output_dir / "python" / config.package_name
            sdk_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate main client
            client_code = self._generate_python_client(openapi_spec, config)
            with open(sdk_dir / "client.py", 'w') as f:
                f.write(client_code)
            
            # Generate models
            models_code = self._generate_python_models(openapi_spec, config)
            with open(sdk_dir / "models.py", 'w') as f:
                f.write(models_code)
            
            # Generate __init__.py
            init_code = self._generate_python_init(config)
            with open(sdk_dir / "__init__.py", 'w') as f:
                f.write(init_code)
            
            # Generate setup.py
            setup_code = self._generate_python_setup(config)
            with open(sdk_dir.parent / "setup.py", 'w') as f:
                f.write(setup_code)
            
            # Generate README
            readme_code = self._generate_python_readme(config)
            with open(sdk_dir.parent / "README.md", 'w') as f:
                f.write(readme_code)
            
            logger.info(f"Generated Python SDK at {sdk_dir}")
            return str(sdk_dir)
            
        except Exception as e:
            logger.error(f"Failed to generate Python SDK: {e}")
            raise
    
    def generate_javascript_sdk(self, openapi_spec: Dict[str, Any], 
                               config: SDKConfig) -> str:
        """Generate JavaScript/TypeScript SDK"""
        try:
            sdk_dir = self.output_dir / "javascript" / config.package_name
            sdk_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate main client
            client_code = self._generate_js_client(openapi_spec, config)
            with open(sdk_dir / "client.js", 'w') as f:
                f.write(client_code)
            
            # Generate TypeScript definitions
            types_code = self._generate_js_types(openapi_spec, config)
            with open(sdk_dir / "types.d.ts", 'w') as f:
                f.write(types_code)
            
            # Generate package.json
            package_json = self._generate_js_package_json(config)
            with open(sdk_dir / "package.json", 'w') as f:
                json.dump(package_json, f, indent=2)
            
            # Generate README
            readme_code = self._generate_js_readme(config)
            with open(sdk_dir / "README.md", 'w') as f:
                f.write(readme_code)
            
            logger.info(f"Generated JavaScript SDK at {sdk_dir}")
            return str(sdk_dir)
            
        except Exception as e:
            logger.error(f"Failed to generate JavaScript SDK: {e}")
            raise
    
    def _generate_python_client(self, openapi_spec: Dict[str, Any], 
                               config: SDKConfig) -> str:
        """Generate Python client code"""
        return f'''"""
{config.description}
Generated Python client for ByteGuardX API
"""

import requests
import json
from typing import Dict, List, Any, Optional
from .models import *

class ByteGuardXClient:
    """ByteGuardX API Client"""
    
    def __init__(self, base_url: str = "http://localhost:5000", 
                 api_key: str = None, token: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.token = token
        self.session = requests.Session()
        
        # Set default headers
        if api_key:
            self.session.headers.update({{"X-API-Key": api_key}})
        if token:
            self.session.headers.update({{"Authorization": f"Bearer {{token}}"}})
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request"""
        url = f"{{self.base_url}}{{endpoint}}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    
    # Authentication
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login to ByteGuardX"""
        data = {{"email": email, "password": password}}
        result = self._request("POST", "/auth/login", json=data)
        if "access_token" in result:
            self.token = result["access_token"]
            self.session.headers.update({{"Authorization": f"Bearer {{self.token}}"}})
        return result
    
    def logout(self) -> Dict[str, Any]:
        """Logout from ByteGuardX"""
        return self._request("POST", "/auth/logout")
    
    # Scanning
    def scan_directory(self, directory_path: str, recursive: bool = True,
                      use_cache: bool = True) -> Dict[str, Any]:
        """Start directory scan"""
        data = {{
            "directory_path": directory_path,
            "recursive": recursive,
            "use_cache": use_cache
        }}
        return self._request("POST", "/scan/directory", json=data)
    
    def scan_file(self, file_path: str, content: str = None) -> Dict[str, Any]:
        """Scan single file"""
        data = {{"file_path": file_path}}
        if content:
            data["content"] = content
        return self._request("POST", "/scan/file", json=data)
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get scan results"""
        return self._request("GET", f"/scan/results/{{scan_id}}")
    
    def list_scans(self, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """List scans"""
        params = {{"page": page, "limit": limit}}
        return self._request("GET", "/scan/list", params=params)
    
    # Reports
    def generate_report(self, scan_id: str, format: str = "pdf") -> Dict[str, Any]:
        """Generate scan report"""
        data = {{"scan_id": scan_id, "format": format}}
        return self._request("POST", "/report/generate", json=data)
    
    def get_report(self, report_id: str) -> bytes:
        """Download report"""
        response = self.session.get(f"{{self.base_url}}/report/download/{{report_id}}")
        response.raise_for_status()
        return response.content
    
    # AI Suggestions
    def get_fix_suggestions(self, finding_id: str) -> Dict[str, Any]:
        """Get AI-powered fix suggestions"""
        return self._request("GET", f"/fix/suggestions/{{finding_id}}")
    
    def apply_fix(self, finding_id: str, fix_type: str) -> Dict[str, Any]:
        """Apply suggested fix"""
        data = {{"fix_type": fix_type}}
        return self._request("POST", f"/fix/apply/{{finding_id}}", json=data)
    
    # Health
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        return self._request("GET", "/health")
'''

    def _generate_python_models(self, openapi_spec: Dict[str, Any], 
                               config: SDKConfig) -> str:
        """Generate Python model classes"""
        return '''"""
Data models for ByteGuardX API
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from datetime import datetime

@dataclass
class ScanResult:
    """Scan result model"""
    scan_id: str
    status: str
    directory_path: str
    total_files: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    started_at: str
    completed_at: Optional[str] = None
    scan_duration: Optional[float] = None

@dataclass
class Finding:
    """Security finding model"""
    id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence_score: float
    scanner_type: str

@dataclass
class FixSuggestion:
    """Fix suggestion model"""
    suggestion_id: str
    finding_id: str
    fix_type: str
    description: str
    code_changes: List[Dict[str, Any]]
    confidence_score: float
    estimated_effort: str

@dataclass
class Report:
    """Report model"""
    report_id: str
    scan_id: str
    format: str
    status: str
    generated_at: str
    download_url: Optional[str] = None
'''

    def _generate_python_init(self, config: SDKConfig) -> str:
        """Generate Python __init__.py"""
        return f'''"""
{config.description}
Version: {config.version}
"""

from .client import ByteGuardXClient
from .models import *

__version__ = "{config.version}"
__author__ = "{config.author}"

__all__ = ["ByteGuardXClient", "ScanResult", "Finding", "FixSuggestion", "Report"]
'''

    def _generate_python_setup(self, config: SDKConfig) -> str:
        """Generate Python setup.py"""
        return f'''from setuptools import setup, find_packages

setup(
    name="{config.package_name}",
    version="{config.version}",
    author="{config.author}",
    description="{config.description}",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
    ],
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
'''

    def _generate_python_readme(self, config: SDKConfig) -> str:
        """Generate Python README"""
        return f'''# {config.package_name}

{config.description}

## Installation

```bash
pip install {config.package_name}
```

## Usage

```python
from {config.package_name} import ByteGuardXClient

# Initialize client
client = ByteGuardXClient(
    base_url="https://api.byteguardx.com",
    api_key="your-api-key"
)

# Login (if using username/password)
client.login("user@example.com", "password")

# Start a scan
result = client.scan_directory("/path/to/code")
scan_id = result["scan_id"]

# Get results
results = client.get_scan_results(scan_id)

# Generate report
report = client.generate_report(scan_id, format="pdf")
```

## API Reference

### Authentication

- `login(email, password)` - Login with credentials
- `logout()` - Logout

### Scanning

- `scan_directory(path, recursive=True)` - Scan directory
- `scan_file(path, content=None)` - Scan single file
- `get_scan_results(scan_id)` - Get scan results
- `list_scans(page=1, limit=20)` - List scans

### Reports

- `generate_report(scan_id, format="pdf")` - Generate report
- `get_report(report_id)` - Download report

### AI Suggestions

- `get_fix_suggestions(finding_id)` - Get fix suggestions
- `apply_fix(finding_id, fix_type)` - Apply fix

## License

{config.license}
'''

    def _generate_js_client(self, openapi_spec: Dict[str, Any], 
                           config: SDKConfig) -> str:
        """Generate JavaScript client code"""
        return f'''/**
 * {config.description}
 * Generated JavaScript client for ByteGuardX API
 */

class ByteGuardXClient {{
    constructor(baseUrl = 'http://localhost:5000', apiKey = null, token = null) {{
        this.baseUrl = baseUrl.replace(/\\/$/, '');
        this.apiKey = apiKey;
        this.token = token;
        this.defaultHeaders = {{}};
        
        if (apiKey) {{
            this.defaultHeaders['X-API-Key'] = apiKey;
        }}
        if (token) {{
            this.defaultHeaders['Authorization'] = `Bearer ${{token}}`;
        }}
    }}
    
    async _request(method, endpoint, options = {{}}) {{
        const url = `${{this.baseUrl}}${{endpoint}}`;
        const headers = {{
            'Content-Type': 'application/json',
            ...this.defaultHeaders,
            ...options.headers
        }};
        
        const config = {{
            method,
            headers,
            ...options
        }};
        
        if (options.body && typeof options.body === 'object') {{
            config.body = JSON.stringify(options.body);
        }}
        
        const response = await fetch(url, config);
        
        if (!response.ok) {{
            throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
        }}
        
        return response.json();
    }}
    
    // Authentication
    async login(email, password) {{
        const result = await this._request('POST', '/auth/login', {{
            body: {{ email, password }}
        }});
        
        if (result.access_token) {{
            this.token = result.access_token;
            this.defaultHeaders['Authorization'] = `Bearer ${{this.token}}`;
        }}
        
        return result;
    }}
    
    async logout() {{
        return this._request('POST', '/auth/logout');
    }}
    
    // Scanning
    async scanDirectory(directoryPath, recursive = true, useCache = true) {{
        return this._request('POST', '/scan/directory', {{
            body: {{
                directory_path: directoryPath,
                recursive,
                use_cache: useCache
            }}
        }});
    }}
    
    async scanFile(filePath, content = null) {{
        const body = {{ file_path: filePath }};
        if (content) {{
            body.content = content;
        }}
        
        return this._request('POST', '/scan/file', {{ body }});
    }}
    
    async getScanResults(scanId) {{
        return this._request('GET', `/scan/results/${{scanId}}`);
    }}
    
    async listScans(page = 1, limit = 20) {{
        const params = new URLSearchParams({{ page, limit }});
        return this._request('GET', `/scan/list?${{params}}`);
    }}
    
    // Reports
    async generateReport(scanId, format = 'pdf') {{
        return this._request('POST', '/report/generate', {{
            body: {{ scan_id: scanId, format }}
        }});
    }}
    
    async getReport(reportId) {{
        const response = await fetch(`${{this.baseUrl}}/report/download/${{reportId}}`, {{
            headers: this.defaultHeaders
        }});
        
        if (!response.ok) {{
            throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
        }}
        
        return response.blob();
    }}
    
    // AI Suggestions
    async getFixSuggestions(findingId) {{
        return this._request('GET', `/fix/suggestions/${{findingId}}`);
    }}
    
    async applyFix(findingId, fixType) {{
        return this._request('POST', `/fix/apply/${{findingId}}`, {{
            body: {{ fix_type: fixType }}
        }});
    }}
    
    // Health
    async healthCheck() {{
        return this._request('GET', '/health');
    }}
}}

module.exports = ByteGuardXClient;
'''

    def _generate_js_types(self, openapi_spec: Dict[str, Any], 
                          config: SDKConfig) -> str:
        """Generate TypeScript type definitions"""
        return '''/**
 * TypeScript definitions for ByteGuardX API
 */

export interface ScanResult {
    scan_id: string;
    status: string;
    directory_path: string;
    total_files: number;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    started_at: string;
    completed_at?: string;
    scan_duration?: number;
}

export interface Finding {
    id: string;
    vulnerability_type: string;
    severity: string;
    title: string;
    description: string;
    file_path: string;
    line_number: number;
    code_snippet: string;
    confidence_score: number;
    scanner_type: string;
}

export interface FixSuggestion {
    suggestion_id: string;
    finding_id: string;
    fix_type: string;
    description: string;
    code_changes: Array<{[key: string]: any}>;
    confidence_score: number;
    estimated_effort: string;
}

export interface Report {
    report_id: string;
    scan_id: string;
    format: string;
    status: string;
    generated_at: string;
    download_url?: string;
}

export declare class ByteGuardXClient {
    constructor(baseUrl?: string, apiKey?: string, token?: string);
    
    login(email: string, password: string): Promise<any>;
    logout(): Promise<any>;
    
    scanDirectory(directoryPath: string, recursive?: boolean, useCache?: boolean): Promise<ScanResult>;
    scanFile(filePath: string, content?: string): Promise<ScanResult>;
    getScanResults(scanId: string): Promise<ScanResult>;
    listScans(page?: number, limit?: number): Promise<{scans: ScanResult[]}>;
    
    generateReport(scanId: string, format?: string): Promise<Report>;
    getReport(reportId: string): Promise<Blob>;
    
    getFixSuggestions(findingId: string): Promise<FixSuggestion[]>;
    applyFix(findingId: string, fixType: string): Promise<any>;
    
    healthCheck(): Promise<any>;
}
'''

    def _generate_js_package_json(self, config: SDKConfig) -> Dict[str, Any]:
        """Generate package.json"""
        return {
            "name": config.package_name,
            "version": config.version,
            "description": config.description,
            "main": "client.js",
            "types": "types.d.ts",
            "author": config.author,
            "license": config.license,
            "keywords": ["security", "vulnerability", "scanning", "api", "client"],
            "dependencies": {},
            "devDependencies": {
                "@types/node": "^18.0.0",
                "typescript": "^4.7.0"
            },
            "scripts": {
                "build": "tsc",
                "test": "echo \"Error: no test specified\" && exit 1"
            }
        }

    def _generate_js_readme(self, config: SDKConfig) -> str:
        """Generate JavaScript README"""
        return f'''# {config.package_name}

{config.description}

## Installation

```bash
npm install {config.package_name}
```

## Usage

```javascript
const ByteGuardXClient = require('{config.package_name}');

// Initialize client
const client = new ByteGuardXClient(
    'https://api.byteguardx.com',
    'your-api-key'
);

// Login (if using username/password)
await client.login('user@example.com', 'password');

// Start a scan
const result = await client.scanDirectory('/path/to/code');
const scanId = result.scan_id;

// Get results
const results = await client.getScanResults(scanId);

// Generate report
const report = await client.generateReport(scanId, 'pdf');
```

## TypeScript Support

This package includes TypeScript definitions:

```typescript
import ByteGuardXClient, {{{{ ScanResult, Finding }}}} from '{config.package_name}';

const client = new ByteGuardXClient();
const result: ScanResult = await client.scanDirectory('/path/to/code');
```

## API Reference

See the TypeScript definitions for complete API documentation.

## License

{config.license}
'''

class PythonSDK:
    """Python SDK generator"""
    pass

class JavaScriptSDK:
    """JavaScript SDK generator"""
    pass

# Global SDK generator
sdk_generator = SDKGenerator()
