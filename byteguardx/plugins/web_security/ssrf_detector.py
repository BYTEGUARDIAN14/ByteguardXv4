"""
Server-Side Request Forgery (SSRF) Detector Plugin
Detects SSRF vulnerabilities in web applications
"""

import re
import logging
from typing import Dict, List, Any
from urllib.parse import urlparse
from ..plugin_framework import BasePlugin, PluginManifest, PluginCategory

logger = logging.getLogger(__name__)

class SSRFDetector(BasePlugin):
    """Scanner for Server-Side Request Forgery vulnerabilities"""
    
    def __init__(self):
        manifest = PluginManifest(
            name="ssrf_detector",
            version="1.0.0",
            author="ByteGuardX Security Team",
            description="Detects Server-Side Request Forgery (SSRF) vulnerabilities in web applications",
            category=PluginCategory.WEB_APPLICATION,
            supported_languages=["python", "javascript", "php", "java", "csharp", "ruby", "go"],
            supported_file_types=[".py", ".js", ".ts", ".php", ".java", ".cs", ".rb", ".go"],
            requires_network=False,
            requires_filesystem=False,
            max_memory_mb=256,
            max_cpu_percent=30,
            timeout_seconds=60,
            trust_level="high",
            dependencies=[],
            api_version="1.0"
        )
        super().__init__(manifest)
        
        self.ssrf_patterns = self._load_ssrf_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.dangerous_functions = self._load_dangerous_functions()
    
    def _load_ssrf_patterns(self) -> Dict[str, Any]:
        """Load SSRF vulnerability patterns"""
        return {
            "url_fetch_with_user_input": {
                "patterns": [
                    # Python patterns
                    r"requests\.(get|post|put|delete|head|options)\s*\(\s*[^,)]*(?:request\.|params\.|args\.|form\.)",
                    r"urllib\.request\.urlopen\s*\(\s*[^)]*(?:request\.|params\.|args\.)",
                    r"httplib\.HTTPConnection\s*\(\s*[^)]*(?:request\.|params\.|args\.)",
                    
                    # JavaScript/Node.js patterns
                    r"fetch\s*\(\s*[^,)]*(?:req\.|request\.|params\.)",
                    r"axios\.(get|post|put|delete)\s*\(\s*[^,)]*(?:req\.|request\.|params\.)",
                    r"http\.get\s*\(\s*[^,)]*(?:req\.|request\.|params\.)",
                    
                    # PHP patterns
                    r"curl_setopt\s*\(\s*[^,]*,\s*CURLOPT_URL\s*,\s*[^)]*\$_(?:GET|POST|REQUEST)",
                    r"file_get_contents\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)",
                    r"fopen\s*\(\s*[^,)]*\$_(?:GET|POST|REQUEST)",
                    
                    # Java patterns
                    r"new\s+URL\s*\(\s*[^)]*request\.getParameter",
                    r"HttpURLConnection.*openConnection\s*\(\s*[^)]*request\.getParameter",
                    r"RestTemplate\.(get|post|put|delete).*request\.getParameter",
                    
                    # C# patterns
                    r"HttpClient\.(Get|Post|Put|Delete).*Request\.",
                    r"WebRequest\.Create\s*\(\s*[^)]*Request\.",
                    r"new\s+Uri\s*\(\s*[^)]*Request\."
                ],
                "description": "URL fetch operation uses unsanitized user input",
                "severity": "high",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "internal_network_access": {
                "patterns": [
                    r"(?:http://|https://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
                    r"(?:http://|https://)?192\.168\.\d+\.\d+",
                    r"(?:http://|https://)?10\.\d+\.\d+\.\d+",
                    r"(?:http://|https://)?172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+",
                    r"(?:http://|https://)?169\.254\.\d+\.\d+",  # Link-local
                    r"(?:http://|https://)?::1",  # IPv6 localhost
                    r"(?:http://|https://)?0x[0-9a-fA-F]+",  # Hex IP
                    r"(?:http://|https://)?[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
                ],
                "description": "Potential access to internal network resources",
                "severity": "medium",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "cloud_metadata_access": {
                "patterns": [
                    r"169\.254\.169\.254",  # AWS/GCP metadata
                    r"metadata\.google\.internal",
                    r"100\.100\.100\.200",  # Alibaba Cloud
                    r"169\.254\.169\.254/latest/meta-data",
                    r"metadata/v1/",
                    r"/computeMetadata/v1/"
                ],
                "description": "Potential cloud metadata service access",
                "severity": "critical",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "file_scheme_access": {
                "patterns": [
                    r"file://",
                    r"ftp://",
                    r"gopher://",
                    r"dict://",
                    r"ldap://",
                    r"jar://",
                    r"netdoc://"
                ],
                "description": "Non-HTTP scheme usage may enable local file access",
                "severity": "high",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "url_redirect_bypass": {
                "patterns": [
                    r"@",  # URL with @ symbol for bypass
                    r"\\",  # Backslash for Windows path
                    r"%2e%2e",  # URL encoded ..
                    r"%2f",  # URL encoded /
                    r"0x",  # Hex encoding
                    r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IP address
                    r"localhost",
                    r"127\.0\.0\.1"
                ],
                "description": "URL contains potential bypass characters",
                "severity": "medium",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "webhook_ssrf": {
                "patterns": [
                    r"webhook.*url.*(?:request\.|params\.|args\.)",
                    r"callback.*url.*(?:request\.|params\.|args\.)",
                    r"notify.*url.*(?:request\.|params\.|args\.)",
                    r"ping.*url.*(?:request\.|params\.|args\.)"
                ],
                "description": "Webhook functionality may be vulnerable to SSRF",
                "severity": "high",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "image_proxy_ssrf": {
                "patterns": [
                    r"image.*proxy.*url",
                    r"thumbnail.*url",
                    r"resize.*url",
                    r"avatar.*url",
                    r"proxy.*image"
                ],
                "description": "Image proxy functionality may enable SSRF",
                "severity": "medium",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            },
            "pdf_generator_ssrf": {
                "patterns": [
                    r"pdf.*url",
                    r"html.*pdf.*url",
                    r"wkhtmltopdf.*url",
                    r"puppeteer.*url",
                    r"headless.*url"
                ],
                "description": "PDF generation from URL may enable SSRF",
                "severity": "medium",
                "cwe_id": "CWE-918",
                "owasp_category": "A10:2021 – Server-Side Request Forgery"
            }
        }
    
    def _load_dangerous_functions(self) -> Dict[str, List[str]]:
        """Load functions that commonly lead to SSRF"""
        return {
            "python": [
                "requests.get", "requests.post", "requests.put", "requests.delete",
                "urllib.request.urlopen", "urllib2.urlopen", "httplib.HTTPConnection",
                "httplib2.Http", "pycurl.Curl"
            ],
            "javascript": [
                "fetch", "axios.get", "axios.post", "http.get", "http.request",
                "https.get", "https.request", "request", "superagent"
            ],
            "php": [
                "curl_exec", "file_get_contents", "fopen", "fsockopen",
                "stream_context_create", "get_headers", "readfile"
            ],
            "java": [
                "HttpURLConnection", "URL.openConnection", "RestTemplate",
                "OkHttpClient", "Apache HttpClient", "Jsoup.connect"
            ],
            "csharp": [
                "HttpClient", "WebRequest", "WebClient", "HttpWebRequest",
                "RestSharp", "Flurl"
            ]
        }
    
    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile regex patterns for performance"""
        compiled = {}
        for name, config in self.ssrf_patterns.items():
            compiled[name] = {
                "regexes": [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                           for pattern in config["patterns"]],
                "config": config
            }
        return compiled
    
    def validate_input(self, content: str, file_path: str) -> bool:
        """Validate input for SSRF scanning"""
        if not content or not content.strip():
            return False
        
        # Check if content contains web-related code
        web_indicators = [
            "http", "url", "request", "fetch", "curl", "get", "post",
            "webhook", "callback", "proxy", "api", "endpoint"
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in web_indicators)
    
    def scan(self, content: str, file_path: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan content for SSRF vulnerabilities"""
        findings = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_data in self.compiled_patterns.items():
                regexes = pattern_data["regexes"]
                config = pattern_data["config"]
                
                for regex in regexes:
                    for match in regex.finditer(line):
                        # Calculate confidence based on context
                        confidence = self._calculate_confidence(pattern_name, line, file_path, match)
                        
                        # Skip low-confidence matches
                        if confidence < 0.4:
                            continue
                        
                        # Generate remediation advice
                        remediation = self._generate_remediation(pattern_name, match.group())
                        
                        finding = {
                            "title": f"SSRF Vulnerability: {config['description']}",
                            "description": config["description"],
                            "severity": config["severity"],
                            "confidence": confidence,
                            "file_path": file_path,
                            "line_number": line_num,
                            "column_start": match.start(),
                            "column_end": match.end(),
                            "context": line.strip(),
                            "scanner_name": self.manifest.name,
                            "cwe_id": config.get("cwe_id", ""),
                            "owasp_category": config.get("owasp_category", ""),
                            "remediation": remediation,
                            "risk_factors": self._assess_risk_factors(pattern_name, line, context),
                            "attack_scenarios": self._generate_attack_scenarios(pattern_name),
                            "detection_metadata": {
                                "pattern_type": pattern_name,
                                "matched_text": match.group(),
                                "vulnerability_type": "ssrf",
                                "language": self._detect_language(file_path),
                                "function_context": self._extract_function_context(line)
                            }
                        }
                        
                        findings.append(finding)
        
        return findings
    
    def _calculate_confidence(self, pattern_name: str, line: str, file_path: str, match) -> float:
        """Calculate confidence score for SSRF findings"""
        base_confidence = 0.6
        
        # Pattern-specific adjustments
        if pattern_name == "cloud_metadata_access":
            base_confidence = 0.9  # Very high confidence for metadata access
        elif pattern_name == "url_fetch_with_user_input":
            base_confidence = 0.8  # High confidence for user input in URL fetch
        elif pattern_name == "file_scheme_access":
            base_confidence = 0.7  # Medium-high confidence for file schemes
        
        # Context adjustments
        line_lower = line.lower()
        
        # Increase confidence for dangerous functions
        language = self._detect_language(file_path)
        dangerous_funcs = self.dangerous_functions.get(language, [])
        if any(func.lower() in line_lower for func in dangerous_funcs):
            base_confidence += 0.1
        
        # Increase confidence for user input indicators
        user_input_indicators = ["request.", "params.", "args.", "$_get", "$_post", "req.query", "req.body"]
        if any(indicator in line_lower for indicator in user_input_indicators):
            base_confidence += 0.15
        
        # Decrease confidence for comments or examples
        if any(indicator in line_lower for indicator in ["example", "test", "demo", "#", "//", "/*"]):
            base_confidence -= 0.3
        
        # Decrease confidence for string literals without variables
        if match.group().startswith('"') and match.group().endswith('"'):
            if not any(var in match.group() for var in ["{", "}", "$", "%"]):
                base_confidence -= 0.2
        
        return max(0.1, min(1.0, base_confidence))
    
    def _generate_remediation(self, pattern_name: str, matched_text: str) -> str:
        """Generate specific remediation advice"""
        remediation_map = {
            "url_fetch_with_user_input": "Validate and sanitize all user input before using in URL requests. Use allowlists for permitted domains/IPs.",
            "internal_network_access": "Block access to internal network ranges (RFC 1918). Implement network-level controls.",
            "cloud_metadata_access": "Block access to cloud metadata services (169.254.169.254). Use IMDSv2 for AWS.",
            "file_scheme_access": "Restrict URL schemes to HTTP/HTTPS only. Block file://, ftp://, and other schemes.",
            "url_redirect_bypass": "Implement proper URL parsing and validation. Check for bypass techniques.",
            "webhook_ssrf": "Validate webhook URLs against allowlist. Implement timeout and size limits.",
            "image_proxy_ssrf": "Validate image URLs and implement content-type checking. Use allowlists.",
            "pdf_generator_ssrf": "Sanitize URLs before PDF generation. Use sandboxed environments."
        }
        
        return remediation_map.get(pattern_name, "Implement proper input validation and URL filtering")
    
    def _assess_risk_factors(self, pattern_name: str, line: str, context: Dict[str, Any]) -> List[str]:
        """Assess risk factors for the finding"""
        risk_factors = []
        
        if pattern_name == "cloud_metadata_access":
            risk_factors.extend([
                "Access to cloud instance metadata",
                "Potential credential theft",
                "Cloud account compromise"
            ])
        
        if pattern_name == "url_fetch_with_user_input":
            risk_factors.extend([
                "Arbitrary URL requests from server",
                "Internal network reconnaissance",
                "Port scanning capabilities"
            ])
        
        if pattern_name == "file_scheme_access":
            risk_factors.extend([
                "Local file system access",
                "Sensitive file disclosure",
                "Configuration file exposure"
            ])
        
        return risk_factors
    
    def _generate_attack_scenarios(self, pattern_name: str) -> List[Dict[str, str]]:
        """Generate realistic attack scenarios"""
        scenarios = {
            "cloud_metadata_access": [
                {
                    "scenario": "AWS Metadata Exploitation",
                    "description": "Attacker accesses http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal IAM credentials",
                    "impact": "Full AWS account compromise"
                }
            ],
            "url_fetch_with_user_input": [
                {
                    "scenario": "Internal Service Discovery",
                    "description": "Attacker scans internal network by requesting http://192.168.1.1:8080/admin",
                    "impact": "Internal network mapping and service discovery"
                }
            ],
            "file_scheme_access": [
                {
                    "scenario": "Local File Disclosure",
                    "description": "Attacker uses file:///etc/passwd to read system files",
                    "impact": "Sensitive file disclosure and system information leakage"
                }
            ]
        }
        
        return scenarios.get(pattern_name, [])
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.php': 'php',
            '.java': 'java',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.go': 'go'
        }
        
        for ext, lang in ext_map.items():
            if file_path.lower().endswith(ext):
                return lang
        
        return 'unknown'
    
    def _extract_function_context(self, line: str) -> str:
        """Extract function context from line"""
        # Simple function name extraction
        function_patterns = [
            r'def\s+(\w+)',  # Python
            r'function\s+(\w+)',  # JavaScript
            r'public\s+\w+\s+(\w+)\s*\(',  # Java/C#
            r'(\w+)\s*\('  # General function call
        ]
        
        for pattern in function_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return "unknown"
