"""
Frontend Security Hardening for ByteGuardX
Provides CSP headers, XSS prevention, and input sanitization utilities
"""

import re
import html
import json
import logging
from typing import Dict, List, Optional, Any
from flask import Response, request
import bleach
from markupsafe import Markup

logger = logging.getLogger(__name__)

class ContentSecurityPolicy:
    """Content Security Policy configuration and enforcement"""
    
    def __init__(self):
        self.default_policy = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
            'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            'font-src': ["'self'", "https://fonts.gstatic.com"],
            'img-src': ["'self'", "data:", "https:"],
            'connect-src': ["'self'", "https://api.byteguardx.com"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'upgrade-insecure-requests': []
        }
        
        self.development_policy = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", "http://localhost:*", "ws://localhost:*"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'font-src': ["'self'", "data:"],
            'img-src': ["'self'", "data:", "http:", "https:"],
            'connect-src': ["'self'", "http://localhost:*", "ws://localhost:*"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"]
        }
    
    def get_policy_string(self, development: bool = False) -> str:
        """Generate CSP policy string"""
        policy = self.development_policy if development else self.default_policy
        
        policy_parts = []
        for directive, sources in policy.items():
            if sources:
                policy_parts.append(f"{directive} {' '.join(sources)}")
            else:
                policy_parts.append(directive)
        
        return '; '.join(policy_parts)
    
    def apply_headers(self, response: Response, development: bool = False) -> Response:
        """Apply CSP and other security headers to response"""
        # Content Security Policy
        csp_policy = self.get_policy_string(development)
        response.headers['Content-Security-Policy'] = csp_policy
        
        # Additional security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # HSTS for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response

class InputSanitizer:
    """Advanced input sanitization for frontend data"""
    
    def __init__(self):
        # Allowed HTML tags for rich content
        self.allowed_tags = [
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote',
            'code', 'pre', 'a'
        ]
        
        # Allowed attributes
        self.allowed_attributes = {
            'a': ['href', 'title'],
            'code': ['class'],
            'pre': ['class']
        }
        
        # Dangerous patterns to remove
        self.dangerous_patterns = [
            r'javascript:',
            r'vbscript:',
            r'data:text/html',
            r'on\w+\s*=',  # Event handlers
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>',
            r'<form[^>]*>.*?</form>'
        ]
    
    def sanitize_html(self, content: str, allow_links: bool = False) -> str:
        """Sanitize HTML content"""
        if not content:
            return ""
        
        try:
            # Remove dangerous patterns first
            for pattern in self.dangerous_patterns:
                content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
            
            # Use bleach for comprehensive sanitization
            tags = self.allowed_tags.copy()
            if not allow_links and 'a' in tags:
                tags.remove('a')
            
            attributes = self.allowed_attributes.copy()
            if not allow_links and 'a' in attributes:
                del attributes['a']
            
            sanitized = bleach.clean(
                content,
                tags=tags,
                attributes=attributes,
                strip=True
            )
            
            return sanitized
            
        except Exception as e:
            logger.error(f"HTML sanitization failed: {e}")
            return html.escape(content)
    
    def sanitize_text(self, content: str) -> str:
        """Sanitize plain text content"""
        if not content:
            return ""
        
        # HTML escape
        sanitized = html.escape(content)
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        return sanitized
    
    def sanitize_json(self, data: Any) -> Any:
        """Recursively sanitize JSON data"""
        if isinstance(data, dict):
            return {key: self.sanitize_json(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_json(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_text(data)
        else:
            return data
    
    def sanitize_plugin_description(self, description: str) -> str:
        """Sanitize plugin descriptions with limited HTML"""
        return self.sanitize_html(description, allow_links=True)
    
    def sanitize_scan_message(self, message: str) -> str:
        """Sanitize scan result messages"""
        return self.sanitize_text(message)
    
    def sanitize_markdown(self, content: str) -> str:
        """Sanitize markdown content"""
        # Convert markdown to HTML first (you'd use a markdown library)
        # For now, treat as plain text
        return self.sanitize_text(content)

class XSSProtection:
    """XSS protection utilities"""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
    
    def protect_output(self, content: str, content_type: str = 'text') -> str:
        """Protect output based on content type"""
        if content_type == 'html':
            return self.sanitizer.sanitize_html(content)
        elif content_type == 'json':
            return json.dumps(self.sanitizer.sanitize_json(json.loads(content)))
        else:
            return self.sanitizer.sanitize_text(content)
    
    def validate_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize input data"""
        return self.sanitizer.sanitize_json(data)

class SecurityMiddleware:
    """Flask middleware for frontend security"""
    
    def __init__(self, app=None, development: bool = False):
        self.csp = ContentSecurityPolicy()
        self.sanitizer = InputSanitizer()
        self.xss_protection = XSSProtection()
        self.development = development
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security middleware with Flask app"""
        app.after_request(self.apply_security_headers)
        app.before_request(self.sanitize_request_data)
    
    def apply_security_headers(self, response: Response) -> Response:
        """Apply security headers to all responses"""
        return self.csp.apply_headers(response, self.development)
    
    def sanitize_request_data(self):
        """Sanitize incoming request data"""
        # Skip JSON sanitization to avoid consuming request body
        # Individual endpoints will handle their own JSON parsing and validation
        pass

# Global instances
csp = ContentSecurityPolicy()
input_sanitizer = InputSanitizer()
xss_protection = XSSProtection()

def create_security_middleware(app, development: bool = False):
    """Create and configure security middleware"""
    return SecurityMiddleware(app, development)

def sanitize_for_frontend(data: Any, content_type: str = 'text') -> Any:
    """Utility function to sanitize data for frontend display"""
    return xss_protection.protect_output(str(data), content_type)

def get_csp_meta_tag(development: bool = False) -> str:
    """Generate CSP meta tag for HTML templates"""
    policy = csp.get_policy_string(development)
    return f'<meta http-equiv="Content-Security-Policy" content="{policy}">'
