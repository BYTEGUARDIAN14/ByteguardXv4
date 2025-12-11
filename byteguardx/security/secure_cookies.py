"""
Secure Cookie Configuration for ByteGuardX
Enforces secure cookie settings in production
"""

import os
import logging
from flask import Flask, request, make_response
from typing import Optional

logger = logging.getLogger(__name__)

class SecureCookieMiddleware:
    """Middleware to enforce secure cookie settings"""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize secure cookie middleware with Flask app"""
        is_production = os.environ.get('ENV', '').lower() == 'production'
        
        # Configure session cookie settings
        app.config.update({
            'SESSION_COOKIE_SECURE': is_production,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Strict',
            'SESSION_COOKIE_NAME': 'byteguardx_session',
            'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hour
        })
        
        # Add response processor to secure all cookies
        @app.after_request
        def secure_cookies(response):
            return self.process_response(response, is_production)
        
        logger.info(f"Secure cookie middleware initialized (production: {is_production})")
    
    def process_response(self, response, is_production: bool):
        """Process response to secure all cookies"""
        try:
            # Get all Set-Cookie headers
            cookies = response.headers.getlist('Set-Cookie')
            
            if not cookies:
                return response
            
            # Remove existing Set-Cookie headers
            response.headers.pop('Set-Cookie', None)
            
            # Process each cookie
            for cookie in cookies:
                secured_cookie = self.secure_cookie_header(cookie, is_production)
                response.headers.add('Set-Cookie', secured_cookie)
            
            return response
            
        except Exception as e:
            logger.error(f"Cookie security processing error: {e}")
            return response
    
    def secure_cookie_header(self, cookie_header: str, is_production: bool) -> str:
        """Secure a single cookie header"""
        try:
            # Parse cookie attributes
            parts = cookie_header.split(';')
            cookie_name_value = parts[0].strip()
            attributes = {}
            
            for part in parts[1:]:
                if '=' in part:
                    key, value = part.strip().split('=', 1)
                    attributes[key.lower()] = value
                else:
                    attributes[part.strip().lower()] = True
            
            # Apply security attributes
            secured_parts = [cookie_name_value]
            
            # HttpOnly (except for CSRF token)
            cookie_name = cookie_name_value.split('=')[0]
            if cookie_name.lower() != 'csrf_token' and 'httponly' not in attributes:
                secured_parts.append('HttpOnly')
            elif 'httponly' in attributes:
                secured_parts.append('HttpOnly')
            
            # Secure flag in production
            if is_production and 'secure' not in attributes:
                secured_parts.append('Secure')
            elif 'secure' in attributes:
                secured_parts.append('Secure')
            
            # SameSite
            if 'samesite' not in attributes:
                secured_parts.append('SameSite=Strict')
            else:
                secured_parts.append(f"SameSite={attributes['samesite']}")
            
            # Preserve other attributes
            for attr, value in attributes.items():
                if attr not in ['httponly', 'secure', 'samesite']:
                    if value is True:
                        secured_parts.append(attr.title())
                    else:
                        secured_parts.append(f"{attr.title()}={value}")
            
            return '; '.join(secured_parts)
            
        except Exception as e:
            logger.error(f"Cookie header processing error: {e}")
            return cookie_header  # Return original if processing fails

def init_secure_cookies(app: Flask):
    """Initialize secure cookie middleware"""
    middleware = SecureCookieMiddleware(app)
    return middleware

# Global instance
secure_cookie_middleware = SecureCookieMiddleware()
