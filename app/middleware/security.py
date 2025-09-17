"""
Security hardening middleware and utilities for the proxy server.

Implements security headers, CSRF protection, input validation,
SQL injection prevention, and security scanning capabilities.
"""

import re
import hashlib
import hmac
import secrets
import time
from typing import Dict, List, Optional, Pattern, Any, Tuple
from functools import wraps
from urllib.parse import parse_qs, urlparse

from sanic import Request, Sanic
from sanic.response import HTTPResponse
from sanic.exceptions import BadRequest, Forbidden
import logging


logger = logging.getLogger(__name__)


class SecurityHeaders:
    """Security headers middleware"""
    
    DEFAULT_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        # More permissive CSP for development and documentation
        'Content-Security-Policy': (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; "
            "style-src 'self' 'unsafe-inline' https: data:; "
            "font-src 'self' https: data:; "
            "img-src 'self' https: data:; "
            "connect-src 'self' ws: wss: https: http:; "
            "object-src 'none';"
        )
    }
    
    @staticmethod
    def add_security_headers(request: Request, response: HTTPResponse) -> HTTPResponse:
        """Add security headers to response"""
        try:
            # Add default security headers
            for header, value in SecurityHeaders.DEFAULT_HEADERS.items():
                # Use more permissive CSP in development for docs
                if header == 'Content-Security-Policy':
                    # Check if this is the docs endpoint
                    if '/docs' in request.path or '/openapi' in request.path:
                        # Very permissive CSP for documentation
                        response.headers[header] = (
                            "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; "
                            "script-src 'self' 'unsafe-inline' 'unsafe-eval' *; "
                            "style-src 'self' 'unsafe-inline' *; "
                            "font-src 'self' *; "
                            "img-src 'self' data: *; "
                            "connect-src 'self' ws: wss: *;"
                        )
                    else:
                        response.headers[header] = value
                else:
                    response.headers[header] = value
            
            # Add server identification header
            response.headers['Server'] = 'Nucleus-Proxy/1.0'
            
            # Remove potentially revealing headers
            response.headers.pop('X-Powered-By', None)
            response.headers.pop('Server-Version', None)
            
        except Exception as e:
            logger.warning(f"Failed to add security headers: {e}")
        
        return response


class CSRFProtection:
    """CSRF protection middleware"""
    
    def __init__(self, secret_key: str, token_lifetime: int = 3600):
        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        self.token_lifetime = token_lifetime
    
    def generate_token(self, session_id: str) -> str:
        """Generate CSRF token for session"""
        timestamp = str(int(time.time()))
        payload = f"{session_id}:{timestamp}"
        signature = hmac.new(self.secret_key, payload.encode(), hashlib.sha256).hexdigest()
        return f"{timestamp}:{signature}"
    
    def validate_token(self, token: str, session_id: str) -> bool:
        """Validate CSRF token"""
        try:
            if ':' not in token:
                return False
            
            timestamp_str, signature = token.split(':', 1)
            timestamp = int(timestamp_str)
            
            # Check token age
            if time.time() - timestamp > self.token_lifetime:
                logger.warning("CSRF token expired")
                return False
            
            # Verify signature
            payload = f"{session_id}:{timestamp_str}"
            expected_signature = hmac.new(self.secret_key, payload.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        
        except (ValueError, TypeError) as e:
            logger.warning(f"CSRF token validation error: {e}")
            return False
    
    def check_request(self, request: Request) -> bool:
        """Check CSRF token for request"""
        # Skip CSRF check for safe methods
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Skip for API endpoints with API key auth
        if request.headers.get('X-API-Key'):
            return True
        
        # Skip for API endpoints (in development/testing)
        if request.path.startswith('/v1/'):
            return True
        
        # Get token from header or form
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token:
            logger.warning("Missing CSRF token")
            return False
        
        # Get session ID (simplified - could use actual session)
        session_id = request.headers.get('X-Session-ID', 'default')
        
        return self.validate_token(token, session_id)


class InputValidator:
    """Input validation and sanitization"""
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)', re.IGNORECASE),
        re.compile(r'(\bunion\s+select\b)', re.IGNORECASE),
        re.compile(r'(\b(or|and)\s+\d+\s*=\s*\d+)', re.IGNORECASE),
        re.compile(r"(['\";])", re.IGNORECASE),
        re.compile(r'(\-\-)', re.IGNORECASE),
        re.compile(r'(/\*|\*/)', re.IGNORECASE)
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<.*?on\w+\s*=.*?>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'vbscript:', re.IGNORECASE),
        re.compile(r'data:text/html', re.IGNORECASE)
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r'\.\.(/|\\)'),
        re.compile(r'(^|/)\.\.($|/)'),
        re.compile(r'%2e%2e'),
        re.compile(r'\\\\'),
        re.compile(r'%00')
    ]
    
    @classmethod
    def check_sql_injection(cls, value: str) -> List[str]:
        """Check for SQL injection patterns"""
        findings = []
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if pattern.search(value):
                findings.append(f"SQL injection pattern detected: {pattern.pattern}")
        return findings
    
    @classmethod
    def check_xss(cls, value: str) -> List[str]:
        """Check for XSS patterns"""
        findings = []
        for pattern in cls.XSS_PATTERNS:
            if pattern.search(value):
                findings.append(f"XSS pattern detected: {pattern.pattern}")
        return findings
    
    @classmethod
    def check_path_traversal(cls, value: str) -> List[str]:
        """Check for path traversal patterns"""
        findings = []
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(value):
                findings.append(f"Path traversal pattern detected: {pattern.pattern}")
        return findings
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            value = str(value)
        
        # Limit length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize whitespace
        value = re.sub(r'\s+', ' ', value).strip()
        
        return value
    
    @classmethod
    def validate_input(cls, value: Any, field_name: str = "input") -> Tuple[bool, List[str]]:
        """Validate input for security issues"""
        if not isinstance(value, str):
            if isinstance(value, (dict, list)):
                # Recursively validate nested structures
                errors = []
                if isinstance(value, dict):
                    for k, v in value.items():
                        valid, sub_errors = cls.validate_input(v, f"{field_name}.{k}")
                        errors.extend(sub_errors)
                else:  # list
                    for i, v in enumerate(value):
                        valid, sub_errors = cls.validate_input(v, f"{field_name}[{i}]")
                        errors.extend(sub_errors)
                return len(errors) == 0, errors
            return True, []
        
        errors = []
        
        # Check for malicious patterns
        errors.extend([f"{field_name}: {msg}" for msg in cls.check_sql_injection(value)])
        errors.extend([f"{field_name}: {msg}" for msg in cls.check_xss(value)])
        errors.extend([f"{field_name}: {msg}" for msg in cls.check_path_traversal(value)])
        
        return len(errors) == 0, errors


class SecurityScanner:
    """Security scanning utilities"""
    
    @staticmethod
    def scan_request(request: Request) -> Dict[str, Any]:
        """Scan request for security issues"""
        findings = {
            'risk_level': 'low',
            'issues': [],
            'recommendations': []
        }
        
        # Check headers for security issues
        suspicious_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'CF-Connecting-IP', 'True-Client-IP'
        ]
        
        for header in suspicious_headers:
            if header in request.headers:
                findings['issues'].append(f"Suspicious header present: {header}")
        
        # Check User-Agent
        user_agent = request.headers.get('User-Agent', '').lower()
        malicious_ua_patterns = [
            'sqlmap', 'nmap', 'nikto', 'dirb', 'gobuster', 'burp',
            'scanner', 'crawler', 'bot', 'spider'
        ]
        
        for pattern in malicious_ua_patterns:
            if pattern in user_agent:
                findings['issues'].append(f"Suspicious User-Agent: {pattern}")
                findings['risk_level'] = 'medium'
        
        # Check request body (only for JSON content)
        content_type = request.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                if hasattr(request, 'json') and request.json:
                    valid, validation_errors = InputValidator.validate_input(request.json)
                    if not valid:
                        findings['issues'].extend(validation_errors)
                        findings['risk_level'] = 'high'
            except Exception:
                # Not valid JSON, skip validation
                pass
        
        # Check query parameters
        for key, value in request.args.items():
            valid, validation_errors = InputValidator.validate_input(value, f"query.{key}")
            if not valid:
                findings['issues'].extend(validation_errors)
                findings['risk_level'] = 'high' if findings['risk_level'] != 'critical' else 'critical'
        
        # Security recommendations
        if findings['issues']:
            findings['recommendations'].extend([
                "Enable request logging and monitoring",
                "Implement rate limiting",
                "Use input validation middleware",
                "Consider blocking suspicious requests"
            ])
        
        return findings
    
    @staticmethod
    def assess_request_risk(request: Request) -> str:
        """Assess overall risk level of request"""
        scan_results = SecurityScanner.scan_request(request)
        return scan_results['risk_level']


def security_middleware(app: Sanic):
    """Register security middleware"""
    
    csrf_protection = CSRFProtection(app.config.get('SECRET_KEY', 'default-secret'))
    
    @app.middleware('request')
    async def security_request_middleware(request: Request):
        """Process security checks on incoming requests"""
        try:
            # Skip security checks for health endpoints
            if request.path in ['/health', '/v1/health']:
                return
            
            # Scan request for security issues
            risk_level = SecurityScanner.assess_request_risk(request)
            
            # Block high/critical risk requests
            if risk_level in ['critical']:
                logger.warning(f"Blocking high-risk request from {request.ip}: {request.path}")
                raise Forbidden("Request blocked due to security policy")
            
            # Check CSRF for state-changing requests (but be lenient in development)
            from app.config import settings
            if settings.log_level.upper() != 'DEBUG' and not csrf_protection.check_request(request):
                # Only enforce CSRF in production (non-DEBUG mode)
                if not request.path.startswith('/docs') and not request.path.startswith('/openapi'):
                    raise Forbidden("Invalid or missing CSRF token")
            
            # Add security context to request
            request.ctx.security = {
                'risk_level': risk_level,
                'csrf_token': csrf_protection.generate_token(request.headers.get('X-Session-ID', 'default'))
            }
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            if isinstance(e, (BadRequest, Forbidden)):
                raise
            # Don't block on security middleware errors
    
    @app.middleware('response')
    async def security_response_middleware(request: Request, response: HTTPResponse):
        """Process security checks on outgoing responses"""
        try:
            # Add security headers
            response = SecurityHeaders.add_security_headers(request, response)
            
            # Add CSRF token to response headers if available
            if hasattr(request.ctx, 'security') and 'csrf_token' in request.ctx.security:
                response.headers['X-CSRF-Token'] = request.ctx.security['csrf_token']
            
        except Exception as e:
            logger.error(f"Security response middleware error: {e}")
        
        return response


def require_security_level(min_level: str = 'medium'):
    """Decorator to require minimum security level"""
    def decorator(f):
        @wraps(f)
        async def decorated_function(request: Request, *args, **kwargs):
            security_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            
            request_level = getattr(request.ctx.security, 'risk_level', 'medium')
            
            if security_levels.get(request_level, 2) >= security_levels.get(min_level, 2):
                logger.warning(f"Request blocked: security level {request_level} >= {min_level}")
                raise Forbidden("Request blocked due to security policy")
            
            return await f(request, *args, **kwargs)
        return decorated_function
    return decorator


def validate_input_decorator(*field_names):
    """Decorator to validate specific request fields"""
    def decorator(f):
        @wraps(f)
        async def decorated_function(request: Request, *args, **kwargs):
            errors = []
            
            # Validate JSON fields
            if hasattr(request, 'json') and request.json:
                for field_name in field_names:
                    if field_name in request.json:
                        valid, validation_errors = InputValidator.validate_input(
                            request.json[field_name], field_name
                        )
                        if not valid:
                            errors.extend(validation_errors)
            
            # Validate query parameters
            for field_name in field_names:
                if field_name in request.args:
                    valid, validation_errors = InputValidator.validate_input(
                        request.args[field_name], f"query.{field_name}"
                    )
                    if not valid:
                        errors.extend(validation_errors)
            
            if errors:
                logger.warning(f"Input validation failed: {errors}")
                raise BadRequest(f"Invalid input: {'; '.join(errors)}")
            
            return await f(request, *args, **kwargs)
        return decorated_function
    return decorator


# Export security utilities
__all__ = [
    'SecurityHeaders',
    'CSRFProtection', 
    'InputValidator',
    'SecurityScanner',
    'security_middleware',
    'require_security_level',
    'validate_input_decorator'
]
