"""
Advanced security system for M7 milestone.

Provides role-based access control (RBAC), API key authentication,
security middleware, audit logging, and security hardening features.
"""

import asyncio
import logging
import json
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from urllib.parse import urlparse

from sanic import Request, HTTPResponse
from sanic.response import JSONResponse

from app.config import settings

logger = logging.getLogger(__name__)


class SecurityLevel(str, Enum):
    """Security levels for operations"""
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


class AuthMethod(str, Enum):
    """Authentication methods"""
    JWT = "jwt"
    API_KEY = "api_key"
    SIGNED_URL = "signed_url"
    BASIC_AUTH = "basic_auth"


@dataclass
class SecurityRule:
    """Security rule for access control"""
    name: str
    resource_pattern: str
    required_permissions: Set[str]
    required_roles: Set[str] = field(default_factory=set)
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    rate_limit: Optional[int] = None
    allowed_methods: Set[str] = field(default_factory=lambda: {"GET", "POST", "PUT", "DELETE"})
    ip_whitelist: List[str] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)
    require_https: bool = True
    
    def matches_resource(self, resource: str) -> bool:
        """Check if rule matches resource pattern"""
        import fnmatch
        return fnmatch.fnmatch(resource, self.resource_pattern)


@dataclass
class SecurityContext:
    """Security context for a request"""
    user_id: str
    tenant_id: str
    permissions: Set[str]
    roles: Set[str]
    auth_method: AuthMethod
    ip_address: str
    user_agent: str
    timestamp: datetime
    session_id: Optional[str] = None
    api_key_id: Optional[str] = None


@dataclass
class AuditLogEntry:
    """Audit log entry for security events"""
    id: str
    timestamp: datetime
    tenant_id: str
    user_id: str
    action: str
    resource: str
    ip_address: str
    user_agent: str
    result: str  # success, failure, denied
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'result': self.result,
            'details': self.details
        }


class SecurityManager:
    """
    Manages advanced security features including RBAC, audit logging,
    and security policy enforcement.
    """
    
    def __init__(self):
        self.security_rules: List[SecurityRule] = []
        self.audit_log: List[AuditLogEntry] = []
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.rate_limiters: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Set[str] = set()
        self._initialized = False
        
        # Security headers to add to all responses
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
        }
    
    async def initialize(self):
        """Initialize the security manager"""
        if self._initialized:
            return
        
        await self._load_security_rules()
        await self._load_api_keys()
        
        self._initialized = True
        logger.info(f"Security manager initialized with {len(self.security_rules)} rules")
    
    async def validate_request(self, request: Request, resource: str, 
                              action: str, context: SecurityContext) -> Tuple[bool, Optional[str]]:
        """Validate request against security policies"""
        try:
            # Check IP blacklist
            if context.ip_address in self.blocked_ips:
                await self._audit_log(context, action, resource, "denied", 
                                    {"reason": "blocked_ip"})
                return False, "IP address blocked"
            
            # Find matching security rules
            matching_rules = [rule for rule in self.security_rules 
                            if rule.matches_resource(resource)]
            
            if not matching_rules:
                # No rules match - allow by default but log
                await self._audit_log(context, action, resource, "success", 
                                    {"reason": "no_matching_rules"})
                return True, None
            
            # Check each matching rule
            for rule in matching_rules:
                is_allowed, reason = await self._check_rule(request, rule, action, context)
                if not is_allowed:
                    await self._audit_log(context, action, resource, "denied", 
                                        {"reason": reason, "rule": rule.name})
                    return False, reason
            
            # All rules passed
            await self._audit_log(context, action, resource, "success")
            return True, None
            
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            await self._audit_log(context, action, resource, "failure", 
                                {"error": str(e)})
            return False, "Security validation failed"
    
    async def _check_rule(self, request: Request, rule: SecurityRule, 
                         action: str, context: SecurityContext) -> Tuple[bool, Optional[str]]:
        """Check a specific security rule"""
        
        # Check required permissions
        if rule.required_permissions and not rule.required_permissions.issubset(context.permissions):
            return False, f"Insufficient permissions: {rule.required_permissions - context.permissions}"
        
        # Check required roles  
        if rule.required_roles and not rule.required_roles.intersection(context.roles):
            return False, f"Required role not found: {rule.required_roles}"
        
        # Check allowed methods
        if request.method not in rule.allowed_methods:
            return False, f"Method {request.method} not allowed"
        
        # Check HTTPS requirement
        if rule.require_https and request.scheme != 'https':
            # Allow HTTP in development
            if not settings.is_production:
                pass  # Allow HTTP in development
            else:
                return False, "HTTPS required"
        
        # Check IP whitelist
        if rule.ip_whitelist and context.ip_address not in rule.ip_whitelist:
            return False, "IP not in whitelist"
        
        # Check IP blacklist
        if rule.ip_blacklist and context.ip_address in rule.ip_blacklist:
            return False, "IP blacklisted"
        
        # Check rate limiting
        if rule.rate_limit:
            if not await self._check_rate_limit(context.user_id, rule.name, rule.rate_limit):
                return False, "Rate limit exceeded"
        
        return True, None
    
    async def _check_rate_limit(self, user_id: str, rule_name: str, limit: int) -> bool:
        """Check rate limiting for user and rule"""
        key = f"{user_id}:{rule_name}"
        now = time.time()
        
        if key not in self.rate_limiters:
            self.rate_limiters[key] = {"count": 0, "window_start": now}
        
        rate_data = self.rate_limiters[key]
        
        # Reset window if needed (1 minute windows)
        if now - rate_data["window_start"] > 60:
            rate_data["count"] = 0
            rate_data["window_start"] = now
        
        if rate_data["count"] >= limit:
            return False
        
        rate_data["count"] += 1
        return True
    
    async def create_api_key(self, tenant_id: str, name: str, permissions: Set[str],
                           expires_at: Optional[datetime] = None) -> str:
        """Create new API key"""
        api_key = f"npk_{secrets.token_urlsafe(32)}"
        
        self.api_keys[api_key] = {
            "tenant_id": tenant_id,
            "name": name,
            "permissions": list(permissions),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "last_used": None,
            "is_active": True
        }
        
        logger.info(f"Created API key: {name} for tenant {tenant_id}")
        return api_key
    
    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return associated data"""
        if api_key not in self.api_keys:
            return None
        
        key_data = self.api_keys[api_key]
        
        if not key_data["is_active"]:
            return None
        
        # Check expiration
        if key_data["expires_at"]:
            expires_at = datetime.fromisoformat(key_data["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                return None
        
        # Update last used
        key_data["last_used"] = datetime.now(timezone.utc).isoformat()
        
        return key_data
    
    async def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key"""
        if api_key in self.api_keys:
            self.api_keys[api_key]["is_active"] = False
            logger.info(f"Revoked API key: {api_key}")
            return True
        return False
    
    def add_security_headers(self, response: HTTPResponse):
        """Add security headers to response"""
        for header, value in self.security_headers.items():
            response.headers[header] = value
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session"""
        timestamp = str(int(time.time()))
        message = f"{session_id}:{timestamp}"
        signature = hmac.new(
            settings.proxy_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{timestamp}.{signature}"
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token"""
        try:
            timestamp, signature = token.split('.')
            
            # Check token age (max 1 hour)
            token_time = int(timestamp)
            if time.time() - token_time > 3600:
                return False
            
            # Verify signature
            message = f"{session_id}:{timestamp}"
            expected_signature = hmac.new(
                settings.proxy_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except (ValueError, TypeError):
            return False
    
    def validate_input(self, input_data: str, max_length: int = 1000, 
                      allowed_chars: Optional[str] = None) -> bool:
        """Validate input for security"""
        if len(input_data) > max_length:
            return False
        
        if allowed_chars:
            return all(c in allowed_chars for c in input_data)
        
        # Basic XSS prevention
        dangerous_patterns = ['<script', 'javascript:', 'onload=', 'onerror=']
        input_lower = input_data.lower()
        return not any(pattern in input_lower for pattern in dangerous_patterns)
    
    async def _audit_log(self, context: SecurityContext, action: str, resource: str,
                        result: str, details: Optional[Dict[str, Any]] = None):
        """Add entry to audit log"""
        entry = AuditLogEntry(
            id=secrets.token_urlsafe(16),
            timestamp=datetime.now(timezone.utc),
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            action=action,
            resource=resource,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            result=result,
            details=details or {}
        )
        
        self.audit_log.append(entry)
        
        # Keep only recent entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]
        
        # Log security events
        if result in ['denied', 'failure']:
            logger.warning(f"Security event: {action} on {resource} {result} for {context.user_id}")
    
    def get_audit_log(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries for tenant"""
        entries = [entry for entry in self.audit_log if entry.tenant_id == tenant_id]
        return [entry.to_dict() for entry in entries[-limit:]]
    
    async def _load_security_rules(self):
        """Load security rules"""
        # Default security rules
        self.security_rules = [
            # Admin endpoints require admin role
            SecurityRule(
                name="admin_endpoints",
                resource_pattern="/v1/admin/*",
                required_permissions={"admin"},
                required_roles={"admin"},
                security_level=SecurityLevel.CRITICAL,
                rate_limit=10
            ),
            
            # Tenant management requires manage_tenant permission
            SecurityRule(
                name="tenant_management",
                resource_pattern="/v1/tenants/*",
                required_permissions={"manage_tenant"},
                security_level=SecurityLevel.HIGH,
                rate_limit=20
            ),
            
            # User management
            SecurityRule(
                name="user_management",
                resource_pattern="/v1/users/*",
                required_permissions={"manage_users"},
                security_level=SecurityLevel.HIGH,
                rate_limit=50
            ),
            
            # File operations
            SecurityRule(
                name="file_upload",
                resource_pattern="/v1/files/upload*",
                required_permissions={"write", "upload"},
                security_level=SecurityLevel.MEDIUM,
                allowed_methods={"POST"},
                rate_limit=100
            ),
            
            SecurityRule(
                name="file_download",
                resource_pattern="/v1/files/download*",
                required_permissions={"read", "download"},
                security_level=SecurityLevel.LOW,
                allowed_methods={"GET"},
                rate_limit=200
            ),
            
            # Monitoring endpoints - require read permission
            SecurityRule(
                name="monitoring",
                resource_pattern="/v1/monitoring/*",
                required_permissions={"read"},
                security_level=SecurityLevel.LOW,
                allowed_methods={"GET", "POST"},
                rate_limit=100
            ),
            
            # Background task control - requires admin
            SecurityRule(
                name="background_task_control",
                resource_pattern="/v1/monitoring/background-tasks/*/run",
                required_permissions={"admin"},
                security_level=SecurityLevel.HIGH,
                allowed_methods={"POST"},
                rate_limit=10
            ),
        ]
        
        logger.info(f"Loaded {len(self.security_rules)} security rules")
    
    async def _load_api_keys(self):
        """Load API keys from storage"""
        # This would load from database in production
        logger.info("API keys loaded")


# Global security manager instance  
_security_manager: Optional[SecurityManager] = None


async def get_security_manager() -> SecurityManager:
    """Get or create the global security manager"""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
        await _security_manager.initialize()
    return _security_manager


async def initialize_security():
    """Initialize the security system"""
    manager = await get_security_manager()
    logger.info("Security system initialized")


async def shutdown_security():
    """Shutdown the security system"""
    global _security_manager
    if _security_manager:
        logger.info("Security system shutdown")
        _security_manager = None