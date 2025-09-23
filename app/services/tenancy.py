"""
Multi-tenant support system for M7 milestone.

Provides tenant isolation, per-tenant configurations, user management,
and data separation across database and file operations.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import secrets

from app.config import settings

# Expose database getter at module scope for testing/mocking
try:  # pragma: no cover - import fallback
    from app.db.sqlite import get_database  # type: ignore
except Exception:  # During import or when DB unavailable in tests
    get_database = None  # type: ignore

logger = logging.getLogger(__name__)


class TenantStatus(str, Enum):
    """Tenant status"""
    ACTIVE = "active"
    SUSPENDED = "suspended" 
    PENDING = "pending"
    DISABLED = "disabled"


class UserRole(str, Enum):
    """User roles within a tenant"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    GUEST = "guest"


@dataclass
class TenantConfig:
    """Tenant configuration settings"""
    max_storage_gb: int = 100
    max_users: int = 10
    max_uploads_per_day: int = 1000
    allowed_file_types: List[str] = field(default_factory=lambda: ["*"])
    custom_branding: Dict[str, str] = field(default_factory=dict)
    webhooks: List[str] = field(default_factory=list)
    features_enabled: List[str] = field(default_factory=lambda: ["upload", "search", "monitoring"])
    api_rate_limits: Dict[str, int] = field(default_factory=lambda: {"requests_per_minute": 100})


@dataclass
class Tenant:
    """Tenant information"""
    id: str
    name: str
    domain: Optional[str]
    status: TenantStatus
    created_at: datetime
    config: TenantConfig
    api_key: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'config': {
                'max_storage_gb': self.config.max_storage_gb,
                'max_users': self.config.max_users,
                'max_uploads_per_day': self.config.max_uploads_per_day,
                'allowed_file_types': self.config.allowed_file_types,
                'custom_branding': self.config.custom_branding,
                'webhooks': self.config.webhooks,
                'features_enabled': self.config.features_enabled,
                'api_rate_limits': self.config.api_rate_limits
            },
            'metadata': self.metadata
        }


@dataclass 
class TenantUser:
    """User within a tenant"""
    id: str
    tenant_id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    permissions: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'tenant_id': self.tenant_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'permissions': list(self.permissions)
        }


class TenancyManager:
    """
    Manages multi-tenant operations including tenant creation,
    user management, and tenant isolation.
    """
    
    def __init__(self):
        self.tenants: Dict[str, Tenant] = {}
        self.tenant_users: Dict[str, List[TenantUser]] = {}
        self.api_key_to_tenant: Dict[str, str] = {}
        self.domain_to_tenant: Dict[str, str] = {}
        self._initialized = False
    
    async def initialize(self):
        """Initialize the tenancy manager"""
        if self._initialized:
            return
        
        # Load tenants from database
        await self._load_tenants()
        
        # Create default tenant if none exist
        if not self.tenants:
            await self._create_default_tenant()
        
        self._initialized = True
        logger.info(f"Tenancy manager initialized with {len(self.tenants)} tenants")
    
    async def create_tenant(self, name: str, domain: Optional[str] = None, 
                           config: Optional[TenantConfig] = None) -> Tenant:
        """Create a new tenant"""
        tenant_id = self._generate_tenant_id(name)
        api_key = self._generate_api_key()
        
        if config is None:
            config = TenantConfig()
        
        tenant = Tenant(
            id=tenant_id,
            name=name,
            domain=domain,
            status=TenantStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            config=config,
            api_key=api_key
        )
        
        # Store tenant
        self.tenants[tenant_id] = tenant
        self.api_key_to_tenant[api_key] = tenant_id
        
        if domain:
            self.domain_to_tenant[domain] = tenant_id
        
        # Initialize tenant users list
        self.tenant_users[tenant_id] = []
        
        # Persist to database
        await self._save_tenant(tenant)
        
        logger.info(f"Created tenant: {name} ({tenant_id})")
        return tenant
    
    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return self.tenants.get(tenant_id)
    
    async def get_tenant_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """Get tenant by API key"""
        tenant_id = self.api_key_to_tenant.get(api_key)
        if tenant_id:
            return self.tenants.get(tenant_id)
        return None
    
    async def get_tenant_by_domain(self, domain: str) -> Optional[Tenant]:
        """Get tenant by domain"""
        tenant_id = self.domain_to_tenant.get(domain)
        if tenant_id:
            return self.tenants.get(tenant_id)
        return None
    
    async def update_tenant_config(self, tenant_id: str, config: TenantConfig) -> bool:
        """Update tenant configuration"""
        if tenant_id not in self.tenants:
            return False
        
        self.tenants[tenant_id].config = config
        await self._save_tenant(self.tenants[tenant_id])
        
        logger.info(f"Updated tenant config: {tenant_id}")
        return True
    
    async def create_tenant_user(self, tenant_id: str, username: str, email: str,
                                role: UserRole = UserRole.USER) -> Optional[TenantUser]:
        """Create a new user within a tenant"""
        if tenant_id not in self.tenants:
            return None
        
        # Check if user already exists
        existing_users = self.tenant_users.get(tenant_id, [])
        if any(u.username == username for u in existing_users):
            return None
        
        # Check tenant user limits
        tenant = self.tenants[tenant_id]
        if len(existing_users) >= tenant.config.max_users:
            return None
        
        user_id = self._generate_user_id(tenant_id, username)
        
        user = TenantUser(
            id=user_id,
            tenant_id=tenant_id,
            username=username,
            email=email,
            role=role,
            created_at=datetime.now(timezone.utc),
            permissions=self._get_default_permissions(role)
        )
        
        # Add to tenant users
        if tenant_id not in self.tenant_users:
            self.tenant_users[tenant_id] = []
        
        self.tenant_users[tenant_id].append(user)
        
        # Persist to database
        await self._save_tenant_user(user)
        
        logger.info(f"Created user: {username} in tenant {tenant_id}")
        return user
    
    async def get_tenant_users(self, tenant_id: str) -> List[TenantUser]:
        """Get all users for a tenant"""
        return self.tenant_users.get(tenant_id, [])
    
    async def get_tenant_user(self, tenant_id: str, username: str) -> Optional[TenantUser]:
        """Get specific user in a tenant"""
        users = self.tenant_users.get(tenant_id, [])
        for user in users:
            if user.username == username:
                return user
        return None
    
    def get_tenant_isolation_prefix(self, tenant_id: str) -> str:
        """Get database table prefix for tenant isolation"""
        return f"tenant_{tenant_id}_"
    
    def get_tenant_storage_path(self, tenant_id: str) -> str:
        """Get storage path for tenant files"""
        return f"/tenant/{tenant_id}"
    
    async def check_tenant_quota(self, tenant_id: str, operation: str) -> bool:
        """Check if tenant can perform operation within quotas"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False
        
        if tenant.status != TenantStatus.ACTIVE:
            return False
        
        # TODO: Implement actual quota checking based on operation
        # For now, just check if tenant is active
        return True
    
    async def record_tenant_usage(self, tenant_id: str, operation: str, size_bytes: int = 0):
        """Record usage for tenant quotas and billing"""
        # TODO: Implement usage tracking
        pass
    
    def _generate_tenant_id(self, name: str) -> str:
        """Generate unique tenant ID"""
        # Create a short, URL-safe tenant ID
        normalized = name.lower().replace(" ", "-").replace("_", "-")
        # Add timestamp suffix to ensure uniqueness
        suffix = str(int(datetime.now(timezone.utc).timestamp()))[-6:]
        return f"{normalized}-{suffix}"
    
    def _generate_api_key(self) -> str:
        """Generate secure API key"""
        return f"npt_{secrets.token_urlsafe(32)}"
    
    def _generate_user_id(self, tenant_id: str, username: str) -> str:
        """Generate unique user ID within tenant"""
        return f"{tenant_id}::{username}"
    
    def _get_default_permissions(self, role: UserRole) -> Set[str]:
        """Get default permissions for a role"""
        permissions = {
            UserRole.ADMIN: {
                "read", "write", "delete", "admin", "manage_users", 
                "manage_tenant", "view_analytics", "manage_webhooks"
            },
            UserRole.USER: {
                "read", "write", "upload", "download", "search"
            },
            UserRole.VIEWER: {
                "read", "download", "search"
            },
            UserRole.GUEST: {
                "read"
            }
        }
        return permissions.get(role, set())
    
    async def _load_tenants(self):
        """Load tenants from database"""
        try:
            db = None
            if callable(get_database):
                db = await get_database()  # type: ignore[misc]
            
            # Load tenants (this would be implemented in the database layer)
            # For now, we'll just log that we're loading
            logger.info("Loading tenants from database...")
            
        except Exception as e:
            logger.error(f"Error loading tenants: {e}")
    
    async def _create_default_tenant(self):
        """Create default tenant for single-tenant usage"""
        default_config = TenantConfig(
            max_storage_gb=1000,
            max_users=100,
            max_uploads_per_day=10000,
            features_enabled=["upload", "search", "monitoring", "admin"]
        )
        
        tenant = await self.create_tenant(
            name="Default",
            domain="default.local",
            config=default_config
        )
        
        # Create admin user
        await self.create_tenant_user(
            tenant_id=tenant.id,
            username="omniverse", 
            email="admin@nucleus-proxy.local",
            role=UserRole.ADMIN
        )
        
        logger.info("Created default tenant with admin user")
    
    async def _save_tenant(self, tenant: Tenant):
        """Save tenant to database"""
        try:
            db = None
            if callable(get_database):
                db = await get_database()  # type: ignore[misc]
            
            # TODO: Implement actual database storage
            # For now, just log the action
            logger.info(f"Saving tenant to database: {tenant.id}")
            
        except Exception as e:
            logger.error(f"Error saving tenant {tenant.id}: {e}")
    
    async def _save_tenant_user(self, user: TenantUser):
        """Save tenant user to database"""
        try:
            db = None
            if callable(get_database):
                db = await get_database()  # type: ignore[misc]
            
            # TODO: Implement actual database storage
            # For now, just log the action
            logger.info(f"Saving tenant user to database: {user.id}")
            
        except Exception as e:
            logger.error(f"Error saving tenant user {user.id}: {e}")


# Global tenancy manager instance
_tenancy_manager: Optional[TenancyManager] = None


async def get_tenancy_manager() -> TenancyManager:
    """Get or create the global tenancy manager"""
    global _tenancy_manager
    if _tenancy_manager is None:
        _tenancy_manager = TenancyManager()
        await _tenancy_manager.initialize()
    return _tenancy_manager


async def initialize_tenancy():
    """Initialize the tenancy system"""
    manager = await get_tenancy_manager()
    logger.info("Tenancy system initialized")


async def shutdown_tenancy():
    """Shutdown the tenancy system"""
    global _tenancy_manager
    if _tenancy_manager:
        logger.info("Tenancy system shutdown")
        _tenancy_manager = None
