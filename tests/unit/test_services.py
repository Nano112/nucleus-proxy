"""
Unit tests for core service components.

Tests individual service classes and their functionality in isolation.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from app.services.tenancy import TenancyManager, Tenant, TenantUser, TenantConfig, TenantStatus, UserRole
from app.services.security import SecurityManager, SecurityRule, SecurityLevel
from app.services.events import EventManager, Event, EventType, EventChannel
from app.services.metrics import MetricsCollector


class TestTenancyManager:
    """Test the TenancyManager service."""

    def test_tenant_creation(self):
        """Test creating a tenant."""
        config = TenantConfig(
            max_storage_gb=100,
            max_users=10,
            features_enabled=["upload", "search"]
        )
        
        tenant = Tenant(
            id="test-001",
            name="Test Tenant",
            domain="test.local",
            status=TenantStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            config=config,
            api_key="test-api-key"
        )
        
        assert tenant.id == "test-001"
        assert tenant.name == "Test Tenant"
        assert tenant.domain == "test.local"
        assert tenant.config.max_storage_gb == 100

    def test_tenant_user_creation(self):
        """Test creating a tenant user."""
        user = TenantUser(
            id="user-001",
            tenant_id="test-001",
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            created_at=datetime.now(timezone.utc),
            permissions={"read", "write"}
        )
        
        assert user.id == "user-001"
        assert user.tenant_id == "test-001"
        assert user.username == "testuser"
        assert "read" in user.permissions
        assert "write" in user.permissions

    @pytest.mark.asyncio
    async def test_tenancy_manager_initialization(self):
        """Test TenancyManager initialization."""
        manager = TenancyManager()
        
        with patch('app.services.tenancy.get_database') as mock_db:
            mock_db.return_value = AsyncMock()
            
            await manager.initialize()
            assert manager._initialized is True


class TestSecurityManager:
    """Test the SecurityManager service."""

    def test_security_rule_creation(self):
        """Test creating a security rule."""
        rule = SecurityRule(
            name="file_access_rule",
            resource_pattern="/v1/files/*",
            required_permissions={"read"},
            security_level=SecurityLevel.MEDIUM
        )
        
        assert rule.name == "file_access_rule"
        assert rule.resource_pattern == "/v1/files/*"
        assert "read" in rule.required_permissions
        assert rule.security_level == SecurityLevel.MEDIUM

    def test_resource_pattern_matching(self):
        """Test resource pattern matching in security rules."""
        rule = SecurityRule(
            name="test_rule",
            resource_pattern="/v1/files/*",
            required_permissions={"read"}
        )
        
        assert rule.matches_resource("/v1/files/list")
        assert rule.matches_resource("/v1/files/info")
        assert not rule.matches_resource("/v1/auth/login")

    @pytest.mark.asyncio
    async def test_security_manager_initialization(self):
        """Test SecurityManager initialization."""
        manager = SecurityManager()
        
        await manager.initialize()
        assert manager._initialized is True
        assert len(manager.security_rules) > 0


class TestEventManager:
    """Test the EventManager service."""

    def test_event_creation(self):
        """Test creating an event."""
        event = Event(
            id="event-001",
            type=EventType.FILE_UPLOADED,
            channel=EventChannel.FILES,
            tenant_id="test-tenant",
            data={"file_path": "/test.txt"},
            timestamp=datetime.now(timezone.utc)
        )
        
        assert event.id == "event-001"
        assert event.type == EventType.FILE_UPLOADED
        assert event.channel == EventChannel.FILES
        assert event.tenant_id == "test-tenant"
        assert event.data["file_path"] == "/test.txt"

    def test_event_serialization(self):
        """Test event serialization to dictionary."""
        event = Event(
            id="event-001",
            type=EventType.FILE_UPLOADED,
            channel=EventChannel.FILES,
            tenant_id="test-tenant",
            data={"file_path": "/test.txt"},
            timestamp=datetime.now(timezone.utc)
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["id"] == "event-001"
        assert event_dict["type"] == "file_uploaded"
        assert event_dict["channel"] == "files"
        assert event_dict["tenant_id"] == "test-tenant"
        assert "timestamp" in event_dict

    @pytest.mark.asyncio
    async def test_event_manager_initialization(self):
        """Test EventManager initialization."""
        manager = EventManager()
        
        await manager.initialize()
        assert manager._initialized is True
        assert isinstance(manager.subscribers, dict)
        assert isinstance(manager.event_history, list)


class TestMetricsCollector:
    """Test the MetricsCollector service."""

    @pytest.mark.asyncio
    async def test_metrics_collector_initialization(self):
        """Test MetricsCollector initialization."""
        collector = MetricsCollector()
        
        await collector.start()
        assert collector._running is True

    def test_metrics_recording(self):
        """Test recording metrics."""
        collector = MetricsCollector()
        
        collector.record_request("GET", "/health", 200, 0.05)
        
        # Check that metrics were recorded
        assert len(collector.request_metrics) > 0
        metric = collector.request_metrics[0]
        assert metric["method"] == "GET"
        assert metric["path"] == "/health"
        assert metric["status"] == 200
        assert metric["duration"] == 0.05

    def test_metrics_aggregation(self):
        """Test metrics aggregation."""
        collector = MetricsCollector()
        
        # Record multiple requests
        collector.record_request("GET", "/health", 200, 0.05)
        collector.record_request("GET", "/health", 200, 0.03)
        collector.record_request("POST", "/v1/auth/login", 200, 0.15)
        
        aggregated = collector.get_aggregated_metrics()
        
        assert "total_requests" in aggregated
        assert aggregated["total_requests"] == 3
        assert "average_response_time" in aggregated
        assert "status_codes" in aggregated
        assert aggregated["status_codes"]["200"] == 3

    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.Process')
    def test_system_metrics_collection(self, mock_process, mock_memory, mock_cpu):
        """Test system metrics collection."""
        # Mock system metrics
        mock_cpu.return_value = 25.5
        mock_memory.return_value = Mock(percent=60.0)
        mock_process_instance = Mock()
        mock_process_instance.cpu_percent.return_value = 5.0
        mock_process_instance.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100MB
        mock_process_instance.num_threads.return_value = 4
        mock_process.return_value = mock_process_instance
        
        collector = MetricsCollector()
        system_metrics = collector.get_system_metrics()
        
        assert "system" in system_metrics
        assert "process" in system_metrics
        assert system_metrics["system"]["cpu_percent"] == 25.5
        assert system_metrics["system"]["memory_percent"] == 60.0
        assert system_metrics["process"]["cpu_percent"] == 5.0
        assert system_metrics["process"]["memory_mb"] == 100.0
        assert system_metrics["process"]["threads"] == 4