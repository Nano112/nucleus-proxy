"""
Core API endpoint tests for the Nucleus Proxy.

Tests basic functionality including health checks, authentication, 
and basic server operations.
"""

import pytest


class TestHealthEndpoints:
    """Test health and status endpoints."""

    async def test_basic_health_check(self, client):
        """Test the basic health endpoint."""
        response = await client.get("/health")
        
        assert response.status == 200
        data = response.json
        
        assert data["status"] == "OK"
        assert data["service"] == "nucleus-proxy"
        assert data["version"] == "0.1.0"
        assert "timestamp" in data

    async def test_monitoring_health_check(self, client):
        """Test the detailed monitoring health endpoint."""
        response = await client.get("/v1/monitoring/health")
        
        assert response.status == 200
        data = response.json
        
        assert data["status"] == "healthy"
        assert "components" in data
        assert "timestamp" in data

    async def test_openapi_docs_available(self, client):
        """Test that OpenAPI documentation is available."""
        response = await client.get("/docs")
        
        assert response.status == 200
        assert "text/html" in response.headers.get("content-type", "")


class TestAuthentication:
    """Test authentication endpoints and flows."""

    async def test_login_endpoint_exists(self, client):
        """Test that login endpoint is available."""
        # Test with empty body to see error response
        response = await client.post("/v1/auth/login")
        
        # Should return 400 for missing body, not 404
        assert response.status == 400
        data = response.json
        assert "error" in data

    async def test_login_with_invalid_data(self, client):
        """Test login with invalid request data."""
        response = await client.post("/v1/auth/login", json={})
        
        assert response.status == 400
        data = response.json
        assert "error" in data

    async def test_logout_endpoint_exists(self, client):
        """Test that logout endpoint is available."""
        response = await client.post("/v1/auth/logout")
        
        assert response.status == 200
        data = response.json
        assert "message" in data


class TestFileOperations:
    """Test file operation endpoints."""

    async def test_list_files_requires_auth(self, client):
        """Test that file listing requires authentication."""
        response = await client.get("/v1/files/list")
        
        assert response.status == 401

    async def test_file_info_requires_auth(self, client):
        """Test that file info requires authentication."""
        response = await client.get("/v1/files/info", params={"path": "/test"})
        
        assert response.status == 401

    async def test_create_directory_requires_auth(self, client):
        """Test that directory creation requires authentication."""
        response = await client.post("/v1/files/create-directory", 
                                   json={"path": "/test"})
        
        assert response.status == 401


class TestMonitoringEndpoints:
    """Test monitoring and metrics endpoints."""

    async def test_system_metrics(self, client):
        """Test system metrics endpoint."""
        response = await client.get("/v1/monitoring/metrics")
        
        assert response.status == 200
        data = response.json
        
        assert "system" in data
        assert "process" in data
        assert "timestamp" in data

    async def test_background_tasks_status(self, client):
        """Test background tasks status endpoint."""
        response = await client.get("/v1/monitoring/background-tasks")
        
        assert response.status == 200
        data = response.json
        
        assert "manager_running" in data
        assert "tasks" in data
        assert "execution_history" in data

    async def test_diagnostics(self, client):
        """Test diagnostics endpoint."""
        response = await client.get("/v1/monitoring/diagnostics")
        
        assert response.status == 200
        data = response.json
        
        assert "python_version" in data
        assert "platform" in data
        assert "process_id" in data


class TestRealTimeEndpoints:
    """Test real-time event system endpoints."""

    async def test_event_history_endpoint(self, client):
        """Test event history endpoint."""
        response = await client.get("/v1/realtime/events/history")
        
        assert response.status == 200
        data = response.json
        
        assert "events" in data
        assert "count" in data
        assert isinstance(data["events"], list)

    async def test_realtime_stats(self, client):
        """Test real-time statistics endpoint."""
        response = await client.get("/v1/realtime/stats")
        
        assert response.status == 200
        data = response.json
        
        assert "realtime_stats" in data
        assert "timestamp" in data

    async def test_test_event_publication(self, client):
        """Test event publication endpoint."""
        event_data = {
            "type": "test_event",
            "channel": "system",
            "data": {"message": "test"}
        }
        
        response = await client.post("/v1/realtime/test-event", json=event_data)
        
        assert response.status == 200
        data = response.json
        
        assert "message" in data
        assert "event" in data