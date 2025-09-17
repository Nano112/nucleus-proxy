"""
Multi-tenancy and security API tests for the Nucleus Proxy.

Tests tenant management, user management, API keys, and security features.
"""

import pytest


class TestTenantManagement:
    """Test tenant management endpoints."""

    async def test_list_tenants_requires_auth(self, client):
        """Test that listing tenants requires authentication."""
        response = await client.get("/v1/tenants")
        
        assert response.status == 401

    async def test_create_tenant_requires_auth(self, client, sample_tenant_data: dict):
        """Test that creating tenants requires authentication."""
        response = await client.post("/v1/tenants", json=sample_tenant_data)
        
        assert response.status == 401

    async def test_get_tenant_requires_auth(self, client):
        """Test that getting tenant details requires authentication."""
        response = await client.get("/v1/tenants/test-tenant")
        
        assert response.status == 401

    async def test_update_tenant_requires_auth(self, client):
        """Test that updating tenants requires authentication."""
        update_data = {"max_storage_gb": 200}
        response = await client.put("/v1/tenants/test-tenant", json=update_data)
        
        assert response.status == 401

    async def test_delete_tenant_requires_auth(self, client):
        """Test that deleting tenants requires authentication."""
        response = await client.delete("/v1/tenants/test-tenant")
        
        assert response.status == 401


class TestTenantUsers:
    """Test tenant user management endpoints."""

    async def test_list_tenant_users_requires_auth(self, client):
        """Test that listing tenant users requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/users")
        
        assert response.status == 401

    async def test_create_tenant_user_requires_auth(self, client, sample_user_data: dict):
        """Test that creating tenant users requires authentication."""
        response = await client.post("/v1/tenants/test-tenant/users", json=sample_user_data)
        
        assert response.status == 401

    async def test_get_tenant_user_requires_auth(self, client):
        """Test that getting tenant user details requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/users/testuser")
        
        assert response.status == 401

    async def test_update_tenant_user_requires_auth(self, client):
        """Test that updating tenant users requires authentication."""
        update_data = {"role": "admin"}
        response = await client.put("/v1/tenants/test-tenant/users/testuser", json=update_data)
        
        assert response.status == 401

    async def test_delete_tenant_user_requires_auth(self, client):
        """Test that deleting tenant users requires authentication."""
        response = await client.delete("/v1/tenants/test-tenant/users/testuser")
        
        assert response.status == 401


class TestAPIKeyManagement:
    """Test API key management endpoints."""

    async def test_list_api_keys_requires_auth(self, client):
        """Test that listing API keys requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/api-keys")
        
        assert response.status == 401

    async def test_create_api_key_requires_auth(self, client, sample_api_key_data: dict):
        """Test that creating API keys requires authentication."""
        response = await client.post("/v1/tenants/test-tenant/api-keys", json=sample_api_key_data)
        
        assert response.status == 401

    async def test_get_api_key_requires_auth(self, client):
        """Test that getting API key details requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/api-keys/test-key-id")
        
        assert response.status == 401

    async def test_delete_api_key_requires_auth(self, client):
        """Test that deleting API keys requires authentication."""
        response = await client.delete("/v1/tenants/test-tenant/api-keys/test-key-id")
        
        assert response.status == 401


class TestSecurityFeatures:
    """Test security and audit features."""

    async def test_tenant_audit_log_requires_auth(self, client):
        """Test that accessing audit logs requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/audit-log")
        
        assert response.status == 401

    async def test_tenant_stats_requires_auth(self, client):
        """Test that accessing tenant stats requires authentication."""
        response = await client.get("/v1/tenants/test-tenant/stats")
        
        assert response.status == 401

    async def test_security_headers_present(self, client):
        """Test that security headers are present in responses."""
        response = await client.get("/health")
        
        # Check for common security headers
        headers = response.headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "X-XSS-Protection" in headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"


class TestUploadEndpoints:
    """Test upload-related endpoints."""

    async def test_create_upload_session_requires_auth(self, client):
        """Test that creating upload sessions requires authentication."""
        upload_data = {
            "path": "/test/file.txt",
            "size": 1024,
            "part_size": 512
        }
        response = await client.post("/v1/uploads/sessions", json=upload_data)
        
        assert response.status == 401

    async def test_list_upload_sessions_requires_auth(self, client):
        """Test that listing upload sessions requires authentication."""
        response = await client.get("/v1/uploads/sessions")
        
        assert response.status == 401


class TestSignedURLs:
    """Test signed URL endpoints."""

    async def test_create_signed_url_requires_auth(self, client):
        """Test that creating signed URLs requires authentication."""
        url_data = {
            "path": "/test/file.txt",
            "operation": "download",
            "expires_in": 3600
        }
        response = await client.post("/v1/signed-urls", json=url_data)
        
        assert response.status == 401

    async def test_list_signed_urls_requires_auth(self, client):
        """Test that listing signed URLs requires authentication."""
        response = await client.get("/v1/signed-urls")
        
        assert response.status == 401