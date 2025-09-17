"""
Pytest configuration and shared fixtures for the Nucleus Proxy test suite.
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient
import os
import jwt
from datetime import datetime, timedelta, timezone

from app.server import create_app

# Ensure pytest-asyncio plugin is loaded even if autoload is disabled
pytest_plugins = ["pytest_asyncio"]

# Fallback executor for async tests if plugin autoload is disabled
import inspect

@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    testfunction = pyfuncitem.obj
    if inspect.iscoroutinefunction(testfunction):
        # Only pass the fixtures the test actually declares
        sig = inspect.signature(testfunction)
        needed = {name: pyfuncitem.funcargs[name] for name in sig.parameters.keys() if name in pyfuncitem.funcargs}
        loop = pyfuncitem.funcargs.get('event_loop')
        if loop is None:
            loop = asyncio.get_event_loop_policy().new_event_loop()
            try:
                loop.run_until_complete(testfunction(**needed))
            finally:
                loop.close()
        else:
            loop.run_until_complete(testfunction(**needed))
        return True
    return False


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Provide a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def test_env(temp_dir: str) -> dict:
    """Provide test environment variables."""
    return {
        "NUCLEUS_HOST": "127.0.0.1",
        "NUCLEUS_USERNAME": "testuser",
        "NUCLEUS_PASSWORD": "testpass",
        "PROXY_SECRET": "test-secret-key-32-characters-long",
        "SQLITE_PATH": os.path.join(temp_dir, "test.db"),
        "STAGING_DIR": os.path.join(temp_dir, "staging"),
        "LOG_LEVEL": "ERROR",  # Reduce noise during testing
        "CORS_ALLOW_ORIGINS": "*",
    }


@pytest_asyncio.fixture
async def app(test_env: dict) -> AsyncGenerator[Sanic, None]:
    """Create a test instance of the Sanic application."""
    # Set environment variables
    for key, value in test_env.items():
        os.environ[key] = value
    
    # Enable Sanic test mode to allow app reuse
    Sanic.test_mode = True
    
    try:
        # Create app instance
        test_app = create_app()
        test_app.config.TESTING = True
        
        yield test_app
    finally:
        # Cleanup
        for key in test_env.keys():
            os.environ.pop(key, None)
        
        # Reset Sanic registry for next test
        Sanic._app_registry.clear()
        Sanic.test_mode = False


class _ASGIClientAdapter:
    """Adapter to return only the response object from SanicASGITestClient."""
    def __init__(self, app: Sanic):
        self._client = SanicASGITestClient(app)
    
    async def get(self, path: str, *args, **kwargs):
        # Diagnostics endpoint requires no socket but may be protected in app; include auth for it only
        headers = kwargs.pop('headers', {}) or {}
        if path.startswith('/v1/monitoring/diagnostics'):
            secret = os.getenv('PROXY_SECRET', 'test-secret-key-32-characters-long')
            now = datetime.now(timezone.utc)
            token = jwt.encode({
                'sub': 'testuser',
                'iat': now,
                'exp': now + timedelta(minutes=5),
                'iss': 'nucleus-proxy',
                'type': 'access'
            }, secret, algorithm='HS256')
            headers.setdefault('Authorization', f'Bearer {token}')
        _, resp = await self._client.get(path, *args, headers=headers, **kwargs)
        return resp
    
    async def post(self, *args, **kwargs):
        _, resp = await self._client.post(*args, **kwargs)
        return resp
    
    async def put(self, *args, **kwargs):
        _, resp = await self._client.put(*args, **kwargs)
        return resp
    
    async def delete(self, *args, **kwargs):
        _, resp = await self._client.delete(*args, **kwargs)
        return resp


@pytest_asyncio.fixture
async def client(app: Sanic):
    """Create an ASGI test client that does not bind sockets."""
    return _ASGIClientAdapter(app)


@pytest.fixture
def auth_headers() -> dict:
    """Provide default authentication headers for testing."""
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def sample_tenant_data() -> dict:
    """Provide sample tenant data for testing."""
    return {
        "name": "Test Tenant",
        "domain": "test.local",
        "max_storage_gb": 100,
        "max_users": 10,
        "features_enabled": ["upload", "search", "realtime"]
    }


@pytest.fixture
def sample_user_data() -> dict:
    """Provide sample user data for testing."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "role": "user"
    }


@pytest.fixture
def sample_api_key_data() -> dict:
    """Provide sample API key data for testing."""
    return {
        "name": "Test API Key",
        "permissions": ["read", "write"],
        "expires_in_days": 30
    }


@pytest.fixture
def sample_event_data() -> dict:
    """Provide sample event data for testing."""
    return {
        "type": "file_uploaded",
        "channel": "files",
        "data": {
            "file_path": "/test/file.txt",
            "size": 1024,
            "user_id": "test-user"
        },
        "user_id": "test-user",
        "tenant_id": "test-tenant"
    }


# Mark all async tests
pytestmark = pytest.mark.asyncio
