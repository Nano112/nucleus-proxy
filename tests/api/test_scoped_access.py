"""Tests for scoped token issuance and path-based access controls."""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict

import jwt
import pytest
from unittest.mock import AsyncMock, patch

from app.routes.auth import create_jwt_token
from app.db.sqlite import UploadState
from app.config import settings


pytestmark = pytest.mark.asyncio


async def _issue_base_token(client, username: str = "admin") -> str:
    """Authenticate against the API and return the issued access token."""

    with patch("app.routes.auth.get_nucleus_client", new_callable=AsyncMock) as mock_get_client:
        nucleus_client = AsyncMock()
        nucleus_client.authenticate.return_value = {"status": "OK"}
        mock_get_client.return_value = nucleus_client

        response = await client.post(
            "/v1/auth/login",
            json={"username": username, "password": "secret"},
        )

    assert response.status == 200, response.text
    payload = response.json
    return payload["access_token"]


@pytest.mark.asyncio
async def test_login_includes_issue_tokens_ability(client, test_env):
    token = await _issue_base_token(client)

    decoded = jwt.decode(token, test_env["PROXY_SECRET"], algorithms=["HS256"])
    assert "abilities" in decoded
    assert "issue-tokens" in decoded["abilities"]
    assert decoded["meta"]["auth_method"] == "password"


@pytest.mark.asyncio
async def test_issue_scoped_token_normalizes_scope(client, test_env):
    issuer_token = await _issue_base_token(client, username="root")

    request_payload = {
        "subject": "scoped-user",
        "expires_in_minutes": 15,
        "scopes": [
            {"path": "tenant/project/", "permissions": ["write", "read", "execute"]},
        ],
        "metadata": {"from_service": "laravel"},
    }

    response = await client.post(
        "/v1/auth/token",
        headers={"Authorization": f"Bearer {issuer_token}"},
        json=request_payload,
    )

    assert response.status == 201, response.text
    payload = response.json

    assert payload["subject"] == "scoped-user"
    assert payload["abilities"] == ["scoped-access"]
    assert payload["scopes"] == [{"path": "/tenant/project", "permissions": ["read", "write"]}]
    assert payload["meta"]["issued_by"] == "root"
    assert payload["meta"]["from_service"] == "laravel"

    scoped_token = payload["access_token"]
    decoded = jwt.decode(scoped_token, test_env["PROXY_SECRET"], algorithms=["HS256"])
    assert decoded["scopes"] == [{"path": "/tenant/project", "permissions": ["read", "write"]}]


@pytest.mark.asyncio
async def test_restricted_token_cannot_issue_tokens(client):
    restricted_token = create_jwt_token(
        "scoped-user",
        scopes=[{"path": "/restricted", "permissions": ["read"]}],
        abilities=["issue-tokens"],
    )

    response = await client.post(
        "/v1/auth/token",
        headers={"Authorization": f"Bearer {restricted_token}"},
        json={
            "subject": "other",
            "scopes": [{"path": "/restricted", "permissions": ["read"]}],
        },
    )

    assert response.status == 403
    data = response.json
    assert data["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_cannot_grant_issue_token_ability_without_permission(client):
    issuer_token = await _issue_base_token(client)

    response = await client.post(
        "/v1/auth/token",
        headers={"Authorization": f"Bearer {issuer_token}"},
        json={
            "subject": "another-user",
            "scopes": [{"path": "/", "permissions": ["read"]}],
            "abilities": ["issue-tokens"],
        },
    )

    assert response.status == 403
    data = response.json
    assert data["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_scoped_token_can_read_within_scope(client):
    scoped_token = create_jwt_token(
        "scoped-user",
        scopes=[{"path": "/allowed", "permissions": ["read", "write"]}],
    )

    fake_db = SimpleNamespace(
        get_all_sessions=AsyncMock(return_value=[]),
    )

    fake_nucleus = AsyncMock()
    fake_nucleus.list_directory.return_value = {
        "status": "OK",
        "entries": [
            {"path": "/allowed/report.txt", "path_type": "asset", "size": 128, "modified_time": datetime.utcnow().isoformat()},
        ],
    }

    with (
        patch("app.routes.files.get_database", new_callable=AsyncMock) as mock_db,
        patch("app.routes.files.ensure_authenticated", new_callable=AsyncMock) as mock_auth,
    ):
        mock_db.return_value = fake_db
        mock_auth.return_value = fake_nucleus

        response = await client.get(
            "/v1/files/list",
            params={"path": "/allowed"},
            headers={"Authorization": f"Bearer {scoped_token}"},
        )

    assert response.status == 200
    data = response.json
    assert data["path"] == "/allowed"
    assert data["entries"][0]["name"] == "report.txt"


@pytest.mark.asyncio
async def test_scoped_token_denied_outside_scope(client):
    scoped_token = create_jwt_token(
        "scoped-user",
        scopes=[{"path": "/allowed", "permissions": ["read"]}],
    )

    with patch("app.routes.files.ensure_authenticated", new_callable=AsyncMock) as mock_auth:
        response = await client.get(
            "/v1/files/list",
            params={"path": "/restricted"},
            headers={"Authorization": f"Bearer {scoped_token}"},
        )

    assert response.status == 403
    data = response.json
    assert "Access denied" in data["message"]
    mock_auth.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_virtual_upload_is_transparent(client, test_env, tmp_path):
    staging_root = tmp_path / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)

    virtual_session_dir = staging_root / "session123"
    virtual_session_dir.mkdir(parents=True, exist_ok=True)
    (virtual_session_dir / "part_0").write_bytes(b"dummy")

    scoped_token = create_jwt_token(
        "admin",
        scopes=[{"path": "/", "permissions": ["read", "write"]}],
    )

    session = SimpleNamespace(
        id="session123",
        state=UploadState.PENDING,
        path_dir="/library",
        filename="draft.txt",
        size=10,
        created_at=datetime.utcnow(),
        meta={"sync": {}},
        user_id="admin",
    )

    fake_db = SimpleNamespace(
        get_all_sessions=AsyncMock(return_value=[session]),
        update_session=AsyncMock(return_value=None),
    )

    with (
        patch.object(settings, "staging_dir", str(staging_root)),
        patch("app.routes.files.get_database", new_callable=AsyncMock) as mock_db,
        patch("app.routes.files.get_upload_manager", new_callable=AsyncMock) as mock_manager,
    ):
        mock_db.return_value = fake_db
        mock_manager.return_value = AsyncMock()

        response = await client.post(
            "/v1/files/delete",
            headers={"Authorization": f"Bearer {scoped_token}"},
            json={"path": "/library/draft.txt"},
        )

    assert response.status == 200
    data = response.json
    assert data["was_virtual"] is True
    assert data["session_id"] == "session123"
    fake_db.update_session.assert_awaited_with(
        "session123",
        state=UploadState.EXPIRED,
        error="Upload canceled by user",
    )


@pytest.mark.asyncio
async def test_delete_real_file_calls_nucleus(client):
    scoped_token = create_jwt_token(
        "admin",
        scopes=[{"path": "/", "permissions": ["read", "write"]}],
    )

    fake_db = SimpleNamespace(
        get_all_sessions=AsyncMock(return_value=[]),
    )

    fake_nucleus = AsyncMock()
    fake_nucleus.delete_path.return_value = {"status": "OK"}

    with (
        patch("app.routes.files.get_database", new_callable=AsyncMock) as mock_db,
        patch("app.routes.files.ensure_authenticated", new_callable=AsyncMock) as mock_auth,
    ):

        mock_db.return_value = fake_db
        mock_auth.return_value = fake_nucleus

        response = await client.post(
            "/v1/files/delete",
            headers={"Authorization": f"Bearer {scoped_token}"},
            json={"path": "/docs/report.pdf"},
        )

    assert response.status == 200
    data = response.json
    assert data["message"] == "File deleted successfully"
    fake_nucleus.delete_path.assert_awaited_with("/docs/report.pdf")
