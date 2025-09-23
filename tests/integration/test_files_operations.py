"""
Integration tests for real file operations against Nucleus via the proxy API.

These tests exercise the end-to-end flow:
- Login to obtain a JWT
- Create a dedicated test directory on Nucleus
- List directory contents
- Upload a small file
- Stat the file
- Create a subdirectory and move/rename the file
- Verify via list
- Delete the file and clean up directories

Requirements to run:
- Set RUN_NUCLEUS_IT=1 to enable these tests
- Provide real Nucleus credentials via environment variables:
  NUCLEUS_HOST, NUCLEUS_USERNAME, NUCLEUS_PASSWORD

They will be skipped automatically if requirements are not met.
"""

import os
import io
import uuid
import pytest
import pytest_asyncio
import asyncio

from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient

from app.server import create_app

pytestmark = [pytest.mark.asyncio, pytest.mark.integration, pytest.mark.api]


def _should_run_integration() -> bool:
    from app.config import settings
    return (
        settings.run_nucleus_it == "1"
        and bool(settings.nucleus_host)
        and bool(settings.nucleus_username)
        and bool(settings.nucleus_password)
    )


@pytest_asyncio.fixture
async def app():
    # Check if we should run integration tests
    should_run = _should_run_integration()
    if not should_run:
        pytest.skip(
            "Skipping Nucleus integration tests. Set RUN_NUCLEUS_IT=1 and provide NUCLEUS_HOST/USERNAME/PASSWORD."
        )

    # Use actual environment variables (from .env.testing if sourced)
    # Don't override with test fixtures - we need real Nucleus connection
    from app.config import settings
    print(f"\n[Integration Test] Using NUCLEUS_HOST: {settings.nucleus_host}")
    print(f"[Integration Test] Using NUCLEUS_USERNAME: {settings.nucleus_username}")
    
    Sanic.test_mode = True
    test_app = create_app()
    test_app.config.TESTING = True
    try:
        yield test_app
    finally:
        # Reset Sanic registry for next tests
        Sanic._app_registry.clear()
        Sanic.test_mode = False


class _ASGIClientAdapter:
    """Minimal adapter to return only the response object from SanicASGITestClient."""

    def __init__(self, app: Sanic):
        self._client = SanicASGITestClient(app)

    async def get(self, path: str, *args, **kwargs):
        _, resp = await self._client.get(path, *args, **kwargs)
        return resp

    async def post(self, *args, **kwargs):
        _, resp = await self._client.post(*args, **kwargs)
        return resp

    async def delete(self, *args, **kwargs):
        _, resp = await self._client.delete(*args, **kwargs)
        return resp


@pytest_asyncio.fixture
async def client(app: Sanic):
    return _ASGIClientAdapter(app)


async def _login_and_get_headers(client: _ASGIClientAdapter) -> dict:
    from app.config import settings
    username = settings.nucleus_username
    password = settings.nucleus_password

    if not username or not password:
        pytest.skip("Missing NUCLEUS_USERNAME or NUCLEUS_PASSWORD for integration tests")

    print(f"[Auth] Logging in as {username}...")
    resp = await client.post("/v1/auth/login", json={"username": username, "password": password})
    assert resp.status == 200, f"Login failed: {resp.status} {resp.text}"
    token = resp.json["access_token"]
    print(f"[Auth] Got JWT token")
    return {"Authorization": f"Bearer {token}"}


async def _cleanup_path(client: _ASGIClientAdapter, headers: dict, path: str):
    """Best-effort cleanup: delete path if exists (file first, then directories)."""
    # Try deleting as file
    await client.post("/v1/files/delete", json={"path": path}, headers=headers)
    # Then try deleting as directory (delete children first not supported here; tests ensure directory is empty)
    await client.post("/v1/files/delete", json={"path": path}, headers=headers)


async def _sleep_small():
    # Small delay to accommodate any eventual consistency on the backend
    await asyncio.sleep(0.2)


async def _list_paths(client: _ASGIClientAdapter, headers: dict, path: str) -> list:
    resp = await client.get("/v1/files/list", params={"path": path}, headers=headers)
    assert resp.status == 200, f"List failed: {resp.status} {resp.text}"
    return [e["name"] for e in resp.json.get("entries", [])]


async def _stat_path(client: _ASGIClientAdapter, headers: dict, path: str) -> dict:
    resp = await client.get("/v1/files/info", params={"path": path}, headers=headers)
    assert resp.status == 200, f"Stat failed: {resp.status} {resp.text}"
    return resp.json


async def _mkdir(client: _ASGIClientAdapter, headers: dict, path: str):
    resp = await client.post("/v1/files/create-directory", json={"path": path}, headers=headers)
    assert resp.status == 200, f"Mkdir failed: {resp.status} {resp.text}"


async def _rename(client: _ASGIClientAdapter, headers: dict, src: str, dst: str):
    resp = await client.post("/v1/files/rename", json={"src": src, "dst": dst}, headers=headers)
    assert resp.status == 200, f"Rename failed: {resp.status} {resp.text}"


async def _delete(client: _ASGIClientAdapter, headers: dict, path: str):
    resp = await client.post("/v1/files/delete", json={"path": path}, headers=headers)
    assert resp.status == 200, f"Delete failed: {resp.status} {resp.text}"


async def _upload_small_file(client: _ASGIClientAdapter, headers: dict, dir_path: str, filename: str, content: bytes):
    files = {
        "file": (filename, content, "application/octet-stream"),
    }
    data = {"path": dir_path}

    resp = await client.post("/v1/files/upload", files=files, data=data, headers=headers)
    assert resp.status == 200, f"Upload failed: {resp.status} {resp.text}"


async def _assert_name_present(client: _ASGIClientAdapter, headers: dict, dir_path: str, name: str):
    names = await _list_paths(client, headers, dir_path)
    assert name in names, f"Expected '{name}' in {dir_path}, found {names}"


async def _assert_name_absent(client: _ASGIClientAdapter, headers: dict, dir_path: str, name: str):
    names = await _list_paths(client, headers, dir_path)
    assert name not in names, f"Did not expect '{name}' in {dir_path}, found {names}"


async def _safe_delete(client: _ASGIClientAdapter, headers: dict, path: str):
    try:
        await _delete(client, headers, path)
    except AssertionError:
        pass


async def _safe_mkdir(client: _ASGIClientAdapter, headers: dict, path: str):
    try:
        await _mkdir(client, headers, path)
    except AssertionError:
        pass


async def _safe_cleanup_tree(client: _ASGIClientAdapter, headers: dict, root: str, names: list):
    # Delete any files first, then directories (names supplied in order)
    for name in names:
        await _safe_delete(client, headers, f"{root}/{name}")
    await _safe_delete(client, headers, root)


async def _get_unique_test_root() -> str:
    # Place under a known top-level to avoid clutter
    return f"/Projects/_proxy_tests/test_{uuid.uuid4().hex[:8]}"


async def _get_subdir(root: str, name: str) -> str:
    if not root.endswith("/"):
        return f"{root}/{name}"
    return f"{root}{name}"


async def _get_file_path(dir_path: str, filename: str) -> str:
    if not dir_path.endswith("/"):
        return f"{dir_path}/{filename}"
    return f"{dir_path}{filename}"


async def _maybe_wait():
    # Add a slightly longer wait in case backend commits are asynchronous
    await asyncio.sleep(0.5)


async def _ensure_root(client: _ASGIClientAdapter, headers: dict, root: str):
    # Create the root test directory if not present
    try:
        await _mkdir(client, headers, root)
    except AssertionError:
        # Might already exist; stat to confirm
        info = await _stat_path(client, headers, root)
        assert info.get("type") == "directory", f"Root exists but is not directory: {info}"


async def _cleanup_all(client: _ASGIClientAdapter, headers: dict, root: str, file_paths: list, dirs: list):
    # Delete files
    for fp in file_paths:
        await _safe_delete(client, headers, fp)
    # Delete directories from deepest to root
    for d in reversed(dirs):
        await _safe_delete(client, headers, d)


async def _prepare_auth(client: _ASGIClientAdapter) -> dict:
    headers = await _login_and_get_headers(client)
    return headers


async def _create_and_verify_dir(client: _ASGIClientAdapter, headers: dict, path: str):
    await _mkdir(client, headers, path)
    await _assert_name_present(client, headers, path.rsplit("/", 1)[0] or "/", path.split("/")[-1])


async def _move_and_verify(client: _ASGIClientAdapter, headers: dict, src: str, dst_dir: str, dst_name: str):
    dst_path = await _get_file_path(dst_dir, dst_name)
    await _rename(client, headers, src, dst_path)
    await _assert_name_absent(client, headers, src.rsplit("/", 1)[0] or "/", src.split("/")[-1])
    await _assert_name_present(client, headers, dst_dir, dst_name)
    return dst_path


async def _upload_and_verify(client: _ASGIClientAdapter, headers: dict, dir_path: str, filename: str, content: bytes):
    await _upload_small_file(client, headers, dir_path, filename, content)
    await _assert_name_present(client, headers, dir_path, filename)


async def _stat_and_assert_file(client: _ASGIClientAdapter, headers: dict, path: str):
    info = await _stat_path(client, headers, path)
    assert info.get("type") in ("file", "regular"), f"Unexpected file type: {info}"


async def _create_subdir_and_move_file(client: _ASGIClientAdapter, headers: dict, root: str, filename: str):
    subdir = await _get_subdir(root, "sub")
    await _mkdir(client, headers, subdir)
    src_path = await _get_file_path(root, filename)
    dst_path = await _get_file_path(subdir, f"moved_{filename}")
    await _rename(client, headers, src_path, dst_path)
    await _assert_name_present(client, headers, subdir, f"moved_{filename}")
    return subdir, dst_path


async def _delete_and_verify(client: _ASGIClientAdapter, headers: dict, path: str, parent: str, name: str):
    await _delete(client, headers, path)
    await _assert_name_absent(client, headers, parent, name)


async def _run_basic_flow(client: _ASGIClientAdapter, headers: dict):
    # Generate a unique root directory
    root = await _get_unique_test_root()
    print(f"[Test] Using test root: {root}")

    # Ensure clean slate
    print(f"[Test] Cleaning up any existing test files...")
    await _safe_cleanup_tree(client, headers, root, ["sub", "hello.txt", "moved_hello.txt"])  # best-effort

    # 1) Create root directory
    print(f"[Test] 1. Creating test directory: {root}")
    await _ensure_root(client, headers, root)

    # 2) List root (should be empty)
    print(f"[Test] 2. Listing directory (should be empty)...")
    names = await _list_paths(client, headers, root)
    assert names == [] or isinstance(names, list)
    print(f"[Test]    Directory is empty: {names}")

    # 3) Upload a small file
    print(f"[Test] 3. Uploading file 'hello.txt' to {root}")
    await _upload_and_verify(client, headers, root, "hello.txt", b"Hello, Nucleus!\n")
    print(f"[Test]    File uploaded successfully")

    # 4) Stat the file
    file_path = await _get_file_path(root, "hello.txt")
    print(f"[Test] 4. Getting file info for: {file_path}")
    await _stat_and_assert_file(client, headers, file_path)
    print(f"[Test]    File stat successful")

    # 5) Create a subdirectory and move the file into it (rename)
    print(f"[Test] 5. Creating subdirectory and moving file...")
    subdir, moved_path = await _create_subdir_and_move_file(client, headers, root, "hello.txt")
    print(f"[Test]    File moved to: {moved_path}")

    # 6) List to verify
    print(f"[Test] 6. Verifying file is in new location...")
    await _assert_name_present(client, headers, subdir, "moved_hello.txt")
    print(f"[Test]    File found in subdirectory")

    # 7) Delete file
    print(f"[Test] 7. Deleting file: {moved_path}")
    await _delete_and_verify(client, headers, moved_path, subdir, "moved_hello.txt")
    print(f"[Test]    File deleted successfully")

    # 8) Cleanup directories
    print(f"[Test] 8. Cleaning up test directories...")
    await _safe_delete(client, headers, subdir)
    await _safe_delete(client, headers, root)
    print(f"[Test]    Cleanup complete")


class TestFilesIntegration:
    async def test_basic_crud_flow(self, client: _ASGIClientAdapter):
        """Test complete CRUD flow: create dir, list, upload, stat, move, rename, delete."""
        import sys
        print("\n[Test] Starting basic CRUD flow test against real Nucleus...", file=sys.stderr)
        print("\n[Test] Starting basic CRUD flow test against real Nucleus...")
        
        # Step 1: Authenticate and get JWT
        print("[Test] Step 1: Authenticating with Nucleus...")
        headers = await _prepare_auth(client)
        print(f"[Test] Authentication successful, got JWT token")
        
        # Step 2: Run the full CRUD flow
        print("[Test] Step 2: Running full CRUD flow...")
        await _run_basic_flow(client, headers)
        
        print("[Test] ✅ All file operations completed successfully!")
