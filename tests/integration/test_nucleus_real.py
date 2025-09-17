"""
Real integration test for Nucleus file operations.

This test connects to the actual Nucleus server and performs file operations.
It will automatically run if the .env.testing file contains valid credentials.
"""

import os
import uuid
import pytest
import asyncio
from datetime import datetime

from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient
from app.server import create_app
from app.config import settings


@pytest.mark.asyncio
async def test_real_nucleus_file_operations():
    """Direct test of file operations against real Nucleus server."""
    
    # Debug: Print current settings
    print(f"\nDEBUG: Settings loaded:")
    print(f"  run_nucleus_it = {settings.run_nucleus_it!r}")
    print(f"  nucleus_host = {settings.nucleus_host!r}")
    print(f"  nucleus_username = {settings.nucleus_username!r}")
    print(f"  Password present = {bool(settings.nucleus_password)}")
    
    # Check if we should run
    if settings.run_nucleus_it != "1":
        print(f"SKIPPING: run_nucleus_it is {settings.run_nucleus_it!r}, not '1'")
        pytest.skip("Set RUN_NUCLEUS_IT=1 in .env.testing to enable this test")
    
    if not all([settings.nucleus_host, settings.nucleus_username, settings.nucleus_password]):
        pytest.skip("Missing Nucleus credentials in .env.testing")
    
    print(f"\n{'='*60}")
    print(f"NUCLEUS INTEGRATION TEST")
    print(f"Host: {settings.nucleus_host}")
    print(f"User: {settings.nucleus_username}")
    print(f"Time: {datetime.now()}")
    print(f"{'='*60}\n")
    
    # Create test app
    Sanic.test_mode = True
    app = create_app()
    app.config.TESTING = True
    
    # Create test client
    client = SanicASGITestClient(app)
    
    try:
        # Step 1: Login to get JWT token
        print("[1] Authenticating with proxy...")
        _, login_response = await client.post(
            "/v1/auth/login",
            json={"username": settings.nucleus_username, "password": settings.nucleus_password}
        )
        assert login_response.status == 200, f"Login failed: {login_response.status} {login_response.text}"
        
        token = login_response.json["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"    ✓ Got JWT token")
        
        # Generate unique test directory
        test_id = uuid.uuid4().hex[:8]
        test_root = f"/Projects/_integration_test_{test_id}"
        test_file = "test.txt"
        test_content = b"Hello from integration test!\n"
        
        print(f"\n[2] Creating test directory: {test_root}")
        _, mkdir_response = await client.post(
            "/v1/files/mkdir",
            json={"path": test_root},
            headers=headers
        )
        assert mkdir_response.status == 200, f"Mkdir failed: {mkdir_response.status} {mkdir_response.text}"
        print(f"    ✓ Directory created")
        
        # Step 3: List directory (should be empty)
        print(f"\n[3] Listing directory...")
        _, list_response = await client.get(
            "/v1/files/list",
            params={"path": test_root},
            headers=headers
        )
        assert list_response.status == 200, f"List failed: {list_response.status} {list_response.text}"
        entries = list_response.json.get("entries", [])
        assert entries == [], f"Expected empty dir, got: {entries}"
        print(f"    ✓ Directory is empty")
        
        # Step 4: Upload a file
        print(f"\n[4] Uploading file: {test_file}")
        files = {"file": (test_file, test_content, "text/plain")}
        data = {"path": test_root}
        
        _, upload_response = await client.post(
            "/v1/files/upload",
            files=files,
            data=data,
            headers=headers
        )
        assert upload_response.status == 200, f"Upload failed: {upload_response.status} {upload_response.text}"
        print(f"    ✓ File uploaded")
        
        # Step 5: Verify file exists
        print(f"\n[5] Verifying file exists...")
        _, list_response2 = await client.get(
            "/v1/files/list",
            params={"path": test_root},
            headers=headers
        )
        assert list_response2.status == 200
        entries = [e["name"] for e in list_response2.json.get("entries", [])]
        assert test_file in entries, f"File not found. Entries: {entries}"
        print(f"    ✓ File found in directory")
        
        # Step 6: Get file info
        file_path = f"{test_root}/{test_file}"
        print(f"\n[6] Getting file info: {file_path}")
        _, stat_response = await client.get(
            "/v1/files/stat",
            params={"path": file_path},
            headers=headers
        )
        assert stat_response.status == 200, f"Stat failed: {stat_response.status} {stat_response.text}"
        file_info = stat_response.json
        assert file_info.get("type") in ["file", "regular"], f"Wrong type: {file_info}"
        print(f"    ✓ File info retrieved")
        
        # Step 7: Create subdirectory and move file
        subdir = f"{test_root}/subdir"
        new_path = f"{subdir}/renamed_{test_file}"
        
        print(f"\n[7] Creating subdirectory: {subdir}")
        _, mkdir2_response = await client.post(
            "/v1/files/mkdir",
            json={"path": subdir},
            headers=headers
        )
        assert mkdir2_response.status == 200
        print(f"    ✓ Subdirectory created")
        
        print(f"\n[8] Moving file: {file_path} -> {new_path}")
        _, move_response = await client.post(
            "/v1/files/rename",
            json={"src": file_path, "dst": new_path},
            headers=headers
        )
        assert move_response.status == 200, f"Move failed: {move_response.status} {move_response.text}"
        print(f"    ✓ File moved")
        
        # Step 9: Verify file in new location
        print(f"\n[9] Verifying file in new location...")
        _, list_response3 = await client.get(
            "/v1/files/list",
            params={"path": subdir},
            headers=headers
        )
        assert list_response3.status == 200
        entries = [e["name"] for e in list_response3.json.get("entries", [])]
        assert f"renamed_{test_file}" in entries, f"Renamed file not found. Entries: {entries}"
        print(f"    ✓ File found in subdirectory")
        
        # Step 10: Delete the file
        print(f"\n[10] Deleting file: {new_path}")
        _, delete_response = await client.post(
            "/v1/files/delete",
            json={"path": new_path},
            headers=headers
        )
        assert delete_response.status == 200, f"Delete failed: {delete_response.status} {delete_response.text}"
        print(f"    ✓ File deleted")
        
        # Step 11: Clean up directories
        print(f"\n[11] Cleaning up test directories...")
        
        # Delete subdirectory
        _, delete_subdir_response = await client.post(
            "/v1/files/delete",
            json={"path": subdir},
            headers=headers
        )
        # Best effort - might fail if not empty
        
        # Delete root directory
        _, delete_root_response = await client.post(
            "/v1/files/delete",
            json={"path": test_root},
            headers=headers
        )
        print(f"    ✓ Cleanup complete")
        
        print(f"\n{'='*60}")
        print(f"✅ ALL TESTS PASSED - Nucleus integration working!")
        print(f"{'='*60}\n")
        
    finally:
        # Reset Sanic
        Sanic._app_registry.clear()
        Sanic.test_mode = False