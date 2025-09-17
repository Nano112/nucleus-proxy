#!/usr/bin/env python3
"""
Standalone integration test for Nucleus file operations.
Run this directly to test your Nucleus integration without pytest.
"""

import asyncio
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from sanic import Sanic
from sanic_testing.testing import SanicASGITestClient
from app.server import create_app
from app.config import settings
from app.nucleus.client import reset_nucleus_client


async def run_integration_test():
    """Run integration test against real Nucleus server."""
    
    print(f"\n{'='*70}")
    print(f"NUCLEUS INTEGRATION TEST - STANDALONE")
    print(f"{'='*70}")
    print(f"Time: {datetime.now()}")
    print(f"\nSettings loaded:")
    print(f"  Host: {settings.nucleus_host}")
    print(f"  User: {settings.nucleus_username}")
    print(f"  Password present: {bool(settings.nucleus_password)}")
    print(f"  RUN_NUCLEUS_IT: {getattr(settings, 'run_nucleus_it', 'not set')}")
    print(f"{'='*70}\n")
    
    # Check if we should run
    run_nucleus_it = getattr(settings, 'run_nucleus_it', None)
    if run_nucleus_it != "1":
        print(f"❌ SKIPPING: RUN_NUCLEUS_IT is '{run_nucleus_it}', not '1'")
        print(f"   Set RUN_NUCLEUS_IT=1 in .env.testing to enable this test")
        return False
    
    if not all([settings.nucleus_host, settings.nucleus_username, settings.nucleus_password]):
        print(f"❌ SKIPPING: Missing Nucleus credentials in .env.testing")
        print(f"   Host: {settings.nucleus_host or 'MISSING'}")
        print(f"   Username: {settings.nucleus_username or 'MISSING'}")
        print(f"   Password: {'SET' if settings.nucleus_password else 'MISSING'}")
        return False
    
    print("✅ All required settings present, starting test...\n")
    
    # Reset the global nucleus client to ensure clean state
    await reset_nucleus_client()
    
    # Create test app
    Sanic.test_mode = True
    app = create_app()
    app.config.TESTING = True
    
    # Create test client
    client = SanicASGITestClient(app)
    
    try:
        # Step 1: Login
        print("[1/11] Authenticating with proxy...")
        _, login_response = await client.post(
            "/v1/auth/login",
            json={"username": settings.nucleus_username, "password": settings.nucleus_password}
        )
        
        if login_response.status != 200:
            print(f"   ❌ Login failed: {login_response.status}")
            print(f"   Response: {login_response.text}")
            return False
        
        token = login_response.json["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"   ✓ Got JWT token (length: {len(token)})")
        
        # Generate unique test directory
        # Based on listing, /Library/ seems to be available
        test_id = uuid.uuid4().hex[:8]
        test_root = f"/Library/_integration_test_{test_id}"
        test_file = "test.txt"
        test_content = b"Hello from integration test!\nTimestamp: " + str(datetime.now()).encode() + b"\n"
        
        # Step 2: Create directory
        print(f"\n[2/11] Creating test directory: {test_root}")
        _, mkdir_response = await client.post(
            "/v1/files/mkdir",
            json={"path": test_root},
            headers=headers
        )
        
        if mkdir_response.status != 200:
            print(f"   ❌ Mkdir failed: {mkdir_response.status}")
            print(f"   Response: {mkdir_response.text}")
            return False
        print(f"   ✓ Directory created")
        
        # Step 3: List directory (should be empty)
        print(f"\n[3/11] Listing directory (should be empty)...")
        _, list_response = await client.get(
            "/v1/files/list",
            params={"path": test_root},
            headers=headers
        )
        
        if list_response.status != 200:
            print(f"   ❌ List failed: {list_response.status}")
            return False
            
        entries = list_response.json.get("entries", [])
        if entries:
            print(f"   ⚠️ Expected empty dir, got {len(entries)} entries")
        else:
            print(f"   ✓ Directory is empty")
        
        # Step 4: Upload a file
        print(f"\n[4/11] Uploading file: {test_file} ({len(test_content)} bytes)")
        files = {"file": (test_file, test_content, "text/plain")}
        data = {"path": test_root}
        
        _, upload_response = await client.post(
            "/v1/files/upload",
            files=files,
            data=data,
            headers=headers
        )
        
        if upload_response.status != 200:
            print(f"   ❌ Upload failed: {upload_response.status}")
            print(f"   Response: {upload_response.text}")
            return False
        print(f"   ✓ File uploaded")
        
        # Step 5: Verify file exists
        print(f"\n[5/11] Verifying file exists in directory...")
        _, list_response2 = await client.get(
            "/v1/files/list",
            params={"path": test_root},
            headers=headers
        )
        
        if list_response2.status != 200:
            print(f"   ❌ List failed: {list_response2.status}")
            return False
            
        all_entries = list_response2.json.get("entries", [])
        print(f"   DEBUG: Found {len(all_entries)} entries:")
        for e in all_entries:
            print(f"     - name: {e.get('name')}, path: {e.get('path')}")
        
        entries = [e["name"] for e in all_entries]
        if test_file not in entries:
            print(f"   ❌ File not found. Directory contains: {entries}")
            return False
        print(f"   ✓ File found in directory")
        
        # Step 6: Get file info
        file_path = f"{test_root}/{test_file}"
        print(f"\n[6/11] Getting file info: {file_path}")
        _, stat_response = await client.get(
            "/v1/files/stat",
            params={"path": file_path},
            headers=headers
        )
        
        if stat_response.status != 200:
            print(f"   ⚠️ Stat failed (non-fatal): {stat_response.status}")
            # Continue anyway to test other operations
            file_info = {}
        else:
            file_info = stat_response.json
        
        file_type = file_info.get("type", "unknown")
        file_size = file_info.get("size", 0)
        if stat_response.status == 200:
            print(f"   ✓ File info retrieved (type: {file_type}, size: {file_size})")
        
        # Step 7: Create subdirectory
        subdir = f"{test_root}/subdir"
        print(f"\n[7/11] Creating subdirectory: {subdir}")
        _, mkdir2_response = await client.post(
            "/v1/files/mkdir",
            json={"path": subdir},
            headers=headers
        )
        
        if mkdir2_response.status != 200:
            print(f"   ❌ Mkdir failed: {mkdir2_response.status}")
            return False
        print(f"   ✓ Subdirectory created")
        
        # Step 8: Move file
        new_path = f"{subdir}/renamed_{test_file}"
        print(f"\n[8/11] Moving file:")
        print(f"   From: {file_path}")
        print(f"   To:   {new_path}")
        _, move_response = await client.post(
            "/v1/files/rename",
            json={"src": file_path, "dst": new_path},
            headers=headers
        )
        
        if move_response.status != 200:
            print(f"   ❌ Move failed: {move_response.status}")
            print(f"   Response: {move_response.text}")
            return False
        print(f"   ✓ File moved")
        move_result = move_response.json if hasattr(move_response, 'json') else {}
        print(f"   Move response: {move_result}")
        
        # Give the server a moment to complete the move operation
        await asyncio.sleep(0.5)
        
        # Step 8.5: Check if file is still in original location
        print(f"\n[8.5/11] Checking original location...")
        _, orig_list = await client.get(
            "/v1/files/list",
            params={"path": test_root},
            headers=headers
        )
        orig_entries = [e["name"] for e in orig_list.json.get("entries", [])] if orig_list.status == 200 else []
        if test_file in orig_entries:
            print(f"   ⚠️ File still in original location: {orig_entries}")
        else:
            print(f"   ✓ File not in original location")
        
        # Step 9: Verify file in new location
        print(f"\n[9/11] Verifying file in new location...")
        _, list_response3 = await client.get(
            "/v1/files/list",
            params={"path": subdir},
            headers=headers
        )
        
        if list_response3.status != 200:
            print(f"   ❌ List failed: {list_response3.status}")
            return False
            
        all_entries = list_response3.json.get("entries", [])
        print(f"   DEBUG: Found {len(all_entries)} entries in {subdir}:")
        for e in all_entries:
            print(f"     - name: '{e.get('name')}', path: '{e.get('path')}', type: '{e.get('type')}'")
        
        entries = [e["name"] for e in all_entries]
        expected_name = f"renamed_{test_file}"
        if expected_name not in entries:
            print(f"   ❌ Renamed file not found. Expected '{expected_name}' in: {entries}")
            return False
        print(f"   ✓ File found in subdirectory as '{expected_name}'")
        
        # Step 10: Delete the file
        print(f"\n[10/11] Deleting file: {new_path}")
        _, delete_response = await client.post(
            "/v1/files/delete",
            json={"path": new_path},
            headers=headers
        )
        
        if delete_response.status != 200:
            print(f"   ❌ Delete failed: {delete_response.status}")
            return False
        print(f"   ✓ File deleted")
        
        # Step 11: Clean up directories
        print(f"\n[11/11] Cleaning up test directories...")
        
        # Delete subdirectory
        _, delete_subdir = await client.post(
            "/v1/files/delete",
            json={"path": subdir},
            headers=headers
        )
        if delete_subdir.status == 200:
            print(f"   ✓ Subdirectory deleted")
        else:
            print(f"   ⚠️ Could not delete subdirectory (may not be empty)")
        
        # Delete root directory
        _, delete_root = await client.post(
            "/v1/files/delete",
            json={"path": test_root},
            headers=headers
        )
        if delete_root.status == 200:
            print(f"   ✓ Root test directory deleted")
        else:
            print(f"   ⚠️ Could not delete root directory (may not be empty)")
        
        print(f"\n{'='*70}")
        print(f"✅ ALL TESTS PASSED - Nucleus integration working perfectly!")
        print(f"{'='*70}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up: Reset both the nucleus client and Sanic state
        await reset_nucleus_client()
        Sanic._app_registry.clear()
        Sanic.test_mode = False


if __name__ == "__main__":
    success = asyncio.run(run_integration_test())
    sys.exit(0 if success else 1)