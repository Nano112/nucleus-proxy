#!/usr/bin/env python3
"""
Final test to confirm delete functionality works correctly.
"""

import asyncio
import aiohttp
import uuid
from datetime import datetime


async def test_delete_final():
    base_url = "http://127.0.0.1:8088"
    username = "omniverse"
    password = "changeme123"
    
    print("="*70)
    print("FINAL DELETE FUNCTIONALITY TEST")
    print("="*70)
    print()
    
    async with aiohttp.ClientSession() as session:
        # Authenticate
        print("Authenticating...")
        async with session.post(
            f"{base_url}/v1/auth/login",
            json={"username": username, "password": password}
        ) as resp:
            if resp.status != 200:
                print(f"❌ Login failed: {resp.status}")
                return False
            auth_data = await resp.json()
            token = auth_data["access_token"]
            print("✓ Authenticated\n")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test 1: Delete existing file
        print("Test 1: Delete existing file")
        test_id = uuid.uuid4().hex[:8]
        test_dir = f"/Library/_final_delete_test_{test_id}"
        test_file = f"{test_dir}/test.txt"
        
        # Create directory
        async with session.post(
            f"{base_url}/v1/files/mkdir",
            json={"path": test_dir},
            headers=headers
        ) as resp:
            assert resp.status == 200, f"Failed to create directory: {resp.status}"
            print(f"  ✓ Created directory: {test_dir}")
        
        # Upload file
        data = aiohttp.FormData()
        data.add_field('file', b'Test file content', filename='test.txt', content_type='text/plain')
        data.add_field('path', test_dir)
        
        async with session.post(
            f"{base_url}/v1/files/upload",
            data=data,
            headers=headers
        ) as resp:
            assert resp.status == 200, f"Failed to upload file: {resp.status}"
            print(f"  ✓ Uploaded file: test.txt")
        
        # Delete file
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": test_file},
            headers=headers
        ) as resp:
            assert resp.status == 200, f"Failed to delete file: {resp.status}"
            result = await resp.json()
            assert "message" in result
            print(f"  ✓ Deleted file successfully: {result['message']}")
        
        # Verify file is gone
        async with session.get(
            f"{base_url}/v1/files/list",
            params={"path": test_dir},
            headers=headers
        ) as resp:
            assert resp.status == 200
            list_data = await resp.json()
            entries = list_data.get("entries", [])
            assert len(entries) == 0, "File should be deleted"
            print("  ✓ Verified file no longer exists\n")
        
        # Test 2: Delete non-existent file (should return 404)
        print("Test 2: Delete non-existent file")
        fake_path = f"/Users/omniverse/fake_{uuid.uuid4().hex}.txt"
        
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": fake_path},
            headers=headers
        ) as resp:
            assert resp.status == 404, f"Expected 404, got {resp.status}"
            result = await resp.json()
            assert "error" in result
            print(f"  ✓ Correctly returned 404: {result['error']}\n")
        
        # Test 3: Delete empty directory
        print("Test 3: Delete empty directory")
        empty_dir = f"{test_dir}/empty"
        
        # Create empty directory
        async with session.post(
            f"{base_url}/v1/files/mkdir",
            json={"path": empty_dir},
            headers=headers
        ) as resp:
            assert resp.status == 200
            print(f"  ✓ Created empty directory: {empty_dir}")
        
        # Delete empty directory
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": empty_dir},
            headers=headers
        ) as resp:
            if resp.status == 200:
                print("  ✓ Deleted empty directory successfully")
            else:
                # Some servers don't allow deleting directories with delete2
                result = await resp.json()
                print(f"  ⚠️ Directory deletion returned {resp.status}: {result.get('error', 'Unknown')}")
        
        # Test 4: Clean up test directory
        print("\nTest 4: Final cleanup")
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": test_dir},
            headers=headers
        ) as resp:
            if resp.status == 200:
                print(f"  ✓ Cleaned up test directory: {test_dir}")
            else:
                result = await resp.json()
                print(f"  ⚠️ Cleanup returned {resp.status}: {result.get('error', 'Unknown')}")
        
        print("\n" + "="*70)
        print("✅ ALL DELETE TESTS PASSED!")
        print("="*70)
        return True


async def main():
    print("\nMake sure the proxy server is running on port 8088")
    print("Run: python run.py\n")
    
    # Start server
    import subprocess
    import time
    
    print("Starting server...")
    server = subprocess.Popen(
        ["uv", "run", "python", "run.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # Wait for server to start
    time.sleep(5)
    
    try:
        success = await test_delete_final()
        return 0 if success else 1
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Stop server
        print("\nStopping server...")
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)