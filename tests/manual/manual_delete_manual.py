#!/usr/bin/env python3
"""
Manual test for delete operations.
"""

import asyncio
import aiohttp
import tempfile
import uuid
from datetime import datetime


async def test_delete():
    base_url = "http://127.0.0.1:8088"
    username = "omniverse"
    password = "changeme123"
    
    async with aiohttp.ClientSession() as session:
        # Step 1: Login
        print("1. Authenticating...")
        async with session.post(
            f"{base_url}/v1/auth/login",
            json={"username": username, "password": password}
        ) as resp:
            if resp.status != 200:
                print(f"   ❌ Login failed: {resp.status}")
                text = await resp.text()
                print(f"   Response: {text}")
                return
            auth_data = await resp.json()
            token = auth_data["access_token"]
            print(f"   ✓ Authenticated")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 2: Create test directory
        test_id = uuid.uuid4().hex[:8]
        test_dir = f"/Library/_delete_test_{test_id}"
        print(f"\n2. Creating test directory: {test_dir}")
        async with session.post(
            f"{base_url}/v1/files/mkdir",
            json={"path": test_dir},
            headers=headers
        ) as resp:
            if resp.status != 200:
                print(f"   ❌ Mkdir failed: {resp.status}")
                text = await resp.text()
                print(f"   Response: {text}")
                return
            print(f"   ✓ Directory created")
        
        # Step 3: Upload a test file
        test_file = "test_delete.txt"
        test_content = f"Test file for deletion - {datetime.now()}"
        print(f"\n3. Uploading test file: {test_file}")
        
        data = aiohttp.FormData()
        data.add_field('file', test_content.encode(), filename=test_file, content_type='text/plain')
        data.add_field('path', test_dir)
        
        async with session.post(
            f"{base_url}/v1/files/upload",
            data=data,
            headers=headers
        ) as resp:
            if resp.status != 200:
                print(f"   ❌ Upload failed: {resp.status}")
                text = await resp.text()
                print(f"   Response: {text}")
                return
            print(f"   ✓ File uploaded")
        
        # Step 4: Verify file exists
        print(f"\n4. Verifying file exists...")
        async with session.get(
            f"{base_url}/v1/files/list",
            params={"path": test_dir},
            headers=headers
        ) as resp:
            if resp.status != 200:
                print(f"   ❌ List failed: {resp.status}")
                return
            list_data = await resp.json()
            entries = list_data.get("entries", [])
            file_exists = any(e.get("name") == test_file for e in entries)
            if file_exists:
                print(f"   ✓ File exists in directory")
            else:
                print(f"   ❌ File not found in directory")
                print(f"   Entries: {[e.get('name') for e in entries]}")
        
        # Step 5: Delete the file
        file_path = f"{test_dir}/{test_file}"
        print(f"\n5. Deleting file: {file_path}")
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": file_path},
            headers=headers
        ) as resp:
            response_text = await resp.text()
            print(f"   Response status: {resp.status}")
            print(f"   Response body: {response_text}")
            
            if resp.status == 200:
                print(f"   ✓ Delete succeeded (200 OK)")
            elif resp.status == 404:
                print(f"   ⚠️ File not found (404) - This means the path was invalid")
            elif resp.status == 500:
                print(f"   ❌ Server error (500) - Check the server logs")
            else:
                print(f"   ❌ Unexpected status: {resp.status}")
        
        # Step 6: Verify file is gone
        print(f"\n6. Verifying file is deleted...")
        async with session.get(
            f"{base_url}/v1/files/list",
            params={"path": test_dir},
            headers=headers
        ) as resp:
            if resp.status != 200:
                print(f"   ❌ List failed: {resp.status}")
                return
            list_data = await resp.json()
            entries = list_data.get("entries", [])
            file_exists = any(e.get("name") == test_file for e in entries)
            if not file_exists:
                print(f"   ✓ File successfully deleted")
            else:
                print(f"   ❌ File still exists after deletion")
                print(f"   Entries: {[e.get('name') for e in entries]}")
        
        # Step 7: Try to delete non-existent file
        fake_path = f"/Users/omniverse/nonexistent_{uuid.uuid4().hex}.txt"
        print(f"\n7. Testing delete of non-existent file: {fake_path}")
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": fake_path},
            headers=headers
        ) as resp:
            response_text = await resp.text()
            print(f"   Response status: {resp.status}")
            print(f"   Response body: {response_text}")
            
            if resp.status == 404:
                print(f"   ✓ Correctly returned 404 for non-existent file")
            else:
                print(f"   ⚠️ Expected 404 but got {resp.status}")
        
        # Step 8: Clean up - delete test directory
        print(f"\n8. Cleaning up test directory: {test_dir}")
        async with session.post(
            f"{base_url}/v1/files/delete",
            json={"path": test_dir},
            headers=headers
        ) as resp:
            if resp.status == 200:
                print(f"   ✓ Test directory deleted")
            else:
                text = await resp.text()
                print(f"   ⚠️ Could not delete directory: {resp.status}")
                print(f"   Response: {text}")
        
        print(f"\n✅ Delete test completed!")


if __name__ == "__main__":
    print("=" * 70)
    print("MANUAL DELETE OPERATION TEST")
    print("=" * 70)
    print("\nMake sure the proxy server is running on port 8088")
    print("Run: python run.py\n")
    
    try:
        asyncio.run(test_delete())
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()