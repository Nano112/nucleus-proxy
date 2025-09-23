#!/usr/bin/env python3
"""
Test different delete methods to find the correct one.
"""

import asyncio
import json
from app.nucleus.client import NucleusClient
from app.config import settings


async def test_delete_methods():
    """Test different delete commands."""
    print("Testing different delete methods...")
    
    client = NucleusClient(settings.nucleus_host)
    
    # Authenticate
    result = await client.authenticate(settings.nucleus_username, settings.nucleus_password)
    if result.get('status') != 'OK':
        print(f"Authentication failed: {result}")
        return
    
    print("✓ Authenticated successfully")
    
    # Establish persistent API connection
    if not await client.authorize_api_connection():
        print("Failed to authorize API connection")
        return
    
    print("✓ API connection established\n")
    
    # Create test directory and file
    test_dir = "/Library/_delete_method_test/"
    test_file = f"{test_dir}test.txt"
    
    print(f"Creating test directory: {test_dir}")
    result = await client.create_folder(test_dir)
    if result.get('status') not in ['OK', 'DONE', 'ALREADY_EXISTS']:
        print(f"Failed to create directory: {result}")
        return
    
    # Upload a test file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"Test file for deletion methods")
        temp_path = tf.name
    
    print(f"Uploading test file...")
    result = await client.upload_file_single_shot(temp_path, test_dir, "test.txt")
    print(f"Upload result: {result.get('status', result)}")
    
    # Clean up temp file
    import os
    os.unlink(temp_path)
    
    # Wait a moment for file to appear
    await asyncio.sleep(1)
    
    # Verify file exists
    list_result = await client.list_directory(test_dir)
    print(f"List result status: {list_result.get('status')}")
    entries = list_result.get('entries', [])
    print(f"Directory entries: {entries}")
    file_exists = any(
        e.get('name') == 'test.txt' or 
        e.get('path', '').endswith('test.txt')
        for e in entries if isinstance(e, dict)
    )
    print(f"File exists before delete: {file_exists}")
    
    if not file_exists:
        print("File was not created successfully, cannot test deletion")
        return
    
    # Test different delete methods
    test_paths = [
        test_file,  # Full path
        test_file.rstrip('/'),  # Ensure no trailing slash for file
    ]
    
    for path in test_paths:
        print(f"\n{'='*60}")
        print(f"Testing path format: {path}")
        
        # Method 1: delete2 (what we currently use)
        print("\n1. Testing delete2 command:")
        payload = {
            "id": client.get_next_request_id(),
            "command": "delete2",
            "path": path
        }
        try:
            message = json.dumps(payload)
            print(f"   Sending: {message}")
            await client.api_websocket.send(message)
            response_data = await asyncio.wait_for(client.api_websocket.recv(), timeout=5)
            response = client.decode_response(response_data)
            print(f"   Response: {response}")
            
            if response.get('status') in ['OK', 'DONE']:
                print("   ✓ delete2 succeeded!")
                break
        except Exception as e:
            print(f"   Error: {e}")
        
        # Method 2: delete (without the 2)
        print("\n2. Testing delete command:")
        payload = {
            "id": client.get_next_request_id(),
            "command": "delete",
            "path": path
        }
        try:
            message = json.dumps(payload)
            print(f"   Sending: {message}")
            await client.api_websocket.send(message)
            response_data = await asyncio.wait_for(client.api_websocket.recv(), timeout=5)
            response = client.decode_response(response_data)
            print(f"   Response: {response}")
            
            if response.get('status') in ['OK', 'DONE']:
                print("   ✓ delete succeeded!")
                break
        except Exception as e:
            print(f"   Error: {e}")
        
        # Method 3: obliterate (permanent delete)
        print("\n3. Testing obliterate command:")
        payload = {
            "id": client.get_next_request_id(),
            "command": "obliterate",
            "path": path
        }
        try:
            message = json.dumps(payload)
            print(f"   Sending: {message}")
            await client.api_websocket.send(message)
            response_data = await asyncio.wait_for(client.api_websocket.recv(), timeout=5)
            response = client.decode_response(response_data)
            print(f"   Response: {response}")
            
            if response.get('status') in ['OK', 'DONE']:
                print("   ✓ obliterate succeeded!")
                break
        except Exception as e:
            print(f"   Error: {e}")
        
        # Method 4: delete2 with path object (like stat2 and create_directory)
        print("\n4. Testing delete2 with path object:")
        payload = {
            "id": client.get_next_request_id(),
            "command": "delete2",
            "path": {"path": path}
        }
        try:
            message = json.dumps(payload)
            print(f"   Sending: {message}")
            await client.api_websocket.send(message)
            response_data = await asyncio.wait_for(client.api_websocket.recv(), timeout=5)
            response = client.decode_response(response_data)
            print(f"   Response: {response}")
            
            if response.get('status') in ['OK', 'DONE']:
                print("   ✓ delete2 with path object succeeded!")
                break
        except Exception as e:
            print(f"   Error: {e}")
        
        # Method 5: delete2 with paths array (like rename2)
        print("\n5. Testing delete2 with paths array:")
        payload = {
            "id": client.get_next_request_id(),
            "command": "delete2",
            "paths": [path]
        }
        try:
            message = json.dumps(payload)
            print(f"   Sending: {message}")
            await client.api_websocket.send(message)
            response_data = await asyncio.wait_for(client.api_websocket.recv(), timeout=5)
            response = client.decode_response(response_data)
            print(f"   Response: {response}")
            
            if response.get('status') in ['OK', 'DONE']:
                print("   ✓ delete2 with paths array succeeded!")
                break
        except Exception as e:
            print(f"   Error: {e}")
    
    # Check if file still exists
    print(f"\n{'='*60}")
    print("Checking if file still exists after delete attempts...")
    list_result = await client.list_directory(test_dir)
    entries = list_result.get('entries', [])
    file_exists = any(
        e.get('name') == 'test.txt' or 
        e.get('path', '').endswith('test.txt')
        for e in entries if isinstance(e, dict)
    )
    
    if file_exists:
        print("❌ File still exists - none of the delete methods worked")
        print(f"Directory contents: {[e.get('name') for e in entries if isinstance(e, dict)]}")
    else:
        print("✓ File was successfully deleted!")
    
    # Try to clean up the directory
    print(f"\nCleaning up test directory...")
    result = await client.delete_path(test_dir)
    print(f"Directory delete result: {result}")
    
    await client.close()
    print("\n✓ Test completed")


if __name__ == "__main__":
    asyncio.run(test_delete_methods())