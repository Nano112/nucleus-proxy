#!/usr/bin/env python3
"""Debug script to test upload operations directly."""

import asyncio
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.nucleus.client import NucleusClient
from app.config import settings


async def test_upload():
    """Test upload operations directly."""
    print(f"Connecting to Nucleus at {settings.nucleus_host}...")
    
    client = NucleusClient(settings.nucleus_host)
    
    # Authenticate
    result = await client.authenticate(settings.nucleus_username, settings.nucleus_password)
    if result.get('status') != 'OK':
        print(f"Authentication failed: {result}")
        return
    
    print(f"✓ Authenticated successfully")
    
    # Establish persistent API connection
    if not await client.authorize_api_connection():
        print("Failed to authorize API connection")
        return
    
    print(f"✓ API connection established\n")
    
    # Create test directory
    test_dir = "/Library/_upload_debug/"
    print(f"Creating test directory: {test_dir}")
    result = await client.create_folder(test_dir)
    print(f"Create result: {result}")
    
    # Create a test file
    test_content = b"Hello from debug upload test!\n"
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tf:
        tf.write(test_content)
        temp_path = tf.name
    
    print(f"\nUploading test file to {test_dir}")
    result = await client.upload_file_single_shot(temp_path, test_dir)
    print(f"Upload result: {result}")
    
    # List directory
    print(f"\nListing directory {test_dir}:")
    result = await client.list_directory(test_dir)
    print(f"List result status: {result.get('status')}")
    
    entries = result.get('entries', [])
    print(f"Found {len(entries)} entries:")
    for entry in entries:
        print(f"  - Entry: {entry}")
        if isinstance(entry, dict):
            print(f"    Name: {entry.get('name', 'NO NAME')}")
            print(f"    Path: {entry.get('path', 'NO PATH')}")
            print(f"    Type: {entry.get('path_type', 'NO TYPE')}")
    
    # Clean up temp file
    import os
    os.unlink(temp_path)
    
    # Try to delete test dir
    print(f"\nCleaning up...")
    await client.delete_path(test_dir)
    
    # Close connection
    await client.close()
    print("\n✓ Connection closed")


if __name__ == "__main__":
    asyncio.run(test_upload())