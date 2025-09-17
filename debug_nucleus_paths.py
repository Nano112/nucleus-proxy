#!/usr/bin/env python3
"""Debug script to list root directories on Nucleus."""

import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.nucleus.client import NucleusClient
from app.config import settings


async def list_root_directories():
    """List directories at the root of Nucleus."""
    print(f"Connecting to Nucleus at {settings.nucleus_host}...")
    print(f"Authenticating as {settings.nucleus_username}...")
    
    client = NucleusClient(settings.nucleus_host)
    
    # Authenticate
    result = await client.authenticate(settings.nucleus_username, settings.nucleus_password)
    if result.get('status') != 'OK':
        print(f"Authentication failed: {result}")
        return
    
    print(f"✓ Authenticated successfully\n")
    
    # Establish persistent API connection
    if not await client.authorize_api_connection():
        print("Failed to authorize API connection")
        return
    
    print(f"✓ API connection established\n")
    
    # List root directory
    print("Listing root directory '/':")
    result = await client.list_directory("/")
    
    if result.get('status') in ['OK', 'DONE', 'LATEST']:
        entries = result.get('entries', [])
        print(f"Found {len(entries)} entries:\n")
        for entry in entries:
            path_type = entry.get('path_type', 'unknown')
            name = entry.get('name', 'unknown')
            path = entry.get('path', '')
            if path_type == 'directory':
                print(f"  📁 {name:20} -> {path}")
            else:
                print(f"  📄 {name:20} -> {path}")
    else:
        print(f"Failed to list directory: {result}")
    
    # Try to list /Users if it exists
    print("\nTrying to list /Users directory:")
    result = await client.list_directory("/Users")
    if result.get('status') in ['OK', 'DONE', 'LATEST']:
        entries = result.get('entries', [])
        print(f"Found {len(entries)} entries in /Users")
        for entry in entries[:5]:  # Show first 5
            print(f"  - {entry.get('name', 'unknown')}")
        if len(entries) > 5:
            print(f"  ... and {len(entries) - 5} more")
    else:
        print(f"  /Users not accessible: {result.get('status', 'unknown')}")
    
    # Try to list /Projects if it exists
    print("\nTrying to list /Projects directory:")
    result = await client.list_directory("/Projects")
    if result.get('status') in ['OK', 'DONE', 'LATEST']:
        entries = result.get('entries', [])
        print(f"Found {len(entries)} entries in /Projects")
        for entry in entries[:5]:
            print(f"  - {entry.get('name', 'unknown')}")
        if len(entries) > 5:
            print(f"  ... and {len(entries) - 5} more")
    else:
        print(f"  /Projects not accessible: {result.get('status', 'unknown')}")
    
    # Close connection
    await client.close()
    print("\n✓ Connection closed")


if __name__ == "__main__":
    asyncio.run(list_root_directories())