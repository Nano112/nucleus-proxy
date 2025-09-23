#!/usr/bin/env python3
"""Debug script to test stat operations."""

import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app.nucleus.client import NucleusClient
from app.config import settings


async def test_stat():
    """Test stat operations directly."""
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
    
    # List /Library/ directory to see what's there
    print("Listing /Library/:")
    result = await client.list_directory("/Library/")
    if result.get('status') in ['OK', 'DONE', 'LATEST']:
        entries = result.get('entries', [])
        for entry in entries[:3]:
            path = entry.get('path', '')
            print(f"  - {path}")
            
            # If it's a directory, list its contents
            if path.endswith('/'):
                print(f"\nListing {path}:")
                dir_result = await client.list_directory(path)
                if dir_result.get('status') in ['OK', 'DONE', 'LATEST']:
                    dir_entries = dir_result.get('entries', [])
                    for file_entry in dir_entries[:3]:
                        file_path = file_entry.get('path', '')
                        print(f"    - {file_path}")
                        
                        # Try to stat this file
                        if file_path and not file_path.endswith('/'):
                            print(f"      Stat'ing {file_path}...")
                            stat_result = await client.get_file_info(file_path)
                            print(f"      Stat result:")
                            print(f"        status: {stat_result.get('status')}")
                            print(f"        path_type: {stat_result.get('path_type')}")
                            print(f"        size: {stat_result.get('size')}")
                            print(f"        Full response: {stat_result}")
                            break  # Only stat one file
                break  # Only check one directory
    
    # Close connection
    await client.close()
    print("\n✓ Connection closed")


if __name__ == "__main__":
    asyncio.run(test_stat())