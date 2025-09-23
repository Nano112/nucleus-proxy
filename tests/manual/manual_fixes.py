#!/usr/bin/env python3
"""
Test script to verify folder deletion and file upload fixes.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.nucleus.client import ensure_authenticated


async def test_fixes():
    """Test the folder deletion and upload fixes."""
    
    print("Testing folder deletion and file upload fixes...\n")
    
    try:
        # Get authenticated client
        print("Connecting to Nucleus server...")
        client = await ensure_authenticated()
        print("Connected and authenticated\n")
        
        # Test 1: Folder deletion
        print("=" * 60)
        print("TEST 1: Folder Deletion")
        print("=" * 60)
        
        test_dir = f"/Users/test_fixes_{os.getpid()}/"
        print(f"Creating test directory: {test_dir}")
        result = await client.create_directory(test_dir)
        if result.get('status') not in ['OK', 'DONE', 'AlreadyExists']:
            print(f"Failed to create directory: {result}")
            return False
        print("Test directory created")
        
        # Try to delete the empty folder
        print(f"\nDeleting empty folder: {test_dir}")
        delete_result = await client.delete_path(test_dir)
        
        if delete_result.get('status') in ['OK', 'DONE']:
            print(f"SUCCESS: Folder deleted successfully")
        else:
            print(f"FAILED: Could not delete folder: {delete_result}")
            
        # Verify it's gone
        stat_result = await client.get_file_info(test_dir)
        if stat_result.get('status') != 'OK':
            print("VERIFIED: Folder no longer exists")
        else:
            print("WARNING: Folder still exists after deletion")
        
        # Test 2: Create folder with content and delete
        print("\n" + "=" * 60)
        print("TEST 2: Folder with Content")
        print("=" * 60)
        
        test_dir2 = f"/Users/test_folder_content_{os.getpid()}/"
        print(f"Creating test directory: {test_dir2}")
        await client.create_directory(test_dir2)
        
        # Upload a small file to the folder
        print("Uploading test file to folder...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content for folder deletion test")
            temp_path = f.name
        
        upload_result = await client.upload_file_single_shot(
            temp_path, test_dir2, "test_file.txt"
        )
        os.unlink(temp_path)
        
        if upload_result.get('status') == 'OK' or upload_result.get('response'):
            print("Test file uploaded")
        else:
            print(f"Upload failed: {upload_result}")
        
        # Try to delete non-empty folder
        print(f"\nDeleting non-empty folder: {test_dir2}")
        delete_result = await client.delete_path(test_dir2)
        
        if delete_result.get('status') == 'FOLDER_NOT_EMPTY':
            print("EXPECTED: Got FOLDER_NOT_EMPTY error for non-empty folder")
            # Clean up by deleting file first
            await client.delete_path(f"{test_dir2}test_file.txt")
            await client.delete_path(test_dir2)
            print("Cleaned up test folder")
        elif delete_result.get('status') in ['OK', 'DONE']:
            print("WARNING: Non-empty folder was deleted (recursive delete?)")
        else:
            print(f"Got status: {delete_result}")
        
        # Test 3: Small file upload
        print("\n" + "=" * 60)
        print("TEST 3: Small File Upload (Testing timeout fix)")
        print("=" * 60)
        
        test_dir3 = f"/Users/test_upload_{os.getpid()}/"
        print(f"Creating test directory: {test_dir3}")
        await client.create_directory(test_dir3)
        
        # Create a small test file
        print("Creating small test file...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Small test file content\n" * 100)  # ~2.4KB file
            temp_path = f.name
        
        print(f"Uploading small file to {test_dir3}...")
        upload_result = await client.upload_file_single_shot(
            temp_path, test_dir3, "small_test.txt"
        )
        os.unlink(temp_path)
        
        if upload_result.get('status') == 'OK' or upload_result.get('response'):
            print("SUCCESS: Small file uploaded without timeout")
        else:
            print(f"FAILED: Upload failed: {upload_result}")
        
        # Verify file exists
        file_path = f"{test_dir3}small_test.txt"
        stat_result = await client.get_file_info(file_path)
        if stat_result.get('status') == 'OK':
            print(f"VERIFIED: File exists at {file_path}")
            print(f"  Type: {stat_result.get('type')}")
            print(f"  Size: {stat_result.get('size')} bytes")
        else:
            print(f"WARNING: Could not stat uploaded file: {stat_result}")
        
        # Clean up
        print("\nCleaning up test files...")
        await client.delete_path(file_path)
        await client.delete_path(test_dir3)
        print("Cleanup complete")
        
        print("\n" + "=" * 60)
        print("ALL TESTS COMPLETED")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\nERROR: Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main entry point."""
    # Check for Nucleus host
    if not os.getenv('NUCLEUS_HOST'):
        print("ERROR: NUCLEUS_HOST environment variable not set")
        print("Please set it to your Nucleus server address")
        print("Example: export NUCLEUS_HOST=127.0.0.1")
        sys.exit(1)
    
    success = await test_fixes()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())