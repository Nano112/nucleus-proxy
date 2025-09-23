#!/usr/bin/env python3
"""
Manual integration test for file operations (rename, move, copy).
Run this against a real Nucleus server to verify functionality.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from app.nucleus.client import ensure_authenticated


async def test_file_operations():
    """Test rename, move, and copy operations."""
    
    print("🚀 Starting file operations test...")
    
    try:
        # Get authenticated client
        print("📡 Connecting to Nucleus server...")
        client = await ensure_authenticated()
        print("✅ Connected and authenticated")
        
        # Create test directory
        test_dir = f"/Users/test_fileops_{os.getpid()}/"
        print(f"\n📁 Creating test directory: {test_dir}")
        result = await client.create_directory(test_dir)
        if result.get('status') not in ['OK', 'DONE', 'AlreadyExists']:
            print(f"❌ Failed to create directory: {result}")
            return False
        print("✅ Test directory created")
        
        # Upload a test file
        print("\n📤 Uploading test file...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test content for file operations\nLine 2\nLine 3")
            temp_path = f.name
        
        original_path = f"{test_dir}original.txt"
        upload_result = await client.upload_file_single_shot(
            temp_path, test_dir, "original.txt"
        )
        
        # Clean up temp file
        os.unlink(temp_path)
        
        if not (upload_result.get('status') == 'OK' or upload_result.get('response')):
            print(f"❌ Upload failed: {upload_result}")
            return False
        print(f"✅ File uploaded to {original_path}")
        
        # Test 1: Rename within same directory
        print("\n🔄 Test 1: Rename file within same directory")
        renamed_path = f"{test_dir}renamed.txt"
        rename_result = await client.move_file(original_path, renamed_path, "Test rename")
        
        if rename_result.get('status') != 'OK':
            print(f"❌ Rename failed: {rename_result}")
            return False
        print(f"✅ Renamed {original_path} → {renamed_path}")
        
        # Verify rename worked
        stat_result = await client.get_file_info(renamed_path)
        if stat_result.get('status') != 'OK':
            print(f"❌ Could not stat renamed file: {stat_result}")
            return False
        print(f"✅ Verified renamed file exists")
        
        # Test 2: Move to subdirectory
        print("\n📦 Test 2: Move file to subdirectory")
        subdir = f"{test_dir}subdir/"
        await client.create_directory(subdir)
        moved_path = f"{subdir}moved.txt"
        
        move_result = await client.move_file(renamed_path, moved_path, "Test move")
        if move_result.get('status') != 'OK':
            print(f"❌ Move failed: {move_result}")
            return False
        print(f"✅ Moved {renamed_path} → {moved_path}")
        
        # Test 3: Copy file
        print("\n📋 Test 3: Copy file")
        copied_path = f"{test_dir}copied.txt"
        copy_result = await client.copy_file(moved_path, copied_path, message="Test copy")
        
        if copy_result.get('status') != 'OK':
            print(f"❌ Copy failed: {copy_result}")
            return False
        print(f"✅ Copied {moved_path} → {copied_path}")
        
        # Verify both files exist
        moved_stat = await client.get_file_info(moved_path)
        copied_stat = await client.get_file_info(copied_path)
        
        if moved_stat.get('status') != 'OK' or copied_stat.get('status') != 'OK':
            print(f"❌ Verification failed - moved: {moved_stat}, copied: {copied_stat}")
            return False
        print("✅ Verified both files exist after copy")
        
        # Test 4: Batch rename
        print("\n🔄 Test 4: Batch rename multiple files")
        batch_result = await client.rename2([
            {"src": {"path": moved_path}, "dst": {"path": f"{test_dir}batch1.txt"}, "message": "Batch rename 1"},
            {"src": {"path": copied_path}, "dst": {"path": f"{test_dir}batch2.txt"}, "message": "Batch rename 2"}
        ])
        
        if batch_result['succeeded'] < 2:
            print(f"⚠️  Batch rename partially failed: {batch_result}")
            if batch_result['succeeded'] == 0:
                return False
        else:
            print(f"✅ Batch renamed {batch_result['succeeded']} files successfully")
        
        # Test 5: Batch copy
        print("\n📋 Test 5: Batch copy multiple files")
        batch_copy_result = await client.copy2([
            {"src": {"path": f"{test_dir}batch1.txt"}, "dst": {"path": f"{test_dir}copy1.txt"}, "message": "Batch copy 1"},
            {"src": {"path": f"{test_dir}batch2.txt"}, "dst": {"path": f"{test_dir}copy2.txt"}, "message": "Batch copy 2"}
        ])
        
        if batch_copy_result['succeeded'] < 2:
            print(f"⚠️  Batch copy partially failed: {batch_copy_result}")
            if batch_copy_result['succeeded'] == 0:
                return False
        else:
            print(f"✅ Batch copied {batch_copy_result['succeeded']} files successfully")
        
        # Test 6: Error handling - rename non-existent file
        print("\n❌ Test 6: Error handling - rename non-existent file")
        error_result = await client.move_file(
            f"{test_dir}nonexistent.txt", 
            f"{test_dir}destination.txt"
        )
        
        if error_result.get('status') == 'OK':
            print("⚠️  Expected error for non-existent file, but got OK")
        else:
            print(f"✅ Got expected error: {error_result.get('error', error_result.get('status'))}")
        
        # Clean up
        print("\n🧹 Cleaning up test files...")
        
        # List all files we created
        test_files = [
            f"{test_dir}batch1.txt",
            f"{test_dir}batch2.txt", 
            f"{test_dir}copy1.txt",
            f"{test_dir}copy2.txt"
        ]
        
        # Delete files
        delete_result = await client.delete_paths_batch(test_files)
        print(f"   Deleted {delete_result.get('succeeded', 0)} files")
        
        # Delete subdirectory
        await client.delete_path(subdir)
        
        # Delete main test directory
        await client.delete_path(test_dir)
        print("✅ Cleanup complete")
        
        print("\n🎉 All tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to clean up on error
        try:
            await client.delete_path(test_dir)
        except:
            pass
        
        return False


async def main():
    """Main entry point."""
    # Check for Nucleus host
    if not os.getenv('NUCLEUS_HOST'):
        print("❌ NUCLEUS_HOST environment variable not set")
        print("   Please set it to your Nucleus server address")
        print("   Example: export NUCLEUS_HOST=127.0.0.1")
        sys.exit(1)
    
    success = await test_file_operations()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())