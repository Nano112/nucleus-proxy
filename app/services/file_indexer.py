"""
File indexing service for M5 milestone.

Provides functionality to index file metadata from Nucleus into SQLite,
enabling search, filtering, and metadata management capabilities.
"""

import asyncio
import logging
import mimetypes
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import hashlib

from app.config import settings
from app.db.sqlite import Database, FileEntry, FileType, IndexStatus, get_database
from app.nucleus.client import get_nucleus_client

logger = logging.getLogger(__name__)


class FileIndexer:
    """
    Service for indexing file metadata from Nucleus into SQLite.
    
    Provides both full index rebuilds and incremental synchronization
    to keep the local file index up to date with Nucleus state.
    """
    
    def __init__(self, database: Optional[Database] = None):
        self.database = database
        self._nucleus_client = None
        self._sync_in_progress = False
        self._sync_stats = {
            'files_processed': 0,
            'files_indexed': 0,
            'files_updated': 0,
            'files_deleted': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }
    
    async def initialize(self):
        """Initialize the indexer service"""
        if not self.database:
            self.database = await get_database()
        
        # Initialize indexing metadata if not exists
        version = await self.database.get_indexing_metadata('schema_version')
        if not version:
            await self.database.set_indexing_metadata('schema_version', '1.0')
            await self.database.set_indexing_metadata('first_sync', datetime.now(timezone.utc).isoformat())
    
    async def get_nucleus_client(self):
        """Get authenticated Nucleus client"""
        if not self._nucleus_client:
            from app.nucleus.client import get_nucleus_client
            self._nucleus_client = await get_nucleus_client()
        return self._nucleus_client
    
    async def full_sync(self, root_path: str = "/") -> Dict[str, Any]:
        """
        Perform a complete index rebuild from Nucleus.
        
        Args:
            root_path: Root directory to start indexing from
            
        Returns:
            Dictionary with sync statistics
        """
        if self._sync_in_progress:
            return {"error": "Sync already in progress"}
        
        self._sync_in_progress = True
        self._sync_stats = {
            'files_processed': 0,
            'files_indexed': 0,
            'files_updated': 0,
            'files_deleted': 0,
            'errors': 0,
            'start_time': datetime.now(timezone.utc),
            'end_time': None,
            'type': 'full_sync',
            'root_path': root_path
        }
        
        try:
            logger.info(f"Starting full index sync from {root_path}")
            
            nucleus_client = await self.get_nucleus_client()
            indexed_paths = set()
            
            # Recursively index all files
            await self._sync_directory(nucleus_client, root_path, indexed_paths)
            
            # Mark files not seen in this sync as deleted
            await self._mark_missing_files_deleted(indexed_paths)
            
            # Update metadata
            await self.database.set_indexing_metadata('last_full_sync', datetime.now(timezone.utc).isoformat())
            await self.database.set_indexing_metadata('last_sync_stats', {
                **self._sync_stats,
                'start_time': self._sync_stats['start_time'].isoformat() if self._sync_stats.get('start_time') else None,
                'end_time': self._sync_stats['end_time'].isoformat() if self._sync_stats.get('end_time') else None
            })
            
            self._sync_stats['end_time'] = datetime.now(timezone.utc)
            
            logger.info(f"Full sync completed: {self._sync_stats}")
            return self._sync_stats
            
        except Exception as e:
            logger.error(f"Error during full sync: {e}")
            self._sync_stats['errors'] += 1
            self._sync_stats['error'] = str(e)
            return self._sync_stats
        
        finally:
            self._sync_in_progress = False
    
    async def incremental_sync(self, since_hours: int = 1) -> Dict[str, Any]:
        """
        Perform incremental sync of files modified since given time.
        
        Args:
            since_hours: Number of hours to look back for changes
            
        Returns:
            Dictionary with sync statistics
        """
        if self._sync_in_progress:
            return {"error": "Sync already in progress"}
        
        self._sync_in_progress = True
        self._sync_stats = {
            'files_processed': 0,
            'files_indexed': 0,
            'files_updated': 0,
            'files_deleted': 0,
            'errors': 0,
            'start_time': datetime.now(timezone.utc),
            'end_time': None,
            'type': 'incremental_sync',
            'since_hours': since_hours
        }
        
        try:
            logger.info(f"Starting incremental sync (last {since_hours} hours)")
            
            # For now, we'll do a simple approach since Nucleus doesn't have
            # native change tracking - check files that haven't been seen recently
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=since_hours)
            
            # This is a simplified incremental sync - in production you'd want
            # more sophisticated change detection
            nucleus_client = await self.get_nucleus_client()
            
            # Re-index files that haven't been seen recently
            await self._sync_directory(nucleus_client, "/", set())
            
            await self.database.set_indexing_metadata('last_incremental_sync', datetime.now(timezone.utc).isoformat())
            
            self._sync_stats['end_time'] = datetime.now(timezone.utc)
            
            logger.info(f"Incremental sync completed: {self._sync_stats}")
            return self._sync_stats
            
        except Exception as e:
            logger.error(f"Error during incremental sync: {e}")
            self._sync_stats['errors'] += 1
            self._sync_stats['error'] = str(e)
            return self._sync_stats
        
        finally:
            self._sync_in_progress = False
    
    async def index_single_file(self, file_path: str, file_info: Dict[str, Any]) -> bool:
        """
        Index a single file from its metadata.
        
        Args:
            file_path: Full path to the file
            file_info: File metadata from Nucleus
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Parse file path
            path_parts = Path(file_path)
            name = path_parts.name
            parent = str(path_parts.parent) if path_parts.parent != path_parts else "/"
            
            # Determine file type
            file_type = FileType.FILE
            if file_info.get('type') == 'folder':
                file_type = FileType.DIRECTORY
            elif file_info.get('type') == 'link':
                file_type = FileType.LINK
            
            # Guess content type
            content_type = None
            if file_type == FileType.FILE:
                content_type, _ = mimetypes.guess_type(name)
            
            # Parse timestamps
            modified_at = None
            if 'modified' in file_info:
                try:
                    modified_at = datetime.fromisoformat(file_info['modified'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            # Extract other metadata
            size = file_info.get('size', 0) if file_type == FileType.FILE else None
            created_by = file_info.get('created_by')
            checksum = file_info.get('hash', file_info.get('checksum'))
            
            # Build tags from available metadata
            tags = {}
            if 'version' in file_info:
                tags['version'] = file_info['version']
            if 'created' in file_info:
                tags['created'] = file_info['created']
            
            # Create file entry
            file_entry = FileEntry(
                path=file_path,
                name=name,
                parent=parent,
                type=file_type,
                size=size,
                modified_at=modified_at,
                created_by=created_by,
                tags=tags,
                last_seen=datetime.now(timezone.utc),
                checksum=checksum,
                content_type=content_type,
                index_status=IndexStatus.INDEXED
            )
            
            # Save to database
            success = await self.database.index_file(file_entry)
            
            if success:
                self._sync_stats['files_indexed'] += 1
                logger.debug(f"Indexed file: {file_path}")
            else:
                self._sync_stats['errors'] += 1
                logger.error(f"Failed to index file: {file_path}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error indexing file {file_path}: {e}")
            self._sync_stats['errors'] += 1
            return False
    
    async def _sync_directory(self, nucleus_client, dir_path: str, indexed_paths: Set[str]):
        """
        Recursively sync a directory and its contents.
        
        Args:
            nucleus_client: Authenticated Nucleus client
            dir_path: Directory path to sync
            indexed_paths: Set to track indexed file paths
        """
        try:
            # List directory contents from Nucleus
            file_list = await nucleus_client.list_directory(dir_path)
            
            if not file_list or 'entries' not in file_list:
                return
            
            for entry in file_list['entries']:
                try:
                    entry_path = entry.get('path', '')
                    entry_name = entry.get('name', '')
                    
                    # Build full path
                    if dir_path == "/":
                        full_path = f"/{entry_name}"
                    else:
                        full_path = f"{dir_path.rstrip('/')}/{entry_name}"
                    
                    # Track this path
                    indexed_paths.add(full_path)
                    
                    # Index this entry
                    await self.index_single_file(full_path, entry)
                    self._sync_stats['files_processed'] += 1
                    
                    # Recursively process directories
                    if entry.get('type') == 'folder':
                        await self._sync_directory(nucleus_client, full_path, indexed_paths)
                    
                    # Rate limiting to avoid overwhelming Nucleus
                    if self._sync_stats['files_processed'] % 100 == 0:
                        logger.info(f"Processed {self._sync_stats['files_processed']} files")
                        await asyncio.sleep(0.1)  # Brief pause
                        
                except Exception as e:
                    logger.error(f"Error processing entry in {dir_path}: {e}")
                    self._sync_stats['errors'] += 1
                    continue
                    
        except Exception as e:
            logger.error(f"Error syncing directory {dir_path}: {e}")
            self._sync_stats['errors'] += 1
    
    async def _mark_missing_files_deleted(self, indexed_paths: Set[str]):
        """
        Mark files that weren't seen in the current sync as deleted.
        
        Args:
            indexed_paths: Set of paths that were seen in current sync
        """
        try:
            # This would be more efficient with proper database queries,
            # but for simplicity we'll do it this way
            
            # Get all currently indexed files
            stats = await self.database.get_indexing_stats()
            
            # For now, we'll skip this step to avoid accidentally marking
            # files as deleted due to sync issues. In production, you'd want
            # more careful logic here.
            
            logger.info(f"Sync completed, {len(indexed_paths)} files processed")
            
        except Exception as e:
            logger.error(f"Error marking missing files: {e}")
            self._sync_stats['errors'] += 1
    
    async def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status and statistics"""
        status = {
            'sync_in_progress': self._sync_in_progress,
            'current_stats': self._sync_stats.copy() if self._sync_in_progress else None
        }
        
        # Add historical sync info
        last_full_sync = await self.database.get_indexing_metadata('last_full_sync')
        last_incremental_sync = await self.database.get_indexing_metadata('last_incremental_sync')
        last_stats = await self.database.get_indexing_metadata('last_sync_stats')
        
        status['last_full_sync'] = last_full_sync
        status['last_incremental_sync'] = last_incremental_sync
        status['last_sync_stats'] = last_stats
        
        # Add database statistics
        status['index_stats'] = await self.database.get_indexing_stats()
        
        return status
    
    async def cleanup_deleted_files(self, max_age_days: int = 30) -> int:
        """
        Clean up files marked as deleted older than specified age.
        
        Args:
            max_age_days: Maximum age in days for deleted files to keep
            
        Returns:
            Number of files cleaned up
        """
        try:
            import aiosqlite
            async with aiosqlite.connect(self.database.db_path) as db:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_age_days)
                
                # Remove old deleted entries
                cursor = await db.execute("""
                    DELETE FROM file_entries 
                    WHERE index_status = 'deleted' 
                    AND datetime(last_seen) < ?
                """, (cutoff_date.isoformat(),))
                
                deleted_count = cursor.rowcount
                await db.commit()
                
                logger.info(f"Cleaned up {deleted_count} old deleted file entries")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up deleted files: {e}")
            return 0


# Global indexer instance
_file_indexer: Optional[FileIndexer] = None


async def get_file_indexer() -> FileIndexer:
    """Get or create the global file indexer instance"""
    global _file_indexer
    if _file_indexer is None:
        _file_indexer = FileIndexer()
        await _file_indexer.initialize()
    return _file_indexer


async def initialize_file_indexer():
    """Initialize the file indexer on startup"""
    await get_file_indexer()