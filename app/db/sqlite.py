"""
SQLite database models and operations for upload sessions.
Implements the schema from roadmap.md for resumable upload tracking.
"""

import sqlite3
import asyncio
import aiosqlite
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from app.config import settings

logger = logging.getLogger(__name__)


class UploadState(str, Enum):
    """Upload session states"""
    PENDING = "pending"      # Session created, accepting parts
    ASSEMBLING = "assembling"  # All parts received, assembling file
    COMMITTING = "committing"  # Assembled file, committing to Nucleus
    COMPLETED = "completed"   # Successfully committed to Nucleus
    FAILED = "failed"        # Upload or commit failed
    EXPIRED = "expired"      # Session expired due to timeout


class FileType(str, Enum):
    """File type categories"""
    FILE = "file"
    DIRECTORY = "directory"
    LINK = "link"


class IndexStatus(str, Enum):
    """Index synchronization status"""
    PENDING = "pending"      # File discovered but not yet indexed
    INDEXED = "indexed"      # File successfully indexed
    ERROR = "error"          # Indexing failed
    DELETED = "deleted"      # File was deleted from Nucleus


@dataclass
class UploadSession:
    """Upload session data model"""
    id: str
    token_id: str
    user_id: str
    path_dir: str
    filename: str
    size: int
    sha256: Optional[str]
    part_size: int
    received_bytes: int
    created_at: datetime
    state: UploadState
    error: Optional[str]
    meta: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'token_id': self.token_id,
            'user_id': self.user_id,
            'path_dir': self.path_dir,
            'filename': self.filename,
            'size': self.size,
            'sha256': self.sha256,
            'part_size': self.part_size,
            'received_bytes': self.received_bytes,
            'created_at': self.created_at.isoformat(),
            'state': self.state.value,
            'error': self.error,
            'meta': self.meta
        }


@dataclass
class UploadPart:
    """Upload part data model"""
    session_id: str
    index: int
    size: int
    sha256: Optional[str]
    path_on_disk: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'session_id': self.session_id,
            'index': self.index,
            'size': self.size,
            'sha256': self.sha256,
            'path_on_disk': self.path_on_disk
        }


@dataclass
class FileEntry:
    """File metadata entry for indexing"""
    path: str                           # Full path in Nucleus
    name: str                           # Filename only
    parent: str                         # Parent directory path
    type: FileType                      # File, directory, or link
    size: Optional[int]                 # File size in bytes
    modified_at: Optional[datetime]     # Last modification time
    created_by: Optional[str]          # Creator username
    tags: Dict[str, Any]               # File tags and metadata
    last_seen: datetime                # Last time file was seen in sync
    checksum: Optional[str]            # File checksum/hash
    content_type: Optional[str]        # MIME type if known
    index_status: IndexStatus          # Synchronization status
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'path': self.path,
            'name': self.name,
            'parent': self.parent,
            'type': self.type.value,
            'size': self.size,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'created_by': self.created_by,
            'tags': self.tags,
            'last_seen': self.last_seen.isoformat(),
            'checksum': self.checksum,
            'content_type': self.content_type,
            'index_status': self.index_status.value
        }


@dataclass
class IndexingMetadata:
    """Metadata about the indexing process"""
    last_full_sync: Optional[datetime]  # Last complete index rebuild
    last_incremental_sync: Optional[datetime]  # Last incremental update
    total_files: int                    # Total number of indexed files
    total_size: int                     # Total size of all indexed files
    sync_errors: int                    # Number of sync errors
    version: str                        # Schema version
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'last_full_sync': self.last_full_sync.isoformat() if self.last_full_sync else None,
            'last_incremental_sync': self.last_incremental_sync.isoformat() if self.last_incremental_sync else None,
            'total_files': self.total_files,
            'total_size': self.total_size,
            'sync_errors': self.sync_errors,
            'version': self.version
        }


class Database:
    """SQLite database manager for upload sessions"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.sqlite_path
        self._connection: Optional[aiosqlite.Connection] = None
        self._initialized = False
        
        # Ensure database directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize database schema if not already done"""
        if self._initialized:
            return
            
        async with aiosqlite.connect(self.db_path) as db:
            # Enable foreign keys
            await db.execute("PRAGMA foreign_keys = ON")
            
            # Create upload_sessions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS upload_sessions (
                    id TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    path_dir TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT,
                    part_size INTEGER NOT NULL,
                    received_bytes INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    state TEXT DEFAULT 'pending',
                    error TEXT,
                    meta TEXT DEFAULT '{}'
                )
            """)
            
            # Create upload_parts table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS upload_parts (
                    session_id TEXT NOT NULL,
                    part_index INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT,
                    path_on_disk TEXT NOT NULL,
                    PRIMARY KEY (session_id, part_index),
                    FOREIGN KEY (session_id) REFERENCES upload_sessions(id) ON DELETE CASCADE
                )
            """)
            
            # Create file_entries table for indexing
            await db.execute("""
                CREATE TABLE IF NOT EXISTS file_entries (
                    path TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    parent TEXT NOT NULL,
                    type TEXT NOT NULL,
                    size INTEGER,
                    modified_at TIMESTAMP,
                    created_by TEXT,
                    tags TEXT DEFAULT '{}',
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    checksum TEXT,
                    content_type TEXT,
                    index_status TEXT DEFAULT 'pending'
                )
            """)
            
            # Create file search FTS5 table for full-text search
            await db.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS file_search USING fts5(
                    path,
                    name,
                    content=file_entries,
                    content_rowid=rowid
                )
            """)
            
            # Create indexing_metadata table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS indexing_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token_id ON upload_sessions(token_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON upload_sessions(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_state ON upload_sessions(state)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON upload_sessions(created_at)")
            
            # File indexing indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_parent ON file_entries(parent)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_type ON file_entries(type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_modified ON file_entries(modified_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_created_by ON file_entries(created_by)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_status ON file_entries(index_status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_last_seen ON file_entries(last_seen)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_size ON file_entries(size)")
            
            await db.commit()
            
        self._initialized = True
        logger.info(f"Database initialized at {self.db_path}")
    
    async def create_session(self, session: UploadSession) -> bool:
        """Create a new upload session"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO upload_sessions 
                    (id, token_id, user_id, path_dir, filename, size, sha256, part_size, 
                     received_bytes, created_at, state, error, meta)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session.id, session.token_id, session.user_id, session.path_dir,
                    session.filename, session.size, session.sha256, session.part_size,
                    session.received_bytes, session.created_at.isoformat(), session.state.value,
                    session.error, json.dumps(session.meta)
                ))
                await db.commit()
                return True
        except sqlite3.IntegrityError as e:
            logger.error(f"Failed to create session {session.id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Database error creating session: {e}")
            return False
    
    async def get_session(self, session_id: str) -> Optional[UploadSession]:
        """Get upload session by ID"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM upload_sessions WHERE id = ?
                """, (session_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_session(row)
                    return None
        except Exception as e:
            logger.error(f"Database error getting session {session_id}: {e}")
            return None
    
    async def update_session(self, session_id: str, **updates) -> bool:
        """Update session fields"""
        if not updates:
            return True
            
        try:
            # Build dynamic update query
            fields = []
            values = []
            for key, value in updates.items():
                if key == 'meta' and isinstance(value, dict):
                    value = json.dumps(value)
                elif key == 'state' and isinstance(value, UploadState):
                    value = value.value
                fields.append(f"{key} = ?")
                values.append(value)
            
            values.append(session_id)
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(f"""
                    UPDATE upload_sessions SET {', '.join(fields)} WHERE id = ?
                """, values)
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error updating session {session_id}: {e}")
            return False
    
    async def add_part(self, part: UploadPart) -> bool:
        """Add an upload part"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO upload_parts 
                    (session_id, part_index, size, sha256, path_on_disk)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    part.session_id, part.index, part.size, part.sha256, part.path_on_disk
                ))
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error adding part {part.index} for session {part.session_id}: {e}")
            return False
    
    async def get_parts(self, session_id: str) -> List[UploadPart]:
        """Get all parts for a session, ordered by index"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM upload_parts WHERE session_id = ? ORDER BY part_index
                """, (session_id,)) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_part(row) for row in rows]
        except Exception as e:
            logger.error(f"Database error getting parts for session {session_id}: {e}")
            return []
    
    async def get_session_by_token(self, token_id: str) -> Optional[UploadSession]:
        """Get upload session by token ID"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM upload_sessions WHERE token_id = ? AND state != 'completed'
                    ORDER BY created_at DESC LIMIT 1
                """, (token_id,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_session(row)
                    return None
        except Exception as e:
            logger.error(f"Database error getting session by token {token_id}: {e}")
            return None
    
    async def list_sessions(self, user_id: str, limit: int = 50) -> List[UploadSession]:
        """List upload sessions for a user"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM upload_sessions WHERE user_id = ? 
                    ORDER BY created_at DESC LIMIT ?
                """, (user_id, limit)) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_session(row) for row in rows]
        except Exception as e:
            logger.error(f"Database error listing sessions for user {user_id}: {e}")
            return []
    
    async def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired upload sessions and their parts"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get expired sessions
                async with db.execute("""
                    SELECT id, path_dir, filename FROM upload_sessions 
                    WHERE datetime(created_at) < datetime('now', '-{} hours')
                    AND state IN ('pending', 'failed')
                """.format(max_age_hours)) as cursor:
                    expired = await cursor.fetchall()
                
                if not expired:
                    return 0
                
                # Clean up staging files
                for session_id, path_dir, filename in expired:
                    staging_dir = Path(settings.staging_dir) / session_id
                    if staging_dir.exists():
                        import shutil
                        shutil.rmtree(staging_dir, ignore_errors=True)
                
                # Delete from database
                expired_ids = [row[0] for row in expired]
                placeholders = ','.join('?' * len(expired_ids))
                await db.execute(f"""
                    DELETE FROM upload_sessions WHERE id IN ({placeholders})
                """, expired_ids)
                await db.commit()
                
                logger.info(f"Cleaned up {len(expired)} expired upload sessions")
                return len(expired)
        except Exception as e:
            logger.error(f"Database error during cleanup: {e}")
            return 0
    
    # File indexing methods
    
    async def index_file(self, file_entry: FileEntry) -> bool:
        """Index a single file entry"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Insert or update file entry
                await db.execute("""
                    INSERT OR REPLACE INTO file_entries 
                    (path, name, parent, type, size, modified_at, created_by, tags, 
                     last_seen, checksum, content_type, index_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    file_entry.path, file_entry.name, file_entry.parent, file_entry.type.value,
                    file_entry.size, 
                    file_entry.modified_at.isoformat() if file_entry.modified_at else None,
                    file_entry.created_by, json.dumps(file_entry.tags),
                    file_entry.last_seen.isoformat(), file_entry.checksum,
                    file_entry.content_type, file_entry.index_status.value
                ))
                
                # Update FTS index
                await db.execute("""
                    INSERT OR REPLACE INTO file_search(path, name) VALUES (?, ?)
                """, (file_entry.path, file_entry.name))
                
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error indexing file {file_entry.path}: {e}")
            return False
    
    async def get_file(self, path: str) -> Optional[FileEntry]:
        """Get a file entry by path"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM file_entries WHERE path = ?
                """, (path,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_file_entry(row)
                    return None
        except Exception as e:
            logger.error(f"Database error getting file {path}: {e}")
            return None
    
    async def list_files(self, parent_path: str = "/", limit: int = 100, offset: int = 0) -> List[FileEntry]:
        """List files in a directory"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT * FROM file_entries WHERE parent = ? AND index_status = 'indexed'
                    ORDER BY type, name LIMIT ? OFFSET ?
                """, (parent_path, limit, offset)) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_file_entry(row) for row in rows]
        except Exception as e:
            logger.error(f"Database error listing files in {parent_path}: {e}")
            return []
    
    async def search_files(self, query: str, limit: int = 50, offset: int = 0) -> List[FileEntry]:
        """Full-text search for files"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute("""
                    SELECT fe.* FROM file_entries fe
                    JOIN file_search fs ON fe.path = fs.path
                    WHERE fs MATCH ? AND fe.index_status = 'indexed'
                    ORDER BY rank LIMIT ? OFFSET ?
                """, (query, limit, offset)) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_file_entry(row) for row in rows]
        except Exception as e:
            logger.error(f"Database error searching files with query '{query}': {e}")
            return []
    
    async def update_file_tags(self, path: str, tags: Dict[str, Any]) -> bool:
        """Update file tags"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE file_entries SET tags = ?, last_seen = ?
                    WHERE path = ?
                """, (json.dumps(tags), datetime.now(timezone.utc).isoformat(), path))
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error updating tags for {path}: {e}")
            return False
    
    async def mark_file_deleted(self, path: str) -> bool:
        """Mark a file as deleted"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE file_entries SET index_status = 'deleted', last_seen = ?
                    WHERE path = ?
                """, (datetime.now(timezone.utc).isoformat(), path))
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error marking file deleted {path}: {e}")
            return False
    
    async def get_indexing_stats(self) -> Dict[str, Any]:
        """Get indexing statistics"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                stats = {}
                
                # Total counts by status
                async with db.execute("""
                    SELECT index_status, COUNT(*), COALESCE(SUM(size), 0)
                    FROM file_entries GROUP BY index_status
                """) as cursor:
                    status_stats = await cursor.fetchall()
                    for status, count, total_size in status_stats:
                        stats[f'{status}_count'] = count
                        stats[f'{status}_size'] = total_size
                
                # File type distribution
                async with db.execute("""
                    SELECT type, COUNT(*) FROM file_entries 
                    WHERE index_status = 'indexed' GROUP BY type
                """) as cursor:
                    type_stats = await cursor.fetchall()
                    stats['types'] = {file_type: count for file_type, count in type_stats}
                
                # Recent activity
                async with db.execute("""
                    SELECT COUNT(*) FROM file_entries 
                    WHERE datetime(last_seen) > datetime('now', '-1 hour')
                """) as cursor:
                    recent_count = await cursor.fetchone()
                    stats['recent_updates'] = recent_count[0] if recent_count else 0
                
                return stats
        except Exception as e:
            logger.error(f"Database error getting indexing stats: {e}")
            return {}
    
    async def set_indexing_metadata(self, key: str, value: Any) -> bool:
        """Set indexing metadata value"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO indexing_metadata (key, value, updated_at)
                    VALUES (?, ?, ?)
                """, (key, json.dumps(value), datetime.now(timezone.utc).isoformat()))
                await db.commit()
                return True
        except Exception as e:
            logger.error(f"Database error setting metadata {key}: {e}")
            return False
    
    async def get_indexing_metadata(self, key: str) -> Optional[Any]:
        """Get indexing metadata value"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT value FROM indexing_metadata WHERE key = ?
                """, (key,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return json.loads(row[0])
                    return None
        except Exception as e:
            logger.error(f"Database error getting metadata {key}: {e}")
            return None
    
    def _row_to_session(self, row: aiosqlite.Row) -> UploadSession:
        """Convert database row to UploadSession"""
        return UploadSession(
            id=row['id'],
            token_id=row['token_id'],
            user_id=row['user_id'],
            path_dir=row['path_dir'],
            filename=row['filename'],
            size=row['size'],
            sha256=row['sha256'],
            part_size=row['part_size'],
            received_bytes=row['received_bytes'],
            created_at=datetime.fromisoformat(row['created_at']),
            state=UploadState(row['state']),
            error=row['error'],
            meta=json.loads(row['meta'] or '{}')
        )
    
    def _row_to_part(self, row: aiosqlite.Row) -> UploadPart:
        """Convert database row to UploadPart"""
        return UploadPart(
            session_id=row['session_id'],
            index=row['part_index'],
            size=row['size'],
            sha256=row['sha256'],
            path_on_disk=row['path_on_disk']
        )
    
    def _row_to_file_entry(self, row: aiosqlite.Row) -> FileEntry:
        """Convert database row to FileEntry"""
        return FileEntry(
            path=row['path'],
            name=row['name'],
            parent=row['parent'],
            type=FileType(row['type']),
            size=row['size'],
            modified_at=datetime.fromisoformat(row['modified_at']) if row['modified_at'] else None,
            created_by=row['created_by'],
            tags=json.loads(row['tags'] or '{}'),
            last_seen=datetime.fromisoformat(row['last_seen']) if row['last_seen'] else datetime.now(timezone.utc),
            checksum=row['checksum'],
            content_type=row['content_type'],
            index_status=IndexStatus(row['index_status'])
        )


# Global database instance
_database: Optional[Database] = None


async def get_database() -> Database:
    """Get or create the global database instance"""
    global _database
    if _database is None:
        _database = Database()
        await _database.initialize()
    return _database


async def initialize_database():
    """Initialize the database on startup"""
    await get_database()