"""
Upload session management service for resumable uploads.
Handles session creation, part tracking, file assembly, and Nucleus commits.
"""

import os
import uuid
import hashlib
import secrets
import shutil
import tempfile
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from app.db.sqlite import Database, UploadSession, UploadPart, UploadState, get_database
from app.config import settings
from app.nucleus.client import ensure_authenticated

logger = logging.getLogger(__name__)


class UploadToken:
    """Upload token with embedded session information"""
    
    @staticmethod
    def generate(user_id: str, session_id: str) -> str:
        """Generate a secure upload token"""
        # Combine user_id, session_id, and random bytes for token
        data = f"{user_id}:{session_id}:{secrets.token_hex(16)}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def validate(token: str) -> bool:
        """Basic token format validation"""
        return len(token) == 64 and all(c in '0123456789abcdef' for c in token)


class UploadManager:
    """Manages resumable upload sessions and file operations"""
    
    def __init__(self):
        self.staging_dir = Path(settings.staging_dir)
        self.max_upload_size = settings.max_upload_size
        self.default_part_size = settings.part_size_default
        self.commit_max_attempts = settings.upload_commit_max_attempts
        
        # Ensure staging directory exists
        self.staging_dir.mkdir(parents=True, exist_ok=True)
    
    async def create_session(self, user_id: str, filename: str, file_size: int, 
                           path_dir: str, part_size: Optional[int] = None,
                           file_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new upload session.
        
        Args:
            user_id: Authenticated user ID
            filename: Target filename
            file_size: Total file size in bytes
            path_dir: Target directory path in Nucleus
            part_size: Optional custom part size (defaults to config)
            file_sha256: Optional SHA256 hash of complete file
            
        Returns:
            Dictionary with session info and upload token
        """
        try:
            # Validate inputs
            if file_size <= 0:
                return {"error": "File size must be greater than 0"}
            
            if file_size > self.max_upload_size:
                return {"error": f"File size exceeds maximum allowed: {self.max_upload_size} bytes"}
            
            if not filename or not filename.strip():
                return {"error": "Filename is required"}
                
            if not path_dir or not path_dir.strip():
                return {"error": "Target directory path is required"}
            
            # Sanitize filename
            safe_filename = self._sanitize_filename(filename.strip())
            if not safe_filename:
                return {"error": "Invalid filename"}
            
            # Generate session ID and token
            session_id = str(uuid.uuid4())
            upload_token = UploadToken.generate(user_id, session_id)
            
            # Use default part size if not specified
            actual_part_size = part_size or self.default_part_size
            
            # Calculate expected number of parts
            num_parts = (file_size + actual_part_size - 1) // actual_part_size
            
            # Create session object
            session = UploadSession(
                id=session_id,
                token_id=upload_token,
                user_id=user_id,
                path_dir=path_dir.rstrip('/'),
                filename=safe_filename,
                size=file_size,
                sha256=file_sha256,
                part_size=actual_part_size,
                received_bytes=0,
                created_at=datetime.now(),
                state=UploadState.PENDING,
                error=None,
                meta={
                    'expected_parts': num_parts,
                    'client_info': {},
                    'phase': 'pending',
                    'uploaded_parts': 0,
                    'received_bytes': 0,
                    'sync': {
                        'status': 'pending',
                        'uploaded_bytes': 0,
                        'total_bytes': file_size
                    }
                }
            )
            
            # Create staging directory for this session
            session_staging_dir = self.staging_dir / session_id
            session_staging_dir.mkdir(parents=True, exist_ok=True)
            
            # Save to database
            db = await get_database()
            success = await db.create_session(session)
            
            if not success:
                # Clean up staging directory on failure
                shutil.rmtree(session_staging_dir, ignore_errors=True)
                return {"error": "Failed to create upload session"}
            
            logger.info(f"Created upload session {session_id} for user {user_id}: {safe_filename} ({file_size} bytes)")
            
            return {
                "session_id": session_id,
                "upload_token": upload_token,
                "filename": safe_filename,
                "size": file_size,
                "part_size": actual_part_size,
                "expected_parts": num_parts,
                "state": UploadState.PENDING.value
            }
            
        except Exception as e:
            logger.error(f"Error creating upload session: {e}")
            return {"error": "Internal server error"}
    
    async def upload_part(self, upload_token: str, part_index: int, part_data: bytes,
                         part_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Upload a file part for an existing session.
        
        Args:
            upload_token: Upload session token
            part_index: 0-based part index
            part_data: Part file data
            part_sha256: Optional SHA256 hash of this part
            
        Returns:
            Dictionary with upload status and progress info
        """
        try:
            # Validate token format
            if not UploadToken.validate(upload_token):
                return {"error": "Invalid upload token format"}
            
            # Get session from database
            db = await get_database()
            session = await db.get_session_by_token(upload_token)
            
            if not session:
                return {"error": "Upload session not found or expired"}
            
            if session.state != UploadState.PENDING:
                return {"error": f"Upload session is in {session.state.value} state, cannot accept parts"}
            
            session.meta = session.meta or {}
            session.meta.setdefault('sync', {
                'status': 'pending',
                'uploaded_bytes': 0,
                'total_bytes': session.size
            })
            session.meta.setdefault('phase', 'pending')
            session.meta.setdefault('uploaded_parts', 0)
            session.meta.setdefault('received_bytes', session.received_bytes)

            # Validate part index
            expected_parts = session.meta.get('expected_parts', 0)
            if part_index < 0 or part_index >= expected_parts:
                return {"error": f"Part index {part_index} out of range (0-{expected_parts-1})"}
            
            # Validate part size
            part_size = len(part_data)
            if part_size == 0:
                return {"error": "Part data cannot be empty"}
            
            # For last part, size can be smaller than part_size
            is_last_part = part_index == expected_parts - 1
            max_part_size = session.part_size
            if not is_last_part and part_size != max_part_size:
                return {"error": f"Part size {part_size} must be exactly {max_part_size} bytes (except last part)"}
            elif is_last_part and part_size > max_part_size:
                return {"error": f"Last part size {part_size} cannot exceed {max_part_size} bytes"}
            
            # Calculate expected size for last part
            if is_last_part:
                expected_last_size = session.size - (part_index * session.part_size)
                if part_size != expected_last_size:
                    return {"error": f"Last part size {part_size} doesn't match expected {expected_last_size} bytes"}
            
            # Verify SHA256 if provided
            if part_sha256:
                actual_hash = hashlib.sha256(part_data).hexdigest()
                if actual_hash != part_sha256:
                    return {"error": "Part SHA256 hash mismatch"}
            
            # Save part to staging directory
            session_staging_dir = self.staging_dir / session.id
            part_file_path = session_staging_dir / f"part_{part_index:06d}"
            
            try:
                with open(part_file_path, 'wb') as f:
                    f.write(part_data)
            except IOError as e:
                logger.error(f"Failed to write part file {part_file_path}: {e}")
                return {"error": "Failed to save part data"}
            
            # Create part record
            part = UploadPart(
                session_id=session.id,
                index=part_index,
                size=part_size,
                sha256=part_sha256 or hashlib.sha256(part_data).hexdigest(),
                path_on_disk=str(part_file_path)
            )
            
            # Save part to database
            success = await db.add_part(part)
            if not success:
                # Clean up part file on database failure
                part_file_path.unlink(missing_ok=True)
                return {"error": "Failed to record part upload"}

            # Update session received bytes and progress metadata
            new_received_bytes = session.received_bytes + part_size
            session.received_bytes = new_received_bytes

            parts = await db.get_parts(session.id)
            received_parts = len(parts)

            session.meta['phase'] = 'uploading'
            session.meta['uploaded_parts'] = received_parts
            session.meta['received_bytes'] = new_received_bytes
            sync_meta = session.meta.setdefault('sync', {
                'status': 'pending',
                'uploaded_bytes': 0,
                'total_bytes': session.size
            })
            sync_meta.setdefault('total_bytes', session.size)
            if received_parts == expected_parts and new_received_bytes == session.size:
                session.meta['phase'] = 'uploaded'
                if sync_meta.get('status') in (None, 'pending'):
                    sync_meta['status'] = 'pending'
                sync_meta['uploaded_bytes'] = sync_meta.get('uploaded_bytes', 0)
            else:
                sync_meta.setdefault('status', 'pending')

            await db.update_session(session.id, received_bytes=new_received_bytes, meta=session.meta)

            logger.info(f"Received part {part_index} for session {session.id}: {part_size} bytes ({received_parts}/{expected_parts} parts)")

            result = {
                "part_index": part_index,
                "size": part_size,
                "received_bytes": new_received_bytes,
                "total_bytes": session.size,
                "received_parts": received_parts,
                "expected_parts": expected_parts,
                "progress": new_received_bytes / session.size if session.size else 0,
                "phase": session.meta.get('phase')
            }

            # Check if ready for assembly
            if received_parts == expected_parts and new_received_bytes == session.size:
                result["ready_for_commit"] = True
                logger.info(f"All parts received for session {session.id}, ready for commit")
            else:
                result["ready_for_commit"] = False

            return result
            
        except Exception as e:
            logger.error(f"Error uploading part: {e}")
            return {"error": "Internal server error"}
    
    async def commit_upload(self, upload_token: str, verify_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Assemble parts and commit the complete file to Nucleus.
        
        Args:
            upload_token: Upload session token
            verify_sha256: Optional SHA256 hash to verify assembled file
            
        Returns:
            Dictionary with commit status and Nucleus response
        """
        try:
            # Validate token
            if not UploadToken.validate(upload_token):
                return {"error": "Invalid upload token format"}
            
            # Get session
            db = await get_database()
            session = await db.get_session_by_token(upload_token)
            
            if not session:
                return {"error": "Upload session not found or expired"}
            
            if session.state == UploadState.COMPLETED:
                return {"error": "Upload session already completed"}
            
            if session.state in [UploadState.FAILED, UploadState.EXPIRED]:
                return {"error": f"Cannot commit upload in {session.state.value} state"}
            
            loop = asyncio.get_running_loop()
            session.meta = session.meta or {}
            sync_meta = session.meta.setdefault('sync', {
                'status': 'pending',
                'uploaded_bytes': 0,
                'total_bytes': session.size
            })
            sync_meta.setdefault('total_bytes', session.size)
            session.meta['phase'] = 'assembling'
            if sync_meta.get('status') in (None, 'pending', 'uploading'):
                sync_meta['status'] = 'pending'

            # Update state to assembling
            await db.update_session(session.id, state=UploadState.ASSEMBLING, meta=session.meta)

            try:
                # Get all parts
                parts = await db.get_parts(session.id)
                expected_parts = session.meta.get('expected_parts', 0)
                
                if len(parts) != expected_parts:
                    await db.update_session(session.id, state=UploadState.FAILED, 
                                          error=f"Missing parts: {len(parts)}/{expected_parts}")
                    return {"error": f"Missing parts: {len(parts)}/{expected_parts}"}
                
                # Assemble file
                assembled_file_path = await self._assemble_parts(session, parts)
                if not assembled_file_path:
                    await db.update_session(session.id, state=UploadState.FAILED, 
                                          error="Failed to assemble parts")
                    return {"error": "Failed to assemble file parts"}
                
                # Verify SHA256 if provided
                if verify_sha256 or session.sha256:
                    expected_hash = verify_sha256 or session.sha256
                    actual_hash = await self._calculate_file_sha256(assembled_file_path)
                    if actual_hash != expected_hash:
                        await db.update_session(session.id, state=UploadState.FAILED,
                                              error="File SHA256 verification failed")
                        return {"error": "File hash verification failed"}
                
                # Update state to committing
                session.meta['phase'] = 'syncing'
                sync_meta['status'] = 'starting'
                sync_meta['uploaded_bytes'] = 0
                sync_meta['total_bytes'] = session.size
                sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()

                await db.update_session(session.id, state=UploadState.COMMITTING, meta=session.meta)

                # Upload to Nucleus
                nucleus_client = await ensure_authenticated()
                target_path = f"{session.path_dir}/{session.filename}"

                logger.info(f"Committing assembled file to Nucleus: {target_path}")

                last_progress_update = 0.0

                async def on_sync_progress(sent_bytes: int, total_bytes: int):
                    nonlocal last_progress_update
                    now = loop.time()
                    if sent_bytes < total_bytes and (now - last_progress_update) < 1.0:
                        return
                    last_progress_update = now
                    sync_meta['status'] = 'uploading'
                    sync_meta['uploaded_bytes'] = sent_bytes
                    sync_meta['total_bytes'] = total_bytes
                    sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                    await db.update_session(session.id, meta=session.meta)

                upload_result = None
                last_error = None

                for attempt in range(1, self.commit_max_attempts + 1):
                    sync_meta['status'] = 'uploading'
                    sync_meta['uploaded_bytes'] = 0
                    sync_meta['error'] = None
                    sync_meta['attempt'] = attempt
                    sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                    await db.update_session(session.id, meta=session.meta)

                    last_progress_update = 0.0

                    upload_result = await nucleus_client.upload_file_single_shot(
                        str(assembled_file_path),
                        session.path_dir,
                        target_filename=session.filename,
                        progress_callback=on_sync_progress
                    )

                    if upload_result.get('status') == 'OK' or upload_result.get('response'):
                        break

                    last_error = upload_result.get('error', 'Unknown Nucleus error')
                    sync_meta['status'] = 'retrying' if attempt < self.commit_max_attempts else 'failed'
                    sync_meta['error'] = last_error
                    sync_meta['uploaded_bytes'] = upload_result.get('uploaded_bytes', sync_meta.get('uploaded_bytes', 0))
                    sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                    await db.update_session(session.id, meta=session.meta)

                    if attempt < self.commit_max_attempts:
                        await asyncio.sleep(2 * attempt)

                if upload_result and (upload_result.get('status') == 'OK' or upload_result.get('response')):
                    # Success - mark as completed
                    sync_meta.pop('attempt', None)
                    sync_meta.pop('error', None)
                    sync_meta['status'] = 'completed'
                    sync_meta['uploaded_bytes'] = session.size
                    sync_meta['total_bytes'] = session.size
                    sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                    session.meta['phase'] = 'completed'
                    await db.update_session(session.id, state=UploadState.COMPLETED, meta=session.meta, error=None)
                    
                    # Index the newly uploaded file in M5 search index
                    try:
                        await self._index_uploaded_file(target_path, session, assembled_file_path)
                    except Exception as e:
                        logger.warning(f"Failed to index uploaded file {target_path}: {e}")
                        # Don't fail the upload due to indexing issues
                    
                    # Clean up staging directory
                    session_staging_dir = self.staging_dir / session.id
                    shutil.rmtree(session_staging_dir, ignore_errors=True)
                    
                    logger.info(f"Successfully committed upload session {session.id} to Nucleus")
                    
                    return {
                        "status": "completed",
                        "filename": session.filename,
                        "size": session.size,
                        "target_path": target_path,
                        "nucleus_response": upload_result,
                        "indexed": True  # Indicate that file was indexed
                    }
                else:
                    # Failed - update state and return error
                    error_msg = last_error or upload_result.get('error', 'Unknown Nucleus error') if upload_result else 'Unknown Nucleus error'
                    sync_meta['status'] = 'failed'
                    sync_meta['uploaded_bytes'] = sync_meta.get('uploaded_bytes', 0)
                    sync_meta['total_bytes'] = session.size
                    sync_meta['error'] = error_msg
                    sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                    session.meta['phase'] = 'failed'
                    await db.update_session(session.id, state=UploadState.FAILED, error=error_msg, meta=session.meta)
                    
                    return {"error": f"Nucleus upload failed: {error_msg}"}
                    
            except Exception as e:
                # Update session state on any error
                sync_meta = session.meta.setdefault('sync', {})
                sync_meta['status'] = 'failed'
                sync_meta['error'] = str(e)
                sync_meta['uploaded_bytes'] = sync_meta.get('uploaded_bytes', 0)
                sync_meta.setdefault('total_bytes', session.size if 'session' in locals() and session else 0)
                sync_meta['updated_at'] = datetime.now(timezone.utc).isoformat()
                if 'session' in locals() and session:
                    session.meta['phase'] = 'failed'
                    await db.update_session(session.id, state=UploadState.FAILED, error=str(e), meta=session.meta)
                else:
                    await db.update_session(session.id, state=UploadState.FAILED, error=str(e))
                raise
                
        except Exception as e:
            logger.error(f"Error committing upload: {e}")
            return {"error": "Internal server error"}
    
    async def get_session_status(self, upload_token: str) -> Dict[str, Any]:
        """
        Get current status of an upload session.
        
        Args:
            upload_token: Upload session token
            
        Returns:
            Dictionary with session status and progress
        """
        try:
            if not UploadToken.validate(upload_token):
                return {"error": "Invalid upload token format"}
            
            db = await get_database()
            session = await db.get_session_by_token(upload_token)
            
            if not session:
                return {"error": "Upload session not found"}
            
            # Get parts info
            parts = await db.get_parts(session.id)
            received_parts = len(parts)
            expected_parts = session.meta.get('expected_parts', 0)
            
            # Build missing parts list
            received_indices = {part.index for part in parts}
            missing_parts = [i for i in range(expected_parts) if i not in received_indices]
            
            return {
                "session_id": session.id,
                "state": session.state.value,
                "phase": session.meta.get('phase'),
                "filename": session.filename,
                "size": session.size,
                "received_bytes": session.received_bytes,
                "progress": session.received_bytes / session.size if session.size > 0 else 0,
                "part_size": session.part_size,
                "received_parts": received_parts,
                "expected_parts": expected_parts,
                "missing_parts": missing_parts[:20],  # Limit to first 20 missing parts
                "sync": session.meta.get('sync', {}),
                "uploaded_parts": session.meta.get('uploaded_parts'),
                "meta": session.meta,
                "created_at": session.created_at.isoformat(),
                "error": session.error
            }
            
        except Exception as e:
            logger.error(f"Error getting session status: {e}")
            return {"error": "Internal server error"}
    
    async def cleanup_session(self, upload_token: str) -> Dict[str, Any]:
        """
        Clean up an upload session and its staging files.
        
        Args:
            upload_token: Upload session token
            
        Returns:
            Dictionary with cleanup status
        """
        try:
            if not UploadToken.validate(upload_token):
                return {"error": "Invalid upload token format"}
            
            db = await get_database()
            session = await db.get_session_by_token(upload_token)
            
            if not session:
                return {"error": "Upload session not found"}
            
            # Clean up staging directory
            session_staging_dir = self.staging_dir / session.id
            if session_staging_dir.exists():
                shutil.rmtree(session_staging_dir, ignore_errors=True)
            
            # Update session state to expired
            await db.update_session(session.id, state=UploadState.EXPIRED)
            
            logger.info(f"Cleaned up upload session {session.id}")
            
            return {"status": "cleaned_up", "session_id": session.id}
            
        except Exception as e:
            logger.error(f"Error cleaning up session: {e}")
            return {"error": "Internal server error"}
    
    async def _assemble_parts(self, session: UploadSession, parts: List[UploadPart]) -> Optional[Path]:
        """
        Assemble individual parts into a complete file.
        
        Args:
            session: Upload session
            parts: List of upload parts (should be ordered by index)
            
        Returns:
            Path to assembled file or None on failure
        """
        try:
            # Sort parts by index to ensure correct order
            parts.sort(key=lambda p: p.index)
            
            # Create temporary file for assembly
            session_staging_dir = self.staging_dir / session.id
            assembled_file_path = session_staging_dir / f"assembled_{session.filename}"
            
            total_written = 0
            
            with open(assembled_file_path, 'wb') as assembled_file:
                for part in parts:
                    part_path = Path(part.path_on_disk)
                    if not part_path.exists():
                        logger.error(f"Part file not found: {part_path}")
                        return None
                    
                    with open(part_path, 'rb') as part_file:
                        data = part_file.read()
                        if len(data) != part.size:
                            logger.error(f"Part size mismatch: expected {part.size}, got {len(data)}")
                            return None
                        
                        assembled_file.write(data)
                        total_written += len(data)
            
            # Verify total size
            if total_written != session.size:
                logger.error(f"Assembled file size mismatch: expected {session.size}, got {total_written}")
                return None
            
            logger.info(f"Successfully assembled {len(parts)} parts into {assembled_file_path} ({total_written} bytes)")
            return assembled_file_path
            
        except Exception as e:
            logger.error(f"Error assembling parts for session {session.id}: {e}")
            return None
    
    async def _calculate_file_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(65536), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA256 for {file_path}: {e}")
            return ""
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues"""
        if not filename:
            return ""
        
        # Remove path separators and dangerous characters
        import re
        # Keep only alphanumeric, dots, hyphens, underscores, spaces, and common file chars
        sanitized = re.sub(r'[^\w\-_. ]', '', filename)
        
        # Remove leading/trailing whitespace and dots
        sanitized = sanitized.strip('. ')
        
        # Limit length
        if len(sanitized) > 255:
            # Try to preserve extension
            name, ext = os.path.splitext(sanitized)
            if len(ext) <= 10:  # Reasonable extension length
                sanitized = name[:255-len(ext)] + ext
            else:
                sanitized = sanitized[:255]
        
        return sanitized
    
    async def _index_uploaded_file(self, target_path: str, session: UploadSession, file_path: Path):
        """
        Index a newly uploaded file in the M5 search database.
        
        Args:
            target_path: Full path where file was uploaded in Nucleus
            session: Upload session information
            file_path: Local path to the assembled file for metadata extraction
        """
        try:
            from app.services.file_indexer import get_file_indexer
            from app.db.sqlite import FileEntry, FileType, IndexStatus
            from datetime import datetime, timezone
            import mimetypes
            from pathlib import Path as PathlibPath
            
            # Get file indexer
            file_indexer = await get_file_indexer()
            
            # Calculate file metadata
            file_size = file_path.stat().st_size if file_path.exists() else session.size
            file_hash = await self._calculate_file_sha256(file_path) if file_path.exists() else session.sha256
            
            # Parse path components
            path_parts = PathlibPath(target_path)
            filename = path_parts.name
            parent_path = str(path_parts.parent) if path_parts.parent != path_parts else "/"
            
            # Guess content type
            content_type, _ = mimetypes.guess_type(filename)
            
            # Build file metadata for indexing
            file_info = {
                'name': filename,
                'type': 'file',  # All uploads are files
                'size': file_size,
                'created_by': session.user_id,
                'modified': datetime.now(timezone.utc).isoformat(),
                'hash': file_hash,
                'content_type': content_type,
                'upload_session': session.id  # Track which session created this
            }
            
            # Add upload metadata as tags
            if session.meta:
                file_info.update(session.meta)
            
            # Index the file
            success = await file_indexer.index_single_file(target_path, file_info)
            
            if success:
                logger.info(f"Successfully indexed uploaded file: {target_path}")
            else:
                logger.warning(f"Failed to index uploaded file: {target_path}")
                
        except Exception as e:
            logger.error(f"Error indexing uploaded file {target_path}: {e}")
            # Don't raise - indexing failures shouldn't fail uploads


# Global upload manager instance
_upload_manager: Optional[UploadManager] = None


async def get_upload_manager() -> UploadManager:
    """Get or create the global upload manager instance"""
    global _upload_manager
    if _upload_manager is None:
        _upload_manager = UploadManager()
    return _upload_manager
