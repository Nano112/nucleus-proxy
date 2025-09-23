"""
Background cleanup service for completed upload sessions.
Ensures virtual files don't persist after successful uploads.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil

from app.db.sqlite import get_database, UploadState
from app.config import settings

logger = logging.getLogger(__name__)


class UploadCleanupService:
    """Service to clean up completed and expired upload sessions."""
    
    def __init__(self):
        self.cleanup_interval = 60  # Run every 60 seconds
        self.session_ttl_minutes = 5  # Keep completed sessions for 5 minutes
        self.failed_ttl_hours = 1  # Keep failed sessions for 1 hour
        self._task = None
        self._running = False
    
    async def start(self):
        """Start the cleanup service."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._cleanup_loop())
        logger.info("Upload cleanup service started")
    
    async def stop(self):
        """Stop the cleanup service."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Upload cleanup service stopped")
    
    async def _cleanup_loop(self):
        """Main cleanup loop."""
        while self._running:
            try:
                await self._cleanup_sessions()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(self.cleanup_interval)
    
    async def _cleanup_sessions(self):
        """Clean up completed and expired sessions."""
        try:
            db = await get_database()
            now = datetime.now(timezone.utc)
            
            # Get all sessions
            all_sessions = await db.get_all_sessions()
            cleaned = 0
            
            for session in all_sessions:
                should_clean = False
                reason = ""
                
                # Clean up completed sessions older than TTL
                if session.state == UploadState.COMPLETED:
                    age = now - session.created_at
                    if age > timedelta(minutes=self.session_ttl_minutes):
                        should_clean = True
                        reason = "completed session past TTL"
                
                # Clean up failed sessions older than TTL
                elif session.state == UploadState.FAILED:
                    age = now - session.created_at
                    if age > timedelta(hours=self.failed_ttl_hours):
                        should_clean = True
                        reason = "failed session past TTL"
                
                # Clean up expired sessions immediately
                elif session.state == UploadState.EXPIRED:
                    should_clean = True
                    reason = "expired session"
                
                if should_clean:
                    # Clean up staging directory
                    staging_dir = Path(settings.staging_dir) / session.id
                    if staging_dir.exists():
                        try:
                            shutil.rmtree(staging_dir)
                            logger.debug(f"Removed staging directory for session {session.id}")
                        except Exception as e:
                            logger.warning(f"Failed to remove staging directory {staging_dir}: {e}")
                    
                    # Delete session from database
                    try:
                        await db.delete_session(session.id)
                        logger.info(f"Cleaned up {reason}: {session.id} ({session.filename})")
                        cleaned += 1
                    except Exception as e:
                        logger.error(f"Failed to delete session {session.id}: {e}")
            
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} upload sessions")
                
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")


# Global instance
_cleanup_service = None


async def get_cleanup_service() -> UploadCleanupService:
    """Get or create the cleanup service instance."""
    global _cleanup_service
    if _cleanup_service is None:
        _cleanup_service = UploadCleanupService()
    return _cleanup_service


async def start_cleanup_service():
    """Start the cleanup service."""
    service = await get_cleanup_service()
    await service.start()


async def stop_cleanup_service():
    """Stop the cleanup service."""
    global _cleanup_service
    if _cleanup_service:
        await _cleanup_service.stop()
        _cleanup_service = None