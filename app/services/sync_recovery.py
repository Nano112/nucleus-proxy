"""
Sync recovery service for handling interrupted uploads on proxy restart.

This service checks for pending upload sessions on startup and attempts to
resume or complete their sync to Nucleus.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from app.db.sqlite import Database, UploadState, get_database
from app.services.upload_manager import get_upload_manager

logger = logging.getLogger(__name__)


class SyncRecoveryService:
    """
    Service to recover and resume interrupted upload syncs after proxy restart.
    """
    
    def __init__(self, database: Database = None):
        self.database = database
        self.recovery_stats = {
            'sessions_found': 0,
            'sessions_resumed': 0,
            'sessions_completed': 0,
            'sessions_failed': 0,
            'sessions_expired': 0
        }
        self._recovery_in_progress = False
    
    async def initialize(self):
        """Initialize the recovery service."""
        if not self.database:
            self.database = await get_database()
        
        logger.info("Sync recovery service initialized")
    
    async def recover_interrupted_syncs(self) -> Dict[str, Any]:
        """
        Check for and recover interrupted upload syncs.
        
        This should be called on proxy startup to resume any uploads
        that were in progress when the proxy was stopped.
        
        Returns:
            Dictionary with recovery statistics
        """
        if self._recovery_in_progress:
            logger.warning("Recovery already in progress")
            return {'error': 'Recovery already in progress'}
        
        self._recovery_in_progress = True
        start_time = datetime.now(timezone.utc)
        
        try:
            logger.info("Starting sync recovery process...")
            
            # Query for sessions that need recovery
            sessions_to_recover = await self._find_sessions_to_recover()
            self.recovery_stats['sessions_found'] = len(sessions_to_recover)
            
            if not sessions_to_recover:
                logger.info("No sessions found for recovery")
                return self.recovery_stats
            
            logger.info(f"Found {len(sessions_to_recover)} sessions to recover")
            
            # Process each session
            upload_manager = await get_upload_manager()
            
            for session in sessions_to_recover:
                try:
                    await self._recover_session(session, upload_manager)
                except Exception as e:
                    logger.error(f"Error recovering session {session.id}: {e}")
                    self.recovery_stats['sessions_failed'] += 1
            
            # Log recovery results
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(f"Sync recovery completed in {elapsed:.1f}s: {self.recovery_stats}")
            
            return self.recovery_stats
            
        except Exception as e:
            logger.error(f"Sync recovery failed: {e}")
            return {'error': str(e), **self.recovery_stats}
        finally:
            self._recovery_in_progress = False
    
    async def _find_sessions_to_recover(self) -> List[Any]:
        """
        Find upload sessions that need recovery.
        
        Returns sessions that are:
        - In ASSEMBLING or COMMITTING state (interrupted mid-sync)
        - In PENDING state but older than 5 minutes (likely abandoned)
        - Not older than 24 hours (to avoid recovering very old sessions)
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            pending_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            
            # Get all sessions from database
            all_sessions = await self.database.get_all_sessions()
            
            sessions_to_recover = []
            for session in all_sessions:
                # Skip completed, failed, or expired sessions
                if session.state in [UploadState.COMPLETED, UploadState.FAILED, UploadState.EXPIRED]:
                    continue
                
                # Skip sessions older than 24 hours
                if session.created_at < cutoff_time:
                    # Mark as expired
                    await self.database.update_session(session.id, state=UploadState.EXPIRED)
                    self.recovery_stats['sessions_expired'] += 1
                    continue
                
                # Recover sessions in mid-sync states
                if session.state in [UploadState.ASSEMBLING, UploadState.COMMITTING]:
                    sessions_to_recover.append(session)
                    logger.info(f"Found session {session.id} in {session.state} state for recovery")
                
                # Recover old pending sessions that might be stuck
                elif session.state == UploadState.PENDING and session.created_at < pending_cutoff:
                    # Check if all parts are received
                    parts = await self.database.get_parts(session.id)
                    expected_parts = session.meta.get('expected_parts', 0)
                    
                    if len(parts) == expected_parts and expected_parts > 0:
                        sessions_to_recover.append(session)
                        logger.info(f"Found complete pending session {session.id} for recovery")
            
            return sessions_to_recover
            
        except Exception as e:
            logger.error(f"Error finding sessions to recover: {e}")
            return []
    
    async def _recover_session(self, session: Any, upload_manager: Any):
        """
        Attempt to recover a single upload session.
        
        Args:
            session: Upload session to recover
            upload_manager: Upload manager instance
        """
        try:
            logger.info(f"Recovering session {session.id} (state: {session.state})")
            
            # Check session parts
            parts = await self.database.get_parts(session.id)
            expected_parts = session.meta.get('expected_parts', 0)
            
            if len(parts) != expected_parts:
                logger.warning(f"Session {session.id} has incomplete parts ({len(parts)}/{expected_parts})")
                # Mark as failed if parts are missing
                await self.database.update_session(
                    session.id, 
                    state=UploadState.FAILED,
                    error="Incomplete parts after recovery"
                )
                self.recovery_stats['sessions_failed'] += 1
                return
            
            # Update session state to indicate recovery
            session.meta['recovered_at'] = datetime.now(timezone.utc).isoformat()
            session.meta['recovery_attempt'] = session.meta.get('recovery_attempt', 0) + 1
            await self.database.update_session(session.id, meta=session.meta)
            
            # Attempt to commit the upload
            logger.info(f"Attempting to commit recovered session {session.id}")
            result = await upload_manager.commit_upload(
                upload_token=session.token_id,
                verify_sha256=session.sha256
            )
            
            if result.get('status') == 'completed' or not result.get('error'):
                logger.info(f"Successfully recovered session {session.id}")
                self.recovery_stats['sessions_completed'] += 1
            else:
                logger.error(f"Failed to recover session {session.id}: {result.get('error')}")
                self.recovery_stats['sessions_failed'] += 1
            
            self.recovery_stats['sessions_resumed'] += 1
            
        except Exception as e:
            logger.error(f"Error in session recovery for {session.id}: {e}")
            self.recovery_stats['sessions_failed'] += 1
            
            # Mark session as failed if recovery fails
            try:
                await self.database.update_session(
                    session.id,
                    state=UploadState.FAILED,
                    error=f"Recovery failed: {str(e)}"
                )
            except:
                pass


# Global instance
_sync_recovery_service = None


async def get_sync_recovery_service() -> SyncRecoveryService:
    """Get or create the global sync recovery service instance."""
    global _sync_recovery_service
    if _sync_recovery_service is None:
        _sync_recovery_service = SyncRecoveryService()
        await _sync_recovery_service.initialize()
    return _sync_recovery_service


async def initialize_sync_recovery():
    """Initialize sync recovery service on startup."""
    service = await get_sync_recovery_service()
    
    # Schedule recovery to run shortly after startup
    async def run_recovery():
        await asyncio.sleep(5)  # Wait 5 seconds for other services to initialize
        logger.info("Running sync recovery check...")
        result = await service.recover_interrupted_syncs()
        if result.get('sessions_found', 0) > 0:
            logger.info(f"Sync recovery completed: {result}")
    
    asyncio.create_task(run_recovery())
    
    logger.info("Sync recovery service scheduled")


async def shutdown_sync_recovery():
    """Shutdown sync recovery service."""
    global _sync_recovery_service
    if _sync_recovery_service:
        logger.info("Shutting down sync recovery service")
        _sync_recovery_service = None