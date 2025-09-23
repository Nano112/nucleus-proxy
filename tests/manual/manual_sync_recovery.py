#!/usr/bin/env python3
"""
Test sync recovery by simulating an interrupted upload
"""
import asyncio
import hashlib
import os
from pathlib import Path
import sys
import json
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.db.sqlite import get_database, UploadState, UploadSession, UploadPart


async def create_interrupted_session():
    """Create an upload session that appears to have been interrupted."""
    
    # Get database client
    db = await get_database()
    
    # Create a fake session that appears to have been interrupted during ASSEMBLING
    import uuid
    session_id_1 = str(uuid.uuid4())
    
    session = UploadSession(
        id=session_id_1,
        token_id='test-recovery-token-001',
        user_id='test-user',
        path_dir='/test',
        filename='interrupted_upload.txt',
        size=1024 * 100,  # 100KB
        sha256=hashlib.sha256(b'test content').hexdigest(),
        part_size=1024 * 10,  # 10KB parts
        received_bytes=1024 * 100,  # All bytes received
        created_at=datetime.now(timezone.utc),
        state=UploadState.ASSEMBLING,
        error=None,
        meta={
            'expected_parts': 10,
            'assembled_path': '/tmp/test_assembled.dat',
            'nucleus_path': '/test/interrupted_upload.txt',
            'content_type': 'text/plain'
        }
    )
    
    # Create the session
    await db.create_session(session)
    print(f"Created interrupted session: {session.id}")
    
    # Add parts to make it look complete
    for i in range(10):
        part = UploadPart(
            session_id=session.id,
            index=i,
            size=1024 * 10,
            sha256=hashlib.sha256(f'part{i}'.encode()).hexdigest(),
            path_on_disk=f'/tmp/part_{i}.dat'
        )
        await db.add_part(part)
    
    print(f"Added 10 parts to session {session.id}")
    
    # Create another session in PENDING state that's old
    session_id_2 = str(uuid.uuid4())
    
    old_session = UploadSession(
        id=session_id_2,
        token_id='test-recovery-token-002',
        user_id='test-user',
        path_dir='/test',
        filename='old_pending.txt',
        size=1024 * 50,
        sha256=hashlib.sha256(b'old content').hexdigest(),
        part_size=1024 * 10,
        received_bytes=1024 * 50,
        created_at=datetime.now(timezone.utc),
        state=UploadState.PENDING,
        error=None,
        meta={
            'expected_parts': 5,
            'content_type': 'text/plain'
        }
    )
    
    await db.create_session(old_session)
    
    # Manually update created_at to be 10 minutes ago
    import aiosqlite
    old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    async with aiosqlite.connect(db.db_path) as conn:
        await conn.execute(
            "UPDATE upload_sessions SET created_at = ? WHERE id = ?",
            (old_time.isoformat(), old_session.id)
        )
        await conn.commit()
    
    print(f"Created old pending session: {old_session.id}")
    
    # Add all parts for old session
    for i in range(5):
        part = UploadPart(
            session_id=old_session.id,
            index=i,
            size=1024 * 10,
            sha256=hashlib.sha256(f'oldpart{i}'.encode()).hexdigest(),
            path_on_disk=f'/tmp/old_part_{i}.dat'
        )
        await db.add_part(part)
    
    print(f"Added 5 parts to old session {old_session.id}")
    
    return session.id, old_session.id


async def check_recovery_results(session_ids):
    """Check if the sessions were recovered."""
    
    db = await get_database()
    
    for session_id in session_ids:
        session = await db.get_session(session_id)
        if session:
            print(f"\nSession {session_id}:")
            print(f"  State: {session.state}")
            print(f"  Filename: {session.filename}")
            if session.error:
                print(f"  Error: {session.error}")
            if session.meta.get('recovered_at'):
                print(f"  Recovered at: {session.meta['recovered_at']}")
            if session.meta.get('recovery_attempt'):
                print(f"  Recovery attempts: {session.meta['recovery_attempt']}")
        else:
            print(f"\nSession {session_id} not found")


async def main():
    print("Setting up test interrupted upload sessions...")
    
    # Create interrupted sessions
    session_ids = await create_interrupted_session()
    
    print(f"\nCreated test sessions: {session_ids}")
    print("\nNow restart the proxy server to trigger recovery on startup.")
    print("The sync recovery service should run 5 seconds after startup.")
    
    # Wait a moment
    await asyncio.sleep(2)
    
    print("\nChecking session states...")
    await check_recovery_results(session_ids)
    
    print("\n\nTo manually trigger recovery, you can call the recovery endpoint:")
    print("curl -X POST http://localhost:8088/admin/sync/recover")


if __name__ == "__main__":
    asyncio.run(main())