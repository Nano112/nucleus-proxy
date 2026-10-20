import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from app.db.sqlite import Database,UploadSession,UploadState
from app.services import upload_cleanup as module


def session(id,created_at,state=UploadState.COMPLETED):
    return UploadSession(id=id,token_id=id+'-token',user_id='user',path_dir='/files',filename=id+'.bin',size=1,sha256=None,part_size=1,received_bytes=1,created_at=created_at,state=state,error=None,meta={})


def test_cleanup_handles_sessions_stored_without_timezone(tmp_path,monkeypatch):
    async def run():
        db=Database(str(tmp_path/'sessions.db'));await db.initialize()
        old=datetime.now(timezone.utc)-timedelta(hours=2)
        assert await db.create_session(session('legacy',old.replace(tzinfo=None)))
        assert await db.create_session(session('current',old))
        assert await db.create_session(session('recent',datetime.now(timezone.utc)))
        assert all(s.created_at.tzinfo for s in await db.get_all_sessions())
        monkeypatch.setattr(module,'get_database',AsyncMock(return_value=db))
        monkeypatch.setattr(module.settings,'staging_dir',str(tmp_path/'staging'))
        await module.UploadCleanupService()._cleanup_sessions()
        assert [s.id for s in await db.get_all_sessions()]==['recent']
    asyncio.run(run())
