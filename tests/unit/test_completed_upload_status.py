
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock

from app.db.sqlite import Database,UploadSession,UploadState
from app.services import upload_manager as module


def test_completed_session_remains_queryable_and_retry_does_not_upload(tmp_path,monkeypatch):
    async def run():
        db=Database(str(tmp_path/'sessions.db'));await db.initialize()
        session=UploadSession(id='done',token_id='completed-token',user_id='user',path_dir='/files',filename='large.bin',size=4096,sha256=None,part_size=4096,received_bytes=4096,created_at=datetime.now(),state=UploadState.COMPLETED,error=None,meta={'expected_parts':1})
        assert await db.create_session(session)
        found=await db.get_session_by_token('completed-token')
        assert found is not None and found.state==UploadState.COMPLETED
        monkeypatch.setattr(module,'get_database',AsyncMock(return_value=db))
        monkeypatch.setattr(module.UploadToken,'validate',lambda token:True)
        authenticate=AsyncMock();monkeypatch.setattr(module,'ensure_authenticated',authenticate)
        monkeypatch.setattr(module.settings,'staging_dir',str(tmp_path/'staging'))
        result=await module.UploadManager().commit_upload('completed-token')
        assert result['status']=='completed' and result['target_path']=='/files/large.bin'
        authenticate.assert_not_awaited()
    asyncio.run(run())
