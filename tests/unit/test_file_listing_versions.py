import asyncio,json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from app.routes import files


def test_listing_exposes_authoritative_version_and_content_hash(monkeypatch):
    entry={'path':'/scene.usd','path_type':'asset','size':42,'modified_timestamp':123,'etag':'v7','hash_type':'sha-256-flat','hash_value':'abc','hash_bsize':1048576}
    client=SimpleNamespace(list_directory=AsyncMock(return_value={'status':'DONE','entries':[entry]}))
    monkeypatch.setattr(files,'ensure_authenticated',AsyncMock(return_value=client))
    monkeypatch.setattr(files,'ensure_path_permission',lambda *args:None)
    request=SimpleNamespace(args={'path':'/','include_syncing':'false'})
    response=asyncio.run(files.list_files.__wrapped__(request))
    item=json.loads(response.body)['entries'][0]
    assert item['modified_at']==123
    assert item['etag']=='v7'
    assert item['hash_type']=='sha-256-flat'
    assert item['hash_value']=='abc'
    assert item['hash_bsize']==1048576
