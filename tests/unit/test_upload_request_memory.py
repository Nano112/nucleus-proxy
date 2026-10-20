"""Regression: long multipart sessions must not retain earlier request bodies."""
import asyncio
import hashlib
import tracemalloc
from unittest.mock import AsyncMock

from sanic import Sanic
from sanic.compat import Header
from sanic.request import Request
from sanic.request.form import File, RequestParameters

from app.routes import uploads


def test_completed_parts_do_not_accumulate_in_retained_requests(monkeypatch):
    app = Sanic('upload-buffer-retention-regression')
    manager = AsyncMock()
    expected = hashlib.sha256(b'x' * (2 * 1024 * 1024)).hexdigest()

    async def persist(**kw):
        assert hashlib.sha256(kw['part_data']).hexdigest() == expected
        return {'received_parts': kw['part_index'] + 1}

    manager.upload_part.side_effect = persist
    monkeypatch.setattr(uploads, 'get_upload_manager', AsyncMock(return_value=manager))
    # Bypass only JWT middleware; exercise the actual Sanic multipart Request
    # and upload endpoint. Retain Request objects as a protocol/task cycle can.
    retained = []

    async def run():
        for index in range(24):
            request = Request(b'/v1/uploads/part', Header(), '1.1', 'POST', None, app)
            request.body = b'r' * (2 * 1024 * 1024)
            request.parsed_form = RequestParameters({'upload_token': ['test-token'], 'part_index': [str(index)]})
            request.parsed_files = RequestParameters({'part_data': [File('application/octet-stream', b'x' * (2 * 1024 * 1024), 'part.bin')]})
            response = await uploads.upload_part.__wrapped__(request)
            assert response.status == 200
            manager.reset_mock()  # The mock itself must not retain call payloads.
            retained.append(request)

    tracemalloc.start()
    try:
        asyncio.run(run())
        current, _ = tracemalloc.get_traced_memory()
        assert current < 8 * 1024 * 1024, f'Retained upload memory: {current}'
        assert len(retained) == 24
    finally:
        tracemalloc.stop()
