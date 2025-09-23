"""Unit tests for NucleusClient delete_path behaviour."""

import pytest
from unittest.mock import AsyncMock, patch

from app.nucleus.client import NucleusClient


@pytest.mark.asyncio
async def test_delete_path_client_behaviour():
    """Ensure delete_path delegates to call_api_method and handles responses."""
    client = NucleusClient("test-host")
    client.connection_token = "test-token"
    client.api_websocket = AsyncMock()
    client.request_id = 1

    with patch.object(client, "call_api_method", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"status": "OK"}
        result = await client.delete_path("/test/file.txt")

        mock_call.assert_called_once()
        payload = mock_call.call_args.args[0]
        assert payload["command"] == "delete2"
        assert payload["path"] == "/test/file.txt"
        assert result["status"] == "OK"

    with patch.object(client, "call_api_method", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"status": "INVALID"}
        result = await client.delete_path("/missing.txt")
        assert result["status"] == "INVALID"

    with patch.object(client, "call_api_method", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"error": "failure"}
        result = await client.delete_path("/broken.txt")
        assert result["error"] == "failure"
