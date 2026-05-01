"""
Nucleus WebSocket client with persistent connections.
Based on the working proof_of_concept.py implementation.
"""

import asyncio
import time
from websockets.client import connect as websocket_connect
from websockets.client import WebSocketClientProtocol
import json
import base64
import aiohttp
import logging
from typing import Dict, Any, Optional, Callable, Awaitable, List, Tuple
from app.config import settings

logger = logging.getLogger(__name__)


class NucleusAuthError(RuntimeError):
    """Raised when Nucleus credentials are denied."""
    pass


class NucleusConnectionError(RuntimeError):
    """Raised when the proxy cannot reach the Nucleus server."""
    pass


class NucleusClient:
    """NVIDIA Omniverse Nucleus WebSocket client with persistent connections."""

    def __init__(self, host: Optional[str] = None, k8s_mode: Optional[bool] = None, navigator_mode: Optional[bool] = None):
        self.host = host or settings.nucleus_host
        # When a custom host is provided, disable k8s_mode so we connect
        # directly to the external host rather than internal K8s service DNS.
        if k8s_mode is not None:
            self.k8s_mode = k8s_mode
        elif host and host != settings.nucleus_host:
            self.k8s_mode = False
        else:
            self.k8s_mode = settings.nucleus_k8s_mode

        # Navigator mode: connect via wss://host/omni/<service> on port 443
        # instead of ws://host:<port>/. Used for remote Nucleus servers behind
        # the NVIDIA Navigator reverse proxy.
        if navigator_mode is not None:
            self.navigator_mode = navigator_mode
        elif host and host != settings.nucleus_host:
            # Remote hosts default to navigator mode (reverse-proxied)
            self.navigator_mode = True
        else:
            self.navigator_mode = False

        self.auth_token: Optional[str] = None
        self.connection_token: Optional[str] = None
        self.connection_id: Optional[str] = None
        self.api_websocket: Optional[WebSocketClientProtocol] = None
        self._api_lock = asyncio.Lock()
        self.request_id = 1

        # Port mapping from proof of concept
        self.ports = {
            "discovery": 3333,  # DiscoverySearch.*
            "auth": 3100,  # Credentials.*
            "api": 3009,  # File operations (list, create, stat, etc.)
            "search": 3400,  # Search.*
            "tagging": 3020,  # TaggingService.*
            "lft": 3030,  # Large File Transfer (HTTP only)
        }

        # Navigator reverse proxy path mapping (wss on port 443)
        self.navigator_paths = {
            "discovery": "/omni/discovery",
            "auth": "/omni/auth",
            "api": "/omni/api2",
            "search": "/omni/search2",
            "tagging": "/omni/tagging2",
            "lft": "/omni/lft",
        }

        # Kubernetes Service DNS mapping
        self.k8s_hosts = {
            "discovery": "nucleus-discovery.nucleus.svc.cluster.local",
            "auth": "nucleus-auth.nucleus.svc.cluster.local",
            "api": "nucleus-api.nucleus.svc.cluster.local",
            "search": "nucleus-search.nucleus.svc.cluster.local",
            "tagging": "nucleus-tagging.nucleus.svc.cluster.local",
            "lft": "nucleus-lft.nucleus.svc.cluster.local",
        }

        # Headers for WebSocket connections to mimic browser behavior
        self.headers = {
            "Origin": f"https://{self.host}" if self.navigator_mode else f"http://{self.host}:8080",
            "User-Agent": "Mozilla/5.0 (compatible; Nucleus-Proxy/1.0)",
        }

    def _ws_url(self, service: str) -> str:
        """Build WebSocket URL for a service, respecting k8s/navigator modes."""
        if self.k8s_mode:
            host = self.k8s_hosts.get(service, self.host)
            return f"ws://{host}:{self.ports[service]}/"
        if self.navigator_mode:
            path = self.navigator_paths.get(service, f"/omni/{service}")
            return f"wss://{self.host}{path}"
        return f"ws://{self.host}:{self.ports[service]}/"

    def _lft_base_url(self, path: str = "") -> str:
        """Build LFT (Large File Transfer) HTTP URL."""
        if self.k8s_mode:
            host = self.k8s_hosts.get("lft", self.host)
            return f"http://{host}:{self.ports['lft']}{path}"
        if self.navigator_mode:
            return f"https://{self.host}/omni/lft{path}"
        return f"http://{self.host}:{self.ports['lft']}{path}"

    def get_next_request_id(self) -> int:
        """Get the next request ID for API calls."""
        current_id = self.request_id
        self.request_id += 1
        return current_id

    def encode_message(self, method: str, payload: Dict[str, Any]) -> bytes:
        """Encode WebSocket message in Omniverse SOWS binary format."""
        json_str = json.dumps(payload, separators=(",", ":"))
        json_bytes = json_str.encode("utf-8")

        # SOWS binary envelope: 5-byte header + method + null + length + payload
        message = bytearray([0x01, 0x01, 0x00, 0x00, 0x00])
        message.extend(method.encode("utf-8") + b"\x00")
        message.extend(len(json_bytes).to_bytes(4, "little"))
        message.extend(json_bytes)

        return bytes(message)

    _json_decoder = json.JSONDecoder()

    def decode_response(self, data) -> Dict[str, Any]:
        """Decode response from server.

        Handles concatenated JSON objects in a single frame by parsing
        only the first complete object (common with Navigator proxies).
        """
        try:
            # Handle string responses (JSON)
            if isinstance(data, str):
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    # Multiple concatenated JSON objects — parse the first one
                    obj, _ = self._json_decoder.raw_decode(data)
                    return obj

            # Handle binary responses (SOWS envelope)
            if isinstance(data, bytes):
                # Look for JSON data in binary response
                json_start = data.find(b"{")
                if json_start != -1:
                    json_str = data[json_start:].decode("utf-8")
                    try:
                        return json.loads(json_str)
                    except json.JSONDecodeError:
                        obj, _ = self._json_decoder.raw_decode(json_str)
                        return obj

                # If no JSON found, return raw data
                return {"raw": data.decode("utf-8", errors="ignore")}
        except Exception as e:
            logger.error(f"Decode error: {e}")
            return {"raw": str(data), "decode_error": str(e)}

    async def call_websocket_method(
        self, method: str, payload: Dict[str, Any], port: str
    ) -> Dict[str, Any]:
        """Basic WebSocket method call for non-API services (Discovery, Auth, Search, Tagging)."""
        url = self._ws_url(port)

        try:
            # Try to connect with headers, fallback without if needed
            ws = None
            try:
                ws = await websocket_connect(url, additional_headers=self.headers)
            except TypeError:
                try:
                    ws = await websocket_connect(url, extra_headers=self.headers)
                except TypeError:
                    logger.warning(f"Connecting to {url} without custom headers")
                    ws = await websocket_connect(url)

            # Encode message for SOWS services
            message = self.encode_message(method, payload)
            logger.debug(f"Sending binary to {port}: {method}")

            await ws.send(message)
            response = await asyncio.wait_for(ws.recv(), timeout=15)
            result = self.decode_response(response)

            await ws.close()
            return result

        except asyncio.TimeoutError:
            logger.error(f"Timeout on {url}")
            return {"error": "Request timeout"}
        except Exception as e:
            logger.error(f"WebSocket error on {url}: {e}")
            return {"error": str(e)}

    def _is_connection_error(self, exc: Exception) -> bool:
        """Check if an exception indicates a dead WebSocket that should be reconnected."""
        msg = str(exc).lower()
        return any(kw in msg for kw in ("keepalive", "ping timeout", "close frame", "1011", "connection closed", "no close frame"))

    async def _reconnect_api(self) -> bool:
        """Re-establish the persistent API WebSocket connection."""
        logger.warning("Reconnecting API WebSocket...")
        try:
            if self.api_websocket:
                try:
                    await self.api_websocket.close()
                except Exception:
                    pass
                self.api_websocket = None
            return await self.authorize_api_connection()
        except Exception as e:
            logger.error(f"Reconnect failed: {e}")
            return False

    async def call_api_method(
        self, payload: Dict[str, Any], streaming: bool = False, _retried: bool = False
    ) -> Dict[str, Any]:
        """Use the persistent authorized API connection for file operations."""
        if not self.api_websocket:
            if not await self._reconnect_api():
                return {"error": "No authorized API connection available"}

        async with self._api_lock:
            try:
                message = json.dumps(payload)
                logger.debug(f"Sending JSON via persistent API: {message}")
                await self.api_websocket.send(message)

                expected_id = payload.get("id")

                if streaming:
                    all_entries: List[Dict[str, Any]] = []
                    status: Optional[str] = None
                    try:
                        if not self.api_websocket:
                            if not await self.authorize_api_connection():
                                return {"error": "Failed to authorize API connection"}

                        while True:
                            response_data = await asyncio.wait_for(
                                self.api_websocket.recv(), timeout=15
                            )
                            response = self.decode_response(response_data)

                            if expected_id is not None and response.get("id") not in (
                                None,
                                expected_id,
                            ):
                                logger.debug(
                                    "Skipping response for request %s while waiting for %s",  # noqa: G004
                                    response.get("id"),
                                    expected_id,
                                )
                                continue

                            status = response.get("status")

                            # Handle error statuses immediately
                            if status and status not in {"OK", "DONE", "LATEST"}:
                                return response

                            # Accumulate entries if present
                            if response.get("entries"):
                                all_entries.extend(response["entries"])

                            if status in {"DONE", "LATEST"}:
                                result = response.copy()
                                if all_entries and not response.get("entries"):
                                    result["entries"] = all_entries
                                elif (
                                    all_entries
                                    and response.get("entries") is not all_entries
                                ):
                                    result["entries"] = all_entries
                                return result

                            if status == "INVALID" and not response.get("error"):
                                logger.debug(
                                    "Received interim INVALID status for %s; waiting for next frame",
                                    expected_id,
                                )
                                continue

                            # Continue reading on interim OK responses
                            continue

                    except asyncio.TimeoutError:
                        logger.warning("Timeout waiting for streaming response")
                        if all_entries:
                            return {"status": status or "OK", "entries": all_entries}
                        return {"status": status or "TIMEOUT"}
                    except Exception as e:
                        logger.error(f"Streaming API method failed: {e}")
                        return {"error": str(e)}

                    if all_entries:
                        return {"status": status or "OK", "entries": all_entries}
                    return {"status": status or "UNKNOWN"}

                # Single response
                while True:
                    response_data = await asyncio.wait_for(
                        self.api_websocket.recv(), timeout=15
                    )
                    response = self.decode_response(response_data)
                    if expected_id is not None and response.get("id") not in (
                        None,
                        expected_id,
                    ):
                        logger.debug(
                            "Ignoring response for request %s while awaiting %s",  # noqa: G004
                            response.get("id"),
                            expected_id,
                        )
                        continue
                    if response.get("status") == "INVALID" and not response.get(
                        "error"
                    ):
                        logger.debug(
                            "Received interim INVALID status for %s; waiting for next frame",
                            expected_id,
                        )
                        continue
                    return response

            except Exception as e:
                logger.error(f"API method call failed: {e}")
                if not _retried and self._is_connection_error(e):
                    logger.info("Connection lost — attempting reconnect and retry")
                    if await self._reconnect_api():
                        return await self.call_api_method(payload, streaming=streaming, _retried=True)
                return {"error": str(e)}

    def require_auth(self):
        """Check if authentication is required."""
        if not self.auth_token:
            raise ValueError("Authentication required - call authenticate() first")

    async def close(self):
        """Close persistent connections."""
        if self.api_websocket:
            await self.api_websocket.close()
            self.api_websocket = None

    # Authentication Service (port 3100)
    async def authenticate(
        self, username: Optional[str] = None, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticate with Credentials service."""
        username = username or settings.nucleus_username
        password = password or settings.nucleus_password

        payload = {"version": 1, "username": username, "password": password}
        result = await self.call_websocket_method("Credentials.auth", payload, "auth")

        if result.get("status") == "OK":
            self.auth_token = result.get("access_token")
            logger.info(f"✓ Authenticated as: {username}")
            return result
        else:
            logger.error(f"✗ Authentication failed: {result}")
            return result

    # API Service (port 3009) - File operations with persistent connection
    async def authorize_api_connection(self) -> bool:
        """Establish and authorize persistent API connection."""
        self.require_auth()

        # Close any existing connection
        if self.api_websocket:
            await self.api_websocket.close()
            self.api_websocket = None

        # Reset request ID counter for new connection
        self.request_id = 1

        url = self._ws_url("api")

        try:
            # Create persistent connection
            try:
                self.api_websocket = await websocket_connect(
                    url, additional_headers=self.headers
                )
            except TypeError:
                try:
                    self.api_websocket = await websocket_connect(
                        url, extra_headers=self.headers
                    )
                except TypeError:
                    self.api_websocket = await websocket_connect(url)

            # Send authorization payload with all capabilities from proof of concept
            payload = {
                "token": self.auth_token,
                "version": "1.19",
                "client_capabilities": {
                    "ping": 0,
                    "auth": 5,
                    "authorize_token": 4,
                    "subscribe_server_notifications": 0,
                    "stat2": 3,
                    "list": 4,
                    "list2": 6,
                    "subscribe_list": 3,
                    "service_subscribe_list": 1,
                    "service_resolve_acl": 1,
                    "create": 3,
                    "update": 1,
                    "create_asset": 2,
                    "update_asset": 1,
                    "create_asset_with_hash": 2,
                    "update_asset_with_hash": 1,
                    "create_object": 2,
                    "update_object": 1,
                    "deep_copy_object_struct": 0,
                    "read": 1,
                    "read_asset_version": 0,
                    "read_asset_resolved": 0,
                    "subscribe_read_asset": 1,
                    "read_object_version": 0,
                    "read_object_resolved": 0,
                    "subscribe_read_object": 2,
                    "rename": 2,
                    "rename2": 1,
                    "delete": 1,
                    "delete2": 3,
                    "undelete": 1,
                    "obliterate": 1,
                    "copy2": 3,
                    "create_directory": 1,
                    "lock": 2,
                    "unlock": 1,
                    "copy": 2,
                    "get_transaction_id": 0,
                    "set_path_options": 1,
                    "set_path_options2": 0,
                    "get_acl": 0,
                    "change_acl": 0,
                    "get_acl_v2": 0,
                    "get_acl_resolved": 0,
                    "set_acl_v2": 0,
                    "get_groups": 0,
                    "get_group_users": 0,
                    "get_users": 0,
                    "get_user_groups": 0,
                    "create_group": 0,
                    "rename_group": 0,
                    "remove_group": 0,
                    "add_user_to_group": 0,
                    "remove_user_from_group": 0,
                    "mount": 0,
                    "unmount": 0,
                    "get_mount_info": 0,
                    "checkpoint_version": 1,
                    "replace_version": 1,
                    "get_checkpoints": 1,
                    "get_branches": 1,
                },
                "id": self.get_next_request_id(),  # ID 1 for authorization
                "command": "authorize_token",
            }

            message = json.dumps(payload)
            logger.debug(f"Authorizing persistent API connection: {message}")
            await self.api_websocket.send(message)

            # Wait for authorization response
            response_data = await asyncio.wait_for(
                self.api_websocket.recv(), timeout=15
            )
            result = self.decode_response(response_data)

            if result.get("status") == "OK":
                self.connection_token = result.get("token")
                self.connection_id = result.get("connection_id")
                logger.info(f"✓ Persistent API connection authorized")
                logger.debug(f"  Connection ID: {self.connection_id}")
                logger.debug(f"  LFT address: {result.get('lft_address')}")
                return True
            else:
                logger.error(f"✗ API authorization failed: {result}")
                await self.api_websocket.close()
                self.api_websocket = None
                return False

        except Exception as e:
            logger.error(f"Failed to establish API connection: {e}")
            if self.api_websocket:
                await self.api_websocket.close()
                self.api_websocket = None
            return False

    # Core file operations using persistent API connection
    async def list_directory(
        self, path: str = "/", show_hidden: bool = True
    ) -> Dict[str, Any]:
        """List directory contents using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        # Ensure directory path has trailing slash
        if not path.endswith("/"):
            path = path + "/"

        payload = {
            "id": self.get_next_request_id(),
            "command": "list2",
            "path": path,
            "show_hidden": show_hidden,
        }

        return await self.call_api_method(payload, streaming=True)

    async def create_folder(self, path: str) -> Dict[str, Any]:
        """Create a folder using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        # Ensure path has a trailing slash for directories
        if not path.endswith("/"):
            path = path + "/"

        payload = {
            "id": self.get_next_request_id(),
            "command": "create_directory",
            "path": {"path": path},
        }

        return await self.call_api_method(payload, streaming=False)

    async def get_file_info(self, path: str) -> Dict[str, Any]:
        """Get file/folder information using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        payload = {
            "id": self.get_next_request_id(),
            "command": "stat2",
            "path": {"path": path},
        }

        # stat2 returns streaming responses - first the metadata, then DONE
        try:
            message = json.dumps(payload)
            logger.debug(f"Sending JSON via persistent API: {message}")
            await self.api_websocket.send(message)

            # Get first response which should be the metadata
            response_data = await asyncio.wait_for(
                self.api_websocket.recv(), timeout=15
            )
            result = self.decode_response(response_data)
            logger.debug(f"stat2 first response: {result}")

            # If we got the metadata (status=OK with data), try to read the final DONE status
            if result.get("status") == "OK" and "type" in result:
                try:
                    # Try to read the DONE status (optional)
                    done_data = await asyncio.wait_for(
                        self.api_websocket.recv(), timeout=2
                    )
                    done_response = self.decode_response(done_data)
                    logger.debug(f"stat2 done response: {done_response}")
                except asyncio.TimeoutError:
                    # No DONE response, that's ok
                    logger.debug("No DONE response for stat2, continuing")
                # Return the metadata result
                return result
            else:
                # Single response or error
                logger.debug(f"stat2 single/error response: {result}")
                return result

        except Exception as e:
            logger.error(f"API method call failed: {e}")
            return {"error": str(e)}

    async def delete_legacy(self, path: str) -> Dict[str, Any]:
        """Delete using legacy delete command (needed for folders)."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        # Legacy delete uses 'uri' field and requires trailing slash for folders
        payload = {"id": self.get_next_request_id(), "command": "delete", "uri": path}

        return await self.call_api_method(payload, streaming=False)

    async def delete_path(self, path: str, is_folder: bool = None) -> Dict[str, Any]:
        """Delete file or folder using persistent authorized connection.

        Automatically detects if path is a folder and uses appropriate method.
        """
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        # If not specified, try to detect if it's a folder
        if is_folder is None:
            # Check if we can determine from the path or need to stat it
            stat_result = await self.get_file_info(path)
            if stat_result.get("status") == "OK":
                file_type = stat_result.get("type", "")
                is_folder = file_type in ["folder", "directory", "mount"]
            else:
                # If stat fails, guess based on path
                is_folder = path.endswith("/") or not "." in path.split("/")[-1]

        # For folders, use legacy delete with trailing slash
        if is_folder:
            if not path.endswith("/"):
                path = path + "/"
            return await self.delete_legacy(path)

        # For files, use delete2
        payload = {
            "id": self.get_next_request_id(),
            "command": "delete2",
            "paths_to_delete": [{"path": path}],
        }

        result = await self.call_api_method(payload, streaming=False)

        # Handle the batch response format
        status = result.get("status")
        responses = result.get("responses", [])

        # If we have per-item responses, check the first one (we only sent one path)
        if responses and len(responses) > 0:
            item_status = responses[0]
            # Map individual item status to overall result
            if item_status in ["OK", "Done", "DONE"]:
                return {"status": "OK", "path": path}
            elif item_status in ["NotExist", "InvalidUri", "INVALID_URI"]:
                return {"status": "NOT_EXIST", "error": f"Path does not exist: {path}"}
            elif item_status == "Denied":
                return {"status": "DENIED", "error": f"Permission denied: {path}"}
            elif item_status == "FolderNotEmpty":
                return {
                    "status": "FOLDER_NOT_EMPTY",
                    "error": f"Folder is not empty: {path}",
                }
            else:
                return {
                    "status": item_status,
                    "error": f"Delete failed with status: {item_status}",
                }

        # Return the overall batch status if no per-item responses
        return result

    async def delete_paths_batch(self, paths: List[str]) -> Dict[str, Any]:
        """Delete multiple files or folders in a single batch operation.

        This is more efficient than calling delete_path multiple times.
        """
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        payload = {
            "id": self.get_next_request_id(),
            "command": "delete2",
            "paths_to_delete": [{"path": path} for path in paths],
        }

        result = await self.call_api_method(payload, streaming=False)

        # Handle the batch response format
        status = result.get("status")
        responses = result.get("responses", [])

        # Build detailed results for each path
        results = []
        for i, path in enumerate(paths):
            if i < len(responses):
                item_status = responses[i]
                if item_status in ["OK", "Done", "DONE"]:
                    results.append({"path": path, "status": "OK", "success": True})
                else:
                    results.append(
                        {
                            "path": path,
                            "status": item_status,
                            "success": False,
                            "error": self._get_error_message(item_status),
                        }
                    )
            else:
                # No individual response for this item
                results.append(
                    {
                        "path": path,
                        "status": "UNKNOWN",
                        "success": False,
                        "error": "No response from server",
                    }
                )

        return {
            "status": status,
            "results": results,
            "total": len(paths),
            "succeeded": sum(1 for r in results if r.get("success", False)),
            "failed": sum(1 for r in results if not r.get("success", False)),
        }

    def _get_error_message(self, status: str) -> str:
        """Get a human-readable error message for a status code."""
        error_map = {
            "NotExist": "Path does not exist",
            "Denied": "Permission denied",
            "FolderNotEmpty": "Folder is not empty",
            "InvalidPath": "Invalid path",
            "Unauthenticated": "Not authenticated",
            "ResourceBusy": "Resource is busy",
            "AlreadyExists": "Already exists",
            "NotImplemented": "Operation not implemented",
            "InternalError": "Internal server error",
            "Timeout": "Operation timed out",
            "OperationFailed": "Operation failed",
        }
        return error_map.get(status, f"Operation failed with status: {status}")

    async def rename2(self, paths_to_rename: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Rename or move files/folders using the modern batch API.

        Args:
            paths_to_rename: List of rename operations, each containing:
                - src: Dict with 'path' (required) and 'branch' (optional)
                - dst: Dict with 'path' (required) and 'branch' (optional)
                - message: Optional commit message

        Returns:
            Dict with 'status' and 'responses' array with per-item results
        """
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        payload = {
            "id": self.get_next_request_id(),
            "command": "rename2",
            "paths_to_rename": paths_to_rename,
        }

        result = await self.call_api_method(payload, streaming=False)

        # Process batch response
        status = result.get("status")
        responses = result.get("responses", [])

        # Build detailed results for each path
        results = []
        for i, item in enumerate(paths_to_rename):
            src_path = item["src"]["path"]
            dst_path = item["dst"]["path"]
            if i < len(responses):
                item_status = responses[i]
                if item_status in ["OK", "Done", "DONE"]:
                    results.append(
                        {
                            "src": src_path,
                            "dst": dst_path,
                            "status": "OK",
                            "success": True,
                        }
                    )
                else:
                    results.append(
                        {
                            "src": src_path,
                            "dst": dst_path,
                            "status": item_status,
                            "success": False,
                            "error": self._get_error_message(item_status),
                        }
                    )
            else:
                results.append(
                    {
                        "src": src_path,
                        "dst": dst_path,
                        "status": "UNKNOWN",
                        "success": False,
                        "error": "No response from server",
                    }
                )

        return {
            "status": status,
            "results": results,
            "total": len(paths_to_rename),
            "succeeded": sum(1 for r in results if r.get("success", False)),
            "failed": sum(1 for r in results if not r.get("success", False)),
        }

    async def move_file(
        self, source_path: str, dest_path: str, message: str = "Moved via Nucleus Proxy"
    ) -> Dict[str, Any]:
        """Move or rename a single file/folder (convenience method)."""
        result = await self.rename2(
            [
                {
                    "src": {"path": source_path},
                    "dst": {"path": dest_path},
                    "message": message,
                }
            ]
        )

        # Simplify response for single operation
        if result.get("results") and len(result["results"]) > 0:
            single_result = result["results"][0]
            return {
                "status": (
                    "OK"
                    if single_result.get("success")
                    else single_result.get("status", "ERROR")
                ),
                "src": source_path,
                "dst": dest_path,
                "error": (
                    single_result.get("error")
                    if not single_result.get("success")
                    else None
                ),
            }
        return result

    async def copy2(self, paths_to_copy: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Copy files/folders using the modern batch API with version support.

        Args:
            paths_to_copy: List of copy operations, each containing:
                - src: Dict with 'path' (required), 'branch' (optional), and 'checkpoint' (optional)
                - dst: Dict with 'path' (required) and 'branch' (optional)
                - message: Optional commit message

        Returns:
            Dict with 'status', 'responses' array, and 'transaction_ids' if available
        """
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}

        payload = {
            "id": self.get_next_request_id(),
            "command": "copy2",
            "paths_to_copy": paths_to_copy,
        }

        result = await self.call_api_method(payload, streaming=False)

        # Process batch response
        status = result.get("status")
        responses = result.get("responses", [])
        transaction_ids = result.get("transaction_ids", [])

        # Build detailed results for each path
        results = []
        for i, item in enumerate(paths_to_copy):
            src_path = item["src"]["path"]
            dst_path = item["dst"]["path"]
            checkpoint = item["src"].get("checkpoint")

            result_item = {"src": src_path, "dst": dst_path}
            if checkpoint:
                result_item["checkpoint"] = checkpoint

            if i < len(responses):
                item_status = responses[i]
                if item_status in ["OK", "Done", "DONE"]:
                    result_item.update({"status": "OK", "success": True})
                    if i < len(transaction_ids):
                        result_item["transaction_id"] = transaction_ids[i]
                else:
                    result_item.update(
                        {
                            "status": item_status,
                            "success": False,
                            "error": self._get_error_message(item_status),
                        }
                    )
            else:
                result_item.update(
                    {
                        "status": "UNKNOWN",
                        "success": False,
                        "error": "No response from server",
                    }
                )

            results.append(result_item)

        return {
            "status": status,
            "results": results,
            "total": len(paths_to_copy),
            "succeeded": sum(1 for r in results if r.get("success", False)),
            "failed": sum(1 for r in results if not r.get("success", False)),
            "transaction_ids": transaction_ids,
        }

    async def copy_file(
        self,
        source_path: str,
        dest_path: str,
        checkpoint: Optional[int] = None,
        message: str = "Copied via Nucleus Proxy",
    ) -> Dict[str, Any]:
        """Copy a single file/folder (convenience method).

        Args:
            source_path: Source file/folder path
            dest_path: Destination path
            checkpoint: Optional specific version to copy
            message: Optional commit message
        """
        copy_op = {
            "src": {"path": source_path},
            "dst": {"path": dest_path},
            "message": message,
        }
        if checkpoint:
            copy_op["src"]["checkpoint"] = checkpoint

        result = await self.copy2([copy_op])

        # Simplify response for single operation
        if result.get("results") and len(result["results"]) > 0:
            single_result = result["results"][0]
            return_val = {
                "status": (
                    "OK"
                    if single_result.get("success")
                    else single_result.get("status", "ERROR")
                ),
                "src": source_path,
                "dst": dest_path,
                "error": (
                    single_result.get("error")
                    if not single_result.get("success")
                    else None
                ),
            }
            if single_result.get("transaction_id"):
                return_val["transaction_id"] = single_result["transaction_id"]
            if checkpoint:
                return_val["checkpoint"] = checkpoint
            return return_val
        return result

    def _rewrite_download_url(self, url: str) -> str:
        """Rewrite a Nucleus download URL for navigator mode.

        Nucleus returns internal LFT URLs like http://<internal>:3030/path.
        When using navigator mode, rewrite to https://<host>/omni/lft/path.
        """
        if not self.navigator_mode:
            return url

        import re
        # Match http(s)://host:3030/path or http(s)://host:3030/path
        m = re.match(r'https?://[^/]+:3030(/.*)', url)
        if m:
            lft_path = m.group(1)
            return f"https://{self.host}/omni/lft{lft_path}"

        # Also handle URLs that don't have the port but point to LFT
        return url

    async def get_download_url(self, remote_path: str, _retried: bool = False) -> Dict[str, Any]:
        """Get temporary download URL for a file."""
        if not self.connection_token or not self.api_websocket:
            if not await self._reconnect_api():
                return {"error": "Failed to authorize API connection"}

        payload = {
            "id": self.get_next_request_id(),
            "command": "read",
            "uri": remote_path,
        }

        try:
            async with self._api_lock:
                message = json.dumps(payload)
                await self.api_websocket.send(message)

                while True:
                    response_data = await asyncio.wait_for(
                        self.api_websocket.recv(), timeout=15
                    )
                    response = self.decode_response(response_data)
                    if response and response.get("uri_redirection"):
                        raw_url = response["uri_redirection"]
                        download_url = self._rewrite_download_url(raw_url)
                        logger.info("Download URL: %s -> %s", raw_url, download_url)
                        return {"status": "OK", "download_url": download_url}
                    if response.get("status") in ["DONE", "LATEST"]:
                        break

            return {"error": "Could not retrieve download URL"}

        except Exception as e:
            if not _retried and self._is_connection_error(e):
                logger.info("Connection lost during download URL — reconnecting and retrying")
                if await self._reconnect_api():
                    return await self.get_download_url(remote_path, _retried=True)
            return {"error": f"Failed to get download URL: {e}"}

    # HTTP-based Large File Transfer (port 3030)
    async def upload_file_single_shot(
        self,
        local_file_path: str,
        remote_path: str,
        target_filename: Optional[str] = None,
        progress_callback: Optional[
            Callable[[int, int], Optional[Awaitable[None]]]
        ] = None,
    ) -> Dict[str, Any]:
        """Upload file using HTTP LFT service (single-shot).

        Args:
            local_file_path: Path to the local file to upload
            remote_path: Remote directory path to upload to
            target_filename: Optional target filename (defaults to basename of local_file_path)
        """
        self.require_auth()

        import os

        if not os.path.exists(local_file_path):
            return {"error": f"Local file not found: {local_file_path}"}

        # Use target_filename if provided, otherwise use basename of local file
        filename = target_filename or os.path.basename(local_file_path)
        file_size = os.path.getsize(local_file_path)

        # Ensure remote_path has trailing slash for directory
        if not remote_path.endswith("/"):
            remote_path = remote_path + "/"

        # Encode remote directory path for URL parameter
        encoded_path = base64.b64encode(remote_path.encode()).decode()

        url = self._lft_base_url("/path/bulk/")

        params = {
            "path": encoded_path,
            "token": self.auth_token,
            "message": "Uploaded via Nucleus Proxy",
        }

        async def maybe_report(callback, sent_bytes, total_bytes):
            if not callback:
                return
            result = callback(sent_bytes, total_bytes)
            if asyncio.iscoroutine(result):
                await result

        await maybe_report(progress_callback, 0, file_size)

        chunk_size = max(
            1024 * 1024, min(8 * 1024 * 1024, max(file_size // 64, 1024 * 1024))
        )
        bytes_sent = 0

        async def file_stream():
            nonlocal bytes_sent
            loop = asyncio.get_running_loop()
            with open(local_file_path, "rb") as file_handle:
                while True:
                    chunk = await loop.run_in_executor(
                        None, file_handle.read, chunk_size
                    )
                    if not chunk:
                        break
                    bytes_sent += len(chunk)
                    yield chunk
                    await maybe_report(
                        progress_callback, min(bytes_sent, file_size), file_size
                    )

        writer = aiohttp.MultipartWriter()
        size_part = writer.append(str(file_size))
        size_part.set_content_disposition("form-data", name="size")
        path_part = writer.append(filename)
        path_part.set_content_disposition("form-data", name="path")
        file_part = writer.append(
            file_stream(), headers={"Content-Type": "application/octet-stream"}
        )
        file_part.set_content_disposition("form-data", name="data", filename=filename)

        try:
            timeout = aiohttp.ClientTimeout(total=None)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, params=params, data=writer) as response:
                    if response.status in (200, 201, 204):
                        # Server may return various content types
                        raw_body = await response.read()
                        body_text = (
                            raw_body.decode("utf-8", errors="ignore")
                            if raw_body
                            else ""
                        )

                        # Try to parse JSON, fallback to success status
                        try:
                            result = json.loads(body_text) if body_text else {}
                        except json.JSONDecodeError:
                            result = {"response": body_text or f"{len(raw_body)} bytes"}

                        if isinstance(result, dict) and "status" not in result:
                            result["status"] = "OK"

                        await maybe_report(progress_callback, file_size, file_size)
                        logger.info(f"✓ Upload successful: {filename} -> {remote_path}")
                        return result
                    else:
                        content_type = response.headers.get("Content-Type", "")
                        text_body = await response.text()
                        error_msg = f"Upload failed: {response.status} ({content_type}) - {text_body}"
                        logger.error(f"✗ {error_msg}")
                        return {"error": error_msg, "uploaded_bytes": bytes_sent}

        except Exception as e:
            error_msg = f"Upload exception: {str(e)}"
            logger.error(f"✗ {error_msg}")
            return {"error": error_msg, "uploaded_bytes": bytes_sent}


class NucleusClientPool:
    """Pool of NucleusClient instances keyed by (host, username).

    Supports per-request credentials while reusing authenticated connections.
    Evicts least-recently-used clients when the pool exceeds max_size or
    a client has been idle longer than idle_timeout_seconds.
    """

    def __init__(self, max_size: int = 10, idle_timeout_seconds: float = 1800):
        self.max_size = max_size
        self.idle_timeout = idle_timeout_seconds
        # key -> (client, last_used_timestamp)
        self._clients: Dict[Tuple[str, str], Tuple[NucleusClient, float]] = {}
        self._lock = asyncio.Lock()

    def _key(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Tuple[str, str]:
        return (
            host or settings.nucleus_host,
            username or settings.nucleus_username,
        )

    async def get_client(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> NucleusClient:
        """Get an authenticated client for the given credentials.

        Creates and authenticates a new client if none exists for this
        (host, username) pair.
        """
        key = self._key(host, username)

        async with self._lock:
            await self._evict_expired()

            if key in self._clients:
                client, _ = self._clients[key]
                self._clients[key] = (client, time.monotonic())
                return client

            # Evict LRU if at capacity
            if len(self._clients) >= self.max_size:
                lru_key = min(self._clients, key=lambda k: self._clients[k][1])
                old_client, _ = self._clients.pop(lru_key)
                logger.info("Evicting idle Nucleus client for %s@%s", lru_key[1], lru_key[0])
                await old_client.close()

            # Create, authenticate, and authorize new client
            client = NucleusClient(host=host or settings.nucleus_host)
            auth_result = await client.authenticate(
                username=username or settings.nucleus_username,
                password=password or settings.nucleus_password,
            )
            if auth_result.get("status") != "OK":
                error_msg = auth_result.get("error", "")
                if auth_result.get("status") == "DENIED":
                    raise NucleusAuthError(f"Credentials denied for {key[1]}@{key[0]}")
                if "timeout" in str(error_msg).lower():
                    raise NucleusConnectionError(f"Cannot reach Nucleus at {key[0]}: {error_msg}")
                raise NucleusAuthError(f"Authentication failed for {key[1]}@{key[0]}: {auth_result}")

            if not await client.authorize_api_connection():
                await client.close()
                raise NucleusConnectionError(f"API authorization failed for {key[1]}@{key[0]}")

            self._clients[key] = (client, time.monotonic())
            return client

    async def get_default_client(self) -> NucleusClient:
        """Get the client using global config credentials."""
        return await self.get_client()

    async def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [
            k for k, (_, ts) in self._clients.items()
            if (now - ts) > self.idle_timeout
        ]
        for key in expired:
            client, _ = self._clients.pop(key)
            logger.info("Evicting expired Nucleus client for %s@%s", key[1], key[0])
            await client.close()

    async def close_all(self) -> None:
        """Close all pooled clients."""
        async with self._lock:
            for key, (client, _) in list(self._clients.items()):
                await client.close()
            self._clients.clear()


# ---------------------------------------------------------------------------
# Module-level pool + backwards-compatible helpers
# ---------------------------------------------------------------------------

_client_pool: Optional[NucleusClientPool] = None


def get_client_pool() -> NucleusClientPool:
    """Get or create the global client pool."""
    global _client_pool
    if _client_pool is None:
        _client_pool = NucleusClientPool()
    return _client_pool


async def get_nucleus_client() -> NucleusClient:
    """Backwards compatible — returns the default-credentials client."""
    return await get_client_pool().get_default_client()


async def reset_nucleus_client() -> None:
    """Reset the global pool. Used for testing."""
    global _client_pool
    if _client_pool:
        await _client_pool.close_all()
        _client_pool = None


async def ensure_authenticated() -> NucleusClient:
    """Backwards compatible — returns a fully authenticated default client."""
    return await get_client_pool().get_default_client()


async def get_nucleus_client_for_request(
    host: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> NucleusClient:
    """Get a client with per-request credentials."""
    return await get_client_pool().get_client(host, username, password)
