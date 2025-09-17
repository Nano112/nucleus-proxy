"""
Nucleus WebSocket client with persistent connections.
Based on the working proof_of_concept.py implementation.
"""

import asyncio
from websockets.client import connect as websocket_connect
from websockets.client import WebSocketClientProtocol
import json
import base64
import aiohttp
import logging
from typing import Optional, Dict, Any, List, Callable, Awaitable
from app.config import settings

logger = logging.getLogger(__name__)


class NucleusClient:
    """NVIDIA Omniverse Nucleus WebSocket client with persistent connections."""
    
    def __init__(self, host: Optional[str] = None):
        self.host = host or settings.nucleus_host
        self.auth_token: Optional[str] = None
        self.connection_token: Optional[str] = None
        self.connection_id: Optional[str] = None
        self.api_websocket: Optional[WebSocketClientProtocol] = None
        self.request_id = 1
        
        # Port mapping from proof of concept
        self.ports = {
            "discovery": 3333,    # DiscoverySearch.*
            "auth": 3100,         # Credentials.*
            "api": 3009,          # File operations (list, create, stat, etc.)
            "search": 3400,       # Search.*
            "tagging": 3020,      # TaggingService.*
            "lft": 3030          # Large File Transfer (HTTP only)
        }
        
        # Headers for WebSocket connections to mimic browser behavior
        self.headers = {
            'Origin': f'http://{self.host}:8080',
            'User-Agent': 'Mozilla/5.0 (compatible; Nucleus-Proxy/1.0)'
        }
    
    def get_next_request_id(self) -> int:
        """Get the next request ID for API calls."""
        current_id = self.request_id
        self.request_id += 1
        return current_id
    
    def encode_message(self, method: str, payload: Dict[str, Any]) -> bytes:
        """Encode WebSocket message in Omniverse SOWS binary format."""
        json_str = json.dumps(payload, separators=(',', ':'))
        json_bytes = json_str.encode('utf-8')
        
        # SOWS binary envelope: 5-byte header + method + null + length + payload
        message = bytearray([0x01, 0x01, 0x00, 0x00, 0x00])
        message.extend(method.encode('utf-8') + b'\x00')
        message.extend(len(json_bytes).to_bytes(4, 'little'))
        message.extend(json_bytes)
        
        return bytes(message)
    
    def decode_response(self, data) -> Dict[str, Any]:
        """Decode response from server."""
        try:
            # Handle string responses (JSON)
            if isinstance(data, str):
                return json.loads(data)
            
            # Handle binary responses (SOWS envelope)
            if isinstance(data, bytes):
                # Look for JSON data in binary response
                json_start = data.find(b'{')
                if json_start != -1:
                    json_data = data[json_start:].decode('utf-8')
                    return json.loads(json_data)
                
                # If no JSON found, return raw data
                return {"raw": data.decode('utf-8', errors='ignore')}
        except Exception as e:
            logger.error(f"Decode error: {e}")
            return {"raw": str(data), "decode_error": str(e)}
    
    async def call_websocket_method(self, method: str, payload: Dict[str, Any], port: str) -> Dict[str, Any]:
        """Basic WebSocket method call for non-API services (Discovery, Auth, Search, Tagging)."""
        url = f"ws://{self.host}:{self.ports[port]}/"
        
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
    
    async def call_api_method(self, payload: Dict[str, Any], streaming: bool = False) -> Dict[str, Any]:
        """Use the persistent authorized API connection for file operations."""
        if not self.api_websocket:
            raise ValueError("No authorized API connection available")
        
        try:
            message = json.dumps(payload)
            logger.debug(f"Sending JSON via persistent API: {message}")
            await self.api_websocket.send(message)
            

            if streaming:
                all_entries: List[Dict[str, Any]] = []
                status: Optional[str] = None
                try:
                    if not self.api_websocket:
                        if not await self.authorize_api_connection():
                            return {"error": "Failed to authorize API connection"}

                    while True:
                        response_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=15)
                        response = self.decode_response(response_data)

                        status = response.get("status")

                        # Handle error statuses immediately
                        if status and status not in {"OK", "DONE", "LATEST"}:
                            return response

                        # Accumulate entries if present
                        if response.get("entries"):
                            all_entries.extend(response["entries"])

                        # Treat OK/DONE/LATEST as completion states
                        if status in {"OK", "DONE", "LATEST"}:
                            if all_entries and not response.get("entries"):
                                response = {**response, "entries": all_entries}
                            elif all_entries and response.get("entries") is not all_entries:
                                response = {**response, "entries": all_entries}
                            return response

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

            else:
                # Single response
                response_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=15)
                return self.decode_response(response_data)
                
        except Exception as e:
            logger.error(f"API method call failed: {e}")
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
    async def authenticate(self, username: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate with Credentials service."""
        username = username or settings.nucleus_username
        password = password or settings.nucleus_password
        
        payload = {"version": 1, "username": username, "password": password}
        result = await self.call_websocket_method("Credentials.auth", payload, "auth")
        
        if result.get('status') == 'OK':
            self.auth_token = result.get('access_token')
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
        
        url = f"ws://{self.host}:{self.ports['api']}/"
        
        try:
            # Create persistent connection
            try:
                self.api_websocket = await websocket_connect(url, additional_headers=self.headers)
            except TypeError:
                try:
                    self.api_websocket = await websocket_connect(url, extra_headers=self.headers)
                except TypeError:
                    self.api_websocket = await websocket_connect(url)
            
            # Send authorization payload with all capabilities from proof of concept
            payload = {
                "token": self.auth_token,
                "version": "1.19",
                "client_capabilities": {
                    "ping": 0, "auth": 5, "authorize_token": 4, "subscribe_server_notifications": 0,
                    "stat2": 3, "list": 4, "list2": 6, "subscribe_list": 3, "service_subscribe_list": 1,
                    "service_resolve_acl": 1, "create": 3, "update": 1, "create_asset": 2, "update_asset": 1,
                    "create_asset_with_hash": 2, "update_asset_with_hash": 1, "create_object": 2,
                    "update_object": 1, "deep_copy_object_struct": 0, "read": 1, "read_asset_version": 0,
                    "read_asset_resolved": 0, "subscribe_read_asset": 1, "read_object_version": 0,
                    "read_object_resolved": 0, "subscribe_read_object": 2, "rename": 2, "rename2": 1,
                    "delete": 1, "delete2": 3, "undelete": 1, "obliterate": 1, "copy2": 3,
                    "create_directory": 1, "lock": 2, "unlock": 1, "copy": 2, "get_transaction_id": 0,
                    "set_path_options": 1, "set_path_options2": 0, "get_acl": 0, "change_acl": 0,
                    "get_acl_v2": 0, "get_acl_resolved": 0, "set_acl_v2": 0, "get_groups": 0,
                    "get_group_users": 0, "get_users": 0, "get_user_groups": 0, "create_group": 0,
                    "rename_group": 0, "remove_group": 0, "add_user_to_group": 0, "remove_user_from_group": 0,
                    "mount": 0, "unmount": 0, "get_mount_info": 0, "checkpoint_version": 1,
                    "replace_version": 1, "get_checkpoints": 1, "get_branches": 1
                },
                "id": self.get_next_request_id(),  # ID 1 for authorization
                "command": "authorize_token"
            }
            
            message = json.dumps(payload)
            logger.debug(f"Authorizing persistent API connection: {message}")
            await self.api_websocket.send(message)
            
            # Wait for authorization response
            response_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=15)
            result = self.decode_response(response_data)
            
            if result.get('status') == 'OK':
                self.connection_token = result.get('token')
                self.connection_id = result.get('connection_id')
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
    async def list_directory(self, path: str = "/", show_hidden: bool = True) -> Dict[str, Any]:
        """List directory contents using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}
        
        # Ensure directory path has trailing slash
        if not path.endswith('/'):
            path = path + '/'
        
        payload = {
            "id": self.get_next_request_id(),
            "command": "list2",
            "path": path,
            "show_hidden": show_hidden
        }
        
        return await self.call_api_method(payload, streaming=True)
    
    async def create_folder(self, path: str) -> Dict[str, Any]:
        """Create a folder using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}
        
        # Ensure path has a trailing slash for directories
        if not path.endswith('/'):
            path = path + '/'
        
        payload = {
            "id": self.get_next_request_id(),
            "command": "create_directory",
            "path": {"path": path}
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
            "path": {"path": path}
        }
        
        # stat2 returns streaming responses - first the metadata, then DONE
        try:
            message = json.dumps(payload)
            logger.debug(f"Sending JSON via persistent API: {message}")
            await self.api_websocket.send(message)
            
            # Get first response which should be the metadata
            response_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=15)
            result = self.decode_response(response_data)
            logger.debug(f"stat2 first response: {result}")
            
            # If we got the metadata (status=OK with data), try to read the final DONE status
            if result.get('status') == 'OK' and 'type' in result:
                try:
                    # Try to read the DONE status (optional)
                    done_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=2)
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
    
    async def delete_path(self, path: str) -> Dict[str, Any]:
        """Delete file or folder using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}
        
        payload = {
            "id": self.get_next_request_id(),
            "command": "delete2",
            "path": path
        }
        
        return await self.call_api_method(payload, streaming=False)
    
    async def move_file(self, source_path: str, dest_path: str, message: str = "Moved via Nucleus Proxy") -> Dict[str, Any]:
        """Move or rename a file/folder using persistent authorized connection."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}
        
        payload = {
            "id": self.get_next_request_id(),
            "command": "rename2",
            "paths_to_rename": [{
                "src": {"path": source_path},
                "dst": {"path": dest_path},
                "message": message
            }]
        }
        
        return await self.call_api_method(payload, streaming=False)
    
    async def get_download_url(self, remote_path: str) -> Dict[str, Any]:
        """Get temporary download URL for a file."""
        if not self.connection_token:
            if not await self.authorize_api_connection():
                return {"error": "Failed to authorize API connection"}
        
        payload = {
            "id": self.get_next_request_id(), 
            "command": "read", 
            "uri": remote_path
        }
        
        try:
            message = json.dumps(payload)
            await self.api_websocket.send(message)
            
            while True:
                response_data = await asyncio.wait_for(self.api_websocket.recv(), timeout=15)
                response = self.decode_response(response_data)
                if response and response.get("uri_redirection"):
                    return {"status": "OK", "download_url": response["uri_redirection"]}
                if response.get("status") in ["DONE", "LATEST"]:
                    break
            
            return {"error": "Could not retrieve download URL"}
            
        except Exception as e:
            return {"error": f"Failed to get download URL: {e}"}
    
    # HTTP-based Large File Transfer (port 3030)
    async def upload_file_single_shot(
        self,
        local_file_path: str,
        remote_path: str,
        target_filename: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], Optional[Awaitable[None]]]] = None,
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
        if not remote_path.endswith('/'):
            remote_path = remote_path + '/'
        
        # Encode remote directory path for URL parameter
        encoded_path = base64.b64encode(remote_path.encode()).decode()
        url = f"http://{self.host}:3030/path/bulk/"
        

        params = {
            'path': encoded_path,
            'token': self.auth_token,
            'message': 'Uploaded via Nucleus Proxy'
        }

        async def maybe_report(callback, sent_bytes, total_bytes):
            if not callback:
                return
            result = callback(sent_bytes, total_bytes)
            if asyncio.iscoroutine(result):
                await result

        await maybe_report(progress_callback, 0, file_size)

        chunk_size = max(1024 * 1024, min(8 * 1024 * 1024, max(file_size // 64, 1024 * 1024)))

        async def file_stream():
            sent = 0
            loop = asyncio.get_running_loop()
            with open(local_file_path, 'rb') as file_handle:
                while True:
                    chunk = await loop.run_in_executor(None, file_handle.read, chunk_size)
                    if not chunk:
                        break
                    sent += len(chunk)
                    yield chunk
                    await maybe_report(progress_callback, min(sent, file_size), file_size)

        writer = aiohttp.MultipartWriter()
        size_part = writer.append(str(file_size))
        size_part.set_content_disposition('form-data', name='size')
        path_part = writer.append(filename)
        path_part.set_content_disposition('form-data', name='path')
        file_part = writer.append(file_stream(), headers={'Content-Type': 'application/octet-stream'})
        file_part.set_content_disposition('form-data', name='data', filename=filename)

        try:
            timeout = aiohttp.ClientTimeout(total=None)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, params=params, data=writer) as response:
                    if response.status in (200, 201, 204):
                        # Server may return various content types
                        raw_body = await response.read()
                        body_text = raw_body.decode('utf-8', errors='ignore') if raw_body else ''

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
                        content_type = response.headers.get('Content-Type', '')
                        text_body = await response.text()
                        error_msg = f"Upload failed: {response.status} ({content_type}) - {text_body}"
                        logger.error(f"✗ {error_msg}")
                        return {"error": error_msg}

        except Exception as e:
            error_msg = f"Upload exception: {str(e)}"
            logger.error(f"✗ {error_msg}")
            return {"error": error_msg}



# Global client instance for reuse across requests
_nucleus_client: Optional[NucleusClient] = None


async def get_nucleus_client() -> NucleusClient:
    """Get or create the global Nucleus client instance."""
    global _nucleus_client
    if _nucleus_client is None:
        _nucleus_client = NucleusClient()
    return _nucleus_client


async def reset_nucleus_client() -> None:
    """Reset the global Nucleus client instance. Used for testing."""
    global _nucleus_client
    if _nucleus_client:
        await _nucleus_client.close()
        _nucleus_client = None


async def ensure_authenticated() -> NucleusClient:
    """Ensure the global client is authenticated and ready."""
    client = await get_nucleus_client()
    if not client.auth_token:
        auth_result = await client.authenticate()
        if auth_result.get('status') != 'OK':
            raise RuntimeError(f"Authentication failed: {auth_result}")
    # Ensure we have an authorized API connection
    if not client.connection_token:
        if not await client.authorize_api_connection():
            raise RuntimeError("Failed to authorize API connection")
    return client
