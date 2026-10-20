"""
File operations routes using Nucleus client.
"""

import logging
import aiohttp
import re
from datetime import datetime, timezone
from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json, file_stream
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any, Tuple
from sanic_ext import validate

from app.nucleus.client import ensure_authenticated
from app.routes.auth import (
    ensure_path_permission,
    ensure_paths_permission,
    require_auth,
)
from app.services.file_indexer import get_file_indexer
from app.services.search_engine import (
    get_search_engine, SearchFilter, SearchSort, 
    SortField, SortOrder, FileType as SearchFileType
)

logger = logging.getLogger(__name__)

files_bp = Blueprint("files", url_prefix="/v1/files")


class FileEntry(BaseModel):
    path: str
    name: str
    type: str
    size: Optional[int] = None
    modified_at: Optional[str] = None
    created_by: Optional[str] = None


class ListResponse(BaseModel):
    entries: List[FileEntry]
    total: int
    path: str


class MkdirRequest(BaseModel):
    path: str


class RenameRequest(BaseModel):
    src: str
    dst: str
    message: Optional[str] = "Renamed via Nucleus Proxy"


class DeleteRequest(BaseModel):
    path: str


class BatchDeleteRequest(BaseModel):
    paths: List[str] = Field(..., description="List of paths to delete")


class RenamePathRequest(BaseModel):
    """Request model for renaming/moving a single path"""
    src: str = Field(..., description="Source path")
    dst: str = Field(..., description="Destination path")
    message: Optional[str] = Field("Renamed via Nucleus Proxy", description="Commit message")


class BatchRenameRequest(BaseModel):
    """Request model for batch rename/move operations"""
    paths_to_rename: List[Dict[str, Any]] = Field(..., description="List of rename operations")


class CopyPathRequest(BaseModel):
    """Request model for copying a single path"""
    src: str = Field(..., description="Source path")
    dst: str = Field(..., description="Destination path")
    checkpoint: Optional[int] = Field(None, description="Optional version checkpoint to copy")
    message: Optional[str] = Field("Copied via Nucleus Proxy", description="Commit message")


class BatchCopyRequest(BaseModel):
    """Request model for batch copy operations"""
    paths_to_copy: List[Dict[str, Any]] = Field(..., description="List of copy operations")


class FolderTreeRequest(BaseModel):
    """Request model for creating nested folder structures"""
    base_path: str = Field(..., description="Root path where the structure should be created")
    structure: Dict[str, Any] = Field(..., description="Nested dictionary describing folder hierarchy")

    @field_validator('structure')
    @classmethod
    def validate_structure(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(value, dict) or not value:
            raise ValueError('structure must be a non-empty object mapping folder names to children')
        return value


def _normalize_path(path: str) -> str:
    if not path:
        return '/'
    normalized = re.sub(r'/+', '/', path.replace('\\', '/'))
    if not normalized.startswith('/'):
        normalized = '/' + normalized
    if len(normalized) > 1 and normalized.endswith('/'):
        normalized = normalized[:-1]
    return normalized or '/'


def _normalize_segment(segment: str) -> str:
    if not isinstance(segment, str):
        raise ValueError('Folder names must be strings')
    cleaned = segment.strip().strip('/').strip()
    if not cleaned:
        raise ValueError('Folder names cannot be empty')
    if '/' in cleaned or '\\' in cleaned:
        raise ValueError(f'Folder name "{segment}" contains path separators')
    return cleaned


def _collect_folder_paths(base_path: str, structure: Dict[str, Any]) -> List[str]:
    paths: List[str] = []

    def _traverse(parent: str, node: Dict[str, Any]):
        if not isinstance(node, dict):
            raise ValueError('Each folder must map to an object describing its children')
        for name, child in node.items():
            folder_name = _normalize_segment(name)
            new_path = _normalize_path(f"{parent}/{folder_name}")
            paths.append(new_path)
            child_node = child or {}
            _traverse(new_path, child_node)

    _traverse(_normalize_path(base_path), structure)
    return paths


# M5 Search and Indexing Models

class SearchFilesRequest(BaseModel):
    """Request model for file search"""
    query: Optional[str] = Field(None, description="Full-text search query")
    file_types: Optional[List[str]] = Field(None, description="Filter by file types (file, directory, link)")
    size_min: Optional[int] = Field(None, ge=0, description="Minimum file size in bytes")
    size_max: Optional[int] = Field(None, ge=0, description="Maximum file size in bytes")
    modified_since: Optional[str] = Field(None, description="Modified since date (ISO format)")
    modified_until: Optional[str] = Field(None, description="Modified until date (ISO format)")
    created_by: Optional[str] = Field(None, description="Filter by creator username")
    parent_path: Optional[str] = Field(None, description="Filter by parent directory")
    has_tags: Optional[List[str]] = Field(None, description="Filter by tags")
    content_types: Optional[List[str]] = Field(None, description="Filter by content/MIME types")
    sort_field: Optional[str] = Field("name", description="Sort field (name, size, modified_at, created_by, path, type)")
    sort_order: Optional[str] = Field("asc", description="Sort order (asc, desc)")
    page: Optional[int] = Field(1, ge=1, description="Page number")
    page_size: Optional[int] = Field(50, ge=1, le=500, description="Results per page")

    @field_validator('file_types')
    @classmethod
    def validate_file_types(cls, v):
        if v:
            valid_types = {'file', 'directory', 'link'}
            invalid = set(v) - valid_types
            if invalid:
                raise ValueError(f"Invalid file types: {invalid}")
        return v

    @field_validator('sort_field')
    @classmethod
    def validate_sort_field(cls, v):
        valid_fields = {'name', 'size', 'modified_at', 'created_by', 'path', 'type'}
        if v not in valid_fields:
            raise ValueError(f"Invalid sort field: {v}")
        return v

    @field_validator('sort_order')
    @classmethod
    def validate_sort_order(cls, v):
        if v not in {'asc', 'desc'}:
            raise ValueError(f"Invalid sort order: {v}")
        return v


class UpdateTagsRequest(BaseModel):
    """Request model for updating file tags"""
    tags: Dict[str, Any] = Field(..., description="Tags to set for the file")


class SyncRequest(BaseModel):
    """Request model for index synchronization"""
    sync_type: str = Field("incremental", description="Sync type: 'full' or 'incremental'")
    root_path: Optional[str] = Field("/", description="Root path for full sync")
    since_hours: Optional[int] = Field(1, ge=1, le=168, description="Hours to look back for incremental sync")


@files_bp.get("/list", name="list_files")
@require_auth
async def list_files(request: Request) -> HTTPResponse:
    """
    List directory contents.

    Security: Bearer token required.

    Query Parameters:
    - path: string, directory path to list (default "/")
    - show_hidden: boolean, include dotfiles (default true)
    - include_syncing: boolean, include virtual files for uploads in progress (default true)

    Responses:
    - 200: `{ "entries": FileEntry[], "total": number, "path": string }`
    - 403/404/500: Error details
    """
    try:
        path = request.args.get('path', '/')
        show_hidden = request.args.get('show_hidden', 'true').lower() == 'true'
        include_syncing = request.args.get('include_syncing', 'true').lower() == 'true'

        permission_error = ensure_path_permission(request, path, "read")
        if permission_error:
            return permission_error

        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # List directory contents
        result = await client.list_directory(path, show_hidden)
        
        if result.get('status') not in ['OK', 'DONE', 'LATEST']:
            return sanic_json({
                "error": "Failed to list directory",
                "message": result.get('error', 'Unknown error')
            }, status=500)
        
        # Transform entries to API format
        entries = []
        existing_files = set()
        
        for entry in result.get('entries', []):
            # Extract name from path (last component)
            entry_path = entry.get('path', '')
            entry_name = entry_path.rstrip('/').split('/')[-1] if entry_path else ''
            existing_files.add(entry_name)
            
            entries.append({
                "path": entry_path,
                "name": entry_name,
                "type": entry.get('path_type', 'unknown'),
                "size": entry.get('size'),
                "modified_at": entry.get('modified_timestamp', entry.get('modified_time')),
                "created_by": entry.get('created_by'),
                "etag": entry.get('etag'),
                "hash_type": entry.get('hash_type'),
                "hash_value": entry.get('hash_value'),
                "hash_bsize": entry.get('hash_bsize')
            })
        
        # Add virtual files for currently syncing uploads if enabled
        if include_syncing:
            from app.db.sqlite import get_database, UploadState
            from pathlib import Path
            
            try:
                # Get all active upload sessions for this directory
                db = await get_database()
                all_sessions = await db.get_all_sessions()
                
                # Normalize the path for comparison
                normalized_path = path.rstrip('/') + '/' if not path.endswith('/') else path
                
                for session in all_sessions:
                    # Only show sessions that are actively being processed
                    if session.state in [UploadState.COMPLETED, UploadState.EXPIRED, UploadState.FAILED]:
                        continue
                    
                    # Check if this session is for the current directory
                    session_dir = session.path_dir.rstrip('/') + '/' if not session.path_dir.endswith('/') else session.path_dir
                    if session_dir != normalized_path:
                        continue
                    
                    # Skip if file already exists in Nucleus (upload completed but session not cleaned up)
                    if session.filename in existing_files:
                        continue
                    
                    # Only show virtual file if there's actual data staged on the proxy
                    # Check if staging directory exists and has data
                    from app.config import settings
                    staging_dir = Path(settings.staging_dir) / session.id
                    
                    # Skip sessions that don't have any actual data yet
                    if not staging_dir.exists():
                        continue
                    
                    # Check if there are actual part files
                    part_files = list(staging_dir.glob('part_*'))
                    if not part_files and not (staging_dir / f'assembled_{session.filename}').exists():
                        # No parts and no assembled file - skip this session
                        continue
                    
                    # Determine sync status based on session state and metadata
                    sync_status = "Unknown"
                    sync_progress = 0
                    sync_meta = session.meta.get('sync', {})
                    phase = session.meta.get('phase', 'pending')
                    
                    if session.state == UploadState.PENDING:
                        if session.received_bytes > 0:
                            # Calculate upload progress
                            received = session.received_bytes
                            total = session.size
                            sync_progress = (received / total * 100) if total > 0 else 0
                            
                            if sync_progress >= 100:
                                sync_status = "Ready to sync"
                            else:
                                sync_status = f"Uploading to proxy... ({sync_progress:.0f}%)"
                        else:
                            sync_status = "Starting upload..."
                    elif session.state == UploadState.ASSEMBLING:
                        sync_status = "Assembling file parts..."
                    elif session.state == UploadState.COMMITTING:
                        # Show sync progress if available
                        uploaded_bytes = sync_meta.get('uploaded_bytes', 0)
                        total_bytes = sync_meta.get('total_bytes', session.size)
                        if total_bytes > 0:
                            sync_progress = (uploaded_bytes / total_bytes * 100)
                            sync_status = f"Syncing to Nucleus... ({sync_progress:.0f}%)"
                        else:
                            sync_status = "Syncing to Nucleus..."
                    
                    # Add virtual file entry with clear indication it's temporary
                    virtual_entry = {
                        "path": f"{normalized_path}{session.filename}",
                        "name": session.filename,
                        "type": "file",
                        "size": session.size,
                        "modified_at": session.created_at.isoformat() if session.created_at else None,
                        "created_by": session.user_id,
                        "is_virtual": True,  # Mark as virtual file
                        "is_syncing": True,  # Additional flag to indicate active sync
                        "sync_status": sync_status,
                        "sync_progress": sync_progress,
                        "upload_session_id": session.id,
                        "upload_token": session.token_id,  # Include token for cancellation
                        "upload_state": session.state.value,
                        "has_staged_data": True  # Indicates actual data exists on proxy
                    }
                    
                    entries.append(virtual_entry)
                    
            except Exception as e:
                logger.warning(f"Failed to fetch virtual files for syncing uploads: {e}")
                # Don't fail the whole request if we can't get virtual files
        
        return sanic_json({
            "entries": entries,
            "total": len(entries),
            "path": path
        })
        
    except Exception as e:
        logger.error(f"List files error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to list directory contents"
        }, status=500)


@files_bp.get("/stat", name="stat_file")
@require_auth
async def stat_file(request: Request) -> HTTPResponse:
    """
    File or directory metadata.

    Security: Bearer token required.

    Query Parameters:
    - path: string, file/directory path (required)

    Responses:
    - 200: `{ "path": string, "type": string, "size": number|null, "modified_at": string|null, ... }`
    - 403: Access denied
    - 404/500: Error details
    """
    try:
        path = request.args.get('path')
        if not path:
            return sanic_json({"error": "path parameter required"}, status=400)

        permission_error = ensure_path_permission(request, path, "read")
        if permission_error:
            return permission_error

        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # Get file info
        result = await client.get_file_info(path)
        
        if result.get('status') not in ['OK', 'ALREADY_EXISTS']:
            if result.get('status') == 'DENIED':
                return sanic_json({
                    "error": "Access denied",
                    "message": f"No permission to access: {path}"
                }, status=403)
            return sanic_json({
                "error": "Failed to get file info",
                "message": result.get('error', f"Unknown status: {result.get('status', 'None')}")
            }, status=404)
        
        # Return file info - map from stat2 response format
        # stat2 returns: type, size, created_by, modified_by, created_date_seconds, modified_date_seconds
        file_type = result.get('type', 'unknown')
        if file_type == 'asset':
            file_type = 'file'  # Normalize 'asset' to 'file'
        elif file_type == 'folder':
            file_type = 'directory'
        
        return sanic_json({
            "path": path,
            "type": file_type,
            "size": result.get('size'),
            "modified_at": result.get('modified_date_seconds'),
            "created_by": result.get('created_by'),
            "created_at": result.get('created_date_seconds')
        })
        
    except Exception as e:
        logger.error(f"Stat file error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to get file information"
        }, status=500)


# Aliases for compatibility with tests/clients expecting these paths
@files_bp.get("/info", name="file_info_alias")
@require_auth
async def file_info_alias(request: Request) -> HTTPResponse:
    """Alias for stat_file at /v1/files/info"""
    return await stat_file(request)


@files_bp.post("/mkdir", name="create_directory")
@require_auth
async def create_directory(request: Request) -> HTTPResponse:
    """
    Create directory.

    Security: Bearer token required.

    Request Body (application/json):
    - path: string, directory path to create

    Responses:
    - 200: `{ "message": "Directory created successfully", "path": string }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        data = request.json
        if not data:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            mkdir_req = MkdirRequest(**data)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)

        permission_error = ensure_path_permission(request, mkdir_req.path, "write")
        if permission_error:
            return permission_error

        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # Create directory
        result = await client.create_folder(mkdir_req.path)
        
        if result.get('status') not in ['OK', 'DONE', 'ALREADY_EXISTS']:
            return sanic_json({
                "error": "Failed to create directory",
                "message": result.get('error', f"Unknown status: {result.get('status', 'None')}")
            }, status=500)
        
        return sanic_json({
            "message": "Directory created successfully",
            "path": mkdir_req.path
        })
        
    except Exception as e:
        logger.error(f"Create directory error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to create directory"
        }, status=500)


@files_bp.post("/create-directory", name="create_directory_alias")
@require_auth
async def create_directory_alias(request: Request) -> HTTPResponse:
    """Alias for create_directory at /v1/files/create-directory"""
    return await create_directory(request)


@files_bp.post("/mkdir/tree", name="create_directory_tree")
@require_auth
async def create_directory_tree(request: Request) -> HTTPResponse:
    """Create a nested folder structure under a base path."""

    try:
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        tree_req = FolderTreeRequest(**request.json)
    except Exception as exc:
        return sanic_json({"error": f"Invalid request data: {exc}"}, status=400)

    base_path = _normalize_path(tree_req.base_path)

    try:
        folder_paths = _collect_folder_paths(base_path, tree_req.structure)
    except ValueError as exc:
        return sanic_json({"error": str(exc)}, status=400)

    all_paths = [base_path, *folder_paths]
    permission_error = ensure_paths_permission(request, all_paths, "write")
    if permission_error:
        return permission_error

    client = await ensure_authenticated()

    success_statuses = {"OK", "Done", "DONE", "ALREADY_EXISTS", "AlreadyExists"}
    existing_statuses = {"ALREADY_EXISTS", "AlreadyExists"}

    created_count = 0
    existing_count = 0
    failed_entries: List[Dict[str, Any]] = []
    details: List[Dict[str, Any]] = []

    for path in all_paths:
        try:
            result = await client.create_folder(path)
        except Exception as exc:
            error_entry = {
                "path": path,
                "status": "ERROR",
                "error": str(exc),
            }
            failed_entries.append(error_entry)
            details.append(error_entry)
            continue

        status = result.get('status', 'UNKNOWN')
        entry = {
            "path": path,
            "status": status,
        }
        if result.get('error'):
            entry['error'] = result['error']
        details.append(entry)

        if status in success_statuses and not result.get('error'):
            if status in existing_statuses:
                existing_count += 1
            else:
                created_count += 1
        else:
            failed_entries.append({
                "path": path,
                "status": status,
                "error": result.get('error') or result.get('message') or 'Failed to create directory',
            })

    response_payload = {
        "base_path": base_path,
        "requested": len(all_paths),
        "created": created_count,
        "existing": existing_count,
        "failed": failed_entries,
        "details": details,
    }

    status_code = 200 if not failed_entries else 207
    return sanic_json(response_payload, status=status_code)


# Rename endpoint removed - new implementation below with better error handling


@files_bp.post("/delete", name="delete_path")
@require_auth
async def delete_path(request: Request) -> HTTPResponse:
    """
    Delete a file or folder.

    Security: Bearer token required.

    Request Body (application/json):
    - path: string, path to delete (required)
    - cancel_upload: bool, if true and path is a virtual file, cancel the upload (optional)

    Responses:
    - 200: `{ "status": "OK", "path": string }`
    - 403: Access denied
    - 404: Path not found
    - 500: Error details
    """
    try:
        # Parse and validate request
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            delete_req = DeleteRequest(**request.json)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)

        permission_error = ensure_path_permission(request, delete_req.path, "write")
        if permission_error:
            return permission_error

        # Check if this is a virtual file (upload in progress)
        # Extract directory and filename from path
        path_parts = delete_req.path.rstrip('/').rsplit('/', 1)
        if len(path_parts) == 2:
            dir_path, filename = path_parts
            dir_path = dir_path + '/' if dir_path else '/'
        else:
            dir_path = '/'
            filename = path_parts[0] if path_parts else ''
        
        # Check for active upload sessions for this file
        from app.db.sqlite import get_database, UploadState
        from app.services.upload_manager import get_upload_manager
        from app.config import settings
        from pathlib import Path as PathLib
        import shutil
        
        db = await get_database()
        all_sessions = await db.get_all_sessions()
        
        # Look for matching upload session
        for session in all_sessions:
            # Skip completed/expired sessions
            if session.state in [UploadState.COMPLETED, UploadState.EXPIRED]:
                continue
                
            # Check if this session matches the file to delete
            session_dir = session.path_dir.rstrip('/') + '/' if session.path_dir else '/'
            if session_dir == dir_path and session.filename == filename:
                # Found a matching upload session - this is a virtual file
                logger.info(f"Canceling upload session {session.id} for virtual file {delete_req.path}")
                
                # Cancel the upload
                upload_manager = await get_upload_manager()
                
                # Mark session as expired/canceled
                await db.update_session(session.id, state=UploadState.EXPIRED, error="Upload canceled by user")
                
                # Clean up staging directory
                staging_dir = PathLib(settings.staging_dir) / session.id
                if staging_dir.exists():
                    try:
                        shutil.rmtree(staging_dir)
                        logger.info(f"Cleaned up staging directory for session {session.id}")
                    except Exception as cleanup_error:
                        logger.warning(f"Failed to clean up staging directory: {cleanup_error}")
                
                return sanic_json({
                    "status": "OK",
                    "path": delete_req.path,
                    "message": "Upload canceled and staged data removed",
                    "was_virtual": True,
                    "session_id": session.id
                })
        
        # Not a virtual file - proceed with normal deletion from Nucleus
        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        # Delete file/directory
        result = await client.delete_path(delete_req.path)
        
        status = result.get('status')
        
        # Handle various response statuses
        if status in ['OK', 'DONE', 'Done']:
            return sanic_json({
                "message": "File deleted successfully",
                "path": delete_req.path
            })
        elif status in ['NOT_EXIST', 'NotExist', 'INVALID_URI', 'InvalidUri']:
            return sanic_json({
                "error": "File not found",
                "message": f"The path '{delete_req.path}' does not exist"
            }, status=404)
        elif status == 'DENIED' or status == 'Denied':
            return sanic_json({
                "error": "Permission denied",
                "message": f"You don't have permission to delete '{delete_req.path}'"
            }, status=403)
        elif status == 'FOLDER_NOT_EMPTY' or status == 'FolderNotEmpty':
            return sanic_json({
                "error": "Folder not empty",
                "message": f"Cannot delete '{delete_req.path}' because it is not empty"
            }, status=400)
        elif status == 'INVALID_PARAMETERS' or status == 'InvalidParameters':
            return sanic_json({
                "error": "Invalid parameters",
                "message": f"The delete request parameters are invalid. Path: '{delete_req.path}'"
            }, status=400)
        elif status == 'PartiallyCompleted' or status == 'PARTIALLY_COMPLETED':
            # This happens in batch operations when some items fail
            error_msg = result.get('error', 'Some items could not be deleted')
            return sanic_json({
                "error": "Partial failure",
                "message": error_msg
            }, status=207)  # 207 Multi-Status
        else:
            # Generic error for other statuses
            error_msg = result.get('error', result.get('message', f'Delete failed with status: {status}'))
            logger.warning(f"Delete failed with status {status}: {error_msg} for path {delete_req.path}")
            return sanic_json({
                "error": "Failed to delete file",
                "message": error_msg,
                "status": status
            }, status=500)
        
    except Exception as e:
        logger.error(f"Delete file error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to delete file"
        }, status=500)


@files_bp.get("/download", name="download_file")
@require_auth
async def download_file(request: Request) -> HTTPResponse:
    """
    Download file (redirect).

    Security: Bearer token required.

    Query Parameters:
    - path: string, file path to download (required)

    Responses:
    - 302: Redirect to Nucleus pre‑signed download URL
    - 400/404/500: Error details
    """
    try:
        path = request.args.get('path')
        if not path:
            return sanic_json({"error": "path parameter required"}, status=400)

        permission_error = ensure_path_permission(request, path, "read")
        if permission_error:
            return permission_error

        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # Get download URL from Nucleus
        url_result = await client.get_download_url(path)
        
        if url_result.get('status') != 'OK':
            return sanic_json({
                "error": "Failed to get download URL",
                "message": url_result.get('error', 'File not accessible')
            }, status=404)
        
        download_url = url_result.get('download_url')
        if not download_url:
            return sanic_json({
                "error": "No download URL available",
                "message": "File may not exist or is not accessible"
            }, status=404)
        
        # For now, return a redirect to the download URL
        # In production, you might want to proxy/stream the file
        from sanic.response import redirect
        return redirect(download_url)
        
    except Exception as e:
        logger.error(f"Download file error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to download file"
        }, status=500)


@files_bp.post("/upload", name="upload_file")
@require_auth
async def upload_file(request: Request) -> HTTPResponse:
    """
    Upload file (single‑shot).

    Security: Bearer token required.

    Form Data (multipart/form‑data):
    - file: binary, the file to upload
    - path: string, destination directory path

    Responses:
    - 200: `{ "message": "File uploaded successfully", "filename": string, "destination": string, "size": number }`
    - 400/500: Error details
    """
    try:
        # Check if file is in request
        if not request.files or 'file' not in request.files:
            return sanic_json({"error": "No file provided"}, status=400)
        
        uploaded_file = request.files['file'][0]
        destination_path = request.form.get('path', '/')

        if not uploaded_file.name:
            return sanic_json({"error": "No filename provided"}, status=400)

        permission_error = ensure_path_permission(request, destination_path, "write")
        if permission_error:
            return permission_error

        # Save uploaded file temporarily
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(uploaded_file.body)
            temp_file_path = temp_file.name
        
        try:
            # Get authenticated Nucleus client
            client = await ensure_authenticated()
            
            # Upload to Nucleus with original filename
            result = await client.upload_file_single_shot(temp_file_path, destination_path, uploaded_file.name)
            
            if result.get('status') == 'OK' or result.get('response'):
                return sanic_json({
                    "message": "File uploaded successfully",
                    "filename": uploaded_file.name,
                    "destination": destination_path,
                    "size": len(uploaded_file.body)
                })
            else:
                return sanic_json({
                    "error": "Upload failed",
                    "message": result.get('error', 'Unknown error')
                }, status=500)
        
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except:
                pass
        
    except Exception as e:
        logger.error(f"Upload file error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to upload file"
        }, status=500)


@files_bp.post("/rename", name="rename_path")
@require_auth
async def rename_path(request: Request) -> HTTPResponse:
    """
    Rename or move a file/folder.

    Security: Bearer token required.

    Request Body (application/json):
    - src: string, source path (required)
    - dst: string, destination path (required)
    - message: string, commit message (optional)

    Responses:
    - 200: `{ "status": "OK", "src": string, "dst": string }`
    - 400: Invalid request
    - 403: Access denied
    - 404: Source path not found
    - 409: Destination already exists
    - 500: Error details
    """
    try:
        body = RenamePathRequest(**(request.json or {}))

        permission_error = ensure_paths_permission(request, [body.src, body.dst], "write")
        if permission_error:
            return permission_error

        client = await ensure_authenticated()
        result = await client.move_file(body.src, body.dst, body.message)
        
        status = result.get('status')
        
        # Handle various status codes
        if status == 'OK':
            return sanic_json({
                "status": "OK",
                "src": body.src,
                "dst": body.dst,
                "message": f"Successfully moved {body.src} to {body.dst}"
            })
        elif status == 'NOT_EXIST':
            return sanic_json({
                "error": "Source path not found",
                "path": body.src
            }, status=404)
        elif status == 'DENIED':
            return sanic_json({
                "error": "Permission denied",
                "src": body.src,
                "dst": body.dst
            }, status=403)
        elif status == 'AlreadyExists':
            return sanic_json({
                "error": "Destination already exists",
                "path": body.dst
            }, status=409)
        else:
            return sanic_json({
                "error": result.get('error', f"Operation failed with status: {status}"),
                "status": status,
                "src": body.src,
                "dst": body.dst
            }, status=500)
            
    except ValueError as e:
        return sanic_json({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Rename path error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": str(e)
        }, status=500)


@files_bp.post("/rename/batch", name="rename_paths_batch")
@require_auth
async def rename_paths_batch(request: Request) -> HTTPResponse:
    """
    Batch rename or move multiple files/folders.

    Security: Bearer token required.

    Request Body (application/json):
    - paths_to_rename: array of rename operations, each with:
      - src: object with 'path' (required) and 'branch' (optional)
      - dst: object with 'path' (required) and 'branch' (optional)
      - message: string, commit message (optional)

    Responses:
    - 200: `{ "status": string, "results": array, "succeeded": number, "failed": number }`
    - 400: Invalid request
    - 500: Error details
    """
    try:
        body = BatchRenameRequest(**(request.json or {}))

        paths_to_check = []
        for operation in body.paths_to_rename:
            if not isinstance(operation, dict):
                continue
            src_path = (operation.get('src') or {}).get('path')
            dst_path = (operation.get('dst') or {}).get('path')
            if src_path:
                paths_to_check.append(src_path)
            if dst_path:
                paths_to_check.append(dst_path)

        if paths_to_check:
            permission_error = ensure_paths_permission(request, paths_to_check, "write")
            if permission_error:
                return permission_error

        client = await ensure_authenticated()
        result = await client.rename2(body.paths_to_rename)
        
        # Return detailed batch results
        return sanic_json(result)
        
    except ValueError as e:
        return sanic_json({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Batch rename error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": str(e)
        }, status=500)


@files_bp.post("/copy", name="copy_path")
@require_auth
async def copy_path(request: Request) -> HTTPResponse:
    """
    Copy a file/folder.

    Security: Bearer token required.

    Request Body (application/json):
    - src: string, source path (required)
    - dst: string, destination path (required)
    - checkpoint: integer, optional version checkpoint to copy
    - message: string, commit message (optional)

    Responses:
    - 200: `{ "status": "OK", "src": string, "dst": string, "transaction_id": number|null }`
    - 400: Invalid request
    - 403: Access denied
    - 404: Source path not found
    - 409: Destination already exists
    - 500: Error details
    """
    try:
        body = CopyPathRequest(**(request.json or {}))

        read_error = ensure_path_permission(request, body.src, "read")
        if read_error:
            return read_error
        write_error = ensure_path_permission(request, body.dst, "write")
        if write_error:
            return write_error

        client = await ensure_authenticated()
        result = await client.copy_file(body.src, body.dst, body.checkpoint, body.message)
        
        status = result.get('status')
        
        # Handle various status codes
        if status == 'OK':
            response_data = {
                "status": "OK",
                "src": body.src,
                "dst": body.dst,
                "message": f"Successfully copied {body.src} to {body.dst}"
            }
            if result.get('transaction_id'):
                response_data['transaction_id'] = result['transaction_id']
            if body.checkpoint:
                response_data['checkpoint'] = body.checkpoint
            return sanic_json(response_data)
        elif status == 'NOT_EXIST':
            return sanic_json({
                "error": "Source path not found",
                "path": body.src
            }, status=404)
        elif status == 'DENIED':
            return sanic_json({
                "error": "Permission denied",
                "src": body.src,
                "dst": body.dst
            }, status=403)
        elif status == 'AlreadyExists':
            return sanic_json({
                "error": "Destination already exists",
                "path": body.dst
            }, status=409)
        else:
            return sanic_json({
                "error": result.get('error', f"Operation failed with status: {status}"),
                "status": status,
                "src": body.src,
                "dst": body.dst
            }, status=500)
            
    except ValueError as e:
        return sanic_json({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Copy path error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": str(e)
        }, status=500)


@files_bp.post("/copy/batch", name="copy_paths_batch")
@require_auth
async def copy_paths_batch(request: Request) -> HTTPResponse:
    """
    Batch copy multiple files/folders.

    Security: Bearer token required.

    Request Body (application/json):
    - paths_to_copy: array of copy operations, each with:
      - src: object with 'path' (required), 'branch' (optional), and 'checkpoint' (optional)
      - dst: object with 'path' (required) and 'branch' (optional)
      - message: string, commit message (optional)

    Responses:
    - 200: `{ "status": string, "results": array, "succeeded": number, "failed": number }`
    - 400: Invalid request
    - 500: Error details
    """
    try:
        body = BatchCopyRequest(**(request.json or {}))

        read_paths = []
        write_paths = []
        for operation in body.paths_to_copy:
            if not isinstance(operation, dict):
                continue
            src_path = (operation.get('src') or {}).get('path')
            dst_path = (operation.get('dst') or {}).get('path')
            if src_path:
                read_paths.append(src_path)
            if dst_path:
                write_paths.append(dst_path)

        if read_paths:
            read_error = ensure_paths_permission(request, read_paths, "read")
            if read_error:
                return read_error
        if write_paths:
            write_error = ensure_paths_permission(request, write_paths, "write")
            if write_error:
                return write_error

        client = await ensure_authenticated()
        result = await client.copy2(body.paths_to_copy)
        
        # Return detailed batch results
        return sanic_json(result)
        
    except ValueError as e:
        return sanic_json({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Batch copy error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": str(e)
        }, status=500)


# M5 Search and Indexing Endpoints

@files_bp.post("/search", name="search_files")
@require_auth
async def search_files(request: Request) -> HTTPResponse:
    """
    Search indexed files with filters and sorting.

    Security: Bearer token required.

    Request Body (application/json): fields like `query`, `file_types[]`,
    `size_min`, `size_max`, `modified_since`, `created_by`, `sort_field`,
    `sort_order`, `page`, `page_size`.

    Responses:
    - 200: `{ "files": FileEntry[], "total_count": number, "page": number, "page_size": number, ... }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        body_data = request.json or {}
        
        search_engine = await get_search_engine()
        
        # Build search filters
        filters = SearchFilter()
        
        file_types = body_data.get('file_types')
        if file_types:
            filters.file_types = [SearchFileType(ft) for ft in file_types]
        
        size_min = body_data.get('size_min')
        if size_min is not None:
            filters.size_min = size_min
            
        size_max = body_data.get('size_max')
        if size_max is not None:
            filters.size_max = size_max
            
        modified_since = body_data.get('modified_since')
        if modified_since:
            filters.modified_since = datetime.fromisoformat(modified_since.replace('Z', '+00:00'))
            
        modified_until = body_data.get('modified_until')
        if modified_until:
            filters.modified_until = datetime.fromisoformat(modified_until.replace('Z', '+00:00'))
            
        created_by = body_data.get('created_by')
        if created_by:
            filters.created_by = created_by
            
        parent_path = body_data.get('parent_path')
        if parent_path:
            filters.parent_path = parent_path
            
        has_tags = body_data.get('has_tags')
        if has_tags:
            filters.has_tags = has_tags
            
        content_types = body_data.get('content_types')
        if content_types:
            filters.content_types = content_types
        
        # Build sort configuration
        sort_field = body_data.get('sort_field', 'modified_at')
        sort_order = body_data.get('sort_order', 'desc')
        
        sort = SearchSort(
            field=SortField(sort_field),
            order=SortOrder(sort_order)
        )
        
        # Execute search
        result = await search_engine.search(
            query=body_data.get('query'),
            filters=filters,
            sort=sort,
            page=body_data.get('page', 1),
            page_size=body_data.get('page_size', 20)
        )
        
        # Convert FileEntry objects to dictionaries
        files_data = [file_entry.to_dict() for file_entry in result.files]
        
        return sanic_json({
            "files": files_data,
            "total_count": result.total_count,
            "page": result.page,
            "page_size": result.page_size,
            "has_more": result.has_more,
            "query_time_ms": result.query_time_ms,
            "filters_applied": result.filters_applied
        })
        
    except ValueError as e:
        return sanic_json({"error": f"Invalid request: {e}"}, status=400)
    except Exception as e:
        logger.error(f"Error in file search: {e}")
        return sanic_json({"error": "Search failed"}, status=500)


@files_bp.get("/metadata/<path:path>", name="get_file_metadata")
@require_auth
async def get_file_metadata(request: Request, path: str) -> HTTPResponse:
    """
    Get detailed metadata for a file.

    Security: Bearer token required.

    Path Parameters:
    - path: string, file path (URL‑encoded)

    Responses:
    - 200: `{ "file": { ...metadata... } }`
    - 404/500: Error details
    """
    try:
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Get database instance
        from app.db.sqlite import get_database
        database = await get_database()
        
        # Get file metadata
        file_entry = await database.get_file(path)
        
        if not file_entry:
            return sanic_json({"error": f"File not found: {path}"}, status=404)
        
        return sanic_json({
            "file": file_entry.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error getting file metadata for {path}: {e}")
        return sanic_json({"error": "Failed to get file metadata"}, status=500)


@files_bp.post("/metadata/<path:path>/tags", name="update_file_tags")
@require_auth
async def update_file_tags(request: Request, path: str) -> HTTPResponse:
    """
    Update custom tags on a file.

    Security: Bearer token required.

    Path Parameters:
    - path: string, file path (URL‑encoded)

    Request Body (application/json):
    - tags: object, key/value pairs to store with the file

    Responses:
    - 200: `{ "message": "Tags updated successfully", "file": { ... } }`
    - 400/404/500: Error details
    """
    try:
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Get database instance
        from app.db.sqlite import get_database
        database = await get_database()
        
        # Check if file exists
        file_entry = await database.get_file(path)
        if not file_entry:
            return sanic_json({"error": f"File not found: {path}"}, status=404)
        
        # Parse request body and update tags
        body_data = request.json or {}
        tags = body_data.get('tags', {})
        success = await database.update_file_tags(path, tags)
        
        if not success:
            return sanic_json({"error": "Failed to update tags"}, status=500)
        
        # Get updated file metadata
        updated_file = await database.get_file(path)
        
        return sanic_json({
            "message": "Tags updated successfully",
            "file": updated_file.to_dict() if updated_file else None
        })
        
    except Exception as e:
        logger.error(f"Error updating tags for {path}: {e}")
        return sanic_json({"error": "Failed to update tags"}, status=500)


@files_bp.get("/suggestions", name="get_search_suggestions")
@require_auth
async def get_search_suggestions(request: Request) -> HTTPResponse:
    """
    Autocomplete suggestions for search.

    Security: Bearer token required.

    Query Parameters:
    - q: string, partial query (min 2 chars)
    - limit: integer, number of suggestions (default 10, max 50)

    Responses:
    - 200: `{ "suggestions": string[], "query": string }`
    - 400/500: Error details
    """
    try:
        partial_query = request.args.get('q', '')
        limit = min(int(request.args.get('limit', '10')), 50)
        
        if len(partial_query) < 2:
            return sanic_json({"suggestions": []})
        
        search_engine = await get_search_engine()
        suggestions = await search_engine.suggest_completions(partial_query, limit)
        
        return sanic_json({
            "suggestions": suggestions,
            "query": partial_query
        })
        
    except ValueError as e:
        return sanic_json({"error": f"Invalid parameters: {e}"}, status=400)
    except Exception as e:
        logger.error(f"Error getting suggestions: {e}")
        return sanic_json({"error": "Failed to get suggestions"}, status=500)


@files_bp.get("/facets", name="get_search_facets")
@require_auth
async def get_search_facets(request: Request) -> HTTPResponse:
    """
    Faceted aggregation for search results.

    Security: Bearer token required.

    Query Parameters:
    - query: string, optional search text

    Responses:
    - 200: `{ "facets": { ... }, "query": string|null }`
    - 500: Error details
    """
    try:
        query = request.args.get('query')
        
        search_engine = await get_search_engine()
        facets = await search_engine.get_facets(query)
        
        return sanic_json({
            "facets": facets,
            "query": query
        })
        
    except Exception as e:
        logger.error(f"Error getting facets: {e}")
        return sanic_json({"error": "Failed to get facets"}, status=500)


@files_bp.post("/sync", name="sync_index")
@require_auth
async def sync_index(request: Request) -> HTTPResponse:
    """
    Trigger index synchronization.

    Security: Bearer token required.

    Request Body (application/json):
    - sync_type: string, "full" or "incremental" (default "incremental")
    - root_path: string, root dir for full sync (optional)
    - since_hours: integer, hours lookback for incremental sync

    Responses:
    - 200: `{ "message": "Sync <type> started", "sync_stats": { ... } }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        body_data = request.json or {}
        sync_type = body_data.get('sync_type', 'incremental')
        
        file_indexer = await get_file_indexer()
        
        if sync_type == "full":
            root_path = body_data.get('root_path', '/')
            result = await file_indexer.full_sync(root_path)
        elif sync_type == "incremental":
            since_hours = body_data.get('since_hours', 24)
            result = await file_indexer.incremental_sync(since_hours)
        else:
            return sanic_json({"error": "Invalid sync type. Use 'full' or 'incremental'"}, status=400)
        
        return sanic_json({
            "message": f"Sync {sync_type} started",
            "sync_stats": result
        })
        
    except Exception as e:
        logger.error(f"Error starting sync: {e}")
        return sanic_json({"error": "Failed to start sync"}, status=500)


@files_bp.get("/sync/status", name="get_sync_status")
@require_auth
async def get_sync_status(request: Request) -> HTTPResponse:
    """
    Current synchronization status and recent stats.

    Security: Bearer token required.

    Responses:
    - 200: JSON with sync progress and timestamps
    - 500: Error details
    """
    try:
        file_indexer = await get_file_indexer()
        status = await file_indexer.get_sync_status()
        
        return sanic_json(status)
        
    except Exception as e:
        logger.error(f"Error getting sync status: {e}")
        return sanic_json({"error": "Failed to get sync status"}, status=500)


@files_bp.get("/stats", name="get_index_stats")
@require_auth
async def get_index_stats(request: Request) -> HTTPResponse:
    """
    Indexing statistics and DB metrics.

    Security: Bearer token required.

    Responses:
    - 200: `{ "index_stats": { ... }, "timestamp": string }`
    - 500: Error details
    """
    try:
        # Get database instance
        from app.db.sqlite import get_database
        database = await get_database()
        
        stats = await database.get_indexing_stats()
        
        return sanic_json({
            "index_stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting index stats: {e}")
        return sanic_json({"error": "Failed to get index stats"}, status=500)


@files_bp.get("/index/health", name="get_files_health")
async def get_files_health(request: Request) -> HTTPResponse:
    """
    Health for files/index/search subsystem.

    Public endpoint exposing readiness of indexing, search engine, and DB.

    Responses:
    - 200: `{ "status": "healthy", "services": { ... }, "index_stats": { ... }, "features": string[] }`
    - 503: `{ "status": "unhealthy", "error": string }`
    """
    try:
        # Check database connectivity
        from app.db.sqlite import get_database
        database = await get_database()
        
        # Try a simple query
        stats = await database.get_indexing_stats()
        
        # Check search engine
        search_engine = await get_search_engine()
        
        # Check file indexer
        file_indexer = await get_file_indexer()
        sync_status = await file_indexer.get_sync_status()
        
        return sanic_json({
            "status": "healthy",
            "services": {
                "database": "healthy",
                "search_engine": "healthy", 
                "file_indexer": "healthy"
            },
            "index_stats": {
                "total_indexed": stats.get('indexed_count', 0),
                "total_size": stats.get('indexed_size', 0),
                "last_sync": sync_status.get('last_full_sync') or sync_status.get('last_incremental_sync')
            },
            "features": [
                "file_search",
                "metadata_retrieval", 
                "directory_listing",
                "tag_management",
                "search_suggestions",
                "search_facets",
                "index_synchronization"
            ]
        })
        
    except Exception as e:
        logger.error(f"Files service health check failed: {e}")
        return sanic_json({
            "status": "unhealthy",
            "error": str(e)
        }, status=503)
