"""
File operations routes using Nucleus client.
"""

import logging
import aiohttp
from datetime import datetime, timezone
from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json, file_stream
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from sanic_ext import validate

from app.nucleus.client import ensure_authenticated
from app.routes.auth import require_auth
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

    Responses:
    - 200: `{ "entries": FileEntry[], "total": number, "path": string }`
    - 403/404/500: Error details
    """
    try:
        path = request.args.get('path', '/')
        show_hidden = request.args.get('show_hidden', 'true').lower() == 'true'
        
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
        for entry in result.get('entries', []):
            # Extract name from path (last component)
            entry_path = entry.get('path', '')
            entry_name = entry_path.rstrip('/').split('/')[-1] if entry_path else ''
            
            entries.append({
                "path": entry_path,
                "name": entry_name,
                "type": entry.get('path_type', 'unknown'),
                "size": entry.get('size'),
                "modified_at": entry.get('modified_time'),
                "created_by": entry.get('created_by')
            })
        
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


@files_bp.post("/rename", name="rename_file")
@require_auth
async def rename_file(request: Request) -> HTTPResponse:
    """
    Rename or move a file/directory.

    Security: Bearer token required.

    Request Body (application/json):
    - src: string, source path
    - dst: string, destination path
    - message: string, optional commit message

    Responses:
    - 200: `{ "message": "File renamed successfully", "src": string, "dst": string }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        data = request.json
        if not data:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            rename_req = RenameRequest(**data)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # Rename/move file
        result = await client.move_file(rename_req.src, rename_req.dst, rename_req.message)
        
        if result.get('status') not in ['OK', 'DONE']:
            return sanic_json({
                "error": "Failed to rename file",
                "message": result.get('error', 'Unknown error')
            }, status=500)
        
        return sanic_json({
            "message": "File renamed successfully",
            "src": rename_req.src,
            "dst": rename_req.dst
        })
        
    except Exception as e:
        logger.error(f"Rename file error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to rename file"
        }, status=500)


@files_bp.post("/delete", name="delete_file")
@require_auth
async def delete_file(request: Request) -> HTTPResponse:
    """
    Delete a file or directory.

    Security: Bearer token required.

    Request Body (application/json):
    - path: string, file or directory path to delete

    Responses:
    - 200: `{ "message": "File deleted successfully", "path": string }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        data = request.json
        if not data:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            delete_req = DeleteRequest(**data)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Get authenticated Nucleus client
        client = await ensure_authenticated()
        
        # Delete file/directory
        result = await client.delete_path(delete_req.path)
        
        if result.get('status') not in ['OK', 'DONE']:
            return sanic_json({
                "error": "Failed to delete file",
                "message": result.get('error', 'Unknown error')
            }, status=500)
        
        return sanic_json({
            "message": "File deleted successfully",
            "path": delete_req.path
        })
        
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
