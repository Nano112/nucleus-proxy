"""
Nucleus → S3 export routes.

POST /v1/files/to-s3         — start an export job
GET  /v1/files/to-s3/status/<job_id>  — poll job progress
"""

import asyncio
import logging

from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json

from app.routes.auth import require_auth
from app.nucleus.client import ensure_authenticated, get_nucleus_client_for_request, NucleusAuthError, NucleusConnectionError
from app.services.s3_export import S3ExportManager, S3Config

logger = logging.getLogger(__name__)

export_bp = Blueprint("export", url_prefix="/v1/export")


@export_bp.post("/to-s3")
@require_auth
async def start_export(request: Request) -> HTTPResponse:
    """Start an async Nucleus → S3 export job.

    Body (JSON):
        nucleus_path        — required, path on Nucleus to export
        s3_bucket           — required
        s3_key              — required
        s3_region           — required
        s3_access_key       — required
        s3_secret_key       — required
        s3_endpoint         — optional (for MinIO)
        s3_use_path_style   — optional bool (for MinIO)
        nucleus_url         — optional, override Nucleus host
        nucleus_username    — optional, override credentials
        nucleus_password    — optional, override credentials

    Returns 202 with { job_id, status }.
    """
    body = request.json or {}

    # Validate required fields
    required = ["nucleus_path", "s3_bucket", "s3_key", "s3_region", "s3_access_key", "s3_secret_key"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        return sanic_json({"error": f"Missing required fields: {', '.join(missing)}"}, status=400)

    nucleus_path = body["nucleus_path"]
    s3_config = S3Config(
        bucket=body["s3_bucket"],
        key=body["s3_key"],
        region=body["s3_region"],
        access_key=body["s3_access_key"],
        secret_key=body["s3_secret_key"],
        endpoint=body.get("s3_endpoint"),
        use_path_style=bool(body.get("s3_use_path_style", False)),
    )

    # Get Nucleus client (per-request creds or default)
    nucleus_host = body.get("nucleus_url")
    nucleus_user = body.get("nucleus_username")
    nucleus_pass = body.get("nucleus_password")

    try:
        if nucleus_host or nucleus_user:
            client = await get_nucleus_client_for_request(
                host=nucleus_host,
                username=nucleus_user,
                password=nucleus_pass,
            )
        else:
            client = await ensure_authenticated()
    except NucleusAuthError as exc:
        return sanic_json({"error": f"Nucleus auth denied: {exc}"}, status=403)
    except NucleusConnectionError as exc:
        return sanic_json({"error": f"Nucleus unreachable: {exc}"}, status=502)
    except RuntimeError as exc:
        return sanic_json({"error": f"Nucleus auth failed: {exc}"}, status=502)

    # Get download URL from Nucleus
    dl_result = await client.get_download_url(nucleus_path)
    if dl_result.get("error"):
        return sanic_json(
            {"error": f"Cannot resolve Nucleus file: {dl_result['error']}"},
            status=404,
        )

    download_url = dl_result["download_url"]

    # Create and fire export job
    manager = S3ExportManager()
    job = manager.create_job(nucleus_path, s3_config)
    asyncio.create_task(manager.execute_export(job, download_url))

    return sanic_json(job.to_dict(), status=202)


@export_bp.get("/to-s3/status/<job_id:str>")
@require_auth
async def export_status(request: Request, job_id: str) -> HTTPResponse:
    """Poll an export job's progress."""
    manager = S3ExportManager()
    job = manager.get_job(job_id)

    if not job:
        return sanic_json({"error": "Job not found"}, status=404)

    return sanic_json(job.to_dict())


@export_bp.post("/download-url")
@require_auth
async def get_download_url_endpoint(request: Request) -> HTTPResponse:
    """Resolve a Nucleus file's download URL without starting an S3 export.

    Used by Laravel-mediated imports where Laravel handles the actual
    download and S3 upload itself.

    Body (JSON):
        nucleus_path        — required, path on Nucleus
        nucleus_url         — optional, override Nucleus host
        nucleus_username    — optional, override credentials
        nucleus_password    — optional, override credentials

    Returns { download_url }.
    """
    body = request.json or {}
    nucleus_path = body.get("nucleus_path")
    if not nucleus_path:
        return sanic_json({"error": "nucleus_path is required"}, status=400)

    nucleus_host = body.get("nucleus_url")
    nucleus_user = body.get("nucleus_username")
    nucleus_pass = body.get("nucleus_password")

    try:
        if nucleus_host or nucleus_user:
            client = await get_nucleus_client_for_request(
                host=nucleus_host,
                username=nucleus_user,
                password=nucleus_pass,
            )
        else:
            client = await ensure_authenticated()
    except NucleusAuthError as exc:
        return sanic_json({"error": f"Nucleus auth denied: {exc}"}, status=403)
    except NucleusConnectionError as exc:
        return sanic_json({"error": f"Nucleus unreachable: {exc}"}, status=502)
    except RuntimeError as exc:
        return sanic_json({"error": f"Nucleus auth failed: {exc}"}, status=502)

    dl_result = await client.get_download_url(nucleus_path)
    if dl_result.get("error"):
        return sanic_json(
            {"error": f"Cannot resolve Nucleus file: {dl_result['error']}"},
            status=404,
        )

    return sanic_json({"download_url": dl_result["download_url"]})


@export_bp.post("/list-remote")
@require_auth
async def list_remote(request: Request) -> HTTPResponse:
    """List directory on a remote Nucleus server using per-request credentials.

    This routes through our proxy's client pool so callers only need
    the Nucleus host + credentials — no separate proxy required.

    Body (JSON):
        path                — directory path (default "/")
        nucleus_url         — required, Nucleus server hostname
        nucleus_username    — required
        nucleus_password    — required
        show_hidden         — optional bool (default true)
    """
    body = request.json or {}

    nucleus_host = body.get("nucleus_url")
    nucleus_user = body.get("nucleus_username")
    nucleus_pass = body.get("nucleus_password")

    if not nucleus_host or not nucleus_user:
        return sanic_json(
            {"error": "nucleus_url and nucleus_username are required"},
            status=400,
        )

    path = body.get("path", "/")
    show_hidden = body.get("show_hidden", True)

    try:
        client = await get_nucleus_client_for_request(
            host=nucleus_host,
            username=nucleus_user,
            password=nucleus_pass,
        )
    except NucleusAuthError as exc:
        return sanic_json({"error": f"Nucleus auth denied: {exc}"}, status=403)
    except NucleusConnectionError as exc:
        return sanic_json({"error": f"Nucleus unreachable: {exc}"}, status=502)
    except RuntimeError as exc:
        return sanic_json({"error": f"Nucleus auth failed: {exc}"}, status=502)

    result = await client.list_directory(path, show_hidden=show_hidden)

    if result.get("error"):
        return sanic_json(
            {"error": f"List failed: {result['error']}"},
            status=500,
        )

    # Transform entries to match the /v1/files/list API format
    entries = []
    for entry in result.get("entries", []):
        entry_path = entry.get("path", "")
        entry_name = entry_path.rstrip("/").split("/")[-1] if entry_path else ""
        entries.append({
            "path": entry_path,
            "name": entry_name,
            "type": entry.get("path_type", "unknown"),
            "size": entry.get("size"),
            "modified_at": entry.get("modified_time"),
            "created_by": entry.get("created_by"),
        })

    return sanic_json({
        "status": "OK",
        "path": path,
        "entries": entries,
        "total": len(entries),
    })


@export_bp.post("/stat-remote")
@require_auth
async def stat_remote(request: Request) -> HTTPResponse:
    """Stat a file/directory on a remote Nucleus server.

    Body (JSON):
        path                — required
        nucleus_url         — required
        nucleus_username    — required
        nucleus_password    — required
    """
    body = request.json or {}

    nucleus_host = body.get("nucleus_url")
    nucleus_user = body.get("nucleus_username")
    nucleus_pass = body.get("nucleus_password")

    if not nucleus_host or not nucleus_user:
        return sanic_json(
            {"error": "nucleus_url and nucleus_username are required"},
            status=400,
        )

    path = body.get("path")
    if not path:
        return sanic_json({"error": "path is required"}, status=400)

    try:
        client = await get_nucleus_client_for_request(
            host=nucleus_host,
            username=nucleus_user,
            password=nucleus_pass,
        )
    except NucleusAuthError as exc:
        return sanic_json({"error": f"Nucleus auth denied: {exc}"}, status=403)
    except NucleusConnectionError as exc:
        return sanic_json({"error": f"Nucleus unreachable: {exc}"}, status=502)
    except RuntimeError as exc:
        return sanic_json({"error": f"Nucleus auth failed: {exc}"}, status=502)

    result = await client.get_file_info(path)

    if result.get("error"):
        return sanic_json(
            {"error": f"Stat failed: {result['error']}"},
            status=500,
        )

    return sanic_json(result)


MEDIA_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "tiff", "tif",
    "mp4", "mov", "avi", "webm", "mkv", "wmv", "flv", "m4v",
    "pdf",
}


@export_bp.post("/list-remote-recursive")
@require_auth
async def list_remote_recursive(request: Request) -> HTTPResponse:
    """Recursively list all media files under a directory on a remote Nucleus.

    Body (JSON):
        path                — directory to scan (default "/")
        nucleus_url         — required
        nucleus_username    — required
        nucleus_password    — required
        max_depth           — optional, max recursion depth (default 10)
    """
    body = request.json or {}

    nucleus_host = body.get("nucleus_url")
    nucleus_user = body.get("nucleus_username")
    nucleus_pass = body.get("nucleus_password")

    if not nucleus_host or not nucleus_user:
        return sanic_json(
            {"error": "nucleus_url and nucleus_username are required"},
            status=400,
        )

    root_path = body.get("path", "/")
    max_depth = min(int(body.get("max_depth", 10)), 20)

    try:
        client = await get_nucleus_client_for_request(
            host=nucleus_host,
            username=nucleus_user,
            password=nucleus_pass,
        )
    except NucleusAuthError as exc:
        return sanic_json({"error": f"Nucleus auth denied: {exc}"}, status=403)
    except NucleusConnectionError as exc:
        return sanic_json({"error": f"Nucleus unreachable: {exc}"}, status=502)
    except RuntimeError as exc:
        return sanic_json({"error": f"Nucleus auth failed: {exc}"}, status=502)

    all_files = []

    async def _scan(path: str, depth: int):
        if depth > max_depth:
            return
        result = await client.list_directory(path, show_hidden=False)
        for entry in result.get("entries", []):
            entry_path = entry.get("path", "")
            path_type = entry.get("path_type", "unknown")
            if path_type in ("folder", "directory", "mount"):
                # Skip hidden/system directories like .thumbs, .system
                dir_name = entry_path.rstrip("/").split("/")[-1] if entry_path else ""
                if dir_name.startswith("."):
                    continue
                await _scan(entry_path, depth + 1)
            else:
                name = entry_path.rstrip("/").split("/")[-1] if entry_path else ""
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext in MEDIA_EXTENSIONS:
                    all_files.append({
                        "path": entry_path,
                        "name": name,
                        "type": path_type,
                        "size": entry.get("size"),
                    })

    await _scan(root_path, 0)

    return sanic_json({
        "status": "OK",
        "root": root_path,
        "files": all_files,
        "total": len(all_files),
    })
