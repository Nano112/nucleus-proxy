"""UI routes serving the interactive dashboard and helper APIs."""

from pathlib import Path
from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json, file

from app.routes.auth import require_auth, get_current_user
from app.services.url_signer import get_url_signer


STATIC_ROOT = Path(__file__).resolve().parent.parent / "static"

ui_bp = Blueprint("ui", url_prefix="")
ui_api_bp = Blueprint("ui_api", url_prefix="/ui/api")


@ui_bp.get("/")
async def serve_index(_: Request) -> HTTPResponse:
    """Serve the interactive dashboard."""
    index_path = STATIC_ROOT / "index.html"
    return await file(str(index_path))


@ui_api_bp.post("/signed-upload", name="ui_signed_upload")
@require_auth
async def create_signed_upload(request: Request) -> HTTPResponse:
    payload = request.json or {}
    filename = payload.get('filename')
    path_dir = payload.get('path_dir')
    file_size = payload.get('file_size')
    if not filename or not path_dir or file_size is None:
        return json({"error": "filename, path_dir and file_size are required"}, status=400)

    signer = get_url_signer()
    user = get_current_user(request)
    base_url = f"{request.scheme}://{request.host}"

    result = signer.generate_upload_session_url(
        base_url=base_url,
        user_id=user.get('sub', 'ui-user'),
        filename=filename,
        file_size=file_size,
        path_dir=path_dir,
        ttl_hours=payload.get('ttl_hours', 24),
        part_size=payload.get('part_size'),
        file_sha256=payload.get('file_sha256'),
    )
    return json(result)


@ui_api_bp.post("/signed-download", name="ui_signed_download")
@require_auth
async def create_signed_download(request: Request) -> HTTPResponse:
    payload = request.json or {}
    file_path = payload.get('file_path')
    if not file_path:
        return json({"error": "file_path is required"}, status=400)

    signer = get_url_signer()
    user = get_current_user(request)
    base_url = f"{request.scheme}://{request.host}"

    result = signer.generate_download_url(
        base_url=base_url,
        user_id=user.get('sub', 'ui-user'),
        file_path=file_path,
        ttl_hours=payload.get('ttl_hours', 24),
    )
    return json(result)
