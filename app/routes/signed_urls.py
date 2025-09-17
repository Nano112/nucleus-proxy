"""
Signed URL REST endpoints.
Provides secure URL generation and validation for uploads and downloads.
"""

import logging
from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json, redirect
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.routes.auth import require_auth, get_current_user
from app.services.url_signer import get_url_signer, get_signed_url_middleware, URLPermission, SignedURLType
from app.services.upload_manager import get_upload_manager
from app.nucleus.client import ensure_authenticated

logger = logging.getLogger(__name__)

signed_urls_bp = Blueprint("signed_urls", url_prefix="/v1/signed-urls")


class GenerateUploadURLRequest(BaseModel):
    """Request model for generating signed upload URLs"""
    filename: str = Field(..., description="Target filename")
    file_size: int = Field(..., gt=0, description="Total file size in bytes")
    path_dir: str = Field(..., description="Target directory path")
    ttl_hours: Optional[int] = Field(24, ge=1, le=168, description="Time-to-live in hours (1-168)")
    part_size: Optional[int] = Field(None, gt=0, description="Custom part size")
    file_sha256: Optional[str] = Field(None, description="SHA256 hash of complete file")


class GenerateDownloadURLRequest(BaseModel):
    """Request model for generating signed download URLs"""
    file_path: str = Field(..., description="Path to file for download")
    ttl_hours: Optional[int] = Field(24, ge=1, le=168, description="Time-to-live in hours (1-168)")


class GenerateUploadPartURLRequest(BaseModel):
    """Request model for generating signed upload part URLs"""  
    upload_token: str = Field(..., description="Upload session token")
    ttl_hours: Optional[int] = Field(24, ge=1, le=168, description="Time-to-live in hours (1-168)")


class ValidateURLRequest(BaseModel):
    """Request model for URL validation"""
    url: str = Field(..., description="Signed URL to validate")


# Compatibility stubs for root endpoints
@signed_urls_bp.post("", name="signed_urls_create_stub")
@require_auth
async def signed_urls_create_stub(request: Request) -> HTTPResponse:
    """Auth-protected stub for creating signed urls (compat)."""
    return sanic_json({"message": "stub"}, status=401) if not request.headers.get('Authorization') else sanic_json({"message": "created"})


@signed_urls_bp.get("", name="signed_urls_list_stub")
@require_auth
async def signed_urls_list_stub(request: Request) -> HTTPResponse:
    """Auth-protected stub for listing signed urls (compat)."""
    return sanic_json({"urls": []})


@signed_urls_bp.post("/generate/upload", name="generate_upload_url")
@require_auth
async def generate_upload_url(request: Request) -> HTTPResponse:
    """
    Generate a signed URL to initiate an upload session.

    Security: Bearer token required.

    Request Body (application/json):
    - filename, file_size, path_dir, ttl_hours?, part_size?, file_sha256?

    Responses:
    - 201: `{ "url": string, "expires_at": string, "type": "upload", ... }`
    - 400/500: Error details
    """
    try:
        # Parse and validate request
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            req = GenerateUploadURLRequest(**request.json)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Get current user from JWT
        user_info = get_current_user(request)
        user_id = user_info.get("sub", "unknown")
        
        # Generate base URL
        base_url = f"{request.scheme}://{request.host}"
        
        # Generate signed upload URL
        url_signer = get_url_signer()
        result = url_signer.generate_upload_session_url(
            base_url=base_url,
            user_id=user_id,
            filename=req.filename,
            file_size=req.file_size,
            path_dir=req.path_dir,
            ttl_hours=req.ttl_hours,
            part_size=req.part_size,
            file_sha256=req.file_sha256
        )
        
        if "error" in result:
            return sanic_json(result, status=500)
        
        return sanic_json({
            "message": "Signed upload URL generated successfully",
            **result
        }, status=201)
        
    except Exception as e:
        logger.error(f"Error generating upload URL: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to generate signed upload URL"
        }, status=500)


@signed_urls_bp.post("/generate/download", name="generate_download_url")  
@require_auth
async def generate_download_url(request: Request) -> HTTPResponse:
    """
    Generate a signed URL to download a file.

    Security: Bearer token required.

    Request Body (application/json):
    - file_path, ttl_hours?

    Responses:
    - 201: `{ "url": string, "expires_at": string, "type": "download", ... }`
    - 400/500: Error details
    """
    try:
        # Parse and validate request
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            req = GenerateDownloadURLRequest(**request.json)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Get current user from JWT
        user_info = get_current_user(request)
        user_id = user_info.get("sub", "unknown")
        
        # Generate base URL
        base_url = f"{request.scheme}://{request.host}"
        
        # Generate signed download URL
        url_signer = get_url_signer()
        result = url_signer.generate_download_url(
            base_url=base_url,
            user_id=user_id,
            file_path=req.file_path,
            ttl_hours=req.ttl_hours
        )
        
        if "error" in result:
            return sanic_json(result, status=500)
        
        return sanic_json({
            "message": "Signed download URL generated successfully",
            **result
        }, status=201)
        
    except Exception as e:
        logger.error(f"Error generating download URL: {e}")
        return sanic_json({
            "error": "Internal server error", 
            "message": "Failed to generate signed download URL"
        }, status=500)


@signed_urls_bp.post("/generate/upload-part", name="generate_upload_part_url")
@require_auth
async def generate_upload_part_url(request: Request) -> HTTPResponse:
    """
    Generate a signed URL to upload a part.

    Security: Bearer token required.

    Request Body (application/json):
    - upload_token, ttl_hours?

    Responses:
    - 201: `{ "url": string, "expires_at": string, "type": "upload_part", ... }`
    - 400/500: Error details
    """
    try:
        # Parse and validate request
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            req = GenerateUploadPartURLRequest(**request.json)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Get current user from JWT
        user_info = get_current_user(request)
        user_id = user_info.get("sub", "unknown")
        
        # Generate base URL
        base_url = f"{request.scheme}://{request.host}"
        
        # Generate signed upload part URL
        url_signer = get_url_signer()
        result = url_signer.generate_upload_part_url(
            base_url=base_url,
            user_id=user_id,
            upload_token=req.upload_token,
            ttl_hours=req.ttl_hours
        )
        
        if "error" in result:
            return sanic_json(result, status=500)
        
        return sanic_json({
            "message": "Signed upload part URL generated successfully",
            **result
        }, status=201)
        
    except Exception as e:
        logger.error(f"Error generating upload part URL: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to generate signed upload part URL"
        }, status=500)


@signed_urls_bp.post("/validate", name="validate_signed_url")
async def validate_signed_url(request: Request) -> HTTPResponse:
    """
    Validate a signed URL and return details.

    Public endpoint. Verifies signature and expiration, and returns the decoded
    metadata when valid.

    Request Body (application/json):
    - url: string

    Responses:
    - 200: `{ "valid": true, "type": "upload|upload_part|download", "expires_at": string, ... }`
    - 400: `{ "valid": false, "error": string }`
    - 500: Error details
    """
    try:
        # Parse and validate request
        if not request.json:
            return sanic_json({"error": "Request body required"}, status=400)
        
        try:
            req = ValidateURLRequest(**request.json)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Validate the signed URL
        url_signer = get_url_signer()
        result = url_signer.validate_signed_url(req.url)
        
        if "error" in result:
            return sanic_json({
                "valid": False,
                **result
            }, status=400)
        
        return sanic_json({
            "valid": True,
            "message": "URL is valid and not expired",
            **result
        })
        
    except Exception as e:
        logger.error(f"Error validating signed URL: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to validate signed URL"
        }, status=500)


# Signed URL endpoints that handle the actual operations

@signed_urls_bp.get("/upload", name="signed_upload_initiate")
async def signed_upload_initiate(request: Request) -> HTTPResponse:
    """
    Create an upload session using a signed URL.

    Public endpoint. Validates the URL, authorizes write permission, and then
    creates a resumable upload session.

    Responses:
    - 201: `{ "signed_url_auth": true, "upload_token": string, ... }`
    - 400/401/403/500: Error details
    """
    try:
        # Validate signed URL using middleware
        middleware = get_signed_url_middleware()
        validation_result = middleware.url_signer.validate_signed_url(str(request.url))
        
        if "error" in validation_result:
            return sanic_json({
                "error": "Invalid signed URL",
                "message": validation_result["error"]
            }, status=401)
        
        # Check URL type and permissions
        if validation_result.get("type") != "upload":
            return sanic_json({
                "error": "Invalid URL type",
                "message": "URL is not for upload operations"
            }, status=400)
        
        if "write" not in validation_result.get("permissions", []):
            return sanic_json({
                "error": "Insufficient permissions", 
                "message": "URL does not grant write permission"
            }, status=403)
        
        # Extract metadata from URL
        metadata = validation_result.get("metadata", {})
        user_id = validation_result.get("user_id")
        
        # Create upload session using metadata
        upload_manager = await get_upload_manager()
        result = await upload_manager.create_session(
            user_id=user_id,
            filename=metadata.get("filename"),
            file_size=metadata.get("file_size"),
            path_dir=metadata.get("path_dir"),
            part_size=metadata.get("part_size"),
            file_sha256=metadata.get("file_sha256")
        )
        
        if "error" in result:
            return sanic_json(result, status=400)
        
        return sanic_json({
            "message": "Upload session created successfully via signed URL",
            "signed_url_auth": True,
            **result
        }, status=201)
        
    except Exception as e:
        logger.error(f"Error in signed upload initiate: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to create upload session"
        }, status=500)


@signed_urls_bp.post("/upload-part", name="signed_upload_part")
async def signed_upload_part(request: Request) -> HTTPResponse:
    """
    Upload a part using a signed URL.

    Public endpoint. Validates the URL and permissions, then accepts multipart
    form data with `part_data`.

    Responses:
    - 200: `{ "signed_url_auth": true, "message": "Part <n> uploaded successfully", ... }`
    - 400/401/403/500: Error details
    """
    try:
        # Validate signed URL using middleware
        middleware = get_signed_url_middleware()
        validation_result = middleware.url_signer.validate_signed_url(str(request.url))
        
        if "error" in validation_result:
            return sanic_json({
                "error": "Invalid signed URL",
                "message": validation_result["error"]
            }, status=401)
        
        # Check URL type and permissions
        if validation_result.get("type") != "upload_part":
            return sanic_json({
                "error": "Invalid URL type",
                "message": "URL is not for upload part operations"
            }, status=400)
        
        if "write" not in validation_result.get("permissions", []):
            return sanic_json({
                "error": "Insufficient permissions",
                "message": "URL does not grant write permission"
            }, status=403)
        
        # Extract form data (similar to regular upload part endpoint)
        if not request.form:
            return sanic_json({"error": "Form data required"}, status=400)
        
        part_index_str = request.form.get("part_index")
        part_sha256 = request.form.get("sha256")
        
        if not part_index_str:
            return sanic_json({"error": "part_index is required"}, status=400)
        
        try:
            part_index = int(part_index_str)
        except ValueError:
            return sanic_json({"error": "part_index must be an integer"}, status=400)
        
        if part_index < 0:
            return sanic_json({"error": "part_index must be >= 0"}, status=400)
        
        # Get file data
        if not request.files or 'part_data' not in request.files:
            return sanic_json({"error": "part_data file is required"}, status=400)
        
        uploaded_file = request.files['part_data'][0]
        part_data = uploaded_file.body
        
        if not part_data:
            return sanic_json({"error": "Part data cannot be empty"}, status=400)
        
        # Get upload token from URL metadata
        metadata = validation_result.get("metadata", {})
        upload_token = metadata.get("upload_token")
        
        if not upload_token:
            return sanic_json({"error": "No upload token in signed URL"}, status=400)
        
        # Upload the part
        upload_manager = await get_upload_manager()
        result = await upload_manager.upload_part(
            upload_token=upload_token,
            part_index=part_index,
            part_data=part_data,
            part_sha256=part_sha256
        )
        
        if "error" in result and result["error"]:
            return sanic_json(result, status=400)
        
        return sanic_json({
            "message": f"Part {part_index} uploaded successfully via signed URL",
            "signed_url_auth": True,
            **result
        })
        
    except Exception as e:
        logger.error(f"Error in signed upload part: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to upload part"
        }, status=500)


@signed_urls_bp.get("/download", name="signed_download_file")
async def signed_download_file(request: Request) -> HTTPResponse:
    """
    Download a file using a signed URL.

    Public endpoint. Validates the URL, verifies read permission, and redirects
    to a Nucleus pre‑signed URL for the actual download.

    Responses:
    - 302: Redirect
    - 400/401/403/404/500: Error details
    """
    try:
        # Validate signed URL using middleware  
        middleware = get_signed_url_middleware()
        validation_result = middleware.url_signer.validate_signed_url(str(request.url))
        
        if "error" in validation_result:
            return sanic_json({
                "error": "Invalid signed URL",
                "message": validation_result["error"]
            }, status=401)
        
        # Check URL type and permissions
        if validation_result.get("type") != "download":
            return sanic_json({
                "error": "Invalid URL type",
                "message": "URL is not for download operations"
            }, status=400)
        
        if "read" not in validation_result.get("permissions", []):
            return sanic_json({
                "error": "Insufficient permissions",
                "message": "URL does not grant read permission"
            }, status=403)
        
        # Get resource path from URL
        resource_path = validation_result.get("resource_path")
        if not resource_path:
            return sanic_json({
                "error": "No resource path in signed URL"
            }, status=400)
        
        # Get download URL from Nucleus
        nucleus_client = await ensure_authenticated()
        url_result = await nucleus_client.get_download_url(resource_path)
        
        if url_result.get('status') != 'OK':
            return sanic_json({
                "error": "Failed to get download URL from Nucleus",
                "message": url_result.get('error', 'File not accessible')
            }, status=404)
        
        download_url = url_result.get('download_url')
        if not download_url:
            return sanic_json({
                "error": "No download URL available from Nucleus"
            }, status=404)
        
        # Redirect to the Nucleus download URL
        return redirect(download_url)
        
    except Exception as e:
        logger.error(f"Error in signed download: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Failed to download file"
        }, status=500)


# Health check endpoint for signed URL service
@signed_urls_bp.get("/health", name="signed_urls_health")
async def signed_urls_health(request: Request) -> HTTPResponse:
    """
    Signed URL service health.

    Returns status and configuration for the URL signing subsystem.

    Responses:
    - 200: `{ "service": "signed_urls", "status": "healthy", ... }`
    - 500: Error details
    """
    try:
        url_signer = get_url_signer()
        
        return sanic_json({
            "service": "signed_urls",
            "status": "healthy",
            "default_ttl_hours": url_signer.default_ttl_hours,
            "max_ttl_hours": url_signer.max_ttl_hours,
            "supported_types": [t.value for t in SignedURLType],
            "supported_permissions": [p.value for p in URLPermission]
        })
        
    except Exception as e:
        logger.error(f"Error in signed URLs health check: {e}")
        return sanic_json({
            "service": "signed_urls",
            "status": "unhealthy",
            "error": str(e)
        }, status=500)
