"""
URL signing service for secure upload and download URLs.
Provides HMAC-based URL signing with expiration and access control.
"""

import hmac
import hashlib
import base64
import json
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import logging

from app.config import settings

logger = logging.getLogger(__name__)


class URLPermission(str, Enum):
    """URL permission types"""
    READ = "read"           # Download files
    WRITE = "write"         # Upload files  
    DELETE = "delete"       # Delete files
    LIST = "list"           # List directories
    ADMIN = "admin"         # Administrative operations


class SignedURLType(str, Enum):
    """Types of signed URLs"""
    UPLOAD = "upload"           # Upload session initiation
    UPLOAD_PART = "upload_part" # Individual part upload
    DOWNLOAD = "download"       # File download
    LIST = "list"              # Directory listing


class URLSigner:
    """
    Service for generating and validating signed URLs.
    
    Uses HMAC-SHA256 for cryptographic signing with configurable expiration
    and embedded permissions for fine-grained access control.
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = (secret_key or settings.proxy_secret).encode('utf-8')
        self.default_ttl_hours = 24  # 24 hours default
        self.max_ttl_hours = 168     # 7 days maximum
        
    def generate_signed_url(self, 
                          base_url: str,
                          url_type: SignedURLType,
                          user_id: str,
                          permissions: List[URLPermission],
                          resource_path: Optional[str] = None,
                          ttl_hours: Optional[int] = None,
                          metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate a signed URL with embedded permissions and expiration.
        
        Args:
            base_url: Base URL for the service (e.g., "http://localhost:8088")
            url_type: Type of URL being signed
            user_id: User ID for access control
            permissions: List of permissions granted by this URL
            resource_path: Optional resource path for path-specific URLs
            ttl_hours: Time-to-live in hours (default: 24h, max: 7 days)
            metadata: Additional metadata to embed in the URL
            
        Returns:
            Dictionary containing the signed URL and metadata
        """
        try:
            # Validate TTL
            actual_ttl = ttl_hours or self.default_ttl_hours
            if actual_ttl > self.max_ttl_hours:
                actual_ttl = self.max_ttl_hours
                logger.warning(f"TTL clamped to maximum {self.max_ttl_hours} hours")
            
            # Calculate expiration timestamp using time.time() for consistency
            current_time = time.time()
            expires_timestamp = int(current_time + (actual_ttl * 3600))  # 3600 seconds per hour
            expires_at = datetime.utcfromtimestamp(expires_timestamp)
            
            # Create payload for signing
            payload = {
                "type": url_type.value,
                "user": user_id,
                "permissions": [p.value for p in permissions],
                "expires": expires_timestamp,
                "resource": resource_path,
                "metadata": metadata or {}
            }
            
            # Encode payload as base64
            payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            payload_b64 = base64.urlsafe_b64encode(payload_json).decode('ascii').rstrip('=')
            
            # Generate HMAC signature
            signature = self._generate_signature(payload_b64)
            
            # Build signed URL based on type
            signed_url = self._build_url(base_url, url_type, payload_b64, signature)
            
            logger.info(f"Generated signed {url_type.value} URL for user {user_id} (expires: {expires_at.isoformat()})")
            
            return {
                "url": signed_url,
                "type": url_type.value,
                "expires_at": expires_at.isoformat(),
                "expires_in": actual_ttl * 3600,  # seconds
                "permissions": [p.value for p in permissions],
                "user_id": user_id,
                "resource_path": resource_path
            }
            
        except Exception as e:
            logger.error(f"Error generating signed URL: {e}")
            return {"error": f"Failed to generate signed URL: {e}"}
    
    def validate_signed_url(self, url: str) -> Dict[str, Any]:
        """
        Validate a signed URL and extract its payload.
        
        Args:
            url: The signed URL to validate
            
        Returns:
            Dictionary with validation result and payload data
        """
        try:
            # Parse URL components
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Extract signature components
            payload_b64 = query_params.get('token', [None])[0]
            signature = query_params.get('signature', [None])[0]
            
            if not payload_b64 or not signature:
                return {"error": "Missing signature components in URL"}
            
            # Verify signature
            expected_signature = self._generate_signature(payload_b64)
            if not hmac.compare_digest(signature, expected_signature):
                return {"error": "Invalid URL signature"}
            
            # Decode payload
            try:
                # Add padding if needed for base64 decode
                payload_b64_padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
                payload_json = base64.urlsafe_b64decode(payload_b64_padded)
                payload = json.loads(payload_json.decode('utf-8'))
            except Exception as e:
                return {"error": f"Invalid payload format: {e}"}
            
            # Check expiration with 10 second tolerance for clock skew
            expires_timestamp = payload.get('expires', 0)
            current_time = time.time()
            tolerance_seconds = 10
            
            if expires_timestamp <= (current_time - tolerance_seconds):
                return {"error": "URL has expired"}
            
            # Return validated payload
            expires_at = datetime.utcfromtimestamp(expires_timestamp)
            
            return {
                "valid": True,
                "type": payload.get('type'),
                "user_id": payload.get('user'),
                "permissions": payload.get('permissions', []),
                "resource_path": payload.get('resource'),
                "metadata": payload.get('metadata', {}),
                "expires_at": expires_at.isoformat(),
                "expires_in": max(0, expires_timestamp - current_time)
            }
            
        except Exception as e:
            logger.error(f"Error validating signed URL: {e}")
            return {"error": f"URL validation failed: {e}"}
    
    def generate_upload_session_url(self, 
                                  base_url: str,
                                  user_id: str, 
                                  filename: str,
                                  file_size: int,
                                  path_dir: str,
                                  ttl_hours: Optional[int] = None,
                                  part_size: Optional[int] = None,
                                  file_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a signed URL for creating an upload session.
        
        This allows clients to initiate uploads without JWT authentication.
        """
        metadata = {
            "filename": filename,
            "file_size": file_size,
            "path_dir": path_dir,
            "part_size": part_size,
            "file_sha256": file_sha256
        }
        
        return self.generate_signed_url(
            base_url=base_url,
            url_type=SignedURLType.UPLOAD,
            user_id=user_id,
            permissions=[URLPermission.WRITE],
            resource_path=f"{path_dir}/{filename}",
            ttl_hours=ttl_hours,
            metadata=metadata
        )
    
    def generate_download_url(self,
                            base_url: str,
                            user_id: str,
                            file_path: str,
                            ttl_hours: Optional[int] = None) -> Dict[str, Any]:
        """
        Generate a signed URL for file downloads.
        
        This allows clients to download files without JWT authentication.
        """
        return self.generate_signed_url(
            base_url=base_url,
            url_type=SignedURLType.DOWNLOAD,
            user_id=user_id,
            permissions=[URLPermission.READ],
            resource_path=file_path,
            ttl_hours=ttl_hours
        )
    
    def generate_upload_part_url(self,
                                base_url: str,
                                user_id: str,
                                upload_token: str,
                                ttl_hours: Optional[int] = None) -> Dict[str, Any]:
        """
        Generate a signed URL for uploading individual parts.
        
        This allows clients to upload parts without JWT authentication.
        """
        metadata = {
            "upload_token": upload_token
        }
        
        return self.generate_signed_url(
            base_url=base_url,
            url_type=SignedURLType.UPLOAD_PART,
            user_id=user_id,
            permissions=[URLPermission.WRITE],
            ttl_hours=ttl_hours,
            metadata=metadata
        )
    
    def _generate_signature(self, payload: str) -> str:
        """Generate HMAC-SHA256 signature for payload."""
        signature = hmac.new(
            self.secret_key, 
            payload.encode('ascii'), 
            hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    
    def _build_url(self, base_url: str, url_type: SignedURLType, payload: str, signature: str) -> str:
        """Build the final signed URL based on the URL type."""
        base_url = base_url.rstrip('/')
        
        # Different endpoint patterns for different URL types
        if url_type == SignedURLType.UPLOAD:
            path = "/v1/signed-urls/upload"
        elif url_type == SignedURLType.UPLOAD_PART:
            path = "/v1/signed-urls/upload-part"
        elif url_type == SignedURLType.DOWNLOAD:
            path = "/v1/signed-urls/download"
        elif url_type == SignedURLType.LIST:
            path = "/v1/signed-urls/list"
        else:
            path = "/v1/signed-urls/generic"
        
        # Build query parameters
        params = {
            'token': payload,
            'signature': signature
        }
        query_string = urllib.parse.urlencode(params)
        
        return f"{base_url}{path}?{query_string}"


class SignedURLMiddleware:
    """
    Middleware for validating signed URLs in requests.
    
    Can be used as a decorator similar to @require_auth for signed URL endpoints.
    """
    
    def __init__(self, url_signer: Optional[URLSigner] = None):
        self.url_signer = url_signer or URLSigner()
    
    def require_signed_url(self, required_permissions: Optional[List[URLPermission]] = None):
        """
        Decorator to require and validate signed URLs.
        
        Args:
            required_permissions: List of permissions required for access
        """
        def decorator(f):
            async def wrapper(request, *args, **kwargs):
                # Get the full URL from the request
                full_url = str(request.url)
                
                # Validate the signed URL
                validation_result = self.url_signer.validate_signed_url(full_url)
                
                if "error" in validation_result:
                    from sanic.response import json as sanic_json
                    return sanic_json({
                        "error": "Invalid signed URL",
                        "message": validation_result["error"]
                    }, status=401)
                
                # Check permissions if required
                if required_permissions:
                    url_permissions = set(validation_result.get("permissions", []))
                    required_perms = set(p.value for p in required_permissions)
                    
                    if not required_perms.issubset(url_permissions):
                        from sanic.response import json as sanic_json
                        return sanic_json({
                            "error": "Insufficient permissions",
                            "message": f"Required: {list(required_perms)}, Got: {list(url_permissions)}"
                        }, status=403)
                
                # Add signed URL data to request context
                request.ctx.signed_url = validation_result
                request.ctx.user = {
                    "username": validation_result.get("user_id"),
                    "signed_url_auth": True
                }
                
                return await f(request, *args, **kwargs)
            
            return wrapper
        return decorator
    
    def get_signed_url_data(self, request) -> Dict[str, Any]:
        """Get signed URL data from request context."""
        return getattr(request.ctx, 'signed_url', {})


# Global instances
_url_signer: Optional[URLSigner] = None
_signed_url_middleware: Optional[SignedURLMiddleware] = None


def get_url_signer() -> URLSigner:
    """Get or create the global URL signer instance."""
    global _url_signer
    if _url_signer is None:
        _url_signer = URLSigner()
    return _url_signer


def get_signed_url_middleware() -> SignedURLMiddleware:
    """Get or create the global signed URL middleware instance."""
    global _signed_url_middleware
    if _signed_url_middleware is None:
        _signed_url_middleware = SignedURLMiddleware()
    return _signed_url_middleware