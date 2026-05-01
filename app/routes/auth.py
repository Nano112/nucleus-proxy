"""
Authentication routes for JWT token management.

Provides endpoints for user authentication, token generation,
and session management for the Nucleus Proxy.
"""

import functools
import jwt
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Set

from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json
from pydantic import BaseModel, Field, ValidationError, field_validator

from app.config import settings
from app.nucleus.client import get_nucleus_client, reset_nucleus_client

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", url_prefix="/v1/auth")


VALID_SCOPE_PERMISSIONS: Set[str] = {"read", "write"}


def _normalize_storage_path(path: Optional[str]) -> str:
    """Normalize a storage path to a canonical form."""
    if not path:
        return "/"
    normalized = path.replace("\\", "/").strip()
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    normalized = re.sub(r"/+", "/", normalized)
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized or "/"


def _normalize_scope(scope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return a normalized scope definition or None if invalid."""
    path = _normalize_storage_path(scope.get("path"))
    raw_permissions = scope.get("permissions") or ["read"]
    if not isinstance(raw_permissions, Sequence):
        raw_permissions = ["read"]
    permissions = {str(p).lower() for p in raw_permissions if str(p).lower() in VALID_SCOPE_PERMISSIONS}
    if not permissions:
        permissions = {"read"}
    return {
        "path": path,
        "permissions": sorted(permissions),
    }


def _path_is_within_scope(target_path: str, scope_path: str) -> bool:
    """Return True if target_path is within scope_path."""
    target = _normalize_storage_path(target_path)
    scope = _normalize_storage_path(scope_path)
    if scope == "/":
        return True
    if target == scope:
        return True
    scope_prefix = f"{scope}/"
    return target.startswith(scope_prefix)


def normalize_scopes(scopes: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Normalize list of scopes into canonical format."""
    normalized: List[Dict[str, Any]] = []
    if not scopes:
        return normalized
    for scope in scopes:
        normalized_scope = _normalize_scope(scope or {})
        if normalized_scope:
            normalized.append(normalized_scope)
    return normalized


def token_has_path_permission(payload: Dict[str, Any], path: str, permission: str) -> bool:
    """Check whether the payload's scopes permit an operation on a path."""
    scopes = normalize_scopes(payload.get("scopes"))
    if not scopes:
        return True  # unrestricted token
    requested_permission = permission.lower()
    for scope in scopes:
        if requested_permission in scope["permissions"] and _path_is_within_scope(path, scope["path"]):
            return True
    return False


def ensure_path_permission(request: Request, path: str, permission: str) -> Optional[HTTPResponse]:
    """Return an HTTP response if the request lacks the permission for the path."""
    user_info = getattr(request.ctx, "user", {}) or {}
    payload: Dict[str, Any] = user_info.get("token_payload", {})  # type: ignore[assignment]
    normalized_scopes = normalize_scopes(payload.get("scopes"))
    if token_has_path_permission(payload, path, permission):
        return None
    return sanic_json(
        {
            "error": "Access denied",
            "message": f"Token does not grant {permission.lower()} access to path",
            "path": _normalize_storage_path(path),
            "required_permission": permission.lower(),
            "allowed_scopes": normalized_scopes,
        },
        status=403,
    )


def ensure_paths_permission(request: Request, paths: Sequence[str], permission: str) -> Optional[HTTPResponse]:
    """Ensure the caller has permission for all provided paths."""
    for path in paths:
        response = ensure_path_permission(request, path, permission)
        if response is not None:
            return response
    return None


def get_token_scopes(request: Request) -> List[Dict[str, Any]]:
    """Helper to retrieve scopes from the current request context."""
    user_info = getattr(request.ctx, "user", {}) or {}
    return user_info.get("scopes", [])  # type: ignore[return-value]


def request_has_ability(request: Request, ability: str) -> bool:
    """Return True if the current token includes the given ability."""
    user_info = getattr(request.ctx, "user", {}) or {}
    abilities: Set[str] = user_info.get("abilities", set())  # type: ignore[assignment]
    return ability.lower() in abilities


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., description="Username for Nucleus authentication", json_schema_extra={"example": "omniverse"})
    password: str = Field(..., description="Password for Nucleus authentication", json_schema_extra={"example": "password123"})


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str = Field(..., description="JWT access token for API authentication")
    token_type: str = Field(default="Bearer", description="Token type (always Bearer)")
    expires_in: int = Field(..., description="Token expiration time in seconds", json_schema_extra={"example": 900})


class ScopeDefinition(BaseModel):
    """Scope definition for issued tokens."""

    path: str = Field(..., description="Root path granted by the token")
    permissions: List[str] = Field(default_factory=lambda: ["read"], description="Allowed permissions")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        normalized = _normalize_storage_path(value)
        if not normalized:
            raise ValueError("Path cannot be empty")
        return normalized

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, value: List[str]) -> List[str]:
        perms = {str(item).lower() for item in (value or []) if str(item).lower() in VALID_SCOPE_PERMISSIONS}
        if not perms:
            perms = {"read"}
        return sorted(perms)


class ScopedTokenRequest(BaseModel):
    """Request payload for issuing scoped tokens."""

    subject: str = Field(..., description="Subject to embed in the token (e.g., user identifier)")
    expires_in_minutes: int = Field(60, ge=1, le=60 * 24 * 30, description="Token lifetime in minutes")
    scopes: List[ScopeDefinition] = Field(..., min_length=1, description="List of scope definitions")
    abilities: Optional[List[str]] = Field(None, description="Optional extra abilities for the token")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional metadata payload to embed")


def create_jwt_token(
    username: str,
    expires_in_minutes: int = 15 * 24 * 60,
    *,
    scopes: Optional[Sequence[Dict[str, Any]]] = None,
    abilities: Optional[Sequence[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a JWT token for proxy authentication."""

    now = datetime.now(timezone.utc)
    normalized_scopes = normalize_scopes(scopes)
    normalized_abilities: List[str] = []
    if abilities:
        normalized_abilities = sorted({str(item).lower() for item in abilities if item})

    payload: Dict[str, Any] = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=expires_in_minutes),
        "iss": "nucleus-proxy",
        "type": "access",
    }

    if normalized_scopes:
        payload["scopes"] = normalized_scopes
    if normalized_abilities:
        payload["abilities"] = normalized_abilities
    if metadata:
        payload["meta"] = metadata

    return jwt.encode(payload, settings.proxy_secret, algorithm="HS256")


def verify_jwt_token(token: str) -> Optional[dict]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.proxy_secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None


@auth_bp.post("/login", name="login")
async def login(request: Request) -> HTTPResponse:
    """
    Login and obtain an access token.

    Authenticates credentials against Nucleus and issues a short‑lived JWT
    token for calling protected endpoints in this proxy.

    Request Body (application/json):
    - username: string
    - password: string

    Responses:
    - 200: `{ "access_token": string, "token_type": "Bearer", "expires_in": 900 }`
    - 401: `{ "error": "Authentication failed", "message": "Invalid credentials" }`
    - 400/500: Error details
    """
    try:
        # Parse request body
        data = request.json
        if not data:
            return sanic_json({"error": "Request body required"}, status=400)
        
        # Validate request data
        try:
            login_req = LoginRequest(**data)
        except Exception as e:
            return sanic_json({"error": f"Invalid request data: {e}"}, status=400)
        
        # Authenticate with Nucleus
        client = await get_nucleus_client()
        auth_result = await client.authenticate(login_req.username, login_req.password)

        if auth_result.get('status') != 'OK':
            logger.warning(
                "Primary authentication attempt failed for %s: %s",
                login_req.username,
                auth_result,
            )
            await reset_nucleus_client()
            client = await get_nucleus_client()
            auth_result = await client.authenticate(login_req.username, login_req.password)

        if auth_result.get('status') != 'OK':
            return sanic_json({
                "error": "Authentication failed",
                "message": "Invalid credentials"
            }, status=401)

        # Create proxy JWT token (15 days default) with full access abilities
        abilities = ["full-access", "issue-tokens"]
        access_token = create_jwt_token(
            login_req.username,
            abilities=abilities,
            metadata={"auth_method": "password"},
        )
        
        logger.info(f"User {login_req.username} authenticated successfully")
        # 15 days in seconds
        expiry = 15 * 24 * 60 * 60
        return sanic_json({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expiry
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return sanic_json({
            "error": "Internal server error",
            "message": "Authentication service temporarily unavailable"
        }, status=500)


@auth_bp.post("/logout", name="logout")
async def logout(request: Request) -> HTTPResponse:
    """
    Logout (no‑op for JWT).

    Returns success to indicate the client should discard the token. JWTs are
    stateless and not invalidated server‑side unless a revocation list is used.

    Responses:
    - 200: `{ "message": "Logged out successfully" }`
    """
    # In a full implementation, you might:
    # 1. Add the token to a blacklist
    # 2. Close any persistent Nucleus connections for this user
    # 3. Clean up any session data
    
    return sanic_json({
        "message": "Logged out successfully"
    })


# Middleware for JWT authentication on protected routes
def require_auth(f):
    """Decorator to require JWT authentication."""
    @functools.wraps(f)
    async def wrapper(request: Request, *args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return sanic_json({"error": "Authorization header required"}, status=401)
        
        if not auth_header.startswith('Bearer '):
            return sanic_json({"error": "Invalid authorization header format"}, status=401)
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        payload = verify_jwt_token(token)
        
        if not payload:
            return sanic_json({"error": "Invalid or expired token"}, status=401)
        
        # Add user info to request context
        scopes = normalize_scopes(payload.get("scopes"))
        abilities = {str(item).lower() for item in payload.get("abilities", []) if item}
        request.ctx.user = {
            "username": payload.get("sub"),
            "token_payload": payload,
            "scopes": scopes,
            "abilities": abilities,
            "is_restricted": bool(scopes),
        }

        return await f(request, *args, **kwargs)
    
    return wrapper


def get_current_user(request: Request) -> dict:
    """Get current user information from request context."""
    user_info = getattr(request.ctx, 'user', None)
    if user_info:
        return user_info.get('token_payload', {})
    return {}


@auth_bp.post("/token", name="issue_scoped_token")
@require_auth
async def issue_scoped_token(request: Request) -> HTTPResponse:
    """Issue a scoped access token for downstream services."""

    data = request.json
    if not data:
        return sanic_json({"error": "Request body required"}, status=400)

    try:
        token_request = ScopedTokenRequest(**data)
    except ValidationError as exc:
        return sanic_json({"error": "Invalid request data", "details": exc.errors()}, status=400)

    issuer_info = getattr(request.ctx, "user", {}) or {}
    issuer_payload: Dict[str, Any] = issuer_info.get("token_payload", {})  # type: ignore[assignment]
    issuer_username = issuer_info.get("username")
    issuer_abilities = {str(item).lower() for item in issuer_payload.get("abilities", []) if item}

    if issuer_info.get("is_restricted"):
        return sanic_json(
            {
                "error": "Forbidden",
                "message": "Scoped tokens cannot issue additional tokens",
            },
            status=403,
        )

    if "issue-tokens" not in issuer_abilities:
        return sanic_json(
            {
                "error": "Forbidden",
                "message": "Current token is not permitted to issue scoped tokens",
            },
            status=403,
        )

    normalized_scopes = [scope.model_dump() for scope in token_request.scopes]
    requested_abilities = token_request.abilities or []
    normalized_requested_abilities = sorted({str(item).lower() for item in requested_abilities if item})

    if "issue-tokens" in normalized_requested_abilities and "issue-tokens" not in issuer_abilities:
        return sanic_json(
            {
                "error": "Forbidden",
                "message": "Cannot grant issue-tokens ability with current credentials",
            },
            status=403,
        )

    if not normalized_requested_abilities:
        normalized_requested_abilities = ["scoped-access"]

    metadata = token_request.metadata.copy() if token_request.metadata else {}
    if issuer_username:
        metadata.setdefault("issued_by", issuer_username)
    metadata.setdefault("scoped", True)

    access_token = create_jwt_token(
        token_request.subject,
        expires_in_minutes=token_request.expires_in_minutes,
        scopes=normalized_scopes,
        abilities=normalized_requested_abilities,
        metadata=metadata,
    )

    return sanic_json(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": token_request.expires_in_minutes * 60,
            "subject": token_request.subject,
            "scopes": normalized_scopes,
            "abilities": normalized_requested_abilities,
            "meta": metadata,
        },
        status=201,
    )
