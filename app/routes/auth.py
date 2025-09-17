"""
Authentication routes for JWT token management.

Provides endpoints for user authentication, token generation,
and session management for the Nucleus Proxy.
"""

import jwt
import logging
from datetime import datetime, timedelta, timezone
from sanic import Blueprint, Request, HTTPResponse
from sanic.response import json as sanic_json
from pydantic import BaseModel, Field
from typing import Optional

from app.config import settings
from app.nucleus.client import get_nucleus_client

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", url_prefix="/v1/auth")


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., description="Username for Nucleus authentication", json_schema_extra={"example": "omniverse"})
    password: str = Field(..., description="Password for Nucleus authentication", json_schema_extra={"example": "password123"})


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str = Field(..., description="JWT access token for API authentication")
    token_type: str = Field(default="Bearer", description="Token type (always Bearer)")
    expires_in: int = Field(..., description="Token expiration time in seconds", json_schema_extra={"example": 900})


def create_jwt_token(username: str, expires_in_minutes: int = 15) -> str:
    """Create a JWT token for proxy authentication."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,  # subject (username)
        "iat": now,       # issued at
        "exp": now + timedelta(minutes=expires_in_minutes),  # expiration
        "iss": "nucleus-proxy",  # issuer
        "type": "access"
    }
    
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
            return sanic_json({
                "error": "Authentication failed",
                "message": "Invalid credentials"
            }, status=401)
        
        # Create proxy JWT token
        access_token = create_jwt_token(login_req.username)
        
        logger.info(f"User {login_req.username} authenticated successfully")
        
        return sanic_json({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900  # 15 minutes
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
        request.ctx.user = {
            "username": payload.get("sub"),
            "token_payload": payload
        }
        
        return await f(request, *args, **kwargs)
    
    return wrapper


def get_current_user(request: Request) -> dict:
    """Get current user information from request context."""
    user_info = getattr(request.ctx, 'user', None)
    if user_info:
        return user_info.get('token_payload', {})
    return {}
