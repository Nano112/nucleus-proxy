"""Simple CORS middleware for the proxy."""

from __future__ import annotations

from typing import Iterable

from sanic import Sanic, Request
from sanic.response import text

from app.config import settings
from app.middleware.security import SecurityHeaders

DEFAULT_HEADERS = (
    'Authorization',
    'Content-Type',
    'Accept',
    'Origin',
    'User-Agent',
    'X-Requested-With',
)

DEFAULT_METHODS = (
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
    'OPTIONS',
)


def _normalize_header_values(values: Iterable[str]) -> str:
    return ', '.join(sorted(set(v.strip() for v in values if v)))


def setup_cors(app: Sanic) -> None:
    """Register request/response middleware to add CORS headers."""

    allowed_origins = settings.cors_allow_origins or '*'
    allow_credentials = getattr(settings, 'cors_allow_credentials', False)
    allow_headers = getattr(settings, 'cors_allow_headers', None)
    allow_methods = getattr(settings, 'cors_allow_methods', None)

    header_value = allowed_origins if allowed_origins == '*' else _normalize_header_values(allowed_origins.split(','))
    header_allow_headers = _normalize_header_values(allow_headers.split(',')) if isinstance(allow_headers, str) else _normalize_header_values(allow_headers or DEFAULT_HEADERS)
    header_allow_methods = _normalize_header_values(allow_methods.split(',')) if isinstance(allow_methods, str) else _normalize_header_values(allow_methods or DEFAULT_METHODS)

    def _apply_credentials(response):
        if allow_credentials and header_value != '*':
            response.headers['Access-Control-Allow-Credentials'] = 'true'

    @app.middleware('request')
    async def handle_preflight(request: Request):
        if request.method == 'OPTIONS':
            response = text('', 204)
            response.headers['Access-Control-Allow-Origin'] = header_value
            response.headers['Access-Control-Allow-Headers'] = header_allow_headers
            response.headers['Access-Control-Allow-Methods'] = header_allow_methods
            _apply_credentials(response)
            max_age = getattr(settings, 'cors_max_age', 600)
            response.headers['Access-Control-Max-Age'] = str(max_age)
            response = SecurityHeaders.add_security_headers(request, response)
            return response

    @app.middleware('response')
    async def add_cors_headers(request: Request, response):
        response.headers['Access-Control-Allow-Origin'] = header_value
        response.headers['Access-Control-Allow-Headers'] = header_allow_headers
        response.headers['Access-Control-Allow-Methods'] = header_allow_methods
        _apply_credentials(response)
        return SecurityHeaders.add_security_headers(request, response)
