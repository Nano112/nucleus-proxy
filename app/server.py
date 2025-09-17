"""
Main Sanic application server for the Nucleus Proxy.

Provides HTTP(S) proxy functionality for NVIDIA Omniverse Nucleus servers
with multi-tenancy, security, and real-time event capabilities.
"""

import logging
from pathlib import Path
from sanic import Sanic, Request, HTTPResponse
from sanic.response import json as sanic_json
# from sanic_ext import Extend  # Auto-loaded by Sanic
from app.config import settings
from app.routes.auth import auth_bp
from app.routes.files import files_bp
from app.routes.uploads import uploads_bp
from app.routes.signed_urls import signed_urls_bp
from app.routes.monitoring import monitoring_bp
from app.routes.tenants import tenants_bp
from app.routes.realtime import realtime_bp
from app.routes.ui import ui_bp, ui_api_bp
from app.middleware.monitoring import setup_monitoring_middleware
from app.middleware.security import security_middleware


def create_app() -> Sanic:
    """Create and configure the Sanic application."""
    
    # Create app instance that will be registered in the app registry
    app = Sanic("nucleus-proxy")

    timeout_seconds = max(1, int(settings.request_timeouts))
    app.config.REQUEST_TIMEOUT = timeout_seconds
    app.config.RESPONSE_TIMEOUT = timeout_seconds
    app.config.KEEP_ALIVE_TIMEOUT = max(5, min(timeout_seconds // 2, 120))

    static_dir = Path(__file__).resolve().parent / "static"
    app.static("/static", str(static_dir))
    
    # Configure Sanic-Ext for OpenAPI
    # OpenAPI/Swagger metadata
    app.ext.openapi.title = "Nucleus Proxy API"
    app.ext.openapi.version = "v1"
    app.ext.openapi.description = (
        "HTTP(S) proxy for NVIDIA Omniverse Nucleus with authentication, "
        "file management, uploads, signed URLs, monitoring, multi‑tenant "
        "controls, and realtime event streaming."
    )
    
    # Configure CORS
    app.config.CORS_ORIGINS = settings.cors_allow_origins
    
    # Configure logging
    logging.basicConfig(level=getattr(logging, settings.log_level.upper()))
    logging.getLogger('aiosqlite').setLevel(logging.WARNING)
    
    # Register blueprints
    app.blueprint(auth_bp)
    app.blueprint(files_bp)
    app.blueprint(uploads_bp)
    app.blueprint(signed_urls_bp)
    app.blueprint(monitoring_bp)
    app.blueprint(tenants_bp)
    app.blueprint(realtime_bp)
    app.blueprint(ui_bp)
    app.blueprint(ui_api_bp)
    
    # Setup monitoring middleware
    setup_monitoring_middleware(app)
    
    # Setup security hardening middleware
    security_middleware(app)

    # Add startup tasks
    @app.before_server_start
    async def setup_database(app_instance, loop):
        """Initialize database and services on server start"""
        from app.db.sqlite import initialize_database
        from app.services.file_indexer import initialize_file_indexer
        from app.services.search_engine import initialize_search_engine
        from app.services.metrics import initialize_metrics
        from app.services.background_tasks import initialize_background_tasks
        from app.services.tenancy import initialize_tenancy
        from app.services.security import initialize_security
        from app.services.events import initialize_events
        
        # Initialize core database
        await initialize_database()
        
        # Initialize indexing and search services
        await initialize_file_indexer()
        await initialize_search_engine()
        
        # Initialize monitoring and metrics
        await initialize_metrics()
        await initialize_background_tasks()
        
        # Initialize security and multi-tenancy
        await initialize_tenancy()
        await initialize_security()
        
        # Initialize real-time event system
        await initialize_events()
    
    @app.before_server_stop
    async def cleanup_services(app_instance, loop):
        """Clean up services on server shutdown"""
        from app.services.metrics import shutdown_metrics
        from app.services.background_tasks import shutdown_background_tasks
        from app.services.tenancy import shutdown_tenancy
        from app.services.security import shutdown_security
        from app.services.events import shutdown_events
        
        await shutdown_events()
        await shutdown_security()
        await shutdown_tenancy()
        await shutdown_background_tasks()
        await shutdown_metrics()
    
    # Health endpoint
    @app.get("/health")
    async def health(request: Request) -> HTTPResponse:
        """
        Health check.

        Returns service liveness information. Public endpoint used by load
        balancers and uptime monitors.

        Responses:
        - 200: JSON with `status`, `service`, `version`, `timestamp`.
        """
        from datetime import datetime, timezone
        return sanic_json({
            "status": "OK",
            "service": "nucleus-proxy",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    

    
    # Error handlers are handled by monitoring middleware
    
    return app


# Create app instance at module level for Sanic app loader
app = create_app()


# The main() function is now in run.py
# The app instance is created at module level above for proper multiprocess support
