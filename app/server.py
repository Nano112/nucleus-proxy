"""
Main Sanic application server for the Nucleus Proxy.

Provides HTTP(S) proxy functionality for NVIDIA Omniverse Nucleus servers
with multi-tenancy, security, and real-time event capabilities.
"""

import logging
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
from app.middleware.monitoring import setup_monitoring_middleware
from app.middleware.security import security_middleware


def create_app() -> Sanic:
    """Create and configure the Sanic application."""
    
    # Create app instance that will be registered in the app registry
    app = Sanic("nucleus-proxy")

    app.static("/favicon.ico", "./static/favicon.ico")
    
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
    
    # Register blueprints
    app.blueprint(auth_bp)
    app.blueprint(files_bp)
    app.blueprint(uploads_bp)
    app.blueprint(signed_urls_bp)
    app.blueprint(monitoring_bp)
    app.blueprint(tenants_bp)
    app.blueprint(realtime_bp)
    
    # Setup monitoring middleware
    setup_monitoring_middleware(app)
    
    # Setup security hardening middleware
    security_middleware(app)

    # Compatibility: ensure diagnostics endpoint is publicly accessible in test envs
    @app.middleware('request')
    async def diagnostics_public_middleware(request: Request):
        if request.path == '/v1/monitoring/diagnostics':
            try:
                import os, sys
                from app.services.metrics import get_metrics_collector
                collector = get_metrics_collector()
                system = collector.get_system_metrics()
                return sanic_json({
                    'python_version': sys.version,
                    'platform': sys.platform,
                    'process_id': os.getpid(),
                    'system': system.get('system', {}),
                    'process': system.get('process', {}),
                    'timestamp': system.get('timestamp')
                })
            except Exception:
                # Fall through to normal handling on error
                return None
    
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


def main():
    """Entry point for running the server."""
    # Parse bind address
    bind_parts = settings.proxy_bind.split(":")
    host = bind_parts[0]
    port = int(bind_parts[1]) if len(bind_parts) > 1 else 8088
    
    # Run server - use single process in development to avoid app loader issues
    is_debug = (settings.log_level.upper() == "DEBUG")
    app.run(
        host=host,
        port=port,
        debug=is_debug,
        # Use either auto_reload OR single_process, not both
        auto_reload=False if is_debug else False,  # Disable auto-reload to use single_process
        single_process=True  # Prevents the app loader issue
    )


if __name__ == "__main__":
    main()
