#!/usr/bin/env python3
"""
Run script for the Nucleus Proxy server.
"""

from app.server import app
from app.config import settings

if __name__ == "__main__":
    # Parse bind address
    bind_parts = settings.proxy_bind.split(":")
    host = bind_parts[0]
    port = int(bind_parts[1]) if len(bind_parts) > 1 else 8088
    
    is_debug = (settings.log_level.upper() == "DEBUG")
    workers = max(1, settings.proxy_workers)
    if is_debug:
        workers = 1

    auto_reload = settings.auto_reload

    # Run the app directly - the app instance is already created at module level
    app.run(
        host=host,
        port=port,
        debug=is_debug,
        workers=workers,
        auto_reload=auto_reload,
        access_log=is_debug,
    )
