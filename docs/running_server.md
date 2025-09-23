# Running the Nucleus Proxy Server

The Nucleus Proxy server can be run in several ways, supporting both single-process and multi-process modes.

## Quick Start

```bash
# Run with default settings
python run.py

# Or using uv
uv run python run.py
```

## Configuration via Environment Variables

The server behavior can be controlled through environment variables:

```bash
# Set log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO python run.py

# Set number of worker processes (for production)
PROXY_WORKERS=4 python run.py

# Set bind address and port
PROXY_BIND="0.0.0.0:8088" python run.py

# Enable auto-reload for development
AUTO_RELOAD=1 python run.py
```

## Running in Production (Multi-Process Mode)

For production deployments, use multiple worker processes:

```bash
# Run with 4 workers
LOG_LEVEL=INFO PROXY_WORKERS=4 python run.py

# The server will automatically use single-process mode when DEBUG is enabled
LOG_LEVEL=DEBUG python run.py  # Always uses 1 worker
```

## Using the Sanic CLI

You can also run the server directly with the Sanic CLI:

```bash
# Basic usage
sanic app.server:app

# With custom settings
sanic app.server:app --host 0.0.0.0 --port 8088 --workers 4

# Development mode with auto-reload
sanic app.server:app --dev

# Single process mode (useful for debugging)
sanic app.server:app --single-process
```

## Docker Deployment

When running in Docker, use the following command in your Dockerfile:

```dockerfile
CMD ["python", "run.py"]
```

Or for better signal handling:

```dockerfile
CMD ["sanic", "app.server:app", "--host", "0.0.0.0", "--port", "8088"]
```

## Systemd Service

For systemd deployments, create a service file:

```ini
[Unit]
Description=Nucleus Proxy Server
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/opt/nucleus-proxy
Environment="LOG_LEVEL=INFO"
Environment="PROXY_WORKERS=4"
Environment="PROXY_BIND=0.0.0.0:8088"
ExecStart=/usr/bin/python /opt/nucleus-proxy/run.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## Development vs Production

### Development Mode
- Single worker process
- Debug logging enabled
- Auto-reload enabled
- Access logs enabled

```bash
LOG_LEVEL=DEBUG AUTO_RELOAD=1 python run.py
```

### Production Mode
- Multiple worker processes
- Info/Warning level logging
- Auto-reload disabled
- Access logs disabled (unless explicitly enabled)

```bash
LOG_LEVEL=INFO PROXY_WORKERS=4 python run.py
```

## Health Check

The server provides a health endpoint at `/health` that can be used for monitoring:

```bash
curl http://localhost:8088/health
```

## Troubleshooting

### Address Already in Use

If you get an "Address already in use" error, find and kill the existing process:

```bash
# Find the process
lsof -i :8088

# Kill it
pkill -f "python.*run.py"
```

### Worker Process Issues

If workers fail to start in multi-process mode, try running in single-process mode first to identify startup errors:

```bash
# Run with single process to see detailed errors
sanic app.server:app --single-process
```

### Import Errors in Multi-Process Mode

The app instance must be created at module level in `app/server.py` for multi-process mode to work. The current implementation handles this correctly by creating the app instance at module level:

```python
# app/server.py
app = create_app()  # Created at module level for proper multi-process support
```