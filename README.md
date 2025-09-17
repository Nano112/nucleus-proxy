# Nucleus Proxy

A high-performance HTTP(S) proxy server for NVIDIA Omniverse Nucleus, designed to simplify client integration and provide enterprise-grade features including multi-tenancy, security, and real-time capabilities.

## Features

### 🚀 Core Functionality
- **REST API Interface**: Clean, well-documented REST endpoints for all Nucleus operations
- **Resumable Uploads**: Chunked upload support with automatic retry and progress tracking
- **WebSocket Protocol**: Persistent connections to Nucleus with connection pooling
- **OpenAPI Documentation**: Comprehensive API documentation with interactive examples

### 🏢 Multi-Tenancy
- **Tenant Isolation**: Complete data and resource separation between tenants
- **Per-Tenant Configuration**: Customizable storage limits, user quotas, and feature flags
- **Domain-Based Routing**: Automatic tenant resolution based on request domain
- **User Management**: Role-based access control within each tenant

### 🔒 Security
- **JWT Authentication**: Secure token-based authentication with configurable expiration
- **API Key Management**: Per-tenant API keys with granular permissions
- **RBAC (Role-Based Access Control)**: Flexible permission system with custom roles
- **Security Hardening**: CSRF protection, input validation, security headers
- **Audit Logging**: Comprehensive activity logging for compliance

### ⚡ Real-Time Features  
- **WebSocket Events**: Live file operation notifications and system events
- **Server-Sent Events (SSE)**: HTTP streaming for real-time updates
- **Event Filtering**: Subscribe to specific channels and event types
- **Event History**: Queryable event log with filtering capabilities

### 📊 Monitoring & Operations
- **Health Checks**: Comprehensive system health monitoring
- **Metrics Collection**: Performance and usage metrics with aggregation
- **Background Tasks**: Automated maintenance and cleanup processes
- **System Diagnostics**: Detailed runtime information and troubleshooting

## Quick Start

### Prerequisites
- Python 3.13+
- Access to an NVIDIA Omniverse Nucleus server
- `uv` package manager (recommended) or `pip`

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd nucleus-proxy

# Quick setup for development (creates .env and directories)
python dev-setup.py

# Install dependencies with uv (recommended)
uv sync

# Or with pip
pip install -r pyproject.toml
```

### Configuration

Create a `.env` file in the project root:

```env
# Nucleus Server Configuration
NUCLEUS_HOST=your-nucleus-server.com
NUCLEUS_USERNAME=your-username
NUCLEUS_PASSWORD=your-password

# Proxy Server Configuration  
PROXY_BIND=0.0.0.0:8088
PROXY_SECRET=your-secret-key-32-characters-long

# Database and Storage
SQLITE_PATH=./data/proxy.db
STAGING_DIR=./data/staging

# Upload Configuration
MAX_UPLOAD_SIZE=5368709120  # 5 GB
PART_SIZE_DEFAULT=8388608   # 8 MB

# CORS and Security
CORS_ALLOW_ORIGINS=*
LOG_LEVEL=DEBUG  # DEBUG mode disables strict CSRF for development
```

### Running the Server

```bash
# Start the proxy server
uv run python -m app.server

# Or use the convenience script
uv run python run.py
```

The server will start on `http://localhost:8088` with:
- REST API endpoints under `/v1/`
- Interactive API documentation at `/docs`
- Health check at `/health`

## API Usage

### Authentication

```bash
# Login to get JWT token
curl -X POST http://localhost:8088/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your-username", "password": "your-password"}'

# Use token in subsequent requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8088/v1/files/list?path=/
```

### File Operations

```bash
# List directory contents
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8088/v1/files/list?path=/Users"

# Get file information
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8088/v1/files/info?path=/Users/file.txt"

# Create directory
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/Users/new-folder"}' \
  http://localhost:8088/v1/files/create-directory
```

### Multi-Tenancy

```bash
# Create a new tenant (admin required)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Company", "domain": "company.com", "max_storage_gb": 1000}' \
  http://localhost:8088/v1/tenants

# Create tenant user
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "email": "john@company.com", "role": "user"}' \
  http://localhost:8088/v1/tenants/TENANT_ID/users
```

### Real-Time Events

```javascript
// WebSocket connection
const ws = new WebSocket('ws://localhost:8088/v1/realtime/ws?channels=files&types=file_uploaded');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('File uploaded:', data);
};

// Server-Sent Events
const eventSource = new EventSource('http://localhost:8088/v1/realtime/events?channels=system');

eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('System event:', data);
};
```

## Development

### Project Structure

```
nucleus-proxy/
├── app/                    # Application code
│   ├── db/                # Database layer
│   ├── middleware/        # Custom middleware
│   ├── nucleus/          # Nucleus client
│   ├── routes/           # API route handlers
│   ├── services/         # Business logic services
│   ├── config.py         # Configuration management
│   └── server.py         # Main application server
├── tests/                # Test suite
│   ├── api/              # API integration tests
│   ├── unit/             # Unit tests
│   └── conftest.py       # Test configuration
├── .env                  # Environment configuration
└── pyproject.toml        # Project dependencies
```

### Running Tests

```bash
# Run all tests
uv run python -m pytest

# Run specific test categories
uv run python -m pytest tests/unit/          # Unit tests
uv run python -m pytest tests/api/           # API tests

# Run with coverage
uv run python -m pytest --cov=app tests/
```

### API Documentation

The proxy automatically generates comprehensive OpenAPI documentation available at:
- **Interactive docs**: http://localhost:8088/docs
- **OpenAPI JSON**: http://localhost:8088/openapi.json

**Note**: The documentation uses external CDNs for styling and JavaScript. The Content Security Policy is automatically relaxed for documentation endpoints to ensure proper loading.

## Security Configuration

### Development vs Production

The proxy automatically adjusts security settings based on the environment:

#### Development Mode (LOG_LEVEL=DEBUG)
- **CSRF Protection**: Disabled for easier API testing
- **Content Security Policy**: Permissive by default (allows external CDNs)
- **Error Details**: Detailed error messages in responses
- **CORS**: Permissive by default (`*`)

#### Production Mode (LOG_LEVEL=INFO/WARNING/ERROR)
- **CSRF Protection**: Enabled for state-changing requests
- **Content Security Policy**: Strict, only relaxed for `/docs` endpoints
- **Security Headers**: Full set of security headers applied
- **Error Details**: Generic error messages to prevent information disclosure

### Security Headers

The following security headers are automatically applied:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- Content Security Policy (environment-dependent)

### CORS Configuration

CORS is configured via the `CORS_ALLOW_ORIGINS` environment variable:
```env
# Development - allow all origins
CORS_ALLOW_ORIGINS=*

# Production - specific domains only
CORS_ALLOW_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
```

### Troubleshooting

#### Documentation Not Loading
If you see CSP errors in the browser console when accessing `/docs`:
1. Ensure `LOG_LEVEL=DEBUG` in your `.env` file for development
2. Restart the server after changing the log level
3. Check that external resources (fonts.googleapis.com, cdn.jsdelivr.net) are accessible

#### CSRF Token Errors
If you get "Invalid or missing CSRF token" errors:
1. Set `LOG_LEVEL=DEBUG` for development (disables CSRF)
2. For production, include `X-CSRF-Token` header in requests
3. Use API key authentication (`X-API-Key` header) to bypass CSRF

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`uv run python -m pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.