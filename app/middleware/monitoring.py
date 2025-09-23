"""
Request/response logging and metrics middleware for M6.

Provides automatic request tracking, response time measurement,
error logging, and metrics collection for all API endpoints.
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sanic import Request, HTTPResponse
from sanic.response import JSONResponse

from app.services.metrics import (
    get_metrics_collector, 
    increment_request_counter, 
    record_request_duration
)

logger = logging.getLogger(__name__)


class RequestTracker:
    """Tracks request context and metrics"""
    
    def __init__(self, request: Request):
        self.request = request
        self.request_id = str(uuid.uuid4())[:8]  # Short request ID
        self.start_time = time.time()
        self.start_datetime = datetime.now(timezone.utc)
        self.method = request.method
        self.path = request.path
        self.endpoint = self._normalize_endpoint(request.path)
        self.user_agent = request.headers.get('user-agent', 'unknown')
        self.remote_addr = self._get_remote_addr(request)
        self.content_length = request.headers.get('content-length', 0)
    
    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for metrics grouping"""
        # Replace path parameters with placeholders to group similar routes
        # e.g. /v1/files/metadata/some/file/path -> /v1/files/metadata/{path}
        
        # Common patterns to normalize
        normalizations = [
            ("/v1/files/metadata/", "/v1/files/metadata/{path}"),
            ("/v1/signed-urls/upload", "/v1/signed-urls/upload"),
            ("/v1/signed-urls/download", "/v1/signed-urls/download"),
            ("/v1/uploads/", "/v1/uploads/{id}"),
        ]
        
        for pattern, replacement in normalizations:
            if path.startswith(pattern) and len(path) > len(pattern):
                return replacement
        
        # Default: return the path as-is for exact matching
        return path
    
    def _get_remote_addr(self, request: Request) -> str:
        """Get remote address, considering proxy headers"""
        # Check for proxy headers first
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            # Take the first IP from the list
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fall back to direct connection IP
        return getattr(request, 'remote_addr', 'unknown')
    
    def finish(self, response: HTTPResponse) -> Dict[str, Any]:
        """Finish tracking and return log data"""
        end_time = time.time()
        duration = end_time - self.start_time
        
        log_data = {
            'request_id': self.request_id,
            'timestamp': self.start_datetime.isoformat(),
            'method': self.method,
            'path': self.path,
            'endpoint': self.endpoint,
            'status_code': response.status,
            'duration_ms': round(duration * 1000, 2),
            'remote_addr': self.remote_addr,
            'user_agent': self.user_agent,
            'content_length': self.content_length,
            'response_size': len(response.body) if hasattr(response, 'body') and response.body else 0
        }
        
        # Record metrics
        increment_request_counter(self.method, self.endpoint, response.status)
        record_request_duration(self.method, self.endpoint, duration)
        
        return log_data


def setup_monitoring_middleware(app):
    """Setup request/response monitoring middleware for the Sanic app"""
    
    @app.middleware('request')
    async def before_request(request: Request):
        """Before request middleware - start tracking"""
        # Create request tracker and attach to request context
        tracker = RequestTracker(request)
        request.ctx.tracker = tracker
        
        # Log request start (debug level)
        logger.debug(f"Request {tracker.request_id}: {tracker.method} {tracker.path} from {tracker.remote_addr}")
    
    @app.middleware('response')
    async def after_request(request: Request, response: HTTPResponse):
        """After request middleware - finish tracking and log"""
        # Skip if no tracker (shouldn't happen)
        if not hasattr(request.ctx, 'tracker'):
            return response
        
        tracker = request.ctx.tracker
        log_data = tracker.finish(response)
        
        # Log based on status code and duration
        duration_ms = log_data['duration_ms']
        status_code = log_data['status_code']
        
        # Determine log level based on status and performance
        if status_code >= 500:
            log_level = logging.ERROR
        elif status_code >= 400:
            log_level = logging.WARNING
        elif duration_ms > 5000:  # > 5 seconds
            log_level = logging.WARNING
        elif duration_ms > 1000:  # > 1 second
            log_level = logging.INFO
        else:
            log_level = logging.DEBUG
        
        # Create log message
        message = (
            f"Request {log_data['request_id']}: "
            f"{log_data['method']} {log_data['endpoint']} -> "
            f"{status_code} ({duration_ms}ms)"
        )
        
        # Log with appropriate level
        logger.log(log_level, message, extra={
            'request_data': log_data,
            'request_id': log_data['request_id']
        })
        
        # Record slow requests
        if duration_ms > 1000:
            collector = get_metrics_collector()
            collector.increment_counter("slow_requests_total", {
                "endpoint": tracker.endpoint,
                "method": tracker.method
            })
        
        # Record error requests  
        if status_code >= 400:
            collector = get_metrics_collector()
            collector.increment_counter("error_requests_total", {
                "endpoint": tracker.endpoint,
                "method": tracker.method,
                "status_code": str(status_code)
            })
        
        return response
    
    @app.exception(Exception)
    async def exception_handler(request: Request, exception: Exception):
        """Handle uncaught exceptions with logging and metrics"""
        # Get request tracker if available
        request_id = "unknown"
        endpoint = request.path
        method = request.method
        
        if hasattr(request.ctx, 'tracker'):
            tracker = request.ctx.tracker
            request_id = tracker.request_id
            endpoint = tracker.endpoint
            
            # Finish tracking for the exception case
            duration = time.time() - tracker.start_time
            record_request_duration(method, endpoint, duration)
        
        # Log the exception
        logger.error(
            f"Request {request_id}: Unhandled exception in {method} {endpoint}: {str(exception)}",
            exc_info=exception,
            extra={
                'request_id': request_id,
                'endpoint': endpoint,
                'method': method,
                'exception_type': type(exception).__name__
            }
        )
        
        # Record exception metrics
        collector = get_metrics_collector()
        collector.increment_counter("exceptions_total", {
            "endpoint": endpoint,
            "method": method,
            "exception_type": type(exception).__name__
        })
        
        # Return error response
        return JSONResponse({
            "error": "Internal server error",
            "request_id": request_id,
            "message": str(exception) if app.config.get("DEBUG", False) else "An error occurred"
        }, status=500)


def get_request_context(request: Request) -> Optional[Dict[str, Any]]:
    """Get current request tracking context"""
    if hasattr(request.ctx, 'tracker'):
        tracker = request.ctx.tracker
        return {
            'request_id': tracker.request_id,
            'method': tracker.method,
            'path': tracker.path,
            'endpoint': tracker.endpoint,
            'remote_addr': tracker.remote_addr,
            'start_time': tracker.start_datetime.isoformat()
        }
    return None


def log_custom_metric(request: Request, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Log a custom metric within a request context"""
    collector = get_metrics_collector()
    
    # Add request context to labels if available
    if hasattr(request.ctx, 'tracker'):
        context_labels = {
            "endpoint": request.ctx.tracker.endpoint,
            "method": request.ctx.tracker.method
        }
        if labels:
            context_labels.update(labels)
        labels = context_labels
    
    collector.record_histogram(metric_name, value, labels)