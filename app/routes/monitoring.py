"""
Operational monitoring and health check endpoints for M6.

Provides comprehensive monitoring, metrics collection, health checks,
and operational visibility for production deployment.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

from sanic import Blueprint, Request
from sanic.response import JSONResponse
from pydantic import BaseModel, Field
from sanic_ext import validate

from app.routes.auth import require_auth
from app.services.metrics import get_metrics_collector
from app.services.background_tasks import get_task_manager

logger = logging.getLogger(__name__)

# Create blueprint
monitoring_bp = Blueprint("monitoring", url_prefix="/v1/monitoring")


# Request/Response Models

class HealthCheckRequest(BaseModel):
    """Request model for health checks"""
    include_details: bool = Field(False, description="Include detailed health information")
    check_dependencies: bool = Field(True, description="Check external dependencies")


class MetricsRequest(BaseModel):
    """Request model for metrics retrieval"""
    name_filter: Optional[str] = Field(None, description="Filter metrics by name pattern")
    since_minutes: Optional[int] = Field(60, ge=1, le=1440, description="Get metrics since N minutes ago")
    summary_only: bool = Field(False, description="Return only metric summaries")


# Route handlers

@monitoring_bp.get("/health", name="monitoring_basic_health")
async def basic_health_check(request: Request) -> JSONResponse:
    """
    Basic health.

    Public liveness probe for load balancers. Returns quick status and checks
    DB connectivity opportunistically.

    Responses:
    - 200: `{ "status": "healthy|degraded|unhealthy", "database": "healthy|unhealthy", ... }`
    - 503: Error details
    """
    try:
        # Basic service status
        status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "nucleus-proxy",
            "version": "1.0.0",
            "components": {}
        }
        
        # Quick database check
        try:
            from app.db.sqlite import get_database
            db = await get_database()
            # Just verify we can get a connection
            await db.get_indexing_stats()
            status["database"] = "healthy"
            status["components"]["database"] = "healthy"
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
            status["database"] = "unhealthy"
            status["status"] = "degraded"
            status["components"]["database"] = "unhealthy"
        
        # Other components (best effort)
        try:
            from app.services.metrics import get_metrics_collector
            _ = get_metrics_collector()
            status["components"]["metrics"] = "healthy"
        except Exception:
            status["components"]["metrics"] = "unhealthy"
            status["status"] = "degraded"
        try:
            from app.services.background_tasks import get_task_manager
            _ = await get_task_manager()
            status["components"]["background_tasks"] = "healthy"
        except Exception:
            status["components"]["background_tasks"] = "unhealthy"
            status["status"] = "degraded"
        
        return JSONResponse(status)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse({
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }, status=503)


@monitoring_bp.post("/health/detailed", name="monitoring_detailed_health")
@require_auth
async def detailed_health_check(request: Request) -> JSONResponse:
    """
    Detailed health with component checks.

    Security: Bearer token required.

    Request Body (application/json):
    - include_details: boolean (default false)
    - check_dependencies: boolean (default true)

    Responses:
    - 200: `{ "status": "healthy|degraded", "checks": { ... }, "summary": { ... } }`
    - 503: Error details
    """
    try:
        # Parse request body
        body_data = request.json or {}
        include_details = body_data.get('include_details', False)
        check_dependencies = body_data.get('check_dependencies', True)
        
        health_status = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "healthy",
            "service": "nucleus-proxy",
            "version": "1.0.0",
            "uptime_seconds": None  # Could track server start time
        }
        
        checks = {}
        overall_healthy = True
        
        # Database health
        try:
            from app.db.sqlite import get_database
            db = await get_database()
            stats = await db.get_indexing_stats()
            checks["database"] = {
                "status": "healthy",
                "indexed_files": stats.get("indexed_count", 0),
                "index_size": stats.get("indexed_size", 0),
                "details": "SQLite database operational"
            }
        except Exception as e:
            overall_healthy = False
            checks["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # File indexing service health
        try:
            from app.services.file_indexer import get_file_indexer
            indexer = await get_file_indexer()
            sync_status = await indexer.get_sync_status()
            checks["file_indexer"] = {
                "status": "healthy",
                "sync_in_progress": sync_status.get("sync_in_progress", False),
                "last_sync": sync_status.get("last_full_sync") or sync_status.get("last_incremental_sync"),
                "details": "File indexing service operational"
            }
        except Exception as e:
            logger.warning(f"File indexer health check failed: {e}")
            checks["file_indexer"] = {
                "status": "degraded",
                "error": str(e)
            }
        
        # Search engine health
        try:
            from app.services.search_engine import get_search_engine
            search_engine = await get_search_engine()
            # Quick search test
            result = await search_engine.search(query=None, page=1, page_size=1)
            checks["search_engine"] = {
                "status": "healthy",
                "indexed_files": result.total_count,
                "last_query_time_ms": result.query_time_ms,
                "details": "Search engine operational"
            }
        except Exception as e:
            logger.warning(f"Search engine health check failed: {e}")
            checks["search_engine"] = {
                "status": "degraded", 
                "error": str(e)
            }
        
        # Metrics system health
        try:
            collector = get_metrics_collector()
            metric_names = collector.get_metric_names()
            checks["metrics"] = {
                "status": "healthy",
                "tracked_metrics": len(metric_names),
                "details": "Metrics collection operational"
            }
        except Exception as e:
            logger.warning(f"Metrics health check failed: {e}")
            checks["metrics"] = {
                "status": "degraded",
                "error": str(e)
            }
        
        # External dependency checks (if requested)
        if check_dependencies:
            # Nucleus connectivity check
            try:
                from app.nucleus.client import get_nucleus_client
                nucleus_client = await get_nucleus_client()
                # Quick test - try to list root directory
                result = await nucleus_client.list_directory("/")
                if result and result.get('status') in ['OK', 'DONE']:
                    checks["nucleus"] = {
                        "status": "healthy",
                        "details": "Nucleus server connectivity verified"
                    }
                else:
                    checks["nucleus"] = {
                        "status": "unhealthy",
                        "error": f"Nucleus returned status: {result.get('status') if result else 'no response'}"
                    }
                    overall_healthy = False
            except Exception as e:
                logger.warning(f"Nucleus connectivity check failed: {e}")
                checks["nucleus"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                overall_healthy = False
        
        # System resources
        if include_details:
            try:
                collector = get_metrics_collector()
                system_metrics = collector.get_system_metrics()
                checks["system_resources"] = {
                    "status": "healthy",
                    "cpu_percent": system_metrics.get("process", {}).get("cpu_percent", 0),
                    "memory_mb": system_metrics.get("process", {}).get("memory_mb", 0),
                    "system_memory_percent": system_metrics.get("system", {}).get("memory_percent", 0),
                    "details": "System resources within normal ranges"
                }
                
                # Check for resource alerts
                memory_percent = system_metrics.get("system", {}).get("memory_percent", 0)
                if memory_percent > 90:
                    checks["system_resources"]["status"] = "warning"
                    checks["system_resources"]["details"] = f"High memory usage: {memory_percent}%"
                    
            except Exception as e:
                logger.warning(f"System resources check failed: {e}")
                checks["system_resources"] = {
                    "status": "degraded",
                    "error": str(e)
                }
        
        # Overall status
        health_status["status"] = "healthy" if overall_healthy else "degraded"
        health_status["checks"] = checks
        
        # Count check statuses
        status_counts = {}
        for check in checks.values():
            status = check.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        health_status["summary"] = status_counts
        
        return JSONResponse(health_status)
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        return JSONResponse({
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }, status=503)


@monitoring_bp.post("/metrics", name="monitoring_get_metrics")
@require_auth
async def get_metrics(request: Request) -> JSONResponse:
    """
    Retrieve application metrics.

    Security: Bearer token required.

    Request Body (application/json):
    - name_filter?: string pattern
    - since_minutes?: integer (default 60)
    - summary_only?: boolean (default false)

    Responses:
    - 200: `{ "metrics": [ ... ] | "summaries": [ ... ] }`
    - 500: Error details
    """
    try:
        # Parse request body
        body_data = request.json or {}
        name_filter = body_data.get('name_filter')
        since_minutes = body_data.get('since_minutes', 60)
        summary_only = body_data.get('summary_only', False)
        
        collector = get_metrics_collector()
        
        # Calculate time range
        since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes) if since_minutes else None
        
        if summary_only:
            # Return aggregated summaries
            summaries = collector.get_summaries(name_filter=name_filter)
            metrics_data = [summary.to_dict() for summary in summaries]
        else:
            # Return raw metric points
            metrics = collector.get_metrics(name_filter=name_filter, since=since)
            metrics_data = [metric.to_dict() for metric in metrics]
        
        return JSONResponse({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics_count": len(metrics_data),
            "time_range_minutes": since_minutes,
            "summary_only": summary_only,
            "name_filter": name_filter,
            "metrics": metrics_data
        })
        
    except Exception as e:
        logger.error(f"Error retrieving metrics: {e}")
        return JSONResponse({"error": f"Failed to retrieve metrics: {e}"}, status=500)


@monitoring_bp.get("/metrics", name="monitoring_system_metrics_compat")
async def get_metrics_compat(request: Request) -> JSONResponse:
    """
    Back-compat: GET /v1/monitoring/metrics returns system metrics.
    """
    try:
        collector = get_metrics_collector()
        system_metrics = collector.get_system_metrics()
        return JSONResponse({
            **system_metrics
        })
    except Exception as e:
        logger.error(f"Error getting system metrics (compat): {e}")
        return JSONResponse({"error": f"Failed to get system metrics: {e}"}, status=500)


@monitoring_bp.get("/metrics/names", name="monitoring_metric_names")
@require_auth
async def get_metric_names(request: Request) -> JSONResponse:
    """
    List metric names.

    Security: Bearer token required.

    Responses:
    - 200: `{ "metric_names": string[], "count": number }`
    - 500: Error details
    """
    try:
        collector = get_metrics_collector()
        metric_names = collector.get_metric_names()
        
        return JSONResponse({
            "metric_names": sorted(metric_names),
            "count": len(metric_names)
        })
        
    except Exception as e:
        logger.error(f"Error getting metric names: {e}")
        return JSONResponse({"error": f"Failed to get metric names: {e}"}, status=500)


@monitoring_bp.get("/system", name="monitoring_system_metrics")
@require_auth
async def get_system_metrics(request: Request) -> JSONResponse:
    """
    Detailed system metrics (CPU, memory, disk).

    Security: Bearer token required.

    Responses:
    - 200: JSON with process and system metrics
    - 500: Error details
    """
    try:
        collector = get_metrics_collector()
        system_metrics = collector.get_system_metrics()
        
        return JSONResponse(system_metrics)
        
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return JSONResponse({"error": f"Failed to get system metrics: {e}"}, status=500)


@monitoring_bp.get("/status", name="monitoring_service_status")
@require_auth
async def get_service_status(request: Request) -> JSONResponse:
    """
    Comprehensive service status.

    Security: Bearer token required.

    Aggregates DB, indexing, search, and metrics subsystem status.
    """
    try:
        from app.services.file_indexer import get_file_indexer
        from app.services.search_engine import get_search_engine
        from app.db.sqlite import get_database
        
        # Collect status from all major components
        status = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "nucleus-proxy",
            "version": "1.0.0"
        }
        
        # Database status
        try:
            db = await get_database()
            db_stats = await db.get_indexing_stats()
            status["database"] = {
                "status": "operational",
                "indexed_files": db_stats.get("indexed_count", 0),
                "total_size": db_stats.get("indexed_size", 0),
                "types": db_stats.get("types", {}),
                "recent_updates": db_stats.get("recent_updates", 0)
            }
        except Exception as e:
            status["database"] = {"status": "error", "error": str(e)}
        
        # File indexing status
        try:
            indexer = await get_file_indexer()
            sync_status = await indexer.get_sync_status()
            status["indexing"] = {
                "status": "operational",
                "sync_in_progress": sync_status.get("sync_in_progress", False),
                "last_full_sync": sync_status.get("last_full_sync"),
                "last_incremental_sync": sync_status.get("last_incremental_sync"),
                "index_stats": sync_status.get("index_stats", {})
            }
        except Exception as e:
            status["indexing"] = {"status": "error", "error": str(e)}
        
        # Search engine status
        try:
            search_engine = await get_search_engine()
            search_result = await search_engine.search(query=None, page=1, page_size=1)
            status["search"] = {
                "status": "operational",
                "total_indexed_files": search_result.total_count,
                "last_query_time_ms": search_result.query_time_ms
            }
        except Exception as e:
            status["search"] = {"status": "error", "error": str(e)}
        
        # Metrics status
        try:
            collector = get_metrics_collector()
            metric_names = collector.get_metric_names()
            system_metrics = collector.get_system_metrics()
            status["metrics"] = {
                "status": "operational",
                "tracked_metrics": len(metric_names),
                "system": system_metrics.get("process", {}),
                "database_size_mb": system_metrics.get("database", {}).get("size_mb", 0)
            }
        except Exception as e:
            status["metrics"] = {"status": "error", "error": str(e)}
        
        return JSONResponse(status)
        
    except Exception as e:
        logger.error(f"Error getting service status: {e}")
        return JSONResponse({"error": f"Failed to get service status: {e}"}, status=500)


@monitoring_bp.get("/diagnostics", name="monitoring_diagnostics")
async def get_diagnostics(request: Request) -> JSONResponse:
    """
    Get diagnostic information for troubleshooting.
    """
    try:
        diagnostics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": {},
            "configuration": {},
            "recent_errors": [],
            "performance": {}
        }
        
        # Environment info
        import os
        import sys
        diagnostics["environment"] = {
            "python_version": sys.version,
            "platform": sys.platform,
            "working_directory": os.getcwd(),
            "pid": os.getpid(),
            "process_id": os.getpid()
        }
        diagnostics["python_version"] = diagnostics["environment"]["python_version"]
        diagnostics["platform"] = diagnostics["environment"]["platform"]
        diagnostics["process_id"] = diagnostics["environment"]["process_id"]
        
        # Configuration (safe subset)
        from app.config import settings
        diagnostics["configuration"] = {
            "log_level": settings.log_level,
            "cors_origins": settings.cors_allow_origins,
            "sqlite_path": settings.sqlite_path,
            "staging_dir": settings.staging_dir,
            "max_upload_size": settings.max_upload_size
        }
        
        # Performance metrics
        collector = get_metrics_collector()
        system_metrics = collector.get_system_metrics()
        diagnostics["performance"] = {
            "cpu_percent": system_metrics.get("process", {}).get("cpu_percent", 0),
            "memory_mb": system_metrics.get("process", {}).get("memory_mb", 0),
            "threads": system_metrics.get("process", {}).get("threads", 0),
            "system_load": system_metrics.get("system", {}).get("load_average")
        }
        
        # Recent metrics summaries
        summaries = collector.get_summaries()
        request_metrics = [s for s in summaries if "http_requests" in s.name]
        if request_metrics:
            diagnostics["recent_activity"] = {
                "total_requests": sum(s.count for s in request_metrics),
                "avg_response_time": sum(s.avg_value or 0 for s in request_metrics) / len(request_metrics)
            }
        
        return JSONResponse(diagnostics)
        
    except Exception as e:
        logger.error(f"Error getting diagnostics: {e}")
        return JSONResponse({"error": f"Failed to get diagnostics: {e}"}, status=500)


@monitoring_bp.get("/background-tasks", name="monitoring_background_tasks_status")
async def get_background_tasks_status(request: Request) -> JSONResponse:
    """
    Background task status and history.

    Query Parameters:
    - task?: string filter
    - limit?: integer (default 20, max 1000)

    Responses:
    - 200: `{ "status": { ... }, "history": [ ... ] }`
    - 500: Error details
    """
    try:
        task_manager = await get_task_manager()
        
        # Get query parameters
        task_name = request.args.get('task')
        limit = int(request.args.get('limit', '20'))
        
        status = task_manager.get_task_status()
        history = task_manager.get_task_history(task_name, limit)
        
        # Compatibility shape expected by tests
        return JSONResponse({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "manager_running": status.get("manager_running", False),
            "tasks": status.get("tasks", {}),
            "execution_history": history
        })
        
    except Exception as e:
        logger.error(f"Error getting background task status: {e}")
        return JSONResponse({"error": f"Failed to get background task status: {e}"}, status=500)


@monitoring_bp.post("/background-tasks/<task_name:str>/run", name="monitoring_run_background_task")
@require_auth
async def run_background_task(request: Request, task_name: str) -> JSONResponse:
    """
    Run a background task immediately.

    Security: Bearer token required.

    Path Parameters:
    - task_name: string
    """
    try:
        task_manager = await get_task_manager()
        
        # Run the task
        result = await task_manager.run_task_now(task_name)
        
        return JSONResponse({
            "message": f"Task '{task_name}' executed",
            "result": result.to_dict()
        })
        
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status=404)
    except Exception as e:
        logger.error(f"Error running background task '{task_name}': {e}")
        return JSONResponse({"error": f"Failed to run background task: {e}"}, status=500)


@monitoring_bp.post("/background-tasks/<task_name:str>/enable", name="monitoring_enable_background_task")
@require_auth
async def enable_background_task(request: Request, task_name: str) -> JSONResponse:
    """
    Enable a background task.

    Security: Bearer token required.
    """
    try:
        task_manager = await get_task_manager()
        task_manager.enable_task(task_name)
        
        return JSONResponse({
            "message": f"Task '{task_name}' enabled"
        })
        
    except Exception as e:
        logger.error(f"Error enabling background task '{task_name}': {e}")
        return JSONResponse({"error": f"Failed to enable background task: {e}"}, status=500)


@monitoring_bp.post("/background-tasks/<task_name:str>/disable", name="monitoring_disable_background_task")
@require_auth
async def disable_background_task(request: Request, task_name: str) -> JSONResponse:
    """
    Disable a background task.

    Security: Bearer token required.
    """
    try:
        task_manager = await get_task_manager()
        task_manager.disable_task(task_name)
        
        return JSONResponse({
            "message": f"Task '{task_name}' disabled"
        })
        
    except Exception as e:
        logger.error(f"Error disabling background task '{task_name}': {e}")
        return JSONResponse({"error": f"Failed to disable background task: {e}"}, status=500)
