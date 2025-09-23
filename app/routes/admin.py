"""
Admin endpoints for operational tasks
"""
from sanic import Blueprint, Request
from sanic.response import json as json_response
from sanic.exceptions import Unauthorized
import logging

from app.services.sync_recovery import get_sync_recovery_service
from app.config import settings

logger = logging.getLogger(__name__)

bp = Blueprint("admin", url_prefix="/admin")


@bp.middleware("request")
async def check_admin_auth(request: Request):
    """Simple admin authentication check"""
    # In production, implement proper admin authentication
    # For now, check for a simple admin key header in production mode
    if not settings.is_production:
        # Skip auth in development mode
        return
    
    admin_key = request.headers.get("X-Admin-Key")
    if admin_key != settings.proxy_secret:
        raise Unauthorized("Invalid admin credentials")


@bp.post("/sync/recover")
async def trigger_sync_recovery(request: Request):
    """
    Manually trigger sync recovery for interrupted uploads.
    
    Returns:
        JSON with recovery statistics
    """
    try:
        logger.info("Manual sync recovery triggered")
        
        service = await get_sync_recovery_service()
        result = await service.recover_interrupted_syncs()
        
        return json_response({
            "status": "success",
            "message": "Sync recovery completed",
            "statistics": result
        })
        
    except Exception as e:
        logger.error(f"Error in manual sync recovery: {e}")
        return json_response({
            "status": "error",
            "error": str(e)
        }, status=500)


@bp.get("/sync/status")
async def get_sync_status(request: Request):
    """
    Get current sync recovery statistics.
    
    Returns:
        JSON with current recovery stats
    """
    try:
        service = await get_sync_recovery_service()
        
        return json_response({
            "status": "success",
            "statistics": service.recovery_stats
        })
        
    except Exception as e:
        logger.error(f"Error getting sync status: {e}")
        return json_response({
            "status": "error",
            "error": str(e)
        }, status=500)