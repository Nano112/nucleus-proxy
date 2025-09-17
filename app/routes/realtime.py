"""
Real-time WebSocket and Server-Sent Events (SSE) routes for M8 milestone.

Provides WebSocket endpoint for real-time file operation events, upload progress,
and system notifications with connection management and SSE streaming.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set

from sanic import Blueprint, Request
from sanic.response import HTTPResponse, ResponseStream, json as sanic_json

from app.routes.auth import get_current_user
from app.services.events import (
    get_event_manager, EventSubscriber, EventSubscription, EventChannel, 
    EventType, Event
)
from app.services.tenancy import get_tenancy_manager

logger = logging.getLogger(__name__)

# Create blueprint
realtime_bp = Blueprint("realtime", url_prefix="/v1/realtime")


class WebSocketSubscriber(EventSubscriber):
    """WebSocket event subscriber implementation"""
    
    def __init__(self, websocket, subscriber_id: str, subscription: EventSubscription):
        super().__init__(subscriber_id, subscription)
        self.websocket = websocket
        self.connected = True
    
    async def send_event(self, event: Event):
        """Send event to WebSocket client"""
        if not self.connected:
            return
        
        try:
            await self.websocket.send(event.to_json())
            self.last_seen = datetime.now(timezone.utc)
        except Exception as e:
            logger.warning(f"Failed to send event to WebSocket {self.subscriber_id}: {e}")
            self.connected = False
    
    async def close(self):
        """Close WebSocket connection"""
        self.connected = False
        try:
            await self.websocket.close()
        except:
            pass


class SSESubscriber(EventSubscriber):
    """Server-Sent Events subscriber implementation"""
    
    def __init__(self, response_queue: asyncio.Queue, subscriber_id: str, subscription: EventSubscription):
        super().__init__(subscriber_id, subscription)
        self.response_queue = response_queue
        self.connected = True
    
    async def send_event(self, event: Event):
        """Send event to SSE client"""
        if not self.connected:
            return
        
        try:
            # Format as SSE event
            sse_data = f"id: {event.id}\n"
            sse_data += f"event: {event.type.value}\n"
            sse_data += f"data: {event.to_json()}\n\n"
            
            await self.response_queue.put(sse_data.encode('utf-8'))
            self.last_seen = datetime.now(timezone.utc)
        except Exception as e:
            logger.warning(f"Failed to send event to SSE {self.subscriber_id}: {e}")
            self.connected = False
    
    async def close(self):
        """Close SSE connection"""
        self.connected = False


@realtime_bp.websocket("/ws")
async def websocket_events(request: Request, ws):
    """
    WebSocket for realtime events.

    Query Parameters:
    - channels: comma‑separated channel list or `*`
    - types: comma‑separated event types or `*`
    - user_only: boolean, only user‑scoped events

    Notes:
    - Sends a `connection_established` message on connect.
    - Supports `ping` → `pong` keepalives.
    """
    subscriber_id = None
    
    try:
        # Parse query parameters
        channels_param = request.args.get('channels', '*')
        types_param = request.args.get('types', '*')
        user_only = request.args.get('user_only', 'false').lower() == 'true'
        
        # Parse channels
        if channels_param == '*':
            channels = {EventChannel.ALL}
        else:
            channels = set()
            for channel_name in channels_param.split(','):
                try:
                    channels.add(EventChannel(channel_name.strip()))
                except ValueError:
                    logger.warning(f"Invalid channel: {channel_name}")
        
        # Parse event types
        if types_param == '*':
            event_types = set(EventType)
        else:
            event_types = set()
            for type_name in types_param.split(','):
                try:
                    event_types.add(EventType(type_name.strip()))
                except ValueError:
                    logger.warning(f"Invalid event type: {type_name}")
        
        # Get user context (this would need to be implemented based on your auth system)
        user_id = None
        tenant_id = "default-003776"  # Default tenant for now
        
        # For a real implementation, you'd extract this from JWT or session
        # user_context = await get_current_user_from_request(request)
        # if user_context:
        #     user_id = user_context['user_id']
        #     tenant_id = user_context['tenant_id']
        
        # Create subscription
        subscriber_id = f"ws_{datetime.now(timezone.utc).timestamp()}_{id(ws)}"
        subscription = EventSubscription(
            subscriber_id=subscriber_id,
            tenant_id=tenant_id,
            user_id=user_id if user_only else None,
            channels=channels,
            event_types=event_types
        )
        
        # Create and register subscriber
        event_manager = await get_event_manager()
        subscriber = WebSocketSubscriber(ws, subscriber_id, subscription)
        event_manager.subscribe(subscriber)
        
        # Send connection confirmation
        welcome_event = {
            'id': 'welcome',
            'type': 'connection_established',
            'channel': 'system',
            'tenant_id': tenant_id,
            'user_id': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {
                'subscriber_id': subscriber_id,
                'channels': [ch.value for ch in channels],
                'event_types': [et.value for et in event_types],
                'user_only': user_only
            },
            'metadata': {}
        }
        
        await ws.send(json.dumps(welcome_event))
        
        logger.info(f"WebSocket connected: {subscriber_id} for tenant {tenant_id}")
        
        # Keep connection alive and handle incoming messages
        async for message in ws:
            try:
                # Handle ping/pong or other control messages
                if message == "ping":
                    await ws.send("pong")
                    subscriber.last_seen = datetime.now(timezone.utc)
                elif message == "pong":
                    subscriber.last_seen = datetime.now(timezone.utc)
                else:
                    # Handle other message types if needed
                    logger.debug(f"Received WebSocket message: {message}")
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                break
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    
    finally:
        # Clean up subscriber
        if subscriber_id:
            try:
                event_manager = await get_event_manager()
                event_manager.unsubscribe(subscriber_id)
                logger.info(f"WebSocket disconnected: {subscriber_id}")
            except Exception as e:
                logger.error(f"Error cleaning up WebSocket subscriber: {e}")


@realtime_bp.get("/events", name="realtime_events_sse")
async def sse_events(request: Request):
    """
    Server‑Sent Events stream for realtime events.

    Query Parameters:
    - channels: comma‑separated channel list or `*`
    - types: comma‑separated event types or `*`
    - user_only: boolean, only user‑scoped events
    - last_event_id: resume from event ID

    Notes:
    - Sends `connection_established` event on connect.
    - Sends keepalive comments every 30s.
    """
    
    async def event_stream(response):
        subscriber_id = None
        response_queue = asyncio.Queue()
        
        try:
            # Parse query parameters
            channels_param = request.args.get('channels', '*')
            types_param = request.args.get('types', '*')
            user_only = request.args.get('user_only', 'false').lower() == 'true'
            last_event_id = request.args.get('last_event_id')
            
            # Parse channels
            if channels_param == '*':
                channels = {EventChannel.ALL}
            else:
                channels = set()
                for channel_name in channels_param.split(','):
                    try:
                        channels.add(EventChannel(channel_name.strip()))
                    except ValueError:
                        logger.warning(f"Invalid channel: {channel_name}")
            
            # Parse event types
            if types_param == '*':
                event_types = set(EventType)
            else:
                event_types = set()
                for type_name in types_param.split(','):
                    try:
                        event_types.add(EventType(type_name.strip()))
                    except ValueError:
                        logger.warning(f"Invalid event type: {type_name}")
            
            # Get user context (simplified for now)
            user_id = None
            tenant_id = "default-003776"  # Default tenant
            
            # Create subscription
            subscriber_id = f"sse_{datetime.now(timezone.utc).timestamp()}_{id(request)}"
            subscription = EventSubscription(
                subscriber_id=subscriber_id,
                tenant_id=tenant_id,
                user_id=user_id if user_only else None,
                channels=channels,
                event_types=event_types
            )
            
            # Create and register subscriber
            event_manager = await get_event_manager()
            subscriber = SSESubscriber(response_queue, subscriber_id, subscription)
            event_manager.subscribe(subscriber)
            
            # Send initial SSE headers and connection event
            await response.write("id: welcome\n")
            await response.write("event: connection_established\n")
            welcome_data = {
                'subscriber_id': subscriber_id,
                'channels': [ch.value for ch in channels],
                'event_types': [et.value for et in event_types],
                'user_only': user_only,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            await response.write(f"data: {json.dumps(welcome_data)}\n\n")
            
            # Send historical events if requested
            if last_event_id:
                try:
                    # Get events since last_event_id
                    history = event_manager.get_event_history(
                        tenant_id=tenant_id,
                        channels=list(channels) if EventChannel.ALL not in channels else None,
                        event_types=list(event_types),
                        limit=50
                    )
                    
                    # Send historical events
                    for event in history:
                        if event.id > last_event_id:  # Simple string comparison
                            sse_data = f"id: {event.id}\n"
                            sse_data += f"event: {event.type.value}\n"
                            sse_data += f"data: {event.to_json()}\n\n"
                            await response.write(sse_data)
                except Exception as e:
                    logger.error(f"Error sending historical events: {e}")
            
            logger.info(f"SSE connected: {subscriber_id} for tenant {tenant_id}")
            
            # Stream events
            while subscriber.connected:
                try:
                    # Wait for event with timeout to send keepalive
                    event_data = await asyncio.wait_for(response_queue.get(), timeout=30.0)
                    await response.write(event_data)
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    await response.write(": keepalive\n\n")
                except Exception as e:
                    logger.error(f"Error streaming SSE event: {e}")
                    break
        
        except Exception as e:
            logger.error(f"SSE error: {e}")
        
        finally:
            # Clean up subscriber
            if subscriber_id:
                try:
                    event_manager = await get_event_manager()
                    event_manager.unsubscribe(subscriber_id)
                    logger.info(f"SSE disconnected: {subscriber_id}")
                except Exception as e:
                    logger.error(f"Error cleaning up SSE subscriber: {e}")
    
    # Return streaming response with proper SSE headers
    return ResponseStream(event_stream, headers={
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'  # Disable nginx buffering
    })


@realtime_bp.get("/events/history", name="realtime_events_history")
async def get_event_history(request: Request):
    """
    Get recent historical events.

    Query Parameters:
    - channels?: comma‑separated channel list
    - types?: comma‑separated event types
    - since?: RFC3339/ISO timestamp
    - limit?: integer (default 100, max 1000)

    Responses:
    - 200: `{ "events": [ ... ], "count": number, "filters": { ... } }`
    - 400/500: Error details
    """
    try:
        # Parse query parameters
        channels_param = request.args.get('channels')
        types_param = request.args.get('types')
        since_param = request.args.get('since')
        limit = min(int(request.args.get('limit', '100')), 1000)
        
        # Get user context (simplified)
        tenant_id = "default-003776"  # Default tenant
        
        # Parse channels
        channels = None
        if channels_param:
            channels = []
            for channel_name in channels_param.split(','):
                try:
                    channels.append(EventChannel(channel_name.strip()))
                except ValueError:
                    pass
        
        # Parse event types
        event_types = None
        if types_param:
            event_types = []
            for type_name in types_param.split(','):
                try:
                    event_types.append(EventType(type_name.strip()))
                except ValueError:
                    pass
        
        # Parse since timestamp
        since = None
        if since_param:
            try:
                since = datetime.fromisoformat(since_param.replace('Z', '+00:00'))
            except ValueError:
                return sanic_json({"error": "Invalid since timestamp format"}, status=400)
        
        # Get event history
        event_manager = await get_event_manager()
        events = event_manager.get_event_history(
            tenant_id=tenant_id,
            channels=channels,
            event_types=event_types,
            since=since,
            limit=limit
        )
        
        # Convert to JSON
        events_data = [event.to_dict() for event in events]
        
        return sanic_json({
            "events": events_data,
            "count": len(events_data),
            "tenant_id": tenant_id,
            "filters": {
                "channels": [ch.value for ch in channels] if channels else None,
                "event_types": [et.value for et in event_types] if event_types else None,
                "since": since.isoformat() if since else None,
                "limit": limit
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting event history: {e}")
        return sanic_json({"error": "Failed to get event history"}, status=500)


@realtime_bp.get("/stats", name="realtime_stats")  
async def get_realtime_stats(request: Request):
    """
    Realtime connection and event statistics.

    Responses:
    - 200: `{ "realtime_stats": { ... }, "timestamp": string }`
    - 500: Error details
    """
    try:
        event_manager = await get_event_manager()
        stats = event_manager.get_subscriber_stats()
        
        return sanic_json({
            "realtime_stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting realtime stats: {e}")
        return sanic_json({"error": "Failed to get realtime stats"}, status=500)


@realtime_bp.post("/test-event", name="realtime_test_event")
async def publish_test_event(request: Request):
    """
    Publish a test event (development only).

    Request Body (application/json): `type`, `channel`, `data`, `user_id?`

    Responses:
    - 200: `{ "message": "Test event published", "event": { ... } }`
    - 500: Error details
    """
    try:
        # Parse request body
        body_data = request.json or {}
        event_type = body_data.get('type', 'system_alert')
        channel = body_data.get('channel', 'system')
        data = body_data.get('data', {'message': 'Test event'})
        
        # Get tenant context
        tenant_id = "default-003776"  # Default tenant
        user_id = body_data.get('user_id', 'test-user')
        
        # Publish event (be lenient with event type for tests)
        event_manager = await get_event_manager()
        try:
            etype = EventType(event_type)
        except ValueError:
            etype = EventType.TEST_EVENT
        await event_manager.publish_event(
            event_type=etype,
            channel=EventChannel(channel),
            tenant_id=tenant_id,
            data=data,
            user_id=user_id,
            metadata={'source': 'test_endpoint'}
        )
        
        return sanic_json({
            "message": "Test event published",
            "event": {
                "type": event_type,
                "channel": channel,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "data": data
            }
        })
        
    except Exception as e:
        logger.error(f"Error publishing test event: {e}")
        return sanic_json({"error": "Failed to publish test event"}, status=500)
