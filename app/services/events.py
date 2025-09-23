"""
Event system and broadcasting for M8 milestone.

Provides real-time event publishing/subscribing, event persistence,
and broadcasting to multiple clients with filtering capabilities.
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import weakref
from collections import defaultdict

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Event types for real-time notifications"""
    FILE_UPLOADED = "file_uploaded"  # Back-compat alias used by tests
    TEST_EVENT = "test_event"        # Back-compat for test endpoint
    FILE_UPLOAD_STARTED = "file_upload_started"
    FILE_UPLOAD_PROGRESS = "file_upload_progress"
    FILE_UPLOAD_COMPLETED = "file_upload_completed"
    FILE_UPLOAD_FAILED = "file_upload_failed"
    FILE_DELETED = "file_deleted"
    FILE_INDEXED = "file_indexed"
    SEARCH_COMPLETED = "search_completed"
    SYNC_STARTED = "sync_started"
    SYNC_COMPLETED = "sync_completed"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    TENANT_CREATED = "tenant_created"
    TENANT_UPDATED = "tenant_updated"
    SYSTEM_ALERT = "system_alert"
    QUOTA_WARNING = "quota_warning"
    SECURITY_EVENT = "security_event"


class EventChannel(str, Enum):
    """Event channels for organizing events"""
    FILES = "files"
    UPLOADS = "uploads"
    SEARCH = "search"
    SYSTEM = "system"
    SECURITY = "security"
    USERS = "users"
    TENANTS = "tenants"
    ALL = "*"


@dataclass
class Event:
    """Real-time event data structure"""
    id: str
    type: EventType
    channel: EventChannel
    tenant_id: str
    timestamp: datetime
    data: Dict[str, Any]
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'type': self.type.value,
            'channel': self.channel.value,
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())


@dataclass
class EventSubscription:
    """Event subscription configuration"""
    subscriber_id: str
    tenant_id: str
    user_id: Optional[str]
    channels: Set[EventChannel]
    event_types: Set[EventType]
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def matches_event(self, event: Event) -> bool:
        """Check if subscription matches an event"""
        # Check tenant isolation
        if event.tenant_id != self.tenant_id:
            return False
        
        # Check user isolation (if user_id is specified)
        if self.user_id and event.user_id != self.user_id:
            return False
        
        # Check channels
        if EventChannel.ALL not in self.channels and event.channel not in self.channels:
            return False
        
        # Check event types
        if event.type not in self.event_types:
            return False
        
        # Check custom filters
        for filter_key, filter_value in self.filters.items():
            if filter_key in event.data:
                if event.data[filter_key] != filter_value:
                    return False
        
        return True


class EventSubscriber:
    """Base class for event subscribers"""
    
    def __init__(self, subscriber_id: str, subscription: EventSubscription):
        self.subscriber_id = subscriber_id
        self.subscription = subscription
        self.last_seen = datetime.now(timezone.utc)
    
    async def send_event(self, event: Event):
        """Send event to subscriber (to be implemented by subclasses)"""
        raise NotImplementedError
    
    async def close(self):
        """Close subscriber connection"""
        pass


class EventManager:
    """
    Manages real-time events including publishing, subscribing,
    and broadcasting to connected clients.
    """
    
    def __init__(self):
        self.subscribers: Dict[str, EventSubscriber] = {}
        self.event_history: List[Event] = []
        self.max_history_size = 10000
        self.channel_subscribers: Dict[EventChannel, Set[str]] = defaultdict(set)
        self.type_subscribers: Dict[EventType, Set[str]] = defaultdict(set)
        self._cleanup_task: Optional[asyncio.Task] = None
        self._initialized = False
    
    async def initialize(self):
        """Initialize the event manager"""
        if self._initialized:
            return
        
        # Start cleanup task for expired subscriptions
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_subscribers())
        
        self._initialized = True
        logger.info("Event manager initialized")
    
    async def shutdown(self):
        """Shutdown the event manager"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all subscribers
        for subscriber in list(self.subscribers.values()):
            await subscriber.close()
        
        self.subscribers.clear()
        logger.info("Event manager shutdown")
    
    def subscribe(self, subscriber: EventSubscriber):
        """Add an event subscriber"""
        self.subscribers[subscriber.subscriber_id] = subscriber
        
        # Update channel and type indexes
        subscription = subscriber.subscription
        for channel in subscription.channels:
            self.channel_subscribers[channel].add(subscriber.subscriber_id)
        
        for event_type in subscription.event_types:
            self.type_subscribers[event_type].add(subscriber.subscriber_id)
        
        logger.info(f"Added subscriber: {subscriber.subscriber_id} for tenant {subscription.tenant_id}")
    
    def unsubscribe(self, subscriber_id: str):
        """Remove an event subscriber"""
        if subscriber_id not in self.subscribers:
            return
        
        subscriber = self.subscribers[subscriber_id]
        subscription = subscriber.subscription
        
        # Remove from indexes
        for channel in subscription.channels:
            self.channel_subscribers[channel].discard(subscriber_id)
        
        for event_type in subscription.event_types:
            self.type_subscribers[event_type].discard(subscriber_id)
        
        # Close and remove subscriber
        asyncio.create_task(subscriber.close())
        del self.subscribers[subscriber_id]
        
        logger.info(f"Removed subscriber: {subscriber_id}")
    
    async def publish_event(self, event_type: EventType, channel: EventChannel, 
                          tenant_id: str, data: Dict[str, Any],
                          user_id: Optional[str] = None, 
                          metadata: Optional[Dict[str, Any]] = None):
        """Publish a new event"""
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            channel=channel,
            tenant_id=tenant_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            data=data,
            metadata=metadata or {}
        )
        
        # Store in history
        self.event_history.append(event)
        if len(self.event_history) > self.max_history_size:
            self.event_history = self.event_history[-self.max_history_size//2:]
        
        # Broadcast to subscribers
        await self._broadcast_event(event)
        
        logger.debug(f"Published event: {event_type.value} for tenant {tenant_id}")
    
    async def _broadcast_event(self, event: Event):
        """Broadcast event to matching subscribers"""
        # Get potential subscribers from indexes
        potential_subscribers = set()
        
        # Add subscribers for this channel
        potential_subscribers.update(self.channel_subscribers.get(event.channel, set()))
        potential_subscribers.update(self.channel_subscribers.get(EventChannel.ALL, set()))
        
        # Add subscribers for this event type
        potential_subscribers.update(self.type_subscribers.get(event.type, set()))
        
        # Send event to matching subscribers
        tasks = []
        for subscriber_id in potential_subscribers:
            if subscriber_id in self.subscribers:
                subscriber = self.subscribers[subscriber_id]
                if subscriber.subscription.matches_event(event):
                    tasks.append(subscriber.send_event(event))
        
        # Send events concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_event_history(self, tenant_id: str, channels: Optional[List[EventChannel]] = None,
                         event_types: Optional[List[EventType]] = None,
                         since: Optional[datetime] = None,
                         limit: int = 100) -> List[Event]:
        """Get filtered event history"""
        events = []
        
        for event in reversed(self.event_history[-limit*2:]):  # Get more to filter
            # Check tenant
            if event.tenant_id != tenant_id:
                continue
            
            # Check timestamp
            if since and event.timestamp < since:
                continue
            
            # Check channels
            if channels and event.channel not in channels:
                continue
            
            # Check event types
            if event_types and event.type not in event_types:
                continue
            
            events.append(event)
            
            if len(events) >= limit:
                break
        
        return list(reversed(events))
    
    def get_subscriber_count(self) -> int:
        """Get current subscriber count"""
        return len(self.subscribers)
    
    def get_subscriber_stats(self) -> Dict[str, Any]:
        """Get subscriber statistics"""
        stats = {
            'total_subscribers': len(self.subscribers),
            'by_channel': {},
            'by_tenant': defaultdict(int),
            'event_history_size': len(self.event_history)
        }
        
        # Count by channel
        for channel, subscriber_ids in self.channel_subscribers.items():
            stats['by_channel'][channel.value] = len(subscriber_ids)
        
        # Count by tenant
        for subscriber in self.subscribers.values():
            stats['by_tenant'][subscriber.subscription.tenant_id] += 1
        
        stats['by_tenant'] = dict(stats['by_tenant'])
        
        return stats
    
    async def _cleanup_expired_subscribers(self):
        """Cleanup expired or inactive subscribers"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                now = datetime.now(timezone.utc)
                expired_subscribers = []
                
                for subscriber_id, subscriber in self.subscribers.items():
                    # Remove subscribers inactive for more than 1 hour
                    if now - subscriber.last_seen > timedelta(hours=1):
                        expired_subscribers.append(subscriber_id)
                
                for subscriber_id in expired_subscribers:
                    self.unsubscribe(subscriber_id)
                
                if expired_subscribers:
                    logger.info(f"Cleaned up {len(expired_subscribers)} expired subscribers")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in subscriber cleanup: {e}")


# Event publishing helpers

async def publish_file_upload_started(tenant_id: str, user_id: str, filename: str, size: int):
    """Publish file upload started event"""
    manager = await get_event_manager()
    await manager.publish_event(
        EventType.FILE_UPLOAD_STARTED,
        EventChannel.FILES,
        tenant_id,
        {
            'filename': filename,
            'size': size,
            'progress': 0
        },
        user_id=user_id
    )


async def publish_file_upload_progress(tenant_id: str, user_id: str, filename: str, 
                                     bytes_uploaded: int, total_size: int):
    """Publish file upload progress event"""
    manager = await get_event_manager()
    progress = (bytes_uploaded / total_size * 100) if total_size > 0 else 0
    
    await manager.publish_event(
        EventType.FILE_UPLOAD_PROGRESS,
        EventChannel.FILES,
        tenant_id,
        {
            'filename': filename,
            'bytes_uploaded': bytes_uploaded,
            'total_size': total_size,
            'progress': round(progress, 2)
        },
        user_id=user_id
    )


async def publish_file_upload_completed(tenant_id: str, user_id: str, filename: str, 
                                      file_path: str, size: int):
    """Publish file upload completed event"""
    manager = await get_event_manager()
    await manager.publish_event(
        EventType.FILE_UPLOAD_COMPLETED,
        EventChannel.FILES,
        tenant_id,
        {
            'filename': filename,
            'file_path': file_path,
            'size': size,
            'progress': 100
        },
        user_id=user_id
    )


async def publish_system_alert(tenant_id: str, level: str, message: str, details: Dict[str, Any]):
    """Publish system alert event"""
    manager = await get_event_manager()
    await manager.publish_event(
        EventType.SYSTEM_ALERT,
        EventChannel.SYSTEM,
        tenant_id,
        {
            'level': level,
            'message': message,
            'details': details
        }
    )


async def publish_security_event(tenant_id: str, user_id: str, event_type: str, 
                                resource: str, details: Dict[str, Any]):
    """Publish security event"""
    manager = await get_event_manager()
    await manager.publish_event(
        EventType.SECURITY_EVENT,
        EventChannel.SECURITY,
        tenant_id,
        {
            'security_event_type': event_type,
            'resource': resource,
            'details': details
        },
        user_id=user_id
    )


# Global event manager instance
_event_manager: Optional[EventManager] = None


async def get_event_manager() -> EventManager:
    """Get or create the global event manager"""
    global _event_manager
    if _event_manager is None:
        _event_manager = EventManager()
        await _event_manager.initialize()
    return _event_manager


async def initialize_events():
    """Initialize the event system"""
    manager = await get_event_manager()
    logger.info("Event system initialized")


async def shutdown_events():
    """Shutdown the event system"""
    global _event_manager
    if _event_manager:
        await _event_manager.shutdown()
        _event_manager = None
