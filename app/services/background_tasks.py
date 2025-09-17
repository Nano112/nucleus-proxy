"""
Background task management system for M6 milestone.

Provides scheduled background tasks for maintenance, synchronization,
monitoring, and other operational requirements.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum

from app.config import settings

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Background task status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskResult:
    """Result of a background task execution"""
    task_name: str
    status: TaskStatus
    start_time: datetime
    end_time: Optional[datetime]
    duration_seconds: Optional[float]
    result: Optional[Any] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'task_name': self.task_name,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'result': self.result,
            'error': self.error
        }


class BackgroundTask:
    """Individual background task definition"""
    
    def __init__(self, 
                 name: str,
                 func: Callable,
                 interval_minutes: int,
                 enabled: bool = True,
                 run_on_startup: bool = False):
        self.name = name
        self.func = func
        self.interval_minutes = interval_minutes
        self.enabled = enabled
        self.run_on_startup = run_on_startup
        self.last_run: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self.task_handle: Optional[asyncio.Task] = None
        self.running = False
        
        # Calculate next run time
        if self.enabled:
            if self.run_on_startup:
                self.next_run = datetime.now(timezone.utc)
            else:
                self.next_run = datetime.now(timezone.utc) + timedelta(minutes=self.interval_minutes)
    
    def should_run(self) -> bool:
        """Check if task should run now"""
        if not self.enabled or self.running:
            return False
        
        if self.next_run is None:
            return False
            
        return datetime.now(timezone.utc) >= self.next_run
    
    def update_next_run(self):
        """Update next run time based on interval"""
        if self.enabled:
            self.next_run = datetime.now(timezone.utc) + timedelta(minutes=self.interval_minutes)
        else:
            self.next_run = None


class BackgroundTaskManager:
    """
    Manages and executes background tasks on schedules.
    
    Provides task registration, scheduling, execution monitoring,
    and operational visibility for background operations.
    """
    
    def __init__(self):
        self.tasks: Dict[str, BackgroundTask] = {}
        self.task_results: List[TaskResult] = []
        self.max_results_history = 100
        self.scheduler_task: Optional[asyncio.Task] = None
        self.running = False
        
        # Register default tasks
        self._register_default_tasks()
    
    def _register_default_tasks(self):
        """Register default system maintenance tasks"""
        config = settings.get_background_task_config()
        
        # File indexing sync task
        if config.get('sync_enabled', True):
            self.register_task(
                name="file_sync",
                func=self._file_sync_task,
                interval_minutes=config.get('sync_interval_minutes', 60),
                enabled=True,
                run_on_startup=False
            )
        
        # Cleanup task
        self.register_task(
            name="cleanup",
            func=self._cleanup_task,
            interval_minutes=config.get('cleanup_interval_minutes', 30),
            enabled=True,
            run_on_startup=False
        )
        
        # Metrics cleanup task
        self.register_task(
            name="metrics_cleanup",
            func=self._metrics_cleanup_task,
            interval_minutes=60,  # Every hour
            enabled=True,
            run_on_startup=False
        )
        
        # Health monitoring task
        self.register_task(
            name="health_check",
            func=self._health_check_task,
            interval_minutes=5,   # Every 5 minutes
            enabled=True,
            run_on_startup=True
        )
    
    def register_task(self,
                     name: str,
                     func: Callable,
                     interval_minutes: int,
                     enabled: bool = True,
                     run_on_startup: bool = False):
        """Register a new background task"""
        task = BackgroundTask(
            name=name,
            func=func,
            interval_minutes=interval_minutes,
            enabled=enabled,
            run_on_startup=run_on_startup
        )
        self.tasks[name] = task
        logger.info(f"Registered background task: {name} (interval: {interval_minutes}min, enabled: {enabled})")
    
    def unregister_task(self, name: str):
        """Unregister a background task"""
        if name in self.tasks:
            task = self.tasks[name]
            if task.task_handle and not task.task_handle.done():
                task.task_handle.cancel()
            del self.tasks[name]
            logger.info(f"Unregistered background task: {name}")
    
    def enable_task(self, name: str):
        """Enable a background task"""
        if name in self.tasks:
            self.tasks[name].enabled = True
            self.tasks[name].update_next_run()
            logger.info(f"Enabled background task: {name}")
    
    def disable_task(self, name: str):
        """Disable a background task"""
        if name in self.tasks:
            task = self.tasks[name]
            task.enabled = False
            task.next_run = None
            if task.task_handle and not task.task_handle.done():
                task.task_handle.cancel()
            logger.info(f"Disabled background task: {name}")
    
    async def run_task_now(self, name: str) -> TaskResult:
        """Run a specific task immediately"""
        if name not in self.tasks:
            raise ValueError(f"Task {name} not found")
        
        task = self.tasks[name]
        return await self._execute_task(task)
    
    async def start(self):
        """Start the background task scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Background task manager started")
    
    async def stop(self):
        """Stop the background task scheduler"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel scheduler
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Cancel running tasks
        for task in self.tasks.values():
            if task.task_handle and not task.task_handle.done():
                task.task_handle.cancel()
        
        logger.info("Background task manager stopped")
    
    def get_task_status(self) -> Dict[str, Any]:
        """Get status of all background tasks"""
        tasks_status = {}
        
        for name, task in self.tasks.items():
            tasks_status[name] = {
                'enabled': task.enabled,
                'running': task.running,
                'interval_minutes': task.interval_minutes,
                'last_run': task.last_run.isoformat() if task.last_run else None,
                'next_run': task.next_run.isoformat() if task.next_run else None,
                'run_on_startup': task.run_on_startup
            }
        
        return {
            'manager_running': self.running,
            'tasks': tasks_status,
            'total_tasks': len(self.tasks),
            'enabled_tasks': sum(1 for t in self.tasks.values() if t.enabled),
            'running_tasks': sum(1 for t in self.tasks.values() if t.running)
        }
    
    def get_task_history(self, task_name: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get task execution history"""
        results = self.task_results
        
        if task_name:
            results = [r for r in results if r.task_name == task_name]
        
        # Return most recent results first
        results = sorted(results, key=lambda x: x.start_time, reverse=True)
        return [r.to_dict() for r in results[:limit]]
    
    async def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                # Check which tasks need to run
                for task in self.tasks.values():
                    if task.should_run():
                        # Run task asynchronously without waiting
                        task.task_handle = asyncio.create_task(self._execute_task(task))
                
                # Clean up completed task handles
                for task in self.tasks.values():
                    if task.task_handle and task.task_handle.done():
                        task.task_handle = None
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in background task scheduler: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _execute_task(self, task: BackgroundTask) -> TaskResult:
        """Execute a single background task"""
        start_time = datetime.now(timezone.utc)
        task.running = True
        task.last_run = start_time
        
        result = TaskResult(
            task_name=task.name,
            status=TaskStatus.RUNNING,
            start_time=start_time,
            end_time=None,
            duration_seconds=None
        )
        
        logger.info(f"Starting background task: {task.name}")
        
        try:
            # Execute the task function
            task_result = await task.func()
            
            # Mark as completed
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            result.status = TaskStatus.COMPLETED
            result.end_time = end_time
            result.duration_seconds = duration
            result.result = task_result
            
            logger.info(f"Completed background task: {task.name} ({duration:.1f}s)")
            
            # Record metrics
            from app.services.metrics import get_metrics_collector
            collector = get_metrics_collector()
            collector.increment_counter("background_tasks_total", {
                "task_name": task.name,
                "status": "success"
            })
            collector.record_histogram("background_task_duration_seconds", duration, {
                "task_name": task.name
            })
            
        except Exception as e:
            # Mark as failed
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            result.status = TaskStatus.FAILED
            result.end_time = end_time
            result.duration_seconds = duration
            result.error = str(e)
            
            logger.error(f"Background task failed: {task.name} - {str(e)}")
            
            # Record metrics
            from app.services.metrics import get_metrics_collector
            collector = get_metrics_collector()
            collector.increment_counter("background_tasks_total", {
                "task_name": task.name,
                "status": "error"
            })
            
        finally:
            task.running = False
            task.update_next_run()
            
            # Store result
            self.task_results.append(result)
            
            # Trim history
            if len(self.task_results) > self.max_results_history:
                self.task_results = self.task_results[-self.max_results_history:]
        
        return result
    
    # Default task implementations
    
    async def _file_sync_task(self):
        """Incremental file sync task"""
        try:
            from app.services.file_indexer import get_file_indexer
            indexer = await get_file_indexer()
            
            # Perform incremental sync
            result = await indexer.incremental_sync(since_hours=2)  # Last 2 hours
            
            return {
                'files_processed': result.get('files_processed', 0),
                'files_indexed': result.get('files_indexed', 0),
                'errors': result.get('errors', 0),
                'sync_type': 'incremental'
            }
            
        except Exception as e:
            logger.error(f"File sync task failed: {e}")
            raise
    
    async def _cleanup_task(self):
        """Cleanup old files and data"""
        try:
            from app.db.sqlite import get_database
            db = await get_database()
            
            # Clean up old upload sessions
            cleanup_count = await db.cleanup_expired_sessions(max_age_hours=24)
            
            return {
                'expired_sessions_cleaned': cleanup_count,
                'cleanup_type': 'upload_sessions'
            }
            
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
            raise
    
    async def _metrics_cleanup_task(self):
        """Clean up old metrics data"""
        try:
            from app.services.metrics import get_metrics_collector
            collector = get_metrics_collector()
            
            # Metrics cleanup is handled automatically by the collector
            # This task just reports on metrics status
            summaries = collector.get_summaries()
            
            return {
                'active_metrics': len(summaries),
                'cleanup_type': 'metrics'
            }
            
        except Exception as e:
            logger.error(f"Metrics cleanup task failed: {e}")
            raise
    
    async def _health_check_task(self):
        """Regular health monitoring"""
        try:
            from app.services.metrics import get_metrics_collector
            collector = get_metrics_collector()
            
            # Record system metrics
            system_metrics = collector.get_system_metrics()
            
            # Record database size
            db_size_mb = system_metrics.get('database', {}).get('size_mb', 0)
            collector.record_gauge('database_size_mb', db_size_mb)
            
            # Record active connections/sessions (if available)
            from app.db.sqlite import get_database
            db = await get_database()
            stats = await db.get_indexing_stats()
            
            collector.record_gauge('indexed_files_count', stats.get('indexed_count', 0))
            
            return {
                'database_size_mb': db_size_mb,
                'indexed_files': stats.get('indexed_count', 0),
                'health_status': 'healthy'
            }
            
        except Exception as e:
            logger.error(f"Health check task failed: {e}")
            raise


# Global task manager instance
_task_manager: Optional[BackgroundTaskManager] = None


async def get_task_manager() -> BackgroundTaskManager:
    """Get or create the global background task manager"""
    global _task_manager
    if _task_manager is None:
        _task_manager = BackgroundTaskManager()
    return _task_manager


async def initialize_background_tasks():
    """Initialize and start the background task manager"""
    manager = await get_task_manager()
    await manager.start()


async def shutdown_background_tasks():
    """Shutdown the background task manager"""
    global _task_manager
    if _task_manager:
        await _task_manager.stop()