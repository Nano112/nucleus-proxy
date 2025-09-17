"""
Metrics collection and monitoring service for M6 milestone.

Provides comprehensive metrics collection, aggregation, and monitoring
capabilities for operational visibility and performance tracking.
"""

import asyncio
import logging
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum

logger = logging.getLogger(__name__)


class MetricType(str, Enum):
    """Types of metrics we collect"""
    COUNTER = "counter"           # Monotonic counters (requests, errors)
    GAUGE = "gauge"              # Current values (connections, memory)
    HISTOGRAM = "histogram"       # Distribution of values (response times)
    TIMER = "timer"              # Time duration measurements


@dataclass 
class MetricPoint:
    """Individual metric measurement"""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'name': self.name,
            'value': self.value,
            'type': self.metric_type.value,
            'timestamp': self.timestamp.isoformat(),
            'labels': self.labels
        }


@dataclass
class MetricSummary:
    """Aggregated metric summary"""
    name: str
    metric_type: MetricType
    count: int
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    avg_value: Optional[float] = None
    sum_value: Optional[float] = None
    last_value: Optional[float] = None
    last_updated: Optional[datetime] = None
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'name': self.name,
            'type': self.metric_type.value,
            'count': self.count,
            'min': self.min_value,
            'max': self.max_value,
            'avg': self.avg_value,
            'sum': self.sum_value,
            'last': self.last_value,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'labels': self.labels
        }


class MetricsCollector:
    """
    Comprehensive metrics collection and aggregation service.
    
    Collects metrics from various parts of the application and provides
    aggregated views for monitoring and alerting.
    """
    
    def __init__(self, max_points_per_metric: int = 1000, retention_hours: int = 24):
        self.max_points_per_metric = max_points_per_metric
        self.retention_hours = retention_hours
        
        # Raw metric storage - deques for efficient FIFO
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_points_per_metric))
        self._summaries: Dict[str, MetricSummary] = {}
        self._lock = threading.RLock()
        
        # Common application metrics
        self._init_standard_metrics()
        
        # Start cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

        # Simple request log expected by tests
        self.request_metrics: List[Dict[str, Any]] = []
    
    def _init_standard_metrics(self):
        """Initialize standard application metrics"""
        # HTTP request metrics
        self.record_counter("http_requests_total", 0, {"method": "GET", "status": "200"})
        self.record_counter("http_request_duration_seconds", 0, {"method": "GET"})
        
        # Upload metrics
        self.record_counter("uploads_total", 0, {"status": "success"})
        self.record_gauge("upload_sessions_active", 0)
        
        # Search metrics  
        self.record_counter("search_queries_total", 0)
        self.record_histogram("search_duration_seconds", 0)
        
        # File indexing metrics
        self.record_counter("files_indexed_total", 0)
        self.record_gauge("index_size_files", 0)
        
        # System metrics
        self.record_gauge("database_connections", 0)
        self.record_counter("background_tasks_total", 0, {"status": "success"})
    
    async def start(self):
        """Start the metrics collection service"""
        if self._running:
            return
            
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Metrics collector started")
    
    async def stop(self):
        """Stop the metrics collection service"""
        if not self._running:
            return
            
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Metrics collector stopped")
    
    def record_counter(self, name: str, value: Union[int, float], labels: Optional[Dict[str, str]] = None):
        """Record a counter metric (monotonic increasing)"""
        self._record_metric(name, value, MetricType.COUNTER, labels or {})
    
    def increment_counter(self, name: str, labels: Optional[Dict[str, str]] = None, value: Union[int, float] = 1):
        """Increment a counter by the given value (default 1)"""
        # For counters, we'll track the increment
        self._record_metric(name, value, MetricType.COUNTER, labels or {})
    
    def record_gauge(self, name: str, value: Union[int, float], labels: Optional[Dict[str, str]] = None):
        """Record a gauge metric (current value)"""
        self._record_metric(name, value, MetricType.GAUGE, labels or {})
    
    def record_histogram(self, name: str, value: Union[int, float], labels: Optional[Dict[str, str]] = None):
        """Record a histogram metric (distribution of values)"""
        self._record_metric(name, value, MetricType.HISTOGRAM, labels or {})
    
    def record_timer(self, name: str, value: Union[int, float], labels: Optional[Dict[str, str]] = None):
        """Record a timer metric (duration)"""
        self._record_metric(name, value, MetricType.TIMER, labels or {})
    
    def time_function(self, name: str, labels: Optional[Dict[str, str]] = None):
        """Decorator/context manager to time function execution"""
        return TimerContext(self, name, labels or {})
    
    def _record_metric(self, name: str, value: Union[int, float], metric_type: MetricType, labels: Dict[str, str]):
        """Internal method to record a metric point"""
        # Create metric key with labels for grouping
        label_str = "_".join([f"{k}={v}" for k, v in sorted(labels.items())]) if labels else ""
        metric_key = f"{name}_{label_str}" if label_str else name
        
        now = datetime.now(timezone.utc)
        point = MetricPoint(name, value, metric_type, now, labels)
        
        with self._lock:
            # Add to raw metrics
            self._metrics[metric_key].append(point)
            
            # Update summary
            self._update_summary(metric_key, point)
    
    def _update_summary(self, metric_key: str, point: MetricPoint):
        """Update aggregated summary for a metric"""
        if metric_key not in self._summaries:
            self._summaries[metric_key] = MetricSummary(
                name=point.name,
                metric_type=point.metric_type,
                count=0,
                labels=point.labels
            )
        
        summary = self._summaries[metric_key]
        summary.count += 1
        summary.last_value = point.value
        summary.last_updated = point.timestamp
        
        # Update aggregates
        if summary.min_value is None or point.value < summary.min_value:
            summary.min_value = point.value
        if summary.max_value is None or point.value > summary.max_value:
            summary.max_value = point.value
        
        if summary.sum_value is None:
            summary.sum_value = point.value
        else:
            summary.sum_value += point.value
        
        summary.avg_value = summary.sum_value / summary.count
    
    def get_metrics(self, name_filter: Optional[str] = None, 
                   since: Optional[datetime] = None) -> List[MetricPoint]:
        """Get raw metric points, optionally filtered"""
        results = []
        cutoff = since or (datetime.now(timezone.utc) - timedelta(hours=self.retention_hours))
        
        with self._lock:
            for metric_key, points in self._metrics.items():
                if name_filter and name_filter not in metric_key:
                    continue
                    
                for point in points:
                    if point.timestamp >= cutoff:
                        results.append(point)
        
        return sorted(results, key=lambda p: p.timestamp)
    
    def get_summaries(self, name_filter: Optional[str] = None) -> List[MetricSummary]:
        """Get metric summaries, optionally filtered"""
        with self._lock:
            summaries = []
            for metric_key, summary in self._summaries.items():
                if name_filter and name_filter not in metric_key:
                    continue
                summaries.append(summary)
            return summaries
    
    def get_metric_names(self) -> List[str]:
        """Get all metric names"""
        with self._lock:
            return list(set(summary.name for summary in self._summaries.values()))
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get key system metrics for monitoring"""
        import psutil
        import os
        
        try:
            process = psutil.Process(os.getpid())
            
            system_metrics = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'process': {
                    'cpu_percent': process.cpu_percent(),
                    'memory_mb': process.memory_info().rss / 1024 / 1024,
                    'threads': process.num_threads(),
                    'open_files': 0,
                },
                'system': {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage_percent': psutil.disk_usage('/').percent,
                    'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
                }
            }

            # Safely get open files count if available and list-like
            try:
                if hasattr(process, 'open_files'):
                    of = process.open_files()
                    system_metrics['process']['open_files'] = len(of) if hasattr(of, '__len__') else 0
            except Exception:
                pass
            
            # Database size is optional; avoid async access from sync context
            
            return system_metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {'error': str(e), 'timestamp': datetime.now(timezone.utc).isoformat()}

    # Simple convenience API expected by unit tests
    def record_request(self, method: str, path: str, status: int, duration: float):
        """Record a single HTTP request for basic aggregation tests."""
        entry = {
            'method': method,
            'path': path,
            'status': status,
            'duration': duration,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        self.request_metrics.append(entry)
        # Also feed into the richer metrics streams
        self.increment_counter('http_requests_total', {'method': method, 'status': str(status), 'path': path})
        self.record_histogram('http_request_duration_seconds', duration, {'method': method, 'path': path})

    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """Return simple aggregated metrics summary used by tests."""
        total = len(self.request_metrics)
        avg = sum(m['duration'] for m in self.request_metrics) / total if total else 0.0
        status_codes: Dict[str, int] = {}
        for m in self.request_metrics:
            key = str(m['status'])
            status_codes[key] = status_codes.get(key, 0) + 1
        return {
            'total_requests': total,
            'average_response_time': avg,
            'status_codes': status_codes,
        }
    
    async def _cleanup_loop(self):
        """Background task to clean up old metrics"""
        while self._running:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                await self._cleanup_old_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics cleanup: {e}")
                await asyncio.sleep(60)  # Wait a bit before retrying
    
    async def _cleanup_old_metrics(self):
        """Remove metrics older than retention period"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        
        with self._lock:
            for metric_key in list(self._metrics.keys()):
                points = self._metrics[metric_key]
                # Convert deque to list, filter, convert back
                filtered_points = [p for p in points if p.timestamp >= cutoff]
                
                if len(filtered_points) != len(points):
                    # Replace the deque with filtered points
                    new_deque = deque(filtered_points, maxlen=self.max_points_per_metric)
                    self._metrics[metric_key] = new_deque
                    
                    # If no points left, remove the metric entirely
                    if not filtered_points:
                        del self._metrics[metric_key]
                        if metric_key in self._summaries:
                            del self._summaries[metric_key]


class TimerContext:
    """Context manager for timing operations"""
    
    def __init__(self, collector: MetricsCollector, name: str, labels: Dict[str, str]):
        self.collector = collector
        self.name = name
        self.labels = labels
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.collector.record_timer(self.name, duration, self.labels)


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


async def initialize_metrics():
    """Initialize the metrics collection system"""
    collector = get_metrics_collector()
    await collector.start()


async def shutdown_metrics():
    """Shutdown the metrics collection system"""
    global _metrics_collector
    if _metrics_collector:
        await _metrics_collector.stop()


# Convenience functions for common metrics
def increment_request_counter(method: str, endpoint: str, status_code: int):
    """Increment HTTP request counter"""
    collector = get_metrics_collector()
    labels = {"method": method, "endpoint": endpoint, "status": str(status_code)}
    collector.increment_counter("http_requests_total", labels)


def record_request_duration(method: str, endpoint: str, duration: float):
    """Record HTTP request duration"""
    collector = get_metrics_collector()
    labels = {"method": method, "endpoint": endpoint}
    collector.record_histogram("http_request_duration_seconds", duration, labels)


def increment_upload_counter(status: str, file_size: Optional[int] = None):
    """Increment upload counter"""
    collector = get_metrics_collector()
    labels = {"status": status}
    if file_size:
        # Add size bucket
        if file_size < 1024 * 1024:  # < 1MB
            labels["size_bucket"] = "small"
        elif file_size < 100 * 1024 * 1024:  # < 100MB
            labels["size_bucket"] = "medium"
        else:
            labels["size_bucket"] = "large"
    collector.increment_counter("uploads_total", labels)


def record_search_metrics(query_type: str, duration: float, result_count: int):
    """Record search operation metrics"""
    collector = get_metrics_collector()
    labels = {"type": query_type}
    collector.increment_counter("search_queries_total", labels)
    collector.record_histogram("search_duration_seconds", duration, labels)
    collector.record_histogram("search_result_count", result_count, labels)


def record_sync_metrics(sync_type: str, files_processed: int, duration: float, errors: int):
    """Record file synchronization metrics"""
    collector = get_metrics_collector()
    labels = {"sync_type": sync_type, "status": "success" if errors == 0 else "error"}
    collector.increment_counter("sync_operations_total", labels)
    collector.record_histogram("sync_duration_seconds", duration, labels)
    collector.record_histogram("sync_files_processed", files_processed, labels)
    if errors > 0:
        collector.record_histogram("sync_errors", errors, labels)
