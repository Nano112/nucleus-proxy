"""
Configuration management using Pydantic BaseSettings.
Loads from .env file with environment variable overrides.
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator, Field, ConfigDict
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""
    
    # Nucleus Server Configuration
    nucleus_host: str = "localhost"
    nucleus_origin: Optional[str] = None
    nucleus_username: str = "omniverse"
    nucleus_password: str = "changeme123"
    
    # Proxy Server Configuration  
    proxy_bind: str = "0.0.0.0:8088"
    proxy_secret: str = "change-me-in-production-default-key"
    proxy_workers: int = Field(default=1, ge=1, le=32, description="Number of Sanic worker processes")
    auto_reload: bool = Field(default=False, description="Enable auto reload for development")
    
    # Database and Storage
    sqlite_path: str = "./data/proxy.db"
    staging_dir: str = "./data/staging"
    
    # Upload Configuration
    max_upload_size: int = 5368709120  # 5 GB
    part_size_default: int = 8388608   # 8 MB
    
    # CORS Configuration
    cors_allow_origins: str = "*"
    
    # Timeouts and Performance
    request_timeouts: int = Field(default=600, ge=30, le=3600, description="Request/response timeout in seconds")
    slow_request_threshold_ms: int = Field(default=1000, ge=100, description="Slow request threshold in milliseconds")
    
    # Monitoring / Metrics (M6)
    metrics_retention_hours: int = Field(default=24, ge=1, le=168, description="Metrics retention period")
    metrics_max_points: int = Field(default=1000, ge=100, le=10000, description="Max metric points per series")
    health_check_timeout: int = Field(default=30, ge=5, le=300, description="Health check timeout in seconds")
    
    # Background tasks (M6)
    background_sync_enabled: bool = Field(default=True, description="Enable automatic background sync")
    background_sync_interval_minutes: int = Field(default=60, ge=5, description="Background sync interval")
    background_cleanup_interval_minutes: int = Field(default=30, ge=5, description="Background cleanup interval")
    
    # Testing Configuration
    proxy_base_url: str = "http://127.0.0.1:8088"
    run_nucleus_it: Optional[str] = Field(default="0", description="Enable Nucleus integration tests")
    
    # Logging
    log_level: str = "INFO"
    
    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Invalid log level. Must be one of: {valid_levels}')
        return v.upper()
    
    @field_validator('proxy_secret')
    @classmethod
    def validate_secret(cls, v):
        if len(v) < 16:
            raise ValueError('proxy_secret must be at least 16 characters long')
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return os.getenv('ENVIRONMENT', 'development').lower() == 'production'
    
    def get_monitoring_config(self) -> dict:
        """Get monitoring-specific configuration"""
        return {
            'metrics_retention_hours': self.metrics_retention_hours,
            'metrics_max_points': self.metrics_max_points,
            'health_check_timeout': self.health_check_timeout,
            'slow_request_threshold_ms': self.slow_request_threshold_ms
        }
    
    def get_background_task_config(self) -> dict:
        """Get background task configuration"""
        return {
            'sync_enabled': self.background_sync_enabled,
            'sync_interval_minutes': self.background_sync_interval_minutes,
            'cleanup_interval_minutes': self.background_cleanup_interval_minutes
        }
    
    model_config = ConfigDict(
        env_file=".env.testing" if os.path.exists(".env.testing") else ".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )


# Global settings instance
settings = Settings()
