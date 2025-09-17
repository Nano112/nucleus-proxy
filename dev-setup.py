#!/usr/bin/env python3
"""
Development setup script for Nucleus Proxy.

This script helps set up the development environment with proper
configuration for local development and testing.
"""

import os
import sys
from pathlib import Path


def create_dev_env():
    """Create or update .env file with development-friendly settings."""
    env_path = Path(".env")
    
    # Read existing .env if it exists
    existing_config = {}
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    existing_config[key] = value
    
    # Development-friendly configuration
    dev_config = {
        'NUCLEUS_HOST': existing_config.get('NUCLEUS_HOST', '127.0.0.1'),
        'NUCLEUS_USERNAME': existing_config.get('NUCLEUS_USERNAME', 'omniverse'),  
        'NUCLEUS_PASSWORD': existing_config.get('NUCLEUS_PASSWORD', 'changeme123'),
        'PROXY_BIND': '0.0.0.0:8088',
        'PROXY_SECRET': 'dev-secret-key-change-in-production-32-chars',
        'SQLITE_PATH': './data/proxy.db',
        'STAGING_DIR': './data/staging',
        'MAX_UPLOAD_SIZE': '5368709120',  # 5 GB
        'PART_SIZE_DEFAULT': '8388608',   # 8 MB
        'CORS_ALLOW_ORIGINS': '*',
        'REQUEST_TIMEOUTS': '30',
        'PROXY_BASE_URL': 'http://127.0.0.1:8088',
        'LOG_LEVEL': 'DEBUG'  # Important: DEBUG mode disables strict security for development
    }
    
    # Write new .env file
    with open(env_path, 'w') as f:
        f.write("# Nucleus Proxy Development Configuration\n")
        f.write("# This configuration is optimized for local development\n\n")
        
        f.write("# Nucleus Server Configuration\n")
        f.write(f"NUCLEUS_HOST={dev_config['NUCLEUS_HOST']}\n")
        f.write(f"NUCLEUS_USERNAME={dev_config['NUCLEUS_USERNAME']}\n")
        f.write(f"NUCLEUS_PASSWORD={dev_config['NUCLEUS_PASSWORD']}\n\n")
        
        f.write("# Proxy Server Configuration\n")
        f.write(f"PROXY_BIND={dev_config['PROXY_BIND']}\n")
        f.write(f"PROXY_SECRET={dev_config['PROXY_SECRET']}\n\n")
        
        f.write("# Database and Storage\n")
        f.write(f"SQLITE_PATH={dev_config['SQLITE_PATH']}\n")
        f.write(f"STAGING_DIR={dev_config['STAGING_DIR']}\n\n")
        
        f.write("# Upload Configuration\n")
        f.write(f"MAX_UPLOAD_SIZE={dev_config['MAX_UPLOAD_SIZE']}  # 5 GB\n")
        f.write(f"PART_SIZE_DEFAULT={dev_config['PART_SIZE_DEFAULT']}   # 8 MB\n\n")
        
        f.write("# CORS and Security (Development)\n")
        f.write(f"CORS_ALLOW_ORIGINS={dev_config['CORS_ALLOW_ORIGINS']}\n")
        f.write(f"LOG_LEVEL={dev_config['LOG_LEVEL']}  # DEBUG disables strict CSRF/security\n\n")
        
        f.write("# Timeouts and Performance\n")
        f.write(f"REQUEST_TIMEOUTS={dev_config['REQUEST_TIMEOUTS']}\n\n")
        
        f.write("# Testing Configuration\n")
        f.write(f"PROXY_BASE_URL={dev_config['PROXY_BASE_URL']}\n")
    
    print(f"✅ Created development .env configuration")
    return True


def create_directories():
    """Create necessary directories."""
    directories = ['data', 'data/staging']
    
    for directory in directories:
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        else:
            print(f"📁 Directory already exists: {directory}")


def main():
    """Main setup function."""
    print("🚀 Setting up Nucleus Proxy for development...\n")
    
    # Check if we're in the right directory
    if not Path("app").exists() or not Path("pyproject.toml").exists():
        print("❌ Error: This script must be run from the nucleus-proxy root directory")
        sys.exit(1)
    
    # Create configuration
    create_dev_env()
    
    # Create directories
    create_directories()
    
    print("\n✨ Development setup complete!\n")
    print("Next steps:")
    print("1. Update NUCLEUS_HOST, NUCLEUS_USERNAME, and NUCLEUS_PASSWORD in .env")
    print("2. Install dependencies: uv sync")
    print("3. Run the server: uv run python -m app.server")
    print("4. Open documentation: http://localhost:8088/docs")
    print("5. Run tests: uv run python -m pytest")
    
    print("\n💡 Tips:")
    print("- LOG_LEVEL=DEBUG disables CSRF protection for easier API testing")
    print("- CSP is automatically relaxed for /docs endpoints")
    print("- Use API key authentication to bypass CSRF in production")


if __name__ == "__main__":
    main()