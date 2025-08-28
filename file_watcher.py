#!/usr/bin/env python3
"""
File Watcher - A general purpose file monitoring and upload tool
"""

import os
import sys
import signal
import logging
import toml
from pathlib import Path

def load_config(config_path="config.toml"):
    """Load configuration from TOML file"""
    try:
        with open(config_path, 'r') as f:
            config = toml.load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Configuration file {config_path} not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

def parse_file_size(size_str):
    """Convert size string like '1MB' to bytes"""
    if not size_str:
        return 1024 * 1024  # 1MB default
    
    size_str = size_str.upper()
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    else:
        return int(size_str)

def main():
    """Main entry point"""
    print("File Watcher starting...")
    
    # Load configuration
    config = load_config()
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        # TODO: Start watching files
        print("File Watcher started successfully")
        
        # Keep running until signal received
        signal.pause()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def shutdown_handler(signum, frame):
    """Handle shutdown signals"""
    print("File Watcher shutting down...")
    sys.exit(0)

if __name__ == "__main__":
    main()