#!/usr/bin/env python3
"""
File Watcher - A general purpose file monitoring and upload tool
"""

import os
import sys
import signal
import logging
from pathlib import Path

def main():
    """Main entry point"""
    print("File Watcher starting...")
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        # TODO: Load config, start watching files
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