#!/usr/bin/env python3
"""
File Watcher - A general purpose file monitoring and upload tool
"""

import os
import sys
import signal
import logging
import toml
import glob
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, config):
        self.config = config
        self.watched_files = self._get_watched_files()
    
    def _get_watched_files(self):
        """Get map of file paths to upload URLs based on patterns"""
        watched_files = {}
        
        for url, settings in self.config.get('upload', {}).items():
            for pattern in settings.get('paths', []):
                # Expand glob patterns to actual files
                matching_files = glob.glob(pattern)
                for file_path in matching_files:
                    watched_files[os.path.abspath(file_path)] = url
        
        return watched_files
    
    def _should_process_file(self, file_path):
        """Check if file should be processed based on patterns"""
        abs_path = os.path.abspath(file_path)
        
        # Check if exact file is watched
        if abs_path in self.watched_files:
            return True
            
        # Check if file matches any pattern
        for url, settings in self.config.get('upload', {}).items():
            for pattern in settings.get('paths', []):
                if glob.fnmatch.fnmatch(abs_path, os.path.abspath(pattern)):
                    self.watched_files[abs_path] = url
                    return True
        
        return False
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and self._should_process_file(event.src_path):
            print(f"File created: {event.src_path}")
            # TODO: Upload file
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and self._should_process_file(event.src_path):
            print(f"File modified: {event.src_path}")
            # TODO: Upload file

def start_watching(config):
    """Start watching files for changes"""
    event_handler = FileChangeHandler(config)
    observer = Observer()
    
    # Get all unique directories to watch
    watch_dirs = set()
    for url, settings in config.get('upload', {}).items():
        for pattern in settings.get('paths', []):
            # Get directory part of pattern
            dir_path = os.path.dirname(pattern)
            if dir_path:
                watch_dirs.add(dir_path)
    
    # Start watching each directory
    for watch_dir in watch_dirs:
        if os.path.exists(watch_dir):
            observer.schedule(event_handler, watch_dir, recursive=False)
            print(f"Watching directory: {watch_dir}")
    
    observer.start()
    return observer

def main():
    """Main entry point"""
    print("File Watcher starting...")
    
    # Load configuration
    config = load_config()
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        # Start watching files
        observer = start_watching(config)
        print("File Watcher started successfully")
        
        # Keep running until signal received
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def shutdown_handler(signum, frame):
    """Handle shutdown signals"""
    print("File Watcher shutting down...")
    sys.exit(0)

if __name__ == "__main__":
    main()