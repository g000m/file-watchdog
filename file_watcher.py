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
import requests
import json
import subprocess
from datetime import datetime
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

def validate_config(config):
    """Validate configuration structure and required fields"""
    if not isinstance(config, dict):
        raise ValueError("Config must be a dictionary")
    
    # Check upload section exists and is valid
    upload_section = config.get('upload', {})
    if not isinstance(upload_section, dict) or not upload_section:
        raise ValueError("Config must have 'upload' section with at least one endpoint")
    
    # Validate each upload endpoint
    for url, settings in upload_section.items():
        if not isinstance(settings, dict):
            raise ValueError(f"Upload settings for {url} must be a dictionary")
        
        # Required fields
        if not settings.get('auth_token'):
            raise ValueError(f"Missing required 'auth_token' for endpoint {url}")
        
        if not settings.get('paths'):
            raise ValueError(f"Missing required 'paths' for endpoint {url}")
        
        # Validate paths is a list
        if not isinstance(settings['paths'], list):
            raise ValueError(f"'paths' for endpoint {url} must be a list")
    
    return True

def log_error(message, log_url=None):
    """Log error message to collector if configured"""
    print(f"ERROR: {message}")
    
    if not log_url:
        return
    
    try:
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "ERROR",
            "message": message,
            "service": "file-watcher"
        }
        
        headers = {'Content-Type': 'application/json'}
        requests.post(log_url, json=log_data, headers=headers, timeout=10)
        
    except Exception as e:
        print(f"Failed to send error log: {e}")

def upload_file(file_path, url, auth_token, max_size, retry_attempts=3, retry_delay=5, log_url=None):
    """Upload file to API endpoint with retry logic"""
    
    for attempt in range(retry_attempts):
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                error_msg = f"File {file_path} too large ({file_size} bytes > {max_size} bytes)"
                log_error(error_msg, log_url)
                return False
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Prepare headers
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/octet-stream'
            }
            
            # Send POST request
            response = requests.post(url, data=file_content, headers=headers, timeout=30)
            
            if response.status_code == 200:
                print(f"Successfully uploaded {file_path} to {url}")
                return True
            else:
                error_msg = f"Failed to upload {file_path}: HTTP {response.status_code}"
                print(error_msg)
                if attempt == retry_attempts - 1:  # Last attempt
                    log_error(error_msg, log_url)
                
        except Exception as e:
            error_msg = f"Error uploading {file_path} (attempt {attempt + 1}/{retry_attempts}): {e}"
            print(error_msg)
            if attempt == retry_attempts - 1:  # Last attempt
                log_error(error_msg, log_url)
        
        # Wait before retry (except for last attempt)
        if attempt < retry_attempts - 1:
            wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
            print(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    final_error = f"Failed to upload {file_path} after {retry_attempts} attempts"
    print(final_error)
    log_error(final_error, log_url)
    return False

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, config):
        self.config = config
        self.watched_files = self._get_watched_files()
        self.rate_limit = config.get('rate_limit', 10)  # requests per second
        self.last_request_time = 0
        self.debounce_time = {}  # Track last modification time per file
    
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
        
        # Always process config file changes
        if abs_path.endswith('config.toml'):
            return True
        
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
    
    def _get_upload_url(self, file_path):
        """Get upload URL for a specific file"""
        abs_path = os.path.abspath(file_path)
        return self.watched_files.get(abs_path)
    
    def _apply_rate_limit(self):
        """Apply rate limiting to prevent overwhelming APIs"""
        current_time = time.time()
        min_interval = 1.0 / self.rate_limit  # minimum seconds between requests
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _should_debounce(self, file_path):
        """Check if file change should be debounced (ignore rapid successive changes)"""
        current_time = time.time()
        debounce_seconds = 1.0  # Ignore changes within 1 second of last change
        
        last_time = self.debounce_time.get(file_path, 0)
        if current_time - last_time < debounce_seconds:
            return True  # Should debounce (ignore)
        
        self.debounce_time[file_path] = current_time
        return False  # Should not debounce (process)
    
    
    def _reload_config(self, config_path):
        """Reload configuration from file with atomic update"""
        try:
            # Load and validate new config without affecting current state
            new_config = load_config(config_path)
            validate_config(new_config)
            
            # Calculate new watched files based on new config
            new_watched_files = {}
            for url, settings in new_config.get('upload', {}).items():
                for pattern in settings.get('paths', []):
                    matching_files = glob.glob(pattern)
                    for file_path in matching_files:
                        new_watched_files[os.path.abspath(file_path)] = url
            
            # Atomic update - replace all state at once
            old_config = self.config
            self.config = new_config
            self.watched_files = new_watched_files
            
            # Get all paths being watched for logging
            all_paths = []
            for url, settings in self.config.get('upload', {}).items():
                for pattern in settings.get('paths', []):
                    all_paths.append(pattern)
            
            message = f"Configuration reloaded from {config_path}"
            print(message)
            print(f"Watching {len(all_paths)} path patterns: {all_paths}")
            
            # Always log config reloads with watched paths
            log_url = self.config.get('log_url')
            if log_url:
                try:
                    log_data = {
                        "timestamp": datetime.now().isoformat(),
                        "level": "INFO",
                        "message": message,
                        "service": "file-watcher",
                        "watched_paths": all_paths,
                        "path_count": len(all_paths)
                    }
                    requests.post(log_url, json=log_data, headers={'Content-Type': 'application/json'}, timeout=10)
                except:
                    pass
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to reload config from {config_path}: {e}"
            print(error_msg)
            # Use old config's log_url if available
            log_url = getattr(self, 'config', {}).get('log_url')
            log_error(error_msg, log_url)
            return False
    
    def _handle_file_change(self, file_path, event_type):
        """Handle file change by uploading to appropriate URL"""
        # Handle config file changes specially
        if file_path.endswith('config.toml'):
            if self._should_debounce(file_path):
                print(f"Debouncing config reload for {file_path}")
                return
            self._reload_config(file_path)
            return
        
        upload_url = self._get_upload_url(file_path)
        if not upload_url:
            return
        
        # Debounce rapid file changes
        if self._should_debounce(file_path):
            print(f"Debouncing {event_type} for {file_path}")
            return
        
        # Apply rate limiting
        self._apply_rate_limit()
        
        # Get settings for this URL
        settings = self.config['upload'][upload_url]
        auth_token = settings['auth_token']
        max_size = parse_file_size(settings.get('max_file_size') or self.config.get('max_file_size'))
        
        print(f"File {event_type}: {file_path}")
        retry_attempts = self.config.get('retry_attempts', 3)
        retry_delay = self.config.get('retry_delay', 5)
        log_url = self.config.get('log_url')
        upload_file(file_path, upload_url, auth_token, max_size, retry_attempts, retry_delay, log_url)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and self._should_process_file(event.src_path):
            self._handle_file_change(event.src_path, "created")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and self._should_process_file(event.src_path):
            self._handle_file_change(event.src_path, "modified")

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
    
    # Always watch current directory for config.toml changes
    current_dir = os.getcwd()
    watch_dirs.add(current_dir)
    
    # Start watching each directory
    for watch_dir in watch_dirs:
        if os.path.exists(watch_dir):
            observer.schedule(event_handler, watch_dir, recursive=False)
            print(f"Watching directory: {watch_dir}")
    
    observer.start()
    return observer

def install_service():
    """Install systemd service"""
    service_content = """[Unit]
Description=File Watcher Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={working_dir}
ExecStart=/usr/bin/python3 {script_path}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    
    script_path = os.path.abspath(__file__)
    working_dir = os.path.dirname(script_path)
    
    service_file = service_content.format(
        script_path=script_path,
        working_dir=working_dir
    )
    
    service_path = "/etc/systemd/system/file-watcher.service"
    
    try:
        with open(service_path, 'w') as f:
            f.write(service_file)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "file-watcher.service"], check=True)
        print(f"Service installed at {service_path}")
        print("Use 'systemctl start file-watcher' to start the service")
        
    except PermissionError:
        print("Error: Root permissions required to install service")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error running systemctl command: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error installing service: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        install_service()
        return
        
    print("File Watcher starting...")
    
    # Load and validate configuration
    config = load_config()
    try:
        validate_config(config)
    except ValueError as e:
        print(f"Configuration validation error: {e}")
        sys.exit(1)
    log_url = config.get('log_url')
    
    # Get initial watched paths for logging
    all_paths = []
    for url, settings in config.get('upload', {}).items():
        for pattern in settings.get('paths', []):
            all_paths.append(pattern)
    
    print(f"Watching {len(all_paths)} path patterns: {all_paths}")
    
    # Log startup with watched paths
    if log_url:
        try:
            startup_data = {
                "timestamp": datetime.now().isoformat(),
                "level": "INFO",
                "message": "File Watcher service started",
                "service": "file-watcher",
                "watched_paths": all_paths,
                "path_count": len(all_paths)
            }
            requests.post(log_url, json=startup_data, headers={'Content-Type': 'application/json'}, timeout=10)
        except:
            pass  # Don't fail startup if logging fails
    
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
            print("File Watcher shutting down...")
            observer.stop()
            
            # Send shutdown log for Ctrl+C
            if log_url:
                try:
                    shutdown_data = {
                        "timestamp": datetime.now().isoformat(),
                        "level": "INFO", 
                        "message": "File Watcher service stopped (Ctrl+C)",
                        "service": "file-watcher"
                    }
                    requests.post(log_url, json=shutdown_data, headers={'Content-Type': 'application/json'}, timeout=5)
                except:
                    pass
                    
        observer.join()
        
    except Exception as e:
        error_msg = f"Fatal error: {e}"
        print(error_msg)
        log_error(error_msg, log_url)
        sys.exit(1)
    
    # Log shutdown
    if log_url:
        try:
            shutdown_data = {
                "timestamp": datetime.now().isoformat(),
                "level": "INFO", 
                "message": "File Watcher service stopped",
                "service": "file-watcher"
            }
            requests.post(log_url, json=shutdown_data, headers={'Content-Type': 'application/json'}, timeout=10)
        except:
            pass

def shutdown_handler(signum, frame):
    """Handle shutdown signals"""
    print("File Watcher shutting down...")
    
    # Try to send shutdown log before exiting
    try:
        # Load config to get log_url
        config = load_config()
        log_url = config.get('log_url')
        
        if log_url:
            shutdown_data = {
                "timestamp": datetime.now().isoformat(),
                "level": "INFO", 
                "message": "File Watcher service stopped (signal)",
                "service": "file-watcher"
            }
            requests.post(log_url, json=shutdown_data, headers={'Content-Type': 'application/json'}, timeout=5)
    except:
        pass  # Don't block shutdown if logging fails
    
    sys.exit(0)

if __name__ == "__main__":
    main()