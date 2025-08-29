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
import fnmatch
import time
import requests
import json
import subprocess
import re
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
    """Convert size string like '1MB' to bytes with validation"""
    if not size_str:
        return 1024 * 1024  # 1MB default
    
    try:
        # Convert to string and strip whitespace
        size_str = str(size_str).strip().upper()
        
        if not size_str:
            return 1024 * 1024  # Default if empty after strip
        
        # Handle plain numbers (assume bytes)
        if size_str.isdigit():
            size_bytes = int(size_str)
            if size_bytes < 0:
                raise ValueError("File size cannot be negative")
            return size_bytes
        
        # Handle size units
        if size_str.endswith('KB'):
            size_value = size_str[:-2].strip()
            if not size_value:
                raise ValueError("Missing size value before 'KB'")
            size_num = float(size_value)
            if size_num < 0:
                raise ValueError("File size cannot be negative")
            return int(size_num * 1024)
            
        elif size_str.endswith('MB'):
            size_value = size_str[:-2].strip()
            if not size_value:
                raise ValueError("Missing size value before 'MB'")
            size_num = float(size_value)
            if size_num < 0:
                raise ValueError("File size cannot be negative")
            return int(size_num * 1024 * 1024)
            
        elif size_str.endswith('GB'):
            size_value = size_str[:-2].strip()
            if not size_value:
                raise ValueError("Missing size value before 'GB'")
            size_num = float(size_value)
            if size_num < 0:
                raise ValueError("File size cannot be negative")
            return int(size_num * 1024 * 1024 * 1024)
            
        else:
            # Try to parse as plain number
            size_num = float(size_str)
            if size_num < 0:
                raise ValueError("File size cannot be negative")
            return int(size_num)
            
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid file size format '{size_str}': {e}")

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
        
        # Validate max_file_size if specified
        if 'max_file_size' in settings:
            try:
                parse_file_size(settings['max_file_size'])
            except ValueError as e:
                raise ValueError(f"Invalid max_file_size for endpoint {url}: {e}")
    
    # Validate global max_file_size if specified
    if 'max_file_size' in config:
        try:
            parse_file_size(config['max_file_size'])
        except ValueError as e:
            raise ValueError(f"Invalid global max_file_size: {e}")
    
    return True

def detect_file_type(file_path):
    """Detect file type using magic bytes/file signatures"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)  # Read first 16 bytes for magic number detection
        
        # Common file type signatures
        if header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        elif header.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        elif header.startswith(b'GIF8'):
            return 'image/gif'
        elif header.startswith(b'%PDF'):
            return 'application/pdf'
        elif header.startswith(b'PK\x03\x04') or header.startswith(b'PK\x05\x06') or header.startswith(b'PK\x07\x08'):
            return 'application/zip'
        elif header.startswith(b'\x7fELF'):
            return 'application/x-executable'
        elif header.startswith(b'MZ'):
            return 'application/x-executable'
        elif b'\x00' in header[:8]:  # Binary file detection
            return 'application/octet-stream'
        else:
            return 'text/plain'
            
    except Exception:
        return 'unknown'

def scan_for_sensitive_content(content, file_path):
    """Scan file content for potentially sensitive information"""
    sensitive_patterns = [
        # Private keys
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----', 'Private key detected'),
        (r'-----BEGIN\s+OPENSSH PRIVATE KEY-----', 'SSH private key detected'),
        
        # API keys and tokens  
        (r'["\']?[A-Za-z0-9_-]*api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{16,}', 'API key pattern detected'),
        (r'["\']?[A-Za-z0-9_-]*token["\']?\s*[:=]\s*["\']?[A-Za-z0-9_.-]{16,}', 'Token pattern detected'),
        (r'["\']?bearer["\']?\s*[:=]\s*["\']?[A-Za-z0-9_.-]{16,}', 'Bearer token detected'),
        
        # Database connection strings
        (r'postgresql://[^"\s]+', 'Database connection string detected'),
        (r'mysql://[^"\s]+', 'Database connection string detected'),
        (r'mongodb://[^"\s]+', 'Database connection string detected'),
        
        # AWS credentials
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key detected'),
        (r'aws_secret_access_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}', 'AWS Secret Key detected'),
        
        # Common password patterns
        (r'["\']?password["\']?\s*[:=]\s*["\']?[^\s"\']{8,}', 'Password pattern detected'),
    ]
    
    # Convert bytes to string for text analysis
    if isinstance(content, bytes):
        try:
            content_str = content.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return []  # Skip sensitive content scanning for binary files
    else:
        content_str = content
    
    findings = []
    for pattern, description in sensitive_patterns:
        if re.search(pattern, content_str, re.IGNORECASE):
            findings.append(f"{description} in {file_path}")
    
    return findings

def validate_file_content(file_path, config):
    """Validate file content before upload"""
    try:
        # Get file type
        file_type = detect_file_type(file_path)
        
        # Check if file type is allowed (if configured)
        allowed_types = config.get('allowed_file_types', [])
        if allowed_types and file_type not in allowed_types:
            return False, f"File type {file_type} not in allowed types: {allowed_types}"
        
        # Block executable files by default
        if file_type == 'application/x-executable':
            return False, "Executable files are not allowed for security reasons"
        
        # Check file size before reading content to avoid loading large files
        file_size = os.path.getsize(file_path)
        max_scan_size = 1024 * 1024  # 1MB limit for content scanning
        
        # Skip sensitive content scanning for large binary files
        if file_type.startswith('application/') and file_size > max_scan_size:
            return True, None  # Allow large binary files without content scanning
        
        # Read file content for sensitive data scanning (only for smaller files)
        with open(file_path, 'rb') as f:
            # Limit read size as additional safety
            content = f.read(max_scan_size)
        
        # Scan for sensitive content in text files or small binary files
        sensitive_findings = scan_for_sensitive_content(content, file_path)
        if sensitive_findings:
            return False, f"Sensitive content detected: {'; '.join(sensitive_findings)}"
        
        return True, None
        
    except Exception as e:
        return False, f"Error validating file content: {e}"

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

def upload_file(file_path, url, auth_token, max_size, config, retry_attempts=3, retry_delay=5, log_url=None):
    """Upload file to API endpoint with retry logic and content validation"""
    
    # Validate file content before attempting upload
    is_valid, validation_error = validate_file_content(file_path, config)
    if not is_valid:
        error_msg = f"File validation failed for {file_path}: {validation_error}"
        log_error(error_msg, log_url)
        return False
    
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
            
            # Calculate dynamic timeout based on file size (minimum 30 seconds, +1 second per 100KB)
            dynamic_timeout = max(30, 30 + (file_size // (100 * 1024)))
            
            # Send POST request
            response = requests.post(url, data=file_content, headers=headers, timeout=dynamic_timeout)
            
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
        self.rate_limit = config.get('rate_limit', 10)  # requests per second
        self.last_request_time = 0
        self.debounce_time = {}  # Track last modification time per file
    
    def _should_process_file(self, file_path):
        """Check if file should be processed based on patterns"""
        abs_path = os.path.abspath(file_path)
        
        # Skip symbolic links for security and predictability
        if os.path.islink(abs_path):
            print(f"INFO: Skipping symbolic link: {abs_path}")
            # Log symlink skips to error collector if configured
            log_url = self.config.get('log_url')
            if log_url:
                try:
                    log_data = {
                        "timestamp": datetime.now().isoformat(),
                        "level": "INFO",
                        "message": f"Skipped symbolic link: {abs_path}",
                        "service": "file-watcher"
                    }
                    requests.post(log_url, json=log_data, headers={'Content-Type': 'application/json'}, timeout=5)
                except:
                    pass  # Don't fail processing if logging fails
            return False
        
        # Always process config file changes
        if abs_path.endswith('config.toml'):
            return True
            
        # Check if file matches any pattern
        for url, settings in self.config.get('upload', {}).items():
            for pattern in settings.get('paths', []):
                # Use fnmatch for pattern matching without expanding globs
                if fnmatch.fnmatch(abs_path, pattern) or fnmatch.fnmatch(abs_path, os.path.abspath(pattern)):
                    return True
        
        return False
    
    def _get_upload_url(self, file_path):
        """Get upload URL for a specific file by matching patterns"""
        abs_path = os.path.abspath(file_path)
        
        # Find matching pattern and return corresponding URL
        for url, settings in self.config.get('upload', {}).items():
            for pattern in settings.get('paths', []):
                if fnmatch.fnmatch(abs_path, pattern) or fnmatch.fnmatch(abs_path, os.path.abspath(pattern)):
                    return url
        
        return None
    
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
        
        # Clean up old entries periodically to prevent memory growth
        if len(self.debounce_time) > 1000:  # Cleanup threshold
            cutoff_time = current_time - 3600  # Remove entries older than 1 hour
            old_entries = [path for path, timestamp in self.debounce_time.items() if timestamp < cutoff_time]
            for path in old_entries:
                del self.debounce_time[path]
        
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
            
            # Atomic update - replace config (no need for watched_files with lazy matching)
            old_config = self.config
            self.config = new_config
            
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
        
        # Parse max file size with error handling
        try:
            max_size = parse_file_size(settings.get('max_file_size') or self.config.get('max_file_size'))
        except ValueError as e:
            error_msg = f"Invalid max_file_size configuration: {e}"
            print(error_msg)
            log_error(error_msg, self.config.get('log_url'))
            return  # Skip processing this file
        
        print(f"File {event_type}: {file_path}")
        retry_attempts = self.config.get('retry_attempts', 3)
        retry_delay = self.config.get('retry_delay', 5)
        log_url = self.config.get('log_url')
        upload_file(file_path, upload_url, auth_token, max_size, self.config, retry_attempts, retry_delay, log_url)
    
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
    log_url = config.get('log_url')
    
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
    
    # Track successful and failed directory watches
    successful_dirs = []
    failed_dirs = []
    
    # Start watching each directory with proper error handling
    for watch_dir in watch_dirs:
        if os.path.exists(watch_dir):
            try:
                # Check if directory is readable
                os.listdir(watch_dir)
                observer.schedule(event_handler, watch_dir, recursive=False)
                successful_dirs.append(watch_dir)
                print(f"Watching directory: {watch_dir}")
            except PermissionError:
                error_msg = f"Permission denied accessing directory: {watch_dir}"
                failed_dirs.append(watch_dir)
                print(f"WARNING: {error_msg}")
                log_error(error_msg, log_url)
            except Exception as e:
                error_msg = f"Failed to watch directory {watch_dir}: {e}"
                failed_dirs.append(watch_dir)
                print(f"WARNING: {error_msg}")
                log_error(error_msg, log_url)
        else:
            error_msg = f"Directory does not exist: {watch_dir}"
            failed_dirs.append(watch_dir)
            print(f"WARNING: {error_msg}")
            log_error(error_msg, log_url)
    
    # Check if we successfully watching any directories
    if not successful_dirs:
        error_msg = f"Failed to watch any directories. Configured directories: {list(watch_dirs)}"
        print(f"CRITICAL: {error_msg}")
        log_error(error_msg, log_url)
        raise RuntimeError("No directories available for monitoring - service cannot function")
    
    # Report summary
    if failed_dirs:
        summary_msg = f"Watching {len(successful_dirs)} directories successfully, {len(failed_dirs)} directories failed: {failed_dirs}"
        print(f"WARNING: {summary_msg}")
        log_error(summary_msg, log_url)
    else:
        print(f"Successfully watching all {len(successful_dirs)} directories")
    
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