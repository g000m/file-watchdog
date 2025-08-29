# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a general-purpose file monitoring system that watches for changes to files and automatically uploads them to configured API endpoints. The system is implemented as a Python script using the watchdog library for cross-platform file monitoring.

## Architecture

The project consists of a single Python script (`file_watcher.py`) that:

1. **Monitors** configured file paths and patterns using watchdog
2. **Detects** CREATE and MODIFY events (ignores DELETE events)
3. **Uploads** changed files to configured API endpoints via HTTP POST with Bearer token authentication
4. **Implements** retry logic with exponential backoff for failed uploads
5. **Provides** rate limiting to prevent overwhelming APIs
6. **Logs** errors to optional log collector endpoint
7. **Supports** hot-reload of configuration without service restart
8. **Self-installs** as systemd service

## Configuration

Uses TOML configuration file (`config.toml`) with:
- Multiple upload destinations with different API endpoints and auth tokens
- File patterns (supports glob patterns like `/var/named/*.*.db`)
- Rate limiting, retry logic, and file size limits
- Optional log collector endpoint for structured error logging

Example:
```toml
log_url = "https://logs.example.com/api"
max_file_size = "1MB"
retry_attempts = 3
retry_delay = 5
rate_limit = 10

[upload."https://api.example.com/upload"]
auth_token = "bearer_token_here"
paths = ["/var/named/*.*.db", "/etc/configs/*.conf"]
```

## Common Commands

### Running the watcher
```bash
# Install dependencies (one-time setup)
pip install -r requirements.txt
# OR use virtual environment:
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Run directly
python3 file_watcher.py
# OR with venv: source venv/bin/activate && python3 file_watcher.py

# Stop with Ctrl+C
```

### Service installation (Linux)
```bash
# Install as systemd service (requires sudo)
sudo python3 file_watcher.py install

# Start service
sudo systemctl start file-watcher

# Check status and logs
sudo systemctl status file-watcher
sudo journalctl -u file-watcher -f
```

### PyInstaller packaging
```bash
# Create single executable (includes all dependencies)
pip install pyinstaller
pyinstaller --onefile --name file-watcher file_watcher.py

# Deploy single file: dist/file-watcher
```

## Key Features

- **Cross-platform**: Works on Linux and macOS using watchdog library
- **Production-ready**: Rate limiting, retry logic, error handling, logging
- **Hot-reload**: Configuration changes detected automatically without restart
- **Debouncing**: Prevents duplicate uploads from rapid file system events
- **Service integration**: Self-installing systemd service with auto-restart
- **Structured logging**: JSON logs to external collector with startup/shutdown/error events
- **Security**: Bearer token authentication, configurable file size limits

## File Processing Flow

1. File system event detected → Check against configured patterns
2. Apply debouncing (ignore events within 1 second of previous)
3. Apply rate limiting based on configured requests per second
4. Read file content and check size limits
5. HTTP POST to configured API endpoint with Bearer token
6. Retry with exponential backoff on failures
7. Log errors to collector endpoint if configured

## Development Notes

- Dependencies: watchdog, requests, toml
- Supports both development (venv) and production (system packages) deployment
- All configuration changes logged with watched paths for debugging
- Service runs as root for system file access
- Config file should have restricted permissions (600) to protect tokens

## Development Workflow

Always make a git commit after each feature or set of changes:
1. Stage changes with `git add`
2. Create descriptive commit message summarizing what was implemented/fixed