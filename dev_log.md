# Development Log

## Initial Setup ✓
- Initialized git repository
- Created basic Python file watcher tool

## Features Implemented ✓
1. ✓ TOML configuration loading
2. ✓ File watching (CREATE/MODIFY events) using watchdog
3. ✓ HTTP POST uploads to configured URLs with Bearer auth
4. ✓ Retry logic with exponential backoff
5. ✓ Error logging to optional log collector (JSON format)
6. ✓ Rate limiting (requests per second)
7. ✓ Systemd service registration (`python3 file_watcher.py install`)
8. ✓ Startup/shutdown logging

## Architecture
- Single Python script with watchdog for cross-platform file monitoring
- TOML configuration with upload destinations and file patterns
- Rate limiting and retry logic for production reliability
- Optional structured error logging to external collector
- Self-installing systemd service for easy deployment

## Usage
- Run directly: `python3 file_watcher.py`
- Install service: `sudo python3 file_watcher.py install`
- Start service: `sudo systemctl start file-watcher`
- View logs: `journalctl -u file-watcher -f`