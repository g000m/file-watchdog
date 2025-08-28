# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a BIND DNS zone file monitoring system that watches for changes to DNS zone files and automatically uploads them to a remote API endpoint. The system is implemented as a single Bash script that uses inotify to monitor file system events.

## Architecture

The project consists of a single Bash script (`zonefile_watcher.sh`) that:

1. **Monitors** `/var/named` directory for `.db` file changes using `inotifywait`
2. **Detects** MOVED_TO events (indicating file updates in BIND's atomic file replacement pattern)
3. **Uploads** changed zone files to a remote API using curl with Bearer token authentication
4. **Notifies** via email on upload failures or script termination
5. **Manages** process lifecycle with PID files to prevent multiple instances

## Environment Configuration

The script requires environment variables loaded from `~/scripts/.env`:
- `API_URL`: Remote API endpoint for uploading zone files
- `ZONEFILE_KEY`: Bearer token for API authentication  
- `EMAIL_TO`: Email address for notifications (optional)

## Common Commands

### Running the watcher
```bash
# Run interactively (foreground)
./zonefile_watcher.sh

# Run in background
./zonefile_watcher.sh --background

# Stop running instance
./zonefile_watcher.sh kill

# Test upload with specific file
./zonefile_watcher.sh test /path/to/test.db
```

### Monitoring
```bash
# Check if running
ps aux | grep zonefile_watcher

# View logs
tail -f seen.log

# Check PID file
cat /tmp/zonefile_monitor.pid
```

## Key Implementation Details

- Uses `inotifywait -m -e create -e modify -e delete -e move` for file system monitoring
- Only processes files matching `*.db` pattern
- Implements single-instance protection via PID file at `/tmp/zonefile_monitor.pid`
- Logs all events with timestamps to `seen.log`
- Sends email notifications on API upload failures and script termination
- Handles graceful shutdown with signal traps (INT, TERM, EXIT)

## File Processing Flow

1. File system event detected → Filter for `.db` files → Check for MOVED_TO event
2. Extract domain name from filename (basename without .db extension)  
3. Upload file content to `$API_URL/$FILENAME` with Bearer authentication
4. Log success/failure and send email notification on failure