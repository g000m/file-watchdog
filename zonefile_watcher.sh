#!/bin/bash

# This script monitors a directory for changes to BIND zone files (*.db) and sends an email notification
# when a detected as being moved, which means it was updated.

WATCHED_DIR="/var/named"
LOG_FILE="seen.log"
PATTERN="*.db"
PID_FILE="/tmp/zonefile_monitor.pid"
source ~/scripts/.env

# Function to send email notification
send_email() {
    # exit if EMAIL_TO is not set
    if [[ -z "$EMAIL_TO" ]]; then
        echo "EMAIL_TO is not set. Email notification will not be sent."
        return
    fi

    local FILE="$1"
    local DOMAIN_NAME
    DOMAIN_NAME=$(basename "$FILE" .db) # Extract domain from filename
    local FILE_CONTENT
    FILE_CONTENT=$(cat "$FILE") # Read the file content

    echo -e "Zone file updated for $DOMAIN_NAME: $FILE\n\nContent:\n$FILE_CONTENT" | mail -s "UPDATE $DOMAIN_NAME" "$EMAIL_TO"
}

upload_file() {
    local FILE="$1"
    local FILENAME=$(basename "$FILE")

    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/$FILENAME" \
        -H "Authorization: Bearer $ZONEFILE_KEY" \
        -H "Content-Type: text/plain" \
        --data-binary @"$FILE")

    if [ "$RESPONSE" -ne 200 ]; then
        echo "Failed to upload $FILE. HTTP response code: $RESPONSE" | tee -a "$LOG_FILE"
        send_email "$FILE"
    else
        echo "Successfully uploaded $FILE" | tee -a "$LOG_FILE"
    fi
}

# Function to send exit notification
send_exit_notification() {
    echo "The monitoring script has stopped." | mail -s "Script Stopped" "$EMAIL_TO"
}

# Function to stop the script
stop_script() {
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "Stopping the script (PID: $(cat "$PID_FILE"))."
        kill -9 "$(cat "$PID_FILE")"
        rm -f "$PID_FILE"
        echo "Script stopped."
    else
        echo "No running script instance found."
    fi
    send_exit_notification
    exit 0
}

# Handle the kill option
if [[ "$1" == "kill" ]]; then
    stop_script
fi

# Handle the test option
if [[ "$1" == "test" && -n "$2" ]]; then
    TEST_FILE="$2"
    if [[ -f "$TEST_FILE" ]]; then
        echo "Simulating change detection for file: $TEST_FILE"
        upload_file "$TEST_FILE"
        exit 0
    else
        echo "Test file does not exist: $TEST_FILE"
        exit 1
    fi
fi

# Check if the script is already running
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "The script is already running (PID: $(cat "$PID_FILE"))."
    echo "To stop it, run:"
    echo "  $0 kill"
    exit 1
fi

# Ensure PID file is cleaned up on exit
trap "rm -f '$PID_FILE'; send_exit_notification; exit" INT TERM EXIT

# Write current PID to the PID file
echo $$ >"$PID_FILE"

if [[ "$1" == "--background" ]]; then
    echo "Running in the background. Logs will be written to $LOG_FILE."
    nohup bash "$0" >/dev/null 2>&1 &
    rm -f "$PID_FILE" # Ensure the PID file is removed in this instance
    exit
fi

echo "Monitoring $WATCHED_DIR for changes to files matching pattern '$PATTERN'. To run in the background, use:"
echo "  $0 --background"
echo "Press Ctrl+C to stop."

# Main monitoring loop
inotifywait -m -e create -e modify -e delete -e move "$WATCHED_DIR" --format '%w%f %e' | while read FILE EVENT; do
    # if filename does not match *.db, skip
    if [[ ! "$FILE" == *".db" ]]; then
        continue
    fi

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$TIMESTAMP - Detected event: $EVENT on file: $FILE" | tee -a "$LOG_FILE"

    # Check for MOVED_TO event and send an email notification
    if [[ "$EVENT" == "MOVED_TO" ]]; then
        upload_file "$FILE"
    fi
done

# Cleanup
rm -f "$PID_FILE"
trap - INT TERM EXIT
