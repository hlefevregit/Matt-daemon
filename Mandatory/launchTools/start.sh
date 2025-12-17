#!/bin/bash

DAEMON_NAME="MattDaemon"
DAEMON_PATH="../$DAEMON_NAME"

PID=$(pgrep -f "$DAEMON_NAME")

if [ ! -z "$PID" ]; then
    echo "$DAEMON_NAME is already running (PID $PID)"
    exit 1
fi

echo "Starting $DAEMON_NAME.."

sudo $DAEMON_NAME

sleep 1

PID=$(pgrep -f "$DAEMON_NAME")

if [ -z "$PID" ]; then
    echo "Failed to start $DAEMON_NAME"
else
    echo "$DAEMON_NAME started successfully (PID $PID)"
fi