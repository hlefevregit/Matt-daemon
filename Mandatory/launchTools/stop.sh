#!/bin/bash

DAEMON_NAME="MattDaemon"

LOCKFILE="/var/lock/matt_daemon.lock"

PID=$(pgrep -f "$DAEMON_NAME")

if [ -z "$PID" ]; then
    echo "$DAEMON_NAME is already stopped"
    exit 0
fi

echo "Stopping $DAEMON_NAME..."

echo "quit" | nc localhost 4242 2>/dev/null

sleep 1

PID=$(pgrep -f "$DAEMON_NAME")
if [ -z "$PID" ]; then
    echo "$DAEMON_NAME stopped succesfully."
else
    echo "Could not stop $DAEMON_NAME (PID $PID)"
fi

if [ -f "$LOCKFILE" ]; then
    sudo rm -f "$LOCKFILE"
    echo "Lock file removed."
fi