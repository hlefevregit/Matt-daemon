#!/bin/bash

DAEMON_NAME="MattDaemon"

PID=$(pgrep -f "$DAEMON_NAME")

if [ -z "$PID" ]; then
    echo "🔴 Daemon \"$DAEMON_NAME\" : STOPPED"
else
    echo "🟢 daemon \"$DAEMON_NAME\" : RUNNING"
    echo "PID : $PID"
fi