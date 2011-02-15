#!/bin/sh
PID_FILE=/var/run/userwatch/uw-server.pid
EVENT_DIR=/var/run/userwatch
EVENT_FILE=openvpn-event
if [ -d $EVENT_DIR ]; then
    STAMP=`date '+%Y%m%d_%H%M%S_%N'`
    env | sort > $EVENT_DIR/$EVENT_FILE.$STAMP 2>/dev/null
    [ -r $PID_FILE ] && kill -USR2 `< $PID_FILE` >/dev/null 2>&1
fi
