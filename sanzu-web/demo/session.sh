#!/bin/sh
# Demo on_connect callback: a throwaway Xvfb desktop for the user, served by
# sanzu_server over the gateway's unix socket. A real one starts the session
# as the user (systemd-run --uid, sudo...).
set -eu
USER_NAME=$1
SOCKET=$2
BIN=${SANZU_BIN:-/usr/bin}
CONFIG=${SANZU_WEB_SERVER_CONFIG:-/etc/sanzu-web-server.toml}
DISPLAY_NUM=$(( 100 + $(od -An -N1 -tu1 /dev/urandom) ))
export DISPLAY=:$DISPLAY_NUM
Xvfb "$DISPLAY" -screen 0 1920x1080x24 >/dev/null 2>&1 &
sleep 1
xterm -geometry 80x24+60+60 -T "$USER_NAME" >/dev/null 2>&1 &
"$BIN/sanzu_server" --config "$CONFIG" --unixsock --connect-unixsock \
  --address "$SOCKET" >/tmp/sanzu-web-session-$DISPLAY_NUM.log 2>&1 &
