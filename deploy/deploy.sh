#!/usr/bin/env bash
# deploy.sh — build a static linux binary, upload it with the config and the
# systemd unit, then (re)start the service on the target host.
#
#   deploy.sh user@host [server.json]
#
# GOARCH=amd64 by default; override for arm VPS:  GOARCH=arm64 deploy.sh ...
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${1:?usage: deploy.sh user@host [server.json]}
CONFIG=${2:-deploy/server.json}
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}

( cd core && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags="-s -w" -o ../deploy/vpn-server-linux ./cmd/vpn-server )

ssh "$TARGET" 'mkdir -p /etc/vpn'
scp deploy/vpn-server-linux "$TARGET:/usr/local/bin/vpn-server"
scp "$CONFIG" "$TARGET:/etc/vpn/server.json"
scp deploy/vpn-server.service "$TARGET:/etc/systemd/system/vpn-server.service"
ssh "$TARGET" '
chmod +x /usr/local/bin/vpn-server
systemctl daemon-reload
systemctl enable --now vpn-server
systemctl restart vpn-server
systemctl --no-pager --lines=5 status vpn-server
'
echo "deployed; logs: ssh $TARGET journalctl -u vpn-server -f"
