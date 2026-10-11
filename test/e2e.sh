#!/usr/bin/env bash
# E2E interop tests against the reference Xray client:
#   phase 1 — plain VLESS over TCP (M1)
#   phase 2 — VLESS over REALITY (M2): auth path, camouflage relay path,
#             and rejection of a client with a wrong short id.
set -euo pipefail
cd "$(dirname "$0")"

XRAY=/opt/homebrew/bin/xray
SID="0123456789abcdef"

( cd ../core && go build -o bin/vpn-server ./cmd/vpn-server && go build -o bin/keygen ./cmd/keygen )

KEYS=$(../core/bin/keygen)
PRIV=$(echo "$KEYS" | awk '/Private/{print $3}')
PUB=$(echo "$KEYS" | awk '/Public/{print $3}')

python3 - "$PRIV" "$PUB" "$SID" <<'EOF'
import copy, json, sys
priv, pub, sid = sys.argv[1:4]
uuid = "5bab9cc8-b064-4b53-81c8-117be55d2238"

server = {
    "listen": "127.0.0.1:8443",
    "users": [{"id": uuid}],
    "reality": {
        "dest": "www.apple.com:443",
        "server_names": ["www.apple.com"],
        "private_key": priv,
        "short_ids": [sid],
        "max_time_diff_sec": 300,
    },
}
json.dump(server, open("server-reality.json", "w"), indent=2)

def client_config(socks_port, short_id, flow=""):
    user = {"id": uuid, "encryption": "none"}
    if flow:
        user["flow"] = flow
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks", "port": socks_port, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"udp": False},
        }],
        "outbounds": [{
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": 8443,
                "users": [user],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": "www.apple.com", "fingerprint": "chrome",
                    "publicKey": pub, "shortId": short_id, "spiderX": "/",
                },
            },
        }],
    }

json.dump(client_config(1081, sid), open("xray-client-reality.json", "w"), indent=2)
json.dump(client_config(1082, "ffffffffffffffff"), open("/tmp/xray-bad-sid.json", "w"))
json.dump(client_config(1085, sid, "xtls-rprx-vision"), open("/tmp/xray-vision.json", "w"))
EOF

cleanup() {
    for pid in "$HTTP_PID" "$PLAIN_PID" "$REALITY_PID" "$XRAY_PID" "$XRAY_BAD_PID" "${GEN_PID:-}" "${XRAY3_PID:-}" "${XRAY4_PID:-}"; do
        [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

( cd www && python3 -m http.server 8099 >/dev/null 2>&1 ) &
HTTP_PID=$!
../core/bin/vpn-server -config server.json >/tmp/e2e-plain.log 2>&1 &
PLAIN_PID=$!
../core/bin/vpn-server -config server-reality.json >/tmp/e2e-reality.log 2>&1 &
REALITY_PID=$!
"$XRAY" run -c xray-client.json >/dev/null 2>&1 &
XRAY_PID=$!
"$XRAY" run -c xray-client-reality.json >/dev/null 2>&1 &
XRAY2_PID=$!
"$XRAY" run -c /tmp/xray-bad-sid.json >/dev/null 2>&1 &
XRAY_BAD_PID=$!
"$XRAY" run -c /tmp/xray-vision.json >/dev/null 2>&1 &
XRAY4_PID=$!
sleep 1.5

fail=0
check() {
    if [ "$2" = "0" ]; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi
}

body=$(curl -s --max-time 8 --socks5-hostname 127.0.0.1:1080 http://localhost:8099/hello.txt)
[ "$body" = "hello through vless" ]; check "M1 plain vless (domain)" $?

body=$(curl -s --max-time 8 --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8099/hello.txt)
[ "$body" = "hello through vless" ]; check "M1 plain vless (ipv4)" $?

body=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:1081 http://localhost:8099/hello.txt)
[ "$body" = "hello through vless" ]; check "M2 reality: xray client proxied" $?

code=$(curl -s --max-time 20 --connect-to www.apple.com:443:127.0.0.1:8443 \
    https://www.apple.com/ -o /tmp/e2e-probe.html -w "%{http_code}")
page=$(head -c 200 /tmp/e2e-probe.html 2>/dev/null || true)
[ "$code" = "200" ] && echo "$page" | grep -q "<!DOCTYPE html"
check "M2 reality: prober sees real dest site (relay)" $?

cert=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername www.apple.com 2>/dev/null | grep "^subject" || true)
echo "$cert" | grep -q "CN=www.apple.com"
check "M2 reality: prober sees real dest certificate" $?

code=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:1082 http://127.0.0.1:8099/hello.txt -o /dev/null -w "%{http_code}" || true)
[ "$code" = "000" ]; check "M2 reality: wrong short id rejected" $?

# --- M5: xtls-rprx-vision flow -------------------------------------------------
body=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:1085 http://localhost:8099/hello.txt)
[ "$body" = "hello through vless" ]; check "M5 vision: plain http (early end)" $?

code=$(curl -s --max-time 30 --socks5-hostname 127.0.0.1:1085 https://www.apple.com/ -o /dev/null -w "%{http_code}" || true)
[ "$code" = "200" ]; check "M5 vision: inner TLS 1.3 (direct copy)" $?

# --- M4: full cycle through vpnctl and a vless:// link -----------------------
rm -f server-generated.json
../.venv/bin/python ../tools/vpnctl.py init \
    --host 127.0.0.1 --port 8453 --listen 127.0.0.1:8453 \
    --out server-generated.json --name macbook >/tmp/e2e-init.out
LINK=$(grep '^vless://' /tmp/e2e-init.out | head -1)
[ -n "$LINK" ]; check "M4 vpnctl: init generated a link" $?

../.venv/bin/python ../tools/link2xray.py "$LINK" 1084 >/tmp/xray-from-link.json
../core/bin/vpn-server -config server-generated.json >/tmp/e2e-gen.log 2>&1 &
GEN_PID=$!
"$XRAY" run -c /tmp/xray-from-link.json >/dev/null 2>&1 &
XRAY3_PID=$!
sleep 1.5

body=$(curl -s --max-time 20 --socks5-hostname 127.0.0.1:1084 http://localhost:8099/hello.txt)
[ "$body" = "hello through vless" ]; check "M4 vpnctl: link-only client config proxied" $?

kill "$GEN_PID" "$XRAY3_PID" 2>/dev/null || true

exit $fail
