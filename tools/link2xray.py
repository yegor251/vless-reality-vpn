#!/usr/bin/env python3
"""Convert a vless:// link into a minimal Xray client config.

Usage: link2xray.py "vless://..." [socks_port] > client.json
Used by the e2e tests; handy for debugging links by hand.
"""

import json
import sys
from urllib.parse import parse_qs, urlparse


def link_to_config(link: str, socks_port: int = 1080, listen: str = "127.0.0.1") -> dict:
    p = urlparse(link)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    if q.get("security") != "reality":
        raise SystemExit("only reality links are supported")
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "port": socks_port,
                "listen": listen,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": p.hostname,
                            "port": p.port,
                            "users": [
                                {
                                    "id": p.username,
                                    "encryption": q.get("encryption", "none"),
                                    "flow": q.get("flow", ""),
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": q.get("type", "tcp"),
                    "security": "reality",
                    "realitySettings": {
                        "serverName": q["sni"],
                        "fingerprint": q.get("fp", "chrome"),
                        "publicKey": q["pbk"],
                        "shortId": q["sid"],
                        "spiderX": q.get("spx", "/"),
                    },
                },
            }
        ],
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    socks_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    json.dump(link_to_config(sys.argv[1], socks_port), sys.stdout, indent=2)
    print()
