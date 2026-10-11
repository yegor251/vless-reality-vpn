#!/usr/bin/env python3
"""vpnctl — key, config and vless:// link tooling for the VLESS+REALITY server.

Subcommands:
  keys      generate an x25519 key pair (base64 RawURL, as Xray expects)
  init      generate a server config and vless:// links for its users
  add-user  append a user to an existing config and print its link
  link      print vless:// links for every user in a config
  probe     check that a dest host speaks TLS 1.3 (camouflage candidate)
"""

import argparse
import base64
import json
import secrets
import socket
import ssl
import sys
import uuid as uuidlib
from pathlib import Path
from urllib.parse import quote, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

RAW = serialization.Encoding.Raw


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keys() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub_bytes = priv.public_key().public_bytes(RAW, serialization.PublicFormat.Raw)
    return b64url(priv_bytes), b64url(pub_bytes)


def public_from_private(priv_b64: str) -> str:
    priv = X25519PrivateKey.from_private_bytes(b64url_decode(priv_b64))
    return b64url(priv.public_key().public_bytes(RAW, serialization.PublicFormat.Raw))


def new_short_id() -> str:
    return secrets.token_hex(8)


def load_config(path: Path) -> dict:
    cfg = json.loads(path.read_text())
    if "reality" not in cfg:
        sys.exit(f"{path}: no 'reality' section (plain VLESS configs have no links)")
    return cfg


def build_link(host: str, port: int, user_id: str, sni: str, pbk: str, sid: str, remark: str) -> str:
    params = (
        "encryption=none"
        "&security=reality"
        f"&sni={quote(sni, safe='')}"
        "&fp=chrome"
        f"&pbk={quote(pbk, safe='')}"
        f"&sid={quote(sid, safe='')}"
        "&spx=%2F"
        "&type=tcp"
        "&headerType=none"
    )
    return f"vless://{user_id}@{host}:{port}?{params}#{quote(remark, safe='')}"


def config_links(cfg: dict, host: str, port: int) -> list[tuple[str, str]]:
    reality = cfg["reality"]
    sni = reality["server_names"][0]
    pbk = public_from_private(reality["private_key"])
    links = []
    for i, user in enumerate(cfg["users"]):
        remark = user.get("name") or f"{host}:{port} user{i + 1}"
        links.append((user["id"], build_link(host, port, user["id"], sni, pbk, reality["short_ids"][0], remark)))
    return links


def print_links(cfg: dict, host: str, port: int) -> None:
    for _, link in config_links(cfg, host, port):
        print(link)


def cmd_keys(_args) -> None:
    priv, pub = generate_keys()
    print(f"Private key: {priv}")
    print(f"Public key:  {pub}")


def cmd_init(args) -> None:
    priv, pub = generate_keys()
    user_id = args.uuid or str(uuidlib.uuid4())
    sid = args.short_id or new_short_id()
    cfg = {
        "listen": args.listen,
        "users": [{"id": user_id, "name": args.name}],
        "reality": {
            "dest": args.dest,
            "server_names": [args.sni],
            "private_key": priv,
            "short_ids": [sid],
            "max_time_diff_sec": args.max_time_diff,
        },
    }
    path = Path(args.out)
    if path.exists() and not args.force:
        sys.exit(f"{path} exists (use --force to overwrite)")
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"Server config: {path}")
    print(f"UUID:          {user_id}")
    print(f"Short ID:      {sid}")
    print(f"Public key:    {pub}")
    print()
    print_links(cfg, args.host, args.port)


def cmd_add_user(args) -> None:
    path = Path(args.config)
    cfg = load_config(path)
    user = {"id": str(uuidlib.uuid4()), "name": args.name}
    cfg["users"].append(user)
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    print_links(cfg, args.host, args.port)


def cmd_link(args) -> None:
    print_links(load_config(Path(args.config)), args.host, args.port)


def cmd_probe(args) -> None:
    host, _, port = args.dest.rpartition(":")
    if not host:
        sys.exit("dest must be host:port")
    try:
        raw = socket.create_connection((host, int(port)), timeout=8)
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(raw, server_hostname=host)
    except (OSError, ssl.SSLError) as exc:
        sys.exit(f"FAIL {args.dest}: {exc}")
    with conn:
        version = conn.version()
        cert = conn.getpeercert()
        subject = ", ".join(f"{k}={v}" for kv in cert.get("subject", ()) for k, v in kv)
        alpn = conn.selected_alpn_protocol() or "none"
    if version != "TLSv1.3":
        sys.exit(f"FAIL {args.dest}: {version}, want TLSv1.3")
    print(f"OK {args.dest}: TLS 1.3, ALPN {alpn}, cert: {subject}")


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="vpnctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keys", help="generate an x25519 key pair").set_defaults(func=cmd_keys)

    p = sub.add_parser("init", help="generate a server config and vless:// links")
    p.add_argument("--host", required=True, help="public address clients connect to")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--listen", default="0.0.0.0:443", help="server listen address")
    p.add_argument("--dest", default="www.apple.com:443", help="camouflage target host:port")
    p.add_argument("--sni", default="www.apple.com", help="server name (must match dest)")
    p.add_argument("--out", default="server.json")
    p.add_argument("--name", default="main", help="user display name for the link remark")
    p.add_argument("--uuid", help="fixed user UUID (generated when omitted)")
    p.add_argument("--short-id", help="fixed short id hex (generated when omitted)")
    p.add_argument("--max-time-diff", type=int, default=300)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add-user", help="append a user and print links")
    p.add_argument("--config", default="server.json")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_add_user)

    p = sub.add_parser("link", help="print vless:// links for a config")
    p.add_argument("--config", default="server.json")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.set_defaults(func=cmd_link)

    p = sub.add_parser("probe", help="check a dest host for TLS 1.3")
    p.add_argument("--dest", default="www.apple.com:443")
    p.set_defaults(func=cmd_probe)

    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
