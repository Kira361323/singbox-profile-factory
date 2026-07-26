#!/usr/bin/env python3
import argparse
import base64
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

UTLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
}

INTERNAL_TEMPLATE = {
    "log": {
        "level": "warn"
    },
    "dns": {
        "servers": [
            {
                "tag": "dns",
                "address": "1.1.1.1",
                "detour": "DIRECT"
            }
        ]
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
            "sniff": True
        },
        {
            "type": "tun",
            "tag": "tun-in",
            "address": [
                "172.19.0.1/30"
            ],
            "auto_route": True,
            "strict_route": True,
            "sniff": True
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "DIRECT"
        },
        {
            "type": "block",
            "tag": "REJECT"
        }
    ],
    "route": {
        "final": "DIRECT"
    }
}


def redact_text(text: str) -> str:
    if not text:
        return ""

    text = re.sub(
        r'("?(?:password|uuid|psk|private_key|public_key|token)"?\s*[:=]\s*"?)[^"\s,}]+',
        r"\1REDACTED",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(r"(vmess://)[A-Za-z0-9+/=]+", r"\1REDACTED", text)
    text = re.sub(r"(vless://)[^@[:space:]]+@", r"\1REDACTED@", text)
    text = re.sub(r"(trojan://)[^@[:space:]]+@", r"\1REDACTED@", text)
    text = re.sub(r"(ss://)[^@[:space:]]+@", r"\1REDACTED@", text)
    text = re.sub(r"(ssr://)[A-Za-z0-9_+/=-]+", r"\1REDACTED", text)

    return text


def clean_nulls(obj):
    if isinstance(obj, dict):
        return {
            key: clean_nulls(value)
            for key, value in obj.items()
            if value is not None
        }

    if isinstance(obj, list):
        return [clean_nulls(value) for value in obj if value is not None]

    return obj


def b64decode_any(data: str) -> str:
    data = data.strip().replace("\n", "").replace("\r", "")
    pad = "=" * (-len(data) % 4)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(data + pad).decode("utf-8")
        except Exception:
            pass

    raise ValueError("base64 decode failed")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def normalize_line(line: str):
    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    if "#" in line:
        base, fragment = line.split("#", 1)
        fragment = urllib.parse.unquote(fragment.strip())

        if fragment:
            line = base + "#" + urllib.parse.quote(fragment, safe="")
        else:
            line = base

    if " " in line:
        line = line.replace(" ", "%20")

    return line


def clean_tag(value, fallback: str) -> str:
    if value is None:
        return fallback

    text = urllib.parse.unquote(str(value))
    text = re.sub(r"[\x00-\x1f\x7f]", "", text)
    text = text.strip()

    if not text:
        return fallback

    if len(text) > 120:
        text = text[:120].strip()

    return text


def split_host_port(value: str, default_port: int):
    value = value.strip()

    if not value:
        return None, default_port

    if value.startswith("["):
        host, _, rest = value.partition("]")
        host = host[1:]
        port = default_port

        if rest.startswith(":"):
            port = rest[1:]

        return host, int(port or default_port)

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, int(port or default_port)

    return value, default_port


def build_transport(network: str, params: dict):
    lc = {str(k).lower(): v for k, v in (params or {}).items()}

    net = (network or "tcp").lower()

    if net in ("ws", "websocket"):
        transport = {
            "type": "ws",
            "path": lc.get("path") or "/",
        }

        host = lc.get("host")
        if host:
            transport["headers"] = {"Host": host}

        return transport

    if net in ("grpc", "gun"):
        return {
            "type": "grpc",
            "service_name": lc.get("servicename") or "",
        }

    if net in ("http", "h2"):
        transport = {"type": "http"}

        path = lc.get("path")
        if path:
            transport["path"] = path

        return transport

    if net in ("tcp", "none", ""):
        header_type = (lc.get("type") or lc.get("headertype") or "").lower()

        if header_type == "http":
            return {"type": "http"}

        return None

    return None


def add_tls(outbound: dict, security: str, params: dict, default_server_name: str):
    if security not in ("tls", "reality"):
        return None

    lc = {str(k).lower(): v for k, v in (params or {}).items()}

    tls = {"enabled": True}

    server_name = lc.get("sni") or lc.get("servername")

    if not server_name and default_server_name and not is_ip(default_server_name):
        server_name = default_server_name

    if server_name:
        tls["server_name"] = server_name

    alpn = lc.get("alpn")
    if isinstance(alpn, list):
        alpn = ",".join(str(x) for x in alpn)

    if alpn:
        tls["alpn"] = [x for x in str(alpn).split(",") if x]

    fingerprint = (lc.get("fp") or "").lower()
    if fingerprint in UTLS_FINGERPRINTS:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    insecure = lc.get("allowinsecure") or lc.get("insecure")
    if str(insecure).lower() in ("1", "true", "yes"):
        tls["insecure"] = True

    if security == "reality":
        public_key = lc.get("pbk")

        if not public_key:
            return "skip"

        reality = {
            "enabled": True,
            "public_key": public_key,
        }

        short_id = lc.get("sid")
        if short_id:
            reality["short_id"] = short_id

        tls["reality"] = reality

    outbound["tls"] = tls
    return None


def parse_vless(line: str, index: int):
    parsed = urllib.parse.urlsplit(line)

    uuid = urllib.parse.unquote(parsed.username or "")
    host = parsed.hostname

    if not uuid or not host:
        return None

    port = parsed.port or 443
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    outbound = {
        "type": "vless",
        "tag": clean_tag(parsed.fragment, f"vless-{index}"),
        "server": host,
        "server_port": int(port),
        "uuid": uuid,
    }

    security = (query.get("security") or "none").lower()

    if security in ("tls", "reality"):
        if add_tls(outbound, security, query, host) == "skip":
            return None

    network = query.get("type") or query.get("network") or "tcp"
    transport = build_transport(network, query)

    if transport:
        outbound["transport"] = transport
    else:
        flow = query.get("flow")
        if flow and flow.startswith("xtls-rprx-vision"):
            outbound["flow"] = flow

    return outbound


def parse_trojan(line: str, index: int):
    parsed = urllib.parse.urlsplit(line)

    password = urllib.parse.unquote(parsed.username or "")
    host = parsed.hostname

    if not password or not host:
        return None

    port = parsed.port or 443
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    outbound = {
        "type": "trojan",
        "tag": clean_tag(parsed.fragment, f"trojan-{index}"),
        "server": host,
        "server_port": int(port),
        "password": password,
    }

    security = (query.get("security") or "tls").lower()

    if security in ("tls", "reality"):
        if add_tls(outbound, security, query, host) == "skip":
            return None

    network = query.get("type") or "tcp"
    transport = build_transport(network, query)

    if transport:
        outbound["transport"] = transport

    return outbound


def parse_shadowsocks(line: str, index: int):
    rest = line[len("ss://"):]

    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)

    query_string = ""
    if "?" in rest:
        rest, query_string = rest.split("?", 
