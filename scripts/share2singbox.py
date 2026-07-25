#!/usr/bin/env python3
import argparse
import base64
import json
import re
import sys
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


def b64decode_any(data: str) -> str:
    data = data.strip().replace("\n", "").replace("\r", "")
    pad = "=" * (-len(data) % 4)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(data + pad).decode("utf-8")
        except Exception:
            pass

    raise ValueError("base64 decode failed")


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
    net = (network or "tcp").lower()

    if net in ("ws", "websocket"):
        transport = {
            "type": "ws",
            "path": params.get("path") or "/",
        }

        host = params.get("host") or params.get("Host")
        if host:
            transport["headers"] = {"Host": host}

        return transport

    if net in ("grpc", "gun"):
        return {
            "type": "grpc",
            "service_name": params.get("serviceName") or params.get("servicename") or "",
        }

    if net in ("http", "h2"):
        transport = {"type": "http"}

        path = params.get("path")
        if path:
            transport["path"] = path

        return transport

    if net in ("tcp", "none", ""):
        header_type = (params.get("type") or params.get("headerType") or "").lower()

        if header_type == "http":
            return {"type": "http"}

        return None

    return None


def add_tls(outbound: dict, security: str, params: dict, default_server_name: str):
    if security not in ("tls", "reality"):
        return None

    tls = {"enabled": True}

    server_name = params.get("sni") or params.get("servername") or default_server_name
    if server_name:
        tls["server_name"] = server_name

    alpn = params.get("alpn")
    if isinstance(alpn, list):
        alpn = ",".join(str(x) for x in alpn)

    if alpn:
        tls["alpn"] = [x for x in str(alpn).split(",") if x]

    fingerprint = (params.get("fp") or "").lower()
    if fingerprint in UTLS_FINGERPRINTS:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint,
        }

    insecure = params.get("allowinsecure") or params.get("insecure")
    if str(insecure).lower() in ("1", "true", "yes"):
        tls["insecure"] = True

    if security == "reality":
        public_key = params.get("pbk")

        if not public_key:
            return "skip"

        reality = {
            "enabled": True,
            "public_key": public_key,
        }

        short_id = params.get("sid")
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

    flow = query.get("flow")
    if flow and flow.startswith("xtls-rprx-vision"):
        outbound["flow"] = flow

    security = (query.get("security") or "none").lower()

    if security in ("tls", "reality"):
        if add_tls(outbound, security, query, host) == "skip":
            return None

    network = query.get("type") or query.get("network") or "tcp"
    transport = build_transport(network, query)

    if transport:
        outbound["transport"] = transport

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
        rest, query_string = rest.split("?", 1)

    query = dict(urllib.parse.parse_qsl(query_string, keep_blank_values=True))

    try:
        if "@" in rest:
            userinfo, hostport = rest.rsplit("@", 1)

            try:
                decoded_userinfo = b64decode_any(userinfo)
            except Exception:
                decoded_userinfo = userinfo

            if ":" not in decoded_userinfo:
                return None

            method, password = decoded_userinfo.split(":", 1)
            host, port = split_host_port(hostport, 8388)

        else:
            decoded = b64decode_any(rest)

            if "@" not in decoded:
                return None

            userinfo, hostport = decoded.rsplit("@", 1)

            if ":" not in userinfo:
                return None

            method, password = userinfo.split(":", 1)
            host, port = split_host_port(hostport, 8388)

    except Exception:
        return None

    if not host or not method:
        return None

    return {
        "type": "shadowsocks",
        "tag": clean_tag(fragment, f"ss-{index}"),
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


def parse_vmess(line: str, index: int):
    rest = line[len("vmess://"):]

    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)

    try:
        decoded = b64decode_any(rest)
        data = json.loads(decoded)
    except Exception:
        return None

    host = data.get("add")
    uuid = data.get("id")

    if not host or not uuid:
        return None

    try:
        port = int(data.get("port") or 443)
    except Exception:
        return None

    security = (data.get("scy") or data.get("security") or "auto").lower()
    if security not in (
        "auto",
        "none",
        "zero",
        "aes-128-gcm",
        "chacha20-poly1305",
    ):
        security = "auto"

    try:
        alter_id = int(data.get("aid") or 0)
    except Exception:
        alter_id = 0

    outbound = {
        "type": "vmess",
        "tag": clean_tag(data.get("ps") or fragment, f"vmess-{index}"),
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id,
    }

    tls_value = str(data.get("tls", "")).lower()

    if tls_value in ("tls", "true", "1"):
        tls_params = {
            "sni": data.get("sni"),
            "alpn": data.get("alpn"),
            "allowinsecure": data.get("allowInsecure") or data.get("insecure"),
        }

        add_tls(outbound, "tls", tls_params, data.get("host") or host)

    network = data.get("net") or "tcp"

    transport_params = {
        "path": data.get("path"),
        "host": data.get("host"),
        "serviceName": data.get("serviceName") or data.get("servicename"),
        "type": data.get("type"),
        "headerType": data.get("type"),
    }

    transport = build_transport(network, transport_params)

    if transport:
        outbound["transport"] = transport

    return outbound


def parse_line(line: str, index: int):
    normalized = normalize_line(line)

    if not normalized:
        return None

    try:
        if normalized.startswith("vless://"):
            return parse_vless(normalized, index)

        if normalized.startswith("trojan://"):
            return parse_trojan(normalized, index)

        if normalized.startswith("ss://"):
            return parse_shadowsocks(normalized, index)

        if normalized.startswith("vmess://"):
            return parse_vmess(normalized, index)

    except Exception as exc:
        print(f"parse error line {index}: {exc}", file=sys.stderr)

    return None


def build_profile(outbounds, no_tun=False):
    used_tags = {"DIRECT", "REJECT", "PROXY"}
    fixed_outbounds = []

    for index, outbound in enumerate(outbounds, start=1):
        tag = clean_tag(outbound.get("tag"), f"proxy-{index}")
        base_tag = tag
        counter = 1

        while tag in used_tags:
            counter += 1
            tag = f"{base_tag}-{counter}"

        outbound["tag"] = tag
        used_tags.add(tag)
        fixed_outbounds.append(outbound)

    proxy_tags = [outbound["tag"] for outbound in fixed_outbounds]

    inbounds = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
            "sniff": True,
        }
    ]

    if not no_tun:
        inbounds.append(
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "sniff": True,
            }
        )

    final_outbounds = [
        {
            "type": "direct",
            "tag": "DIRECT",
        },
        {
            "type": "block",
            "tag": "REJECT",
        },
    ]

    final_outbounds.extend(fixed_outbounds)

    route_final = "DIRECT"

    if proxy_tags:
        final_outbounds.append(
            {
                "type": "urltest",
                "tag": "PROXY",
                "outbounds": proxy_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
                "tolerance": 50,
            }
        )
        route_final = "PROXY"

    return {
        "log": {
            "level": "warn",
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns",
                    "address": "1.1.1.1",
                    "detour": "DIRECT",
                }
            ]
        },
        "inbounds": inbounds,
        "outbounds": final_outbounds,
        "route": {
            "final": route_final,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Convert vless/vmess/trojan/ss share links to sing-box profile."
    )

    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--name", default="profile")
    parser.add_argument("--no-tun", action="store_true")

    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        sys.exit(1)

    outbounds = []
    unsupported = 0

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        outbound = parse_line(stripped, index)

        if outbound:
            outbounds.append(outbound)
        else:
            unsupported += 1

    if not outbounds:
        print(
            json.dumps(
                {
                    "parsed": 0,
                    "unsupported": unsupported,
                },
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    profile = build_profile(outbounds, no_tun=args.no_tun)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)

    print(
        json.dumps(
            {
                "parsed": len(outbounds),
                "unsupported": unsupported,
                "output": args.output,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
