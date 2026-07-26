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
        rest, query_string = rest.split("?", 1)

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


def parse_share_lines(lines, max_outbounds: int = 0):
    outbounds = []
    unsupported = 0
    considered = 0

    for index, line in enumerate(lines, start=1):
        if max_outbounds > 0 and len(outbounds) >= max_outbounds:
            break

        normalized = normalize_line(line)

        if not normalized:
            continue

        if not re.match(r"^(vmess|vless|trojan|ss|ssr)://", normalized):
            continue

        considered += 1

        outbound = parse_line(normalized, index)

        if outbound:
            outbounds.append(outbound)
        else:
            unsupported += 1

    return outbounds, unsupported, considered


def parse_input_file(path: str, max_outbounds: int = 0):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return [], 0, 0

    outbounds, unsupported, considered = parse_share_lines(lines, max_outbounds)

    if considered:
        return outbounds, unsupported, considered

    content = "".join(line.strip() for line in lines if line.strip())

    if content:
        try:
            decoded = b64decode_any(content)
            decoded_lines = decoded.splitlines()

            outbounds, unsupported, considered = parse_share_lines(
                decoded_lines,
                max_outbounds,
            )

            if considered:
                return outbounds, unsupported, considered

        except Exception:
            pass

    return [], 0, 0


def load_template(path: str):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return clean_nulls(json.load(f))
        except Exception as exc:
            print(f"template error: {exc}", file=sys.stderr)

    return json.loads(json.dumps(INTERNAL_TEMPLATE))


def ensure_base(profile: dict, no_tun: bool):
    profile.setdefault("log", {"level": "warn"})

    profile.setdefault(
        "dns",
        {
            "servers": [
                {
                    "tag": "dns",
                    "address": "1.1.1.1",
                    "detour": "DIRECT",
                }
            ]
        },
    )

    profile.setdefault("inbounds", [])

    if not isinstance(profile["inbounds"], list):
        profile["inbounds"] = []

    has_mixed = any(
        isinstance(inbound, dict) and inbound.get("tag") == "mixed-in"
        for inbound in profile["inbounds"]
    )

    if not has_mixed:
        profile["inbounds"].insert(
            0,
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True,
            },
        )

    if no_tun:
        profile["inbounds"] = [
            inbound
            for inbound in profile["inbounds"]
            if not (isinstance(inbound, dict) and inbound.get("type") == "tun")
        ]
    else:
        has_tun = any(
            isinstance(inbound, dict) and inbound.get("type") == "tun"
            for inbound in profile["inbounds"]
        )

        if not has_tun:
            profile["inbounds"].append(
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "address": ["172.19.0.1/30"],
                    "auto_route": True,
                    "strict_route": True,
                    "sniff": True,
                }
            )

    profile.setdefault("outbounds", [])

    if not isinstance(profile["outbounds"], list):
        profile["outbounds"] = []

    existing_tags = [
        outbound.get("tag")
        for outbound in profile["outbounds"]
        if isinstance(outbound, dict)
    ]

    if "DIRECT" not in existing_tags:
        profile["outbounds"].insert(
            0,
            {
                "type": "direct",
                "tag": "DIRECT",
            },
        )

    existing_tags = [
        outbound.get("tag")
        for outbound in profile["outbounds"]
        if isinstance(outbound, dict)
    ]

    if "REJECT" not in existing_tags:
        insert_at = 1 if "DIRECT" in existing_tags else 0

        profile["outbounds"].insert(
            insert_at,
            {
                "type": "block",
                "tag": "REJECT",
            },
        )

    profile.setdefault("route", {})

    if not isinstance(profile["route"], dict):
        profile["route"] = {}

    return profile


def assign_unique_tags(outbounds):
    used_tags = {"DIRECT", "REJECT", "Auto", "PROXY"}
    fixed = []

    for index, outbound in enumerate(outbounds, start=1):
        if not isinstance(outbound, dict):
            continue

        tag = clean_tag(outbound.get("tag"), f"proxy-{index}")
        base_tag = tag
        counter = 1

        while tag in used_tags:
            counter += 1
            tag = f"{base_tag}-{counter}"

        outbound["tag"] = tag
        used_tags.add(tag)
        fixed.append(outbound)

    return fixed


def build_profile(proxy_outbounds, template_path: str, no_tun: bool):
    profile = load_template(template_path)
    profile = ensure_base(profile, no_tun)

    profile["outbounds"] = [
        outbound
        for outbound in profile["outbounds"]
        if not (
            isinstance(outbound, dict)
            and outbound.get("tag") in ("Auto", "PROXY")
        )
    ]

    used_tags = {
        outbound.get("tag")
        for outbound in profile["outbounds"]
        if isinstance(outbound, dict) and outbound.get("tag")
    }

    used_tags.update({"Auto", "PROXY"})

    fixed_outbounds = []

    for index, outbound in enumerate(proxy_outbounds, start=1):
        if not isinstance(outbound, dict):
            continue

        outbound_type = outbound.get("type")

        if not outbound_type:
            continue

        if outbound_type in ("direct", "block", "dns", "selector", "urltest"):
            continue

        tag = clean_tag(outbound.get("tag"), f"proxy-{index}")
        base_tag = tag
        counter = 1

        while tag in used_tags:
            counter += 1
            tag = f"{base_tag}-{counter}"

        outbound["tag"] = tag
        used_tags.add(tag)

        fixed_outbounds.append(clean_nulls(outbound))

    proxy_tags = [outbound["tag"] for outbound in fixed_outbounds]

    if proxy_tags:
        auto = {
            "type": "urltest",
            "tag": "Auto",
            "outbounds": proxy_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50,
        }

        selector = {
            "type": "selector",
            "tag": "PROXY",
            "outbounds": ["Auto"] + proxy_tags,
            "default": "Auto",
        }

        profile["outbounds"].extend(fixed_outbounds)
        profile["outbounds"].append(auto)
        profile["outbounds"].append(selector)

        profile["route"]["final"] = "PROXY"
    else:
        profile["route"]["final"] = "DIRECT"

    return clean_nulls(profile)


def load_outbounds_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if isinstance(data.get("outbounds"), list):
            return data["outbounds"]

        if isinstance(data.get("proxies"), list):
            return data["proxies"]

    return []


def minimal_profile_for_outbounds(outbounds):
    return {
        "log": {
            "level": "error"
        },
        "outbounds": [
            {
                "type": "direct",
                "tag": "DIRECT",
            }
        ] + [clean_nulls(outbound) for outbound in outbounds],
        "route": {
            "final": "DIRECT",
        },
    }


def run_singbox_check(profile: dict, singbox_bin: str):
    fd, path = tempfile.mkstemp(suffix=".json", text=True)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(clean_nulls(profile), f, ensure_ascii=False)

        proc = subprocess.run(
            [singbox_bin, "check", "-c", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )

        return proc.returncode == 0, proc.stdout.strip()

    except Exception as exc:
        return False, str(exc)

    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def prune_invalid_outbounds(outbounds, singbox_bin: str):
    print(f"pruning: checking {len(outbounds)} outbounds", file=sys.stderr)

    ok, err = run_singbox_check(minimal_profile_for_outbounds([]), singbox_bin)

    if not ok:
        print(
            f"sing-box direct-only check failed, pruning skipped: {redact_text(err)[:500]}",
            file=sys.stderr,
        )
        return outbounds, []

    def rec(segment):
        if not segment:
            return [], []

        ok, err = run_singbox_check(minimal_profile_for_outbounds(segment), singbox_bin)

        if ok:
            return segment, []

        if len(segment) == 1:
            return [], [(segment[0], err)]

        mid = len(segment) // 2

        good_left, bad_left = rec(segment[:mid])
        good_right, bad_right = rec(segment[mid:])

        return good_left + good_right, bad_left + bad_right

    good, bad = rec(outbounds)

    print(f"pruning: kept {len(good)}, invalid {len(bad)}", file=sys.stderr)

    for outbound, error in bad[:20]:
        tag = outbound.get("tag", "unknown") if isinstance(outbound, dict) else "unknown"
        print(
            f"invalid outbound {tag}: {redact_text(error)[:500]}",
            file=sys.stderr,
        )

    return good, bad


def main():
    parser = argparse.ArgumentParser(
        description="Convert share links or prepared outbounds to a sing-box profile."
    )

    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--template", default=os.environ.get("DEFAULT_TEMPLATE", "templates/base.json"))
    parser.add_argument("--outbounds-json")
    parser.add_argument("--name", default="profile")
    parser.add_argument("--no-tun", action="store_true")
    parser.add_argument("--max-outbounds", type=int, default=0)
    parser.add_argument("--prune", action="store_true")
    parser.add_argument("--sing-box-bin", default="sing-box")

    args = parser.parse_args()

    max_outbounds = max(0, int(args.max_outbounds or 0))

    if args.outbounds_json:
        try:
            outbounds = load_outbounds_json(args.outbounds_json)
        except Exception as exc:
            print(f"cannot load outbounds JSON: {exc}", file=sys.stderr)
            sys.exit(1)

        if max_outbounds > 0:
            outbounds = outbounds[:max_outbounds]

        unsupported = 0
        considered = len(outbounds)

    else:
        outbounds, unsupported, considered = parse_input_file(args.input, max_outbounds)

    if not outbounds:
        print(
            json.dumps(
                {
                    "parsed": 0,
                    "unsupported": unsupported,
                    "considered": considered,
                    "invalid_schema": 0,
                },
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    outbounds = assign_unique_tags(outbounds)

    invalid_schema = 0

    if args.prune:
        if shutil.which(args.sing_box_bin):
            outbounds, bad = prune_invalid_outbounds(outbounds, args.sing_box_bin)
            invalid_schema = len(bad)
        else:
            print("sing-box binary not found, pruning skipped", file=sys.stderr)

    if not outbounds:
        print(
            json.dumps(
                {
                    "parsed": 0,
                    "unsupported": unsupported,
                    "considered": considered,
                    "invalid_schema": invalid_schema,
                },
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    profile = build_profile(outbounds, args.template, args.no_tun)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)

    proxy_count = len(
        [
            outbound
            for outbound in profile.get("outbounds", [])
            if isinstance(outbound, dict)
            and outbound.get("type") not in ("direct", "block", "dns", "selector", "urltest")
        ]
    )

    print(
        json.dumps(
            {
                "parsed": proxy_count,
                "unsupported": unsupported,
                "considered": considered,
                "invalid_schema": invalid_schema,
                "output": args.output,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
