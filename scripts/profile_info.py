#!/usr/bin/env python3
import json
import sys

PROXY_TYPES = {
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "trojan",
    "wireguard",
    "hysteria",
    "vless",
    "shadowtls",
    "tuic",
    "hysteria2",
    "anytls",
    "snell",
}


def main():
    try:
        path = sys.argv[1]

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        outbounds = data.get("outbounds", [])
        if not isinstance(outbounds, list):
            print("0 0")
            return

        total = 0
        proxy = 0

        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue

            total += 1

            if outbound.get("type") in PROXY_TYPES:
                proxy += 1

        print(total, proxy)

    except Exception:
        print("0 0")


if __name__ == "__main__":
    main()
