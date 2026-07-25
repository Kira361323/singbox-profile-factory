#!/usr/bin/env python3
import json
import os
import re
import sys

DEFAULT_UA = os.environ.get("DEFAULT_UA", "clash.meta")
DEFAULT_TEMPLATE = os.environ.get("DEFAULT_TEMPLATE", "templates/base.json")


def sanitize_int(value, default=0):
    try:
        text = str(value).strip()

        if text == "":
            return default

        digits = "".join(ch for ch in text if ch.isdigit())

        if digits == "":
            return default

        return int(digits)

    except Exception:
        return default


def sanitize_name(value):
    text = str(value).strip()
    text = re.sub(r"[^A-Za-z0-9._-]", "_", text)
    text = text.strip("._-")

    if not text:
        return None

    return text


def emit(name, url, max_links, user_agent, template):
    name = sanitize_name(name)

    if not name:
        return

    url = str(url).strip()

    if not re.match(r"^https?://", url):
        return

    max_links = sanitize_int(max_links, 0)
    user_agent = str(user_agent or DEFAULT_UA).strip() or DEFAULT_UA
    template = str(template or DEFAULT_TEMPLATE).strip() or DEFAULT_TEMPLATE

    print(f"{name}\t{url}\t{max_links}\t{user_agent}\t{template}")


def from_providers(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("providers.json must be a JSON array")

    force_max_links = os.environ.get("FORCE_MAX_LINKS", "").strip()
    default_max_links = sanitize_int(os.environ.get("MAX_LINKS", "300"), 300)

    for item in data:
        if not isinstance(item, dict):
            continue

        if not item.get("enabled", True):
            continue

        name = item.get("name")
        url = item.get("url")

        if not name or not url:
            continue

        max_links = item.get("max_links", default_max_links)

        if force_max_links != "":
            max_links = force_max_links

        emit(
            name,
            url,
            max_links,
            item.get("user_agent", DEFAULT_UA),
            item.get("template", DEFAULT_TEMPLATE),
        )


def from_subscriptions_markdown(path):
    force_max_links = os.environ.get("FORCE_MAX_LINKS", "").strip()
    default_max_links = sanitize_int(os.environ.get("MAX_LINKS", "300"), 300)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip().lstrip("\ufeff")

            if not line:
                continue

            if line.startswith("#"):
                continue

            parts = line.split(maxsplit=1)

            if len(parts) != 2:
                continue

            name, url = parts

            max_links = default_max_links

            if force_max_links != "":
                max_links = force_max_links

            emit(name, url, max_links, DEFAULT_UA, DEFAULT_TEMPLATE)


def main():
    providers_path = "providers.json"
    subscriptions_path = "subscriptions.md"

    if os.path.exists(providers_path):
        try:
            from_providers(providers_path)
            return
        except Exception as exc:
            print(f"providers.json error: {exc}", file=sys.stderr)

    if os.path.exists(subscriptions_path):
        from_subscriptions_markdown(subscriptions_path)


if __name__ == "__main__":
    main()
