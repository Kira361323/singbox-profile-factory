#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-subscriptions.md}"
OUT="${2:-profiles}"

MAX_LINKS="${MAX_LINKS:-300}"
MAX_LINKS="${MAX_LINKS//[^0-9]/}"
[[ -z "$MAX_LINKS" ]] && MAX_LINKS=300

mkdir -p "$OUT" /tmp/profile_factory
[[ -f "$SRC" ]] || touch "$SRC"

STATUS="$OUT/STATUS.md"

cat > "$STATUS" <<EOF
# Статус профилей

_Обновлено: $(date -u '+%Y-%m-%d %H:%M UTC')_

Мёртвые серверы не удаляются.
Проверяется только доступность источника и валидность sing-box конфига.

| Профиль | Источник | HTTP | Ссылок | Outbounds | Proxy | sing-box check | Файл |
|---|---|---:|---:|---:|---:|---|---|
EOF

normalize_url() {
  local url="$1"

  if [[ "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$ ]]; then
    echo "https://raw.githubusercontent.com/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/${BASH_REMATCH[3]}"
  else
    echo "$url"
  fi
}

safe_url() {
  local url="$1"
  printf '%s' "$url" | sed -E 's#(https?://[^/]+).*#\1/#'
}

redact_text() {
  sed -E \
    -e 's#(token=)[^&[:space:]"]+#\1REDACTED#gI' \
    -e 's#("password"[[:space:]]*:[[:space:]]*")[^"]+(")#\1REDACTED\2#g' \
    -e 's#("uuid"[[:space:]]*:[[:space:]]*")[^"]+(")#\1REDACTED\2#g' \
    -e 's#("psk"[[:space:]]*:[[:space:]]*")[^"]+(")#\1REDACTED\2#g' \
    -e 's#("private_key"[[:space:]]*:[[:space:]]*")[^"]+(")#\1REDACTED\2#g' \
    -e 's#("public_key"[[:space:]]*:[[:space:]]*")[^"]+(")#\1REDACTED\2#g' \
    -e 's#(vmess://)[A-Za-z0-9+/=]+#\1REDACTED#g' \
    -e 's#(vless://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(trojan://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(ss://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(ssr://)[A-Za-z0-9_+/=-]+#\1REDACTED#g'
}

CLEAN_SRC=$(mktemp)

sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' "$SRC" > "$CLEAN_SRC"

mapfile -t LINES < <(grep -E '^[[:space:]]*[A-Za-z0-9._-]+[[:space:]]+https?://' "$CLEAN_SRC" || true)

echo "Parsed sources: ${#LINES[@]}"

for line in "${LINES[@]}"; do
  [[ -z "$line" ]] && continue

  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%$'\r'}"

  name="${line%%[[:space:]]*}"
  raw_url="${line#*[[:space:]]}"
  raw_url="${raw_url#"${raw_url%%[![:space:]]*}"}"

  url="$(normalize_url "$raw_url")"
  display_url="$(safe_url "$url")"

  echo "source name: $name"

  http="—"
  links="0"
  total="0"
  proxy="0"
  check="—"
  file="—"

  src_file="/tmp/profile_factory/$name.src.txt"
  links_full="/tmp/profile_factory/$name.full.txt"
  links_file="/tmp/profile_factory/$name.links.txt"
  conv_log="/tmp/profile_factory/$name.convert.log"

  code=$(curl -skL -o "$src_file" -w '%{http_code}' --max-time 120 "$url" || echo 000)
  http="$code"

  if [[ "$code" == "200" && -s "$src_file" ]]; then

    sed -e 's/^[[:space:]]*//' -e 's/\r$//' "$src_file" \
      | grep -E '^(vmess|vless|trojan|ss|ssr)://' > "$links_full" || true

    if [[ "$MAX_LINKS" -gt 0 ]]; then
      head -n "$MAX_LINKS" "$links_full" > "$links_file"
    else
      cat "$links_full" > "$links_file"
    fi

    links=$(wc -l < "$links_file" | tr -d ' ')

    if [[ -s "$links_file" ]]; then

      if python3 scripts/share2singbox.py "$links_file" "$OUT/$name.json" --name "$name" > "$conv_log" 2>&1; then

        if sing-box check -c "$OUT/$name.json" > /dev/null 2>&1; then
          check="ok"
          read -r total proxy < <(python3 scripts/profile_info.py "$OUT/$name.json" || echo "0 0")
          file="$name.json"
        else
          echo "sing-box check with tun failed for $name, trying no-tun"

          if python3 scripts/share2singbox.py "$links_file" "$OUT/$name.json" --name "$name" --no-tun >> "$conv_log" 2>&1 \
              && sing-box check -c "$OUT/$name.json" > /dev/null 2>&1; then
            check="ok"
            read -r total proxy < <(python3 scripts/profile_info.py "$OUT/$name.json" || echo "0 0")
            file="$name.json"
          else
            check="invalid"

            echo "sing-box check failed for $name, first 2000 chars:"
            head -c 2000 "$OUT/$name.json" 2>/dev/null | redact_text || true
            echo

            echo "converter log:"
            tail -n 100 "$conv_log" 2>/dev/null | redact_text || true

            rm -f "$OUT/$name.json"
          fi
        fi

      else
        check="convert-fail"

        echo "share2singbox failed for $name:"
        tail -n 100 "$conv_log" 2>/dev/null | redact_text || true

        rm -f "$OUT/$name.json"
      fi

    else
      check="no-links"
    fi
  fi

  echo "| $name | $display_url | $http | $links | $total | $proxy | $check | $file |" >> "$STATUS"
done

if [[ "${#LINES[@]}" -eq 0 ]]; then
  echo "| — | — | — | — | — | — | no sources | — |" >> "$STATUS"
fi

rm -f "$CLEAN_SRC"
