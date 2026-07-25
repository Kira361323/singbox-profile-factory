#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-subscriptions.md}"
OUT="${2:-profiles}"

SC_API="http://127.0.0.1:25500"
LOCAL_RAW="http://127.0.0.1:18080"

MAX_LINKS="${MAX_LINKS:-300}"
MAX_LINKS="${MAX_LINKS//[^0-9]/}"
[[ -z "$MAX_LINKS" ]] && MAX_LINKS=300

mkdir -p "$OUT" /tmp/subsrc

[[ -f "$SRC" ]] || touch "$SRC"

STATUS="$OUT/STATUS.md"

cat > "$STATUS" <<EOF
# Статус профилей

_Обновлено: $(date -u '+%Y-%m-%d %H:%M UTC')_

Мёртвые серверы не удаляются. Проверяется только доступность источника и валидность sing-box конфига.

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

# subconverter запускаем из его каталога, чтобы он видел свои конфиги.
(
  cd subconverter
  exec ./subconverter > /dev/null 2>&1
) &
SC_PID=$!

# Локальный HTTP-сервер для очищенных списков share-ссылок.
python3 -m http.server 18080 --bind 127.0.0.1 --directory /tmp/subsrc > /dev/null 2>&1 &
HTTP_PID=$!

trap 'kill "$SC_PID" "$HTTP_PID" 2>/dev/null || true' EXIT

# Ждём subconverter и локальный HTTP.
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "$SC_API/" && curl -s -o /dev/null "$LOCAL_RAW/"; then
    break
  fi
  sleep 1
done

set +x

mapfile -t LINES < <(grep -E '^[A-Za-z0-9._-]+[[:space:]]+https?://' "$SRC" || true)

for line in "${LINES[@]}"; do
  [[ -z "$line" ]] && continue

  name="${line%%[[:space:]]*}"
  raw_url="${line#*[[:space:]]}"
  url="$(normalize_url "$raw_url")"
  display_url="$(safe_url "$url")"

  http="—"
  links="0"
  total="0"
  proxy="0"
  check="—"
  file="—"

  src_file="/tmp/subsrc/$name.src"
  links_full="/tmp/subsrc/$name.links.full"
  links_file="/tmp/subsrc/$name.links"

  code=$(curl -skL -o "$src_file" -w '%{http_code}' --max-time 120 "$url" || echo 000)
  http="$code"

  if [[ "$code" == "200" && -s "$src_file" ]]; then

    # Вытаскиваем только share-ссылки, если они есть.
    grep -E '^(vmess|vless|trojan|ss|ssr)://' "$src_file" > "$links_full" || true

    if [[ "$MAX_LINKS" -gt 0 ]]; then
      head -n "$MAX_LINKS" "$links_full" > "$links_file"
    else
      cat "$links_full" > "$links_file"
    fi

    links=$(wc -l < "$links_file" | tr -d ' ')

    # Если share-ссылки найдены, скармливаем subconverter очищенный локальный файл.
    # Если нет, вероятно это Clash/base64/другая подписка — пробуем оригинальный URL.
    if [[ -s "$links_file" ]]; then
      conv_url="$LOCAL_RAW/$name.links"
    else
      conv_url="$url"
    fi

    if curl -fsSL -G "$SC_API/sub" \
        --data-urlencode 'target=singbox' \
        --data-urlencode "url=$conv_url" \
        --max-time 300 \
        -o "$OUT/$name.json"; then

      if sing-box check -c "$OUT/$name.json" > /dev/null 2>&1; then
        check="ok"
        read -r total proxy < <(python3 scripts/profile_info.py "$OUT/$name.json" || echo "0 0")
        file="$name.json"
      else
        check="invalid"
        rm -f "$OUT/$name.json"
      fi

    else
      check="convert-fail"
      rm -f "$OUT/$name.json"
    fi
  fi

  echo "| $name | $display_url | $http | $links | $total | $proxy | $check | $file |" >> "$STATUS"
done

if [[ "${#LINES[@]}" -eq 0 ]]; then
  echo "| — | — | — | — | — | — | no sources | — |" >> "$STATUS"
fi