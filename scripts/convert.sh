#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-subscriptions.md}"
OUT="${2:-profiles}"

SC_API="http://127.0.0.1:25500"
LOCAL_RAW="http://127.0.0.1:18080"

MAX_LINKS="${MAX_LINKS:-300}"
MAX_LINKS="${MAX_LINKS//[^0-9]/}"
[[ -z "$MAX_LINKS" ]] && MAX_LINKS=300

SUBCONVERTER_EXTERNAL="${SUBCONVERTER_EXTERNAL:-0}"
TRY_ORIGINAL="${TRY_ORIGINAL:-1}"

mkdir -p "$OUT" /tmp/subsrc
[[ -f "$SRC" ]] || touch "$SRC"

STATUS="$OUT/STATUS.md"
SC_LOG="/tmp/subconverter.log"
HTTP_LOG="/tmp/local_http.log"

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

redact_text() {
  sed -E \
    -e 's#(token=)[^&[:space:]"]+#\1REDACTED#gI' \
    -e 's#(vmess://)[A-Za-z0-9+/=]+#\1REDACTED#g' \
    -e 's#(vless://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(trojan://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(ss://)[^@[:space:]]+@#\1REDACTED@#g' \
    -e 's#(ssr://)[A-Za-z0-9_+/=-]+#\1REDACTED#g'
}

SC_PID=""

if [[ "$SUBCONVERTER_EXTERNAL" != "1" ]]; then
  (
    cd subconverter
    exec ./subconverter > "$SC_LOG" 2>&1
  ) &
  SC_PID=$!
fi

python3 -m http.server 18080 --bind 127.0.0.1 --directory /tmp/subsrc > "$HTTP_LOG" 2>&1 &
HTTP_PID=$!

cleanup() {
  if [[ -n "$SC_PID" ]]; then
    kill "$SC_PID" 2>/dev/null || true
  fi

  kill "$HTTP_PID" 2>/dev/null || true
}

trap cleanup EXIT

for _ in $(seq 1 30); do
  if curl -s -o /dev/null "$SC_API/" && curl -s -o /dev/null "$LOCAL_RAW/"; then
    break
  fi
  sleep 1
done

if ! curl -s -o /dev/null "$SC_API/"; then
  echo "subconverter is not responding at $SC_API"

  if [[ -f "$SC_LOG" ]]; then
    echo "subconverter log:"
    tail -n 200 "$SC_LOG" | redact_text || true
  fi
fi

if ! curl -s -o /dev/null "$LOCAL_RAW/"; then
  echo "local http server is not responding at $LOCAL_RAW"

  if [[ -f "$HTTP_LOG" ]]; then
    echo "local http log:"
    tail -n 200 "$HTTP_LOG" || true
  fi
fi

CLEAN_SRC=$(mktemp)

# Убираем BOM и Windows CRLF
sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' "$SRC" > "$CLEAN_SRC"

mapfile -t LINES < <(grep -E '^[[:space:]]*[A-Za-z0-9._-]+[[:space:]]+https?://' "$CLEAN_SRC" || true)

echo "Parsed sources: ${#LINES[@]}"

for line in "${LINES[@]}"; do
  [[ -z "$line" ]] && continue

  # Убираем ведущие пробелы и возможный CR
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

  src_file="/tmp/subsrc/$name.src.txt"
  links_full="/tmp/subsrc/$name.full.txt"
  links_file="/tmp/subsrc/$name.txt"

  code=$(curl -skL -o "$src_file" -w '%{http_code}' --max-time 120 "$url" || echo 000)
  http="$code"

  if [[ "$code" == "200" && -s "$src_file" ]]; then

    # Нормализуем исходный файл и вытаскиваем share-ссылки.
    sed -e 's/^[[:space:]]*//' -e 's/\r$//' "$src_file" \
      | grep -E '^(vmess|vless|trojan|ss|ssr)://' > "$links_full" || true

    if [[ "$MAX_LINKS" -gt 0 ]]; then
      head -n "$MAX_LINKS" "$links_full" > "$links_file"
    else
      cat "$links_full" > "$links_file"
    fi

    links=$(wc -l < "$links_file" | tr -d ' ')

    attempts=()

    if [[ -s "$links_file" ]]; then
      echo "local input lines for $name: $links"

      echo "local input sample:"
      head -n 3 "$links_file" | redact_text || true

      plain_lines=$(curl -sfS "$LOCAL_RAW/$name.txt" 2>/dev/null | wc -l | tr -d ' ' || true)
      [[ -z "$plain_lines" ]] && plain_lines=0
      echo "local plain fetch lines: $plain_lines"

      attempts+=("$LOCAL_RAW/$name.txt")

      # Base64 fallback: многие V2Ray-подписки представляют собой base64-список ссылок.
      base64 < "$links_file" | tr -d '\n' > "/tmp/subsrc/$name.b64.txt"

      b64_bytes=$(curl -sfS "$LOCAL_RAW/$name.b64.txt" 2>/dev/null | wc -c | tr -d ' ' || true)
      [[ -z "$b64_bytes" ]] && b64_bytes=0
      echo "local base64 fetch bytes: $b64_bytes"

      attempts+=("$LOCAL_RAW/$name.b64.txt")

      if [[ "$TRY_ORIGINAL" == "1" ]]; then
        attempts+=("$url")
      fi
    else
      attempts+=("$url")
    fi

    sc_resp="/tmp/subsrc/$name.subconverter-response"
    converted=""

    for conv_url in "${attempts[@]}"; do
      case "$conv_url" in
        "$LOCAL_RAW/$name.txt")
          attempt_name="local-plain"
          ;;
        "$LOCAL_RAW/$name.b64.txt")
          attempt_name="local-base64"
          ;;
        *)
          attempt_name="original-url"
          ;;
      esac

      echo "trying subconverter target=singbox for $name via $attempt_name"

      sc_code=$(curl -sS -G "$SC_API/sub" \
          --data-urlencode "target=singbox" \
          --data-urlencode "url=$conv_url" \
          --max-time 300 \
          -o "$sc_resp" \
          -w '%{http_code}' || echo 000)

      echo "subconverter HTTP for $name ($attempt_name): $sc_code"

      if [[ "$sc_code" == "200" && -s "$sc_resp" ]]; then
        converted="$attempt_name"
        break
      else
        echo "subconverter response for $name ($attempt_name), first 2000 chars:"

        head -c 2000 "$sc_resp" 2>/dev/null | redact_text || true

        echo
      fi
    done

    if [[ -n "$converted" ]]; then
      mv "$sc_resp" "$OUT/$name.json"

      if sing-box check -c "$OUT/$name.json" > /dev/null 2>&1; then
        check="ok"
        read -r total proxy < <(python3 scripts/profile_info.py "$OUT/$name.json" || echo "0 0")
        file="$name.json"
      else
        check="invalid"
        echo "sing-box check failed for $name, first 2000 chars:"
        head -c 2000 "$OUT/$name.json" 2>/dev/null | redact_text || true
        echo
        rm -f "$OUT/$name.json"
      fi
    else
      check="convert-fail"
      rm -f "$OUT/$name.json" "$sc_resp"
    fi
  fi

  echo "| $name | $display_url | $http | $links | $total | $proxy | $check | $file |" >> "$STATUS"
done

if [[ "${#LINES[@]}" -eq 0 ]]; then
  echo "| — | — | — | — | — | — | no sources | — |" >> "$STATUS"
fi

rm -f "$CLEAN_SRC"
