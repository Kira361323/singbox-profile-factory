#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-profiles}"
PRUNE_INVALID="${PRUNE_INVALID:-1}"

mkdir -p "$OUT" /tmp/profile_factory

STATUS="$OUT/STATUS.md"
SOURCES_TSV="/tmp/profile_factory/sources.tsv"

cat > "$STATUS" <<EOF
# Статус профилей

_Обновлено: $(date -u '+%Y-%m-%d %H:%M UTC')_

Мёртвые серверы не удаляются.
Проверяется доступность источника и валидность sing-box конфига.

| Профиль | Источник | HTTP | Ссылок | Outbounds | Proxy | Engine | sing-box check | Файл |
|---|---|---:|---:|---:|---:|---|---|---|
EOF

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

if ! command -v sing-box >/dev/null 2>&1; then
  echo "sing-box is required" >&2
  exit 1
fi

python3 scripts/sources.py > "$SOURCES_TSV" || true

mapfile -t SOURCE_LINES < "$SOURCES_TSV"

echo "Parsed sources: ${#SOURCE_LINES[@]}"

node_available=0
if command -v node >/dev/null 2>&1; then
  node_available=1
fi

build_and_check() {
  local input="$1"
  local output="$2"
  local template="$3"
  local outbounds_json="${4:-}"

  local args=(
    scripts/share2singbox.py
    "$input"
    "$output"
    --template "$template"
    --max-outbounds "$max_links"
  )

  if [[ "${PRUNE_INVALID:-1}" == "1" ]]; then
    args+=(--prune)
  fi

  if [[ -n "$outbounds_json" ]]; then
    args+=(--outbounds-json "$outbounds_json")
  fi

  echo "python converter args: ${args[*]}" >> "$conv_log"

  if python3 "${args[@]}" >> "$conv_log" 2>&1; then
    echo "sing-box check with tun:" >> "$conv_log"

    if sing-box check -c "$output" >> "$conv_log" 2>&1; then
      return 0
    fi

    echo "sing-box check with tun failed, trying no-tun" >> "$conv_log"

    args+=(--no-tun)

    if python3 "${args[@]}" >> "$conv_log" 2>&1; then
      echo "sing-box check without tun:" >> "$conv_log"

      if sing-box check -c "$output" >> "$conv_log" 2>&1; then
        return 0
      fi
    fi
  else
    echo "python converter failed" >> "$conv_log"
  fi

  return 1
}

for line in "${SOURCE_LINES[@]}"; do
  [[ -z "$line" ]] && continue

  IFS=$'\t' read -r name url max_links ua template <<< "$line"

  [[ -z "$name" || -z "$url" ]] && continue

  max_links="${max_links//[^0-9]/}"
  [[ -z "$max_links" ]] && max_links=0

  [[ -z "$ua" ]] && ua="clash.meta"
  [[ -z "$template" ]] && template="templates/base.json"

  echo "source name: $name"

  http="—"
  links="0"
  total="0"
  proxy="0"
  engine="—"
  check="—"
  file="—"

  src_file="/tmp/profile_factory/$name.src.txt"
  links_full="/tmp/profile_factory/$name.full.txt"
  links_file="/tmp/profile_factory/$name.links.txt"
  node_out="/tmp/profile_factory/$name.node_outbounds.json"
  conv_log="/tmp/profile_factory/$name.convert.log"

  : > "$conv_log"

  code=$(curl -skL -A "$ua" -o "$src_file" -w '%{http_code}' --max-time 120 "$url" || echo 000)
  http="$code"

  if [[ "$code" == "200" && -s "$src_file" ]]; then

    sed -e 's/^[[:space:]]*//' -e 's/\r$//' "$src_file" \
      | grep -E '^(vmess|vless|trojan|ss|ssr)://' > "$links_full" || true

    if [[ "$max_links" -gt 0 ]]; then
      head -n "$max_links" "$links_full" > "$links_file"
    else
      cat "$links_full" > "$links_file"
    fi

    links=$(wc -l < "$links_file" | tr -d ' ')

    if [[ -s "$links_file" ]]; then
      input_file="$links_file"
    else
      input_file="$src_file"
    fi

    rm -f "$OUT/$name.json"

    generated=0

    if build_and_check "$input_file" "$OUT/$name.json" "$template"; then
      generated=1
      engine="python"
    fi

    if [[ "$generated" -eq 0 && "$node_available" -eq 1 && ! -s "$OUT/$name.json" ]]; then
      echo "trying optional Node converter" >> "$conv_log"

      if node scripts/node_convert.mjs "$src_file" "$node_out" >> "$conv_log" 2>&1; then
        if build_and_check "/dev/null" "$OUT/$name.json" "$template" "$node_out"; then
          generated=1
          engine="node"
        fi
      fi
    fi

    if [[ "$generated" -eq 1 ]]; then
      check="ok"
      read -r total proxy < <(python3 scripts/profile_info.py "$OUT/$name.json" || echo "0 0")
      file="$name.json"
    else
      check="convert-fail"

      echo "conversion failed for $name" >&2

      echo "converter log:" >&2
      tail -n 300 "$conv_log" 2>/dev/null | redact_text || true

      if [[ -f "$OUT/$name.json" ]]; then
        echo "generated JSON head:" >&2
        head -c 3000 "$OUT/$name.json" 2>/dev/null | redact_text || true
        rm -f "$OUT/$name.json"
      fi
    fi

  fi

  display_url=$(printf '%s' "$url" | sed -E 's#(https?://[^/]+).*#\1/#')

  echo "| $name | $display_url | $http | $links | $total | $proxy | $engine | $check | $file |" >> "$STATUS"
done

if [[ "${#SOURCE_LINES[@]}" -eq 0 ]]; then
  echo "| — | — | — | — | — | — | — | no sources | — |" >> "$STATUS"
fi
