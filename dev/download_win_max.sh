#!/usr/bin/env bash
set -euo pipefail

config=$(curl -s 'https://max.ru/_api_/config' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Referer: https://download.max.ru/' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://download.max.ru')

url=$(echo "$config" | grep -o '"windowsDesktop"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -o '"https\?://[^"]*"' | tr -d '"')
if [ -z "$url" ]; then echo "Key 'windowsDesktop' not found"; exit 1; fi

echo "Downloading: $url"
curl -L -o MAX.msi "$url" \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
echo "Saved to MAX.msi"
