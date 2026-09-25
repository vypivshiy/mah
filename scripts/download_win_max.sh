#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output|-Out)
      OUT="$2"
      shift 2
      ;;
    *)
      if [ -z "$OUT" ]; then
        OUT="$1"
        shift
      else
        echo "Unknown argument: $1" >&2
        exit 1
      fi
      ;;
  esac
done

if [ -z "$OUT" ]; then
  OUT="$REPO_ROOT/MAX.msi"
elif [ -d "$OUT" ] || [[ "$OUT" == */ ]]; then
  OUT="${OUT%/}/MAX.msi"
fi

mkdir -p "$(dirname "$OUT")"

config=$(curl -s 'https://max.ru/_api_/config' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Referer: https://download.max.ru/' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://download.max.ru')

url=$(echo "$config" | grep -o '"windowsDesktop"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -o '"https\?://[^"]*"' | tr -d '"')
if [ -z "$url" ]; then echo "Key 'windowsDesktop' not found" >&2; exit 1; fi

echo "Downloading: $url"
curl -L -o "$OUT" "$url" \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0'
echo "Saved to $OUT"
