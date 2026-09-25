#!/usr/bin/env bash

# extract_msi.sh
# Extracts MSI via 7z, locates *.core.dll and *.config.dll,
# copies them to the destination directory (defaults to repository root),
# and cleans up the temporary extraction directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MSI=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--msi)
      MSI="$2"
      shift 2
      ;;
    -o|--out|--dest|-d)
      OUT="$2"
      shift 2
      ;;
    *)
      if [ -z "$MSI" ]; then
        MSI="$1"
        shift
      elif [ -z "$OUT" ]; then
        OUT="$1"
        shift
      else
        echo "Unknown argument: $1" >&2
        exit 1
      fi
      ;;
  esac
done

if [ -z "$MSI" ]; then
  MSI="$REPO_ROOT/MAX.msi"
fi

if [ -z "$OUT" ]; then
  OUT="$REPO_ROOT"
fi

if [ ! -f "$MSI" ]; then
  echo "MSI not found: $MSI" >&2
  exit 1
fi

if command -v 7z &>/dev/null; then
  SEVEN_ZIP="7z"
elif command -v 7za &>/dev/null; then
  SEVEN_ZIP="7za"
elif command -v 7z.exe &>/dev/null; then
  SEVEN_ZIP="7z.exe"
else
  echo "Error: 7-Zip executable (7z, 7za, or 7z.exe) not found in PATH" >&2
  exit 1
fi

mkdir -p "$OUT"

TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'max_msi_XXXXXX')

cleanup() {
  if [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
    echo ""
    echo "Temporary extraction folder removed."
  fi
}
trap cleanup EXIT

echo "Target MSI: $MSI"
echo "Destination: $OUT"
echo "Extracting MSI to temporary directory..."

"$SEVEN_ZIP" x "$MSI" "-o$TEMP_DIR" -y > /dev/null

echo ""
echo "Searching for *.core.dll and *.config.dll ..."
echo ""

DLLS=$(find "$TEMP_DIR" -type f \( -name "*.core.dll" -o -name "*.config.dll" \))

if [ -n "$DLLS" ]; then
  echo "$DLLS"

  echo ""
  echo "Copying DLL files to $OUT..."

  while IFS= read -r file; do
    [ -n "$file" ] && cp -f "$file" "$OUT/"
  done <<< "$DLLS"

  echo ""
  echo "DLL files copied to $OUT."
else
  echo "No matching DLL files found."
fi

echo ""
echo "Done."
