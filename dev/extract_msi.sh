#!/usr/bin/env bash

# extract_msi.sh
# Extract MSI using 7z, find *.core.dll, copy to current dir, cleanup after success

set -e

MSI="${1:-./MAX.msi}"
OUT="${2:-./extract}"

if [ ! -f "$MSI" ]; then
  echo "MSI not found: $MSI"
  exit 1
fi

cleanup() {
  if [ -d "$OUT" ]; then
    rm -rf "$OUT"
  fi
}

trap cleanup EXIT

echo "Target MSI: $MSI"
echo "Output dir: $OUT"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "Extracting MSI..."
7z x "$MSI" "-o$OUT" -y > /dev/null

echo ""
echo "Searching for *.core.dll and *.config.dll ..."
echo ""

DLLS=$(find "$OUT" -type f \( -name "*.core.dll" -o -name "*.config.dll" \))

if [ -n "$DLLS" ]; then
  echo "$DLLS"

  echo ""
  echo "Copying DLL files to current directory..."

  while IFS= read -r file; do
    cp -f "$file" .
  done <<< "$DLLS"

  echo ""
  echo "DLL files copied to current directory."
else
  echo "No matching DLL files found."
fi

echo ""
echo "Done."