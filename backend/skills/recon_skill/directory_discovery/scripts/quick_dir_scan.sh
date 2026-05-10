#!/bin/bash
# Feroxbuster quick recursive directory scan
# Usage: quick_dir_scan.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Feroxbuster Quick Scan ==="
feroxbuster -u "$BASE" -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 20 -d 2 --no-state -q --status-codes 200,301,302,403 \
    --timeout 8 2>/dev/null | head -80 || true
echo "DIR_SCAN_DONE"
