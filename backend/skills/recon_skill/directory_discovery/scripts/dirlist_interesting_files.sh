#!/bin/bash
# Download interesting files discovered in directory listings
# Usage: dirlist_interesting_files.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Downloading Interesting Files ==="
for ext in sql db sqlite bak backup conf env log key pem; do
    for dir in / /files/ /uploads/ /backup/ /data/; do
        BODY=$(curl -sS -L --max-time 5 "$BASE$dir" 2>/dev/null) || continue
        FILES=$(echo "$BODY" | grep -oP "href=\"\K[^\"]+\.$ext" | head -3) || true
        for f in $FILES; do
            echo "--- $dir$f ---"
            curl -sS --max-time 10 "$BASE$dir$f" 2>/dev/null | head -50 || true
            echo ""
        done
    done
done
echo "INTERESTING_DOWNLOAD_DONE"
