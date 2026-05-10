#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== URL Crawling ==="
katana -u "$BASE" -d 2 -silent -jc 2>/dev/null | grep "?" | head -30
echo "CRAWL_DONE"
