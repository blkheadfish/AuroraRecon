#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== DalFox XSS Scan ==="
echo "$BASE" | dalfox pipe --silence --only-poc 2>/dev/null | head -20
echo "DALFOX_DONE"
