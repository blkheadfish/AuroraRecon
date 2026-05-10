#!/bin/bash
# WordPress — Full enumeration via wpscan
# Usage: wpscan_enum.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== WPScan Enumeration ==="
wpscan --url "$BASE" --enumerate u,vp,vt --no-banner \
  --random-user-agent --format cli 2>/dev/null | head -150
echo "WPSCAN_DONE"
