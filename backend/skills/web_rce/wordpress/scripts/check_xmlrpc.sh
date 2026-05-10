#!/bin/bash
# WordPress — Check XML-RPC availability
# Usage: check_xmlrpc.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/xmlrpc.php" --max-time 8 2>/dev/null)
echo "XMLRPC_STATUS:$code"
if [ "$code" = "200" ] || [ "$code" = "405" ]; then
  echo "XMLRPC_AVAILABLE"
fi
