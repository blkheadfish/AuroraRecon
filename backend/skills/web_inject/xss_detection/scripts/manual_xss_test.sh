#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Manual XSS Test ==="
PAYLOAD='<script>alert(1)</script>'
ENCODED='%3Cscript%3Ealert(1)%3C%2Fscript%3E'

for param in q search query name id msg message comment text input; do
  result=$(curl -s "$BASE/?${param}=$ENCODED" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "$PAYLOAD"; then
    echo "XSS_REFLECTED:$param"
    exit 0
  fi
done

echo "XSS_NOT_FOUND"
