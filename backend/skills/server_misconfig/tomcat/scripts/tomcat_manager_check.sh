#!/bin/bash
# Tomcat Manager 端点探测
# Usage: tomcat_manager_check.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
code=$(curl -s "$BASE/manager/html" -o /dev/null -w "%{http_code}" --max-time 10 2>/dev/null)
echo "MANAGER_STATUS:$code"
if [ "$code" = "401" ] || [ "$code" = "403" ]; then echo "MANAGER_EXISTS"; fi
