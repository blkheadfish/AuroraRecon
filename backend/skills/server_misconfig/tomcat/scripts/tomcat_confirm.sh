#!/bin/bash
# Tomcat 版本确认
# Usage: tomcat_confirm.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
resp=$(curl -s "$BASE/" --max-time 10 2>/dev/null)
echo "$resp" | head -5
if echo "$resp" | grep -qi "Apache Tomcat\|tomcat"; then echo "TOMCAT_CONFIRMED"; fi
