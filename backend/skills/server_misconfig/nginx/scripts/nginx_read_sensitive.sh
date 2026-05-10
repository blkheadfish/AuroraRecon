#!/bin/bash
# 读取 Nginx 敏感文件内容
# Usage: nginx_read_sensitive.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

for path in /nginx.conf /.env /.git/HEAD /server-status /actuator/env; do
  content=$(curl -s "${ENDPOINT}${path}" --max-time 5 2>/dev/null)
  if [ ${#content} -gt 10 ] && ! echo "$content" | grep -q "404\|Not Found"; then
    echo "=== ${path} ==="
    echo "$content" | head -30
    echo ""
  fi
done
