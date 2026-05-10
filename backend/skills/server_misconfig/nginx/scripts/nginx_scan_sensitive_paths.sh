#!/bin/bash
# 探测 Nginx 敏感路径
# Usage: nginx_scan_sensitive_paths.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

for path in /nginx.conf /.nginx.conf /nginx_status /server-status \
            /status /basic_status /.git/HEAD /.env /.DS_Store \
            /WEB-INF/web.xml /actuator/env; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${ENDPOINT}${path}" --max-time 5 2>/dev/null)
  if [ "$code" = "200" ]; then
    echo "SENSITIVE_PATH:${path}:${code}"
  fi
done
