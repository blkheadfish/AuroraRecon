#!/bin/bash
# 探测 Nginx autoindex 目录遍历
# Usage: nginx_scan_autoindex.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

for path in / /files/ /uploads/ /static/ /images/ /data/ /backup/; do
  content=$(curl -s "${ENDPOINT}${path}" --max-time 5 2>/dev/null)
  if echo "$content" | grep -q "Index of\|Directory listing\|<title>Index"; then
    echo "AUTOINDEX:${path}"
  fi
done
