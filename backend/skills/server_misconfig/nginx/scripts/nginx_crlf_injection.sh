#!/bin/bash
# Nginx CRLF 注入探测
# Usage: nginx_crlf_injection.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

# 测试 URL 路径中的 CRLF
response=$(curl -s -D - "${ENDPOINT}/%0d%0aX-Injected:true" --max-time 10)
if echo "$response" | grep -qi "X-Injected"; then
  echo "CRLF_PATH_INJECTION"
fi
# 测试参数中的 CRLF
response=$(curl -s -D - "${ENDPOINT}/?redirect=http://example.com%0d%0aX-Injected:true" --max-time 10)
if echo "$response" | grep -qi "X-Injected"; then
  echo "CRLF_PARAM_INJECTION"
fi
