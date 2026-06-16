#!/bin/bash
# SMB signing check and relay target generation
# Usage: smb_signing_check.sh <TARGET_IP>
# required_tools: netexec
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "{\"type\":\"status\",\"data\":{\"action\":\"smb_signing_check\",\"target\":\"$TARGET_IP\"}}"

SMB_OUTPUT=$(netexec smb "$TARGET_IP" 2>&1 || true)

if echo "$SMB_OUTPUT" | grep -q "signing:False"; then
  echo "$TARGET_IP" >> /tmp/relay_targets.txt
  echo "{\"type\":\"result\",\"data\":{\"target\":\"$TARGET_IP\",\"smb_signing\":false,\"relay_viable\":true,\"relay_list\":\"/tmp/relay_targets.txt\"}}"
elif echo "$SMB_OUTPUT" | grep -q "signing:True"; then
  echo "{\"type\":\"result\",\"data\":{\"target\":\"$TARGET_IP\",\"smb_signing\":true,\"relay_viable\":false}}"
else
  echo "{\"type\":\"result\",\"data\":{\"target\":\"$TARGET_IP\",\"smb_signing\":\"unknown\",\"relay_viable\":false,\"raw_output\":\"$(echo "$SMB_OUTPUT" | tr '\n' ' ' | sed 's/"/\\"/g')\"}}"
fi

if [ -f /tmp/relay_targets.txt ]; then
  TARGET_COUNT=$(wc -l < /tmp/relay_targets.txt)
  echo "{\"type\":\"summary\",\"data\":{\"relay_targets_total\":$TARGET_COUNT}}"
fi
