#!/bin/bash
# SMB Anonymous Share Access
# Usage: smb_anon_access.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== SMB Share Access ==="
smbmap -H "$TARGET_IP" -r 2>/dev/null | head -50
echo "---"
netexec smb "$TARGET_IP" -u '' -p '' --shares 2>/dev/null | head -20
echo "SMB_ACCESS_DONE"
