#!/bin/bash
# SMB Share Permissions via smbmap
# Usage: smbmap_check.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== SMBMap ==="
smbmap -H "$TARGET_IP" 2>/dev/null
echo "SMBMAP_DONE"
