#!/bin/bash
# SMB Full Enumeration via enum4linux-ng
# Usage: smb_enum.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== SMB Enumeration ==="
enum4linux-ng -A "$TARGET_IP" 2>/dev/null | head -100
echo "SMB_ENUM_DONE"
