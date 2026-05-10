#!/bin/bash
# Check FTP anonymous login
# Usage: check_ftp_anon.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== FTP Anonymous Check ==="
result=$(curl -s --max-time 10 "ftp://anonymous:anonymous@${TARGET_IP}/" 2>&1) || true
if echo "$result" | grep -qiE "drwx|total|index|ftp>"; then
    echo "FTP_ANON_OK"
    echo "$result" | head -20
else
    echo "FTP_ANON_FAILED"
fi
