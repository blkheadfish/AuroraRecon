#!/bin/bash
# Detect authentication services on target
# Usage: detect_services.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== Service Detection ==="
nmap -sT -sV -p 21,22,2222,3389,80,443,8080 --open "$TARGET_IP" 2>/dev/null | grep "open" || true
echo "PROBE_DONE"
