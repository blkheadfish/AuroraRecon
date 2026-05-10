#!/bin/bash
# AJP 端口检查
# Usage: tomcat_ajp_check.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

timeout 5 bash -c "echo '' > /dev/tcp/$TARGET_IP/8009" 2>/dev/null && echo "AJP_OPEN" || echo "AJP_CLOSED"
