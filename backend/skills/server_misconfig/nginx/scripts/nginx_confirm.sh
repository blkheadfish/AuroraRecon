#!/bin/bash
# Nginx 版本确认
# Usage: nginx_confirm.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

curl -s -D - "$ENDPOINT" -o /dev/null --max-time 10
