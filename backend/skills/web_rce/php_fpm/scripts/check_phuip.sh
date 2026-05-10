#!/bin/bash
# PHP-FPM — Check if phuip-fpizdam tool is available
# Usage: check_phuip.sh
set -euo pipefail

if command -v phuip-fpizdam >/dev/null 2>&1; then
  echo "PHUIP_AVAILABLE"
elif [ -x /opt/phuip-fpizdam ]; then
  echo "PHUIP_AVAILABLE"
else
  echo "PHUIP_MISSING"
fi
