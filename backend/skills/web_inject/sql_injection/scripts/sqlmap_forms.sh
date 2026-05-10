#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

sqlmap -u "$ENDPOINT" \
  --forms --batch --random-agent \
  --dbs \
  --threads=4 \
  --level=3 --risk=2 \
  2>&1 | tail -50
