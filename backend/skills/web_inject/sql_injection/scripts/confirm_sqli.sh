#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Extract base URL without query string
BASE_URL=$(echo "$ENDPOINT" | sed 's/\?.*$//')

# Test common parameters for SQL injection
for param in id user_id page uid name q; do
  # Normal request
  normal=$(curl -s "${BASE_URL}?${param}=1" --max-time 8 -o /dev/null -w "%{http_code}:%{size_download}")
  # Single quote
  sqli=$(curl -s "${BASE_URL}?${param}=1'" --max-time 8 -o /dev/null -w "%{http_code}:%{size_download}")
  # Single quote with comment closure
  sqli2=$(curl -s "${BASE_URL}?${param}=1'--+-" --max-time 8 -o /dev/null -w "%{http_code}:%{size_download}")

  normal_code=$(echo "$normal" | cut -d: -f1)
  sqli_code=$(echo "$sqli" | cut -d: -f1)
  sqli2_code=$(echo "$sqli2" | cut -d: -f1)

  # Single quote error but closure recovers = injection point
  if [ "$normal_code" = "200" ] && [ "$sqli_code" = "500" ] && [ "$sqli2_code" = "200" ]; then
    echo "SQLI_PARAM:${param}:error_based"
  fi
  # Single quote causes content difference
  if [ "$normal_code" = "$sqli_code" ] && [ "$(echo "$normal" | cut -d: -f2)" != "$(echo "$sqli" | cut -d: -f2)" ]; then
    echo "SQLI_PARAM:${param}:content_diff"
  fi
done
