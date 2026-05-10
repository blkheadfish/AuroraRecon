#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Check Django framework via response headers
resp_headers=$(curl -s -D - "${ENDPOINT}/" --max-time 10 2>/dev/null)
echo "$resp_headers"

# Check Django debug traceback on nonexistent page
resp_debug=$(curl -s "${ENDPOINT}/nonexistent_xxx" --max-time 10 2>/dev/null)
echo "$resp_debug"

# Check both responses for Django indicators
if echo "$resp_headers" | grep -qi "django\|csrftoken\|csrfmiddlewaretoken\|Django"; then
  echo "DJANGO_CONFIRMED"
elif echo "$resp_debug" | grep -qi "django\|Django\|Traceback"; then
  echo "DJANGO_CONFIRMED"
fi
