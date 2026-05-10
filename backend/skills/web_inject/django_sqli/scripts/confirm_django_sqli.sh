#!/bin/bash
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Test 'date' parameter for SQL injection
resp=$(curl -s "${ENDPOINT}/?date=year%27" --max-time 15 2>/dev/null)
if echo "$resp" | grep -qi "ProgrammingError\|OperationalError\|syntax error\|unterminated"; then
  echo "SQLI_CONFIRMED_date"
fi

# Test 'kind' parameter for SQL injection
resp2=$(curl -s "${ENDPOINT}/?kind=year%27" --max-time 15 2>/dev/null)
if echo "$resp2" | grep -qi "ProgrammingError\|OperationalError\|syntax error\|unterminated"; then
  echo "SQLI_CONFIRMED_kind"
fi
