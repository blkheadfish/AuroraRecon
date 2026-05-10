#!/bin/bash
# PHP-FPM — Detect %0a path injection anomaly (CVE-2019-11043)
# Usage: check_0a_anomaly.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

echo "=== 基线请求 ==="
baseline=$(curl -s -w "\n%{http_code}" "${ENDPOINT}/index.php" --max-time 8 2>/dev/null)
baseline_code=$(echo "$baseline" | tail -1)
baseline_body=$(echo "$baseline" | sed '$d')
baseline_len=${#baseline_body}
echo "BASELINE: code=$baseline_code len=$baseline_len"

echo "=== %0a 注入请求 ==="
anomaly=$(curl -s -w "\n%{http_code}" "${ENDPOINT}/index.php/%0a" --max-time 8 2>/dev/null)
anomaly_code=$(echo "$anomaly" | tail -1)
anomaly_body=$(echo "$anomaly" | sed '$d')
anomaly_len=${#anomaly_body}
echo "ANOMALY: code=$anomaly_code len=$anomaly_len"
echo "ANOMALY_BODY: $anomaly_body"

# Judgment 1: 502/500 status code
if [ "$anomaly_code" = "502" ] || [ "$anomaly_code" = "500" ]; then
  echo "FPM_VULNERABLE_CONFIRMED"
  exit 0
fi

# Judgment 2: FPM error message in body
anomaly_lower=$(echo "$anomaly_body" | tr '[:upper:]' '[:lower:]')
if echo "$anomaly_lower" | grep -qE "file not found|no input file specified|primary script unknown"; then
  echo "FPM_VULNERABLE_CONFIRMED"
  exit 0
fi

# Judgment 3: Status code difference
if [ "$anomaly_code" != "$baseline_code" ] && [ "$anomaly_code" != "404" ] && [ -n "$anomaly_code" ] && [ "$anomaly_code" != "000" ]; then
  echo "FPM_VULNERABLE_LIKELY"
  exit 0
fi

# Judgment 4: Body length drastic change
if [ "$baseline_len" -gt 100 ] && [ "$anomaly_len" -lt 50 ]; then
  echo "FPM_VULNERABLE_LIKELY"
  exit 0
fi

echo "FPM_NOT_VULNERABLE"
