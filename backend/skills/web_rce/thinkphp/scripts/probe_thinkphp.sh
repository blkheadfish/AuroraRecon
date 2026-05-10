#!/bin/bash
# ThinkPHP — Probe for ThinkPHP framework version via response headers and error pages
# Usage: probe_thinkphp.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Check response headers
curl -s -D - "$ENDPOINT" --max-time 10

echo "---SEPARATOR---"

# Trigger error page for version leak
curl -s "${ENDPOINT}/index.php?s=/xxx" --max-time 10
