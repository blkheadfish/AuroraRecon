#!/bin/bash
# Check whether known credentials are available for replay
# Usage: detect_known_creds.sh <known_users_b64> <known_passwords_b64>
set -euo pipefail

KNOWN_USERS_B64="${1:-}"
KNOWN_PASSES_B64="${2:-}"

echo "=== Credential Replay Probe ==="
USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""
echo "users:"
printf '%s\n' "$USERS" | head -10
echo "---"
echo "password_count:"
printf '%s\n' "$PASSES" | sed '/^$/d' | wc -l
echo "PROBE_DONE"
