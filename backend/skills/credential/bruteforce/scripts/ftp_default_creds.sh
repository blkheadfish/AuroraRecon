#!/bin/bash
# FTP default credentials test with hydra
# Usage: ftp_default_creds.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== FTP Credential Test ==="
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
      -t 4 -f ftp://"$TARGET_IP" 2>&1 || true
