#!/bin/bash
# Check for sensitive file disclosure on web server
# Usage: check_sensitive_files.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Sensitive File Check ==="
for path in /.git/HEAD /.env /robots.txt /sitemap.xml /.htaccess \
            /wp-config.php.bak /config.php.bak /web.config \
            /backup.zip /backup.tar.gz /dump.sql; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$path" --max-time 5 2>/dev/null) || true
    if [ "$code" = "200" ]; then
        echo "SENSITIVE_FILE:$path (HTTP 200)"
        curl -s "$BASE$path" --max-time 5 2>/dev/null | head -5 || true
    fi
done
echo "SENSITIVE_CHECK_DONE"
