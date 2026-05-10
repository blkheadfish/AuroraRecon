#!/bin/bash
# Detect and crawl Index of directory listings
# Usage: crawl_directory_listings.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1}"
BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')

echo "=== Directory Listing Crawl ==="
for dir in / /files/ /uploads/ /backup/ /data/ /download/ /public/ /static/ /images/ /docs/; do
    BODY=$(curl -sS -L --max-time 8 "$BASE$dir" 2>/dev/null) || continue
    if echo "$BODY" | grep -qi "Index of\|Parent Directory\|<title>Index of"; then
        echo "DIRLIST_FOUND:$dir"
        echo "$BODY" | grep -oP 'href="\K[^"]+' | head -30 | while read -r link; do
            case "$link" in
                ../*|?*|#*|javascript:*|mailto:*) continue ;;
            esac
            echo "  ENTRY:$dir$link"
        done
        for sub in $(echo "$BODY" | grep -oP 'href="\K[^"]+/' | head -10); do
            case "$sub" in
                ../*) continue ;;
            esac
            SUBBODY=$(curl -sS -L --max-time 5 "$BASE$dir$sub" 2>/dev/null) || continue
            if echo "$SUBBODY" | grep -qi "Index of\|Parent Directory"; then
                echo "  SUBDIR:$dir$sub"
                echo "$SUBBODY" | grep -oP 'href="\K[^"]+' | head -20 | while read -r sublink; do
                    case "$sublink" in
                        ../*|?*|#*) continue ;;
                    esac
                    echo "    SUBENTRY:$dir$sub$sublink"
                done
            fi
        done
    fi
done
echo "DIRLIST_CRAWL_DONE"
