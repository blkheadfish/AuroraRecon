#!/bin/bash
# required_tools: john
# John the Ripper auto-detect hash cracking
# Usage: john_crack.sh <HASHES_FILE>
set -euo pipefail

HASHES_FILE="${1:-/tmp/hashes.txt}"

if [ ! -f "$HASHES_FILE" ]; then
    echo "{\"event\":\"crack_error\",\"payload\":{\"error\":\"file_not_found\",\"file\":\"$HASHES_FILE\"}}"
    echo "[!] Hashes file not found: $HASHES_FILE" >&2
    exit 1
fi

echo "[*] John the Ripper cracking: $HASHES_FILE" >&2

# ── Count hashes ──
HASH_COUNT=$(wc -l < "$HASHES_FILE" | tr -d ' ')
echo "{\"event\":\"crack_start\",\"payload\":{\"tool\":\"john\",\"hash_count\":$HASH_COUNT,\"hash_file\":\"$HASHES_FILE\"}}"

# ── Wordlist selection ──
WORDLIST="${JOHN_WORDLIST:-/usr/share/wordlists/rockyou.txt}"

if [ ! -f "$WORDLIST" ]; then
    # Try common fallback locations
    for wl in /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
              /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt \
              /usr/share/john/password.lst; do
        if [ -f "$wl" ]; then
            WORDLIST="$wl"
            break
        fi
    done

    if [ ! -f "$WORDLIST" ]; then
        echo "{\"event\":\"crack_error\",\"payload\":{\"error\":\"wordlist_not_found\",\"tool\":\"john\",\"expected\":\"/usr/share/wordlists/rockyou.txt\"}}"
        echo "[!] No wordlist found — try: apt install wordlists" >&2
        exit 1
    fi
fi

echo "[*] Using wordlist: $WORDLIST" >&2

# ── Auto-detect hash type ──
echo "[*] Auto-detecting hash type..." >&2
HASH_TYPE=""
DETECT_OUT=$(john --list=formats 2>/dev/null | head -50 || echo "")

# Try to identify hash via a quick test run
RAW_OUT=$(john "$HASHES_FILE" --wordlist="$WORDLIST" --pot=/tmp/john_pot_$$.pot 2>&1 || echo "")
echo "$RAW_OUT" >&2

# Extract detected format from john output
DETECTED_FORMAT=$(echo "$RAW_OUT" | grep -oP 'format\s*=\s*\K\S+' | head -1 || echo "")
if [ -n "$DETECTED_FORMAT" ]; then
    HASH_TYPE="$DETECTED_FORMAT"
    echo "{\"event\":\"crack_format_detected\",\"payload\":{\"tool\":\"john\",\"hash_type\":\"$HASH_TYPE\"}}"
else
    echo "{\"event\":\"crack_format_detected\",\"payload\":{\"tool\":\"john\",\"hash_type\":\"auto\",\"note\":\"john will auto-detect\"}}"
fi

# ── Run John (auto-detect + rockyou) ──
echo "[*] Launching John with wordlist..." >&2

JOHN_OUT=$(john "$HASHES_FILE" --wordlist="$WORDLIST" --pot=/tmp/john_pot_$$.pot --format="${HASH_TYPE:-auto}" 2>&1 || echo "$JOHN_OUT")

# ── Check results ──
CRACKED=$0
JOHN_SHOW=$(john --show "$HASHES_FILE" --pot=/tmp/john_pot_$$.pot 2>/dev/null || echo "")

if [ -n "$JOHN_SHOW" ] && ! echo "$JOHN_SHOW" | grep -qE "^0 password"; then
    CRACKED_COUNT=$(echo "$JOHN_SHOW" | grep -cE ":" 2>/dev/null || echo "0")

    echo "[+] John cracked $CRACKED_COUNT hashes" >&2
    echo "{\"event\":\"crack_success\",\"payload\":{\"tool\":\"john\",\"cracked_count\":$CRACKED_COUNT,\"hashes_total\":$HASH_COUNT}}"

    # Output each cracked hash
    while IFS= read -r line; do
        if [ -n "$line" ] && echo "$line" | grep -qE ":"; then
            USER=$(echo "$line" | cut -d: -f1 | sed 's/"/\\"/g')
            PASS=$(echo "$line" | cut -d: -f2 | sed 's/"/\\"/g')
            [ -n "$USER" ] && [ -n "$PASS" ] && \
                echo "{\"event\":\"credential_found\",\"payload\":{\"tool\":\"john\",\"username\":\"$USER\",\"password\":\"$PASS\",\"hash_type\":\"$HASH_TYPE\"}}"
        fi
    done <<< "$JOHN_SHOW"
else
    echo "[*] John found no passwords with basic wordlist" >&2
    echo "{\"event\":\"crack_fail\",\"payload\":{\"tool\":\"john\",\"cracked_count\":0,\"hashes_total\":$HASH_COUNT}}"

    # ── Attempt rules attack ──
    echo "[*] Running John with --rules..." >&2
    JOHN_RULES=$(john "$HASHES_FILE" --wordlist="$WORDLIST" --rules --pot=/tmp/john_pot_rules_$$.pot --format="${HASH_TYPE:-auto}" 2>&1 || echo "")
    echo "$JOHN_RULES" >&2

    RULES_SHOW=$(john --show "$HASHES_FILE" --pot=/tmp/john_pot_rules_$$.pot 2>/dev/null || echo "")
    if [ -n "$RULES_SHOW" ] && ! echo "$RULES_SHOW" | grep -qE "^0 password"; then
        CRACKED_COUNT=$(echo "$RULES_SHOW" | grep -cE ":" 2>/dev/null || echo "0")
        echo "[+] John rules cracked $CRACKED_COUNT hashes" >&2
        echo "{\"event\":\"crack_success\",\"payload\":{\"tool\":\"john\",\"mode\":\"rules\",\"cracked_count\":$CRACKED_COUNT,\"hashes_total\":$HASH_COUNT}}"

        while IFS= read -r line; do
            if [ -n "$line" ] && echo "$line" | grep -qE ":"; then
                USER=$(echo "$line" | cut -d: -f1 | sed 's/"/\\"/g')
                PASS=$(echo "$line" | cut -d: -f2 | sed 's/"/\\"/g')
                [ -n "$USER" ] && [ -n "$PASS" ] && \
                    echo "{\"event\":\"credential_found\",\"payload\":{\"tool\":\"john\",\"mode\":\"rules\",\"username\":\"$USER\",\"password\":\"$PASS\",\"hash_type\":\"$HASH_TYPE\"}}"
            fi
        done <<< "$RULES_SHOW"
    fi

    rm -f /tmp/john_pot_rules_$$.pot
fi

# ── Cleanup ──
rm -f /tmp/john_pot_$$.pot

# Report final cracked count
FINAL_SHOW=$(john --show "$HASHES_FILE" 2>/dev/null || echo "")
FINAL_CRACKED=$(echo "$FINAL_SHOW" | grep -cE ":" 2>/dev/null || echo "0")

if [ "$FINAL_CRACKED" -gt 0 ]; then
    echo "{\"event\":\"crack_summary\",\"payload\":{\"tool\":\"john\",\"total_cracked\":$FINAL_CRACKED,\"total_hashes\":$HASH_COUNT}}"
    exit 0
else
    echo "{\"event\":\"crack_summary\",\"payload\":{\"tool\":\"john\",\"total_cracked\":0,\"total_hashes\":$HASH_COUNT,\"recommendation\":\"Try hashcat with GPU acceleration or a larger wordlist\"}}"
    exit 1
fi
