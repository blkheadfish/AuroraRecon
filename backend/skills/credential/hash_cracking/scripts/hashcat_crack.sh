#!/bin/bash
# required_tools: hashcat
# hashcat auto mode detection and GPU-accelerated cracking
# Usage: hashcat_crack.sh <HASHES_FILE>
set -euo pipefail

HASHES_FILE="${1:-/tmp/hashes.txt}"

if [ ! -f "$HASHES_FILE" ]; then
    echo "{\"event\":\"crack_error\",\"payload\":{\"error\":\"file_not_found\",\"file\":\"$HASHES_FILE\"}}"
    echo "[!] Hashes file not found: $HASHES_FILE" >&2
    exit 1
fi

echo "[*] hashcat cracking: $HASHES_FILE" >&2

# ── Count hashes ──
HASH_COUNT=$(wc -l < "$HASHES_FILE" | tr -d ' ')
echo "{\"event\":\"crack_start\",\"payload\":{\"tool\":\"hashcat\",\"hash_count\":$HASH_COUNT,\"hash_file\":\"$HASHES_FILE\"}}"

# ── Wordlist selection ──
WORDLIST="${HASHCAT_WORDLIST:-/usr/share/wordlists/rockyou.txt}"

if [ ! -f "$WORDLIST" ]; then
    for wl in /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
              /usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt \
              /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt; do
        if [ -f "$wl" ]; then
            WORDLIST="$wl"
            break
        fi
    done

    if [ ! -f "$WORDLIST" ]; then
        echo "{\"event\":\"crack_error\",\"payload\":{\"error\":\"wordlist_not_found\",\"tool\":\"hashcat\",\"expected\":\"/usr/share/wordlists/rockyou.txt\"}}"
        echo "[!] No wordlist found" >&2
        exit 1
    fi
fi

echo "[*] Using wordlist: $WORDLIST" >&2

# ── Auto-detect hash mode ──
echo "[*] Auto-detecting hash mode..." >&2

HASH_MODE=""
SAMPLE=$(head -1 "$HASHES_FILE" | tr -d '\n\r')

# Signature-based auto-detection
if echo "$SAMPLE" | grep -qE '^\$krb5tgs\$23\$'; then
    HASH_MODE=13100
    HASH_NAME="Kerberos 5 TGS-REP etype 23"
elif echo "$SAMPLE" | grep -qE '^\$krb5asrep\$23\$'; then
    HASH_MODE=18200
    HASH_NAME="Kerberos 5 AS-REP etype 23"
elif echo "$SAMPLE" | grep -qE '^\$6\$'; then
    HASH_MODE=1800
    HASH_NAME="SHA-512 Crypt"
elif echo "$SAMPLE" | grep -qE '^\$5\$'; then
    HASH_MODE=7400
    HASH_NAME="SHA-256 Crypt"
elif echo "$SAMPLE" | grep -qE '^\$2[abxy]\$'; then
    HASH_MODE=3200
    HASH_NAME="bcrypt"
elif echo "$SAMPLE" | grep -qE '^\$1\$'; then
    HASH_MODE=500
    HASH_NAME="MD5 Crypt"
elif echo "$SAMPLE" | grep -qE '::.*:[a-f0-9]{32}:[a-f0-9]{32,}'; then
    # NetNTLMv1: USER::DOMAIN:challenge:HMAC:response
    if echo "$SAMPLE" | grep -qE '::.*:[a-f0-9]{16}:[a-f0-9]{48}:'; then
        HASH_MODE=5500
        HASH_NAME="NetNTLMv1"
    else
        HASH_MODE=5600
        HASH_NAME="NetNTLMv2"
    fi
elif echo "$SAMPLE" | grep -qPE '^[a-f0-9]{32}$'; then
    HASH_MODE=0
    HASH_NAME="MD5 (raw)"
elif echo "$SAMPLE" | grep -qE '^[a-f0-9]{32}:[a-f0-9]{32}$'; then
    # LM:NTLM or just two hex strings
    LM=$(echo "$SAMPLE" | cut -d: -f1)
    NTLM=$(echo "$SAMPLE" | cut -d: -f2)
    if [ "$LM" = "aad3b435b51404eeaad3b435b51404ee" ]; then
        # Empty LM hash → pure NTLM
        HASH_MODE=1000
        HASH_NAME="NTLM (empty LM)"
    elif echo "$NTLM" | grep -qPE '^[a-f0-9]{32}$'; then
        HASH_MODE=1000
        HASH_NAME="NTLM"
    fi
elif echo "$SAMPLE" | grep -qPE '^[a-f0-9]{64}$'; then
    HASH_MODE=1400
    HASH_NAME="SHA-256 (raw)"
elif echo "$SAMPLE" | grep -qPE '^[a-f0-9]{128}$'; then
    HASH_MODE=1700
    HASH_NAME="SHA-512 (raw)"
elif echo "$SAMPLE" | grep -qPE '^[a-f0-9]{40}$'; then
    HASH_MODE=100
    HASH_NAME="SHA-1"
fi

if [ -z "$HASH_MODE" ]; then
    # Fallback: try hashid
    if command -v hashid &>/dev/null; then
        HASHID_OUT=$(hashid -m "$SAMPLE" 2>/dev/null | grep "Hashcat Mode" | awk '{print $NF}' | head -1 || echo "")
        if [ -n "$HASHID_OUT" ]; then
            HASH_MODE="$HASHID_OUT"
            HASH_NAME="detected by hashid"
        fi
    fi
fi

if [ -z "$HASH_MODE" ]; then
    echo "{\"event\":\"crack_error\",\"payload\":{\"error\":\"mode_detection_failed\",\"tool\":\"hashcat\",\"sample\":\"$SAMPLE\"}}"
    echo "[!] Could not detect hash mode — specify manually with -m" >&2
    exit 1
fi

echo "[*] Detected: $HASH_NAME (mode $HASH_MODE)" >&2
echo "{\"event\":\"crack_format_detected\",\"payload\":{\"tool\":\"hashcat\",\"hash_type\":\"$HASH_NAME\",\"mode\":$HASH_MODE}}"

# ── Run hashcat wordlist attack ──
echo "[*] Launching hashcat -m $HASH_MODE -a 0..." >&2

HASHCAT_OUT=$(hashcat -m "$HASH_MODE" -a 0 "$HASHES_FILE" "$WORDLIST" --force --potfile-path=/tmp/hashcat_pot_$$.pot --status --status-timer=5 2>&1 || echo "$HASHCAT_OUT")
echo "$HASHCAT_OUT" >&2

# ── Check results ──
if [ -f "/tmp/hashcat_pot_$$.pot" ] && [ -s "/tmp/hashcat_pot_$$.pot" ]; then
    CRACKED_COUNT=$(wc -l < "/tmp/hashcat_pot_$$.pot" | tr -d ' ')
    echo "[+] hashcat cracked $CRACKED_COUNT hashes" >&2
    echo "{\"event\":\"crack_success\",\"payload\":{\"tool\":\"hashcat\",\"mode\":$HASH_MODE,\"attack\":\"wordlist\",\"cracked_count\":$CRACKED_COUNT,\"hashes_total\":$HASH_COUNT}}"

    while IFS= read -r line; do
        if [ -n "$line" ]; then
            HASH_HEX=$(echo "$line" | cut -d: -f1 | sed 's/"/\\"/g')
            PASS=$(echo "$line" | cut -d: -f2- | sed 's/"/\\"/g')
            echo "{\"event\":\"credential_found\",\"payload\":{\"tool\":\"hashcat\",\"hash\":\"$HASH_HEX\",\"password\":\"$PASS\",\"hash_type\":\"$HASH_NAME\",\"mode\":$HASH_MODE}}"
        fi
    done < "/tmp/hashcat_pot_$$.pot"
else
    echo "[*] hashcat wordlist found no matches" >&2
    echo "{\"event\":\"crack_fail\",\"payload\":{\"tool\":\"hashcat\",\"mode\":$HASH_MODE,\"attack\":\"wordlist\",\"cracked_count\":0,\"hashes_total\":$HASH_COUNT}}"

    # ── Attempt rules attack ──
    RULES_DIR="/usr/share/hashcat/rules"
    BEST_RULES="$RULES_DIR/best64.rule"

    if [ -f "$BEST_RULES" ]; then
        echo "[*] Running hashcat with best64.rule..." >&2
        RULES_OUT=$(hashcat -m "$HASH_MODE" -a 0 "$HASHES_FILE" "$WORDLIST" -r "$BEST_RULES" --force --potfile-path=/tmp/hashcat_pot_rules_$$.pot --status --status-timer=5 2>&1 || echo "")
        echo "$RULES_OUT" >&2

        if [ -f "/tmp/hashcat_pot_rules_$$.pot" ] && [ -s "/tmp/hashcat_pot_rules_$$.pot" ]; then
            CRACKED_RULES=$(wc -l < "/tmp/hashcat_pot_rules_$$.pot" | tr -d ' ')
            echo "[+] hashcat rules cracked $CRACKED_RULES hashes" >&2
            echo "{\"event\":\"crack_success\",\"payload\":{\"tool\":\"hashcat\",\"mode\":$HASH_MODE,\"attack\":\"rules\",\"rules_file\":\"best64.rule\",\"cracked_count\":$CRACKED_RULES,\"hashes_total\":$HASH_COUNT}}"

            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    HASH_HEX=$(echo "$line" | cut -d: -f1 | sed 's/"/\\"/g')
                    PASS=$(echo "$line" | cut -d: -f2- | sed 's/"/\\"/g')
                    echo "{\"event\":\"credential_found\",\"payload\":{\"tool\":\"hashcat\",\"hash\":\"$HASH_HEX\",\"password\":\"$PASS\",\"hash_type\":\"$HASH_NAME\",\"mode\":$HASH_MODE,\"attack\":\"rules\"}}"
                fi
            done < "/tmp/hashcat_pot_rules_$$.pot"
        fi
        rm -f "/tmp/hashcat_pot_rules_$$.pot"
    fi
fi

# ── Show final summary ──
FINAL_POT="/tmp/hashcat_pot_$$.pot"
if [ -f "$FINAL_POT" ] && [ -s "$FINAL_POT" ]; then
    TOTAL_CRACKED=$(wc -l < "$FINAL_POT" | tr -d ' ')
    echo "{\"event\":\"crack_summary\",\"payload\":{\"tool\":\"hashcat\",\"total_cracked\":$TOTAL_CRACKED,\"total_hashes\":$HASH_COUNT}}"
    rm -f "$FINAL_POT"
    exit 0
else
    echo "{\"event\":\"crack_summary\",\"payload\":{\"tool\":\"hashcat\",\"total_cracked\":0,\"total_hashes\":$HASH_COUNT,\"recommendation\":\"Try mask attack (-a 3) or a larger wordlist\"}}"
    rm -f "$FINAL_POT"
    exit 1
fi
