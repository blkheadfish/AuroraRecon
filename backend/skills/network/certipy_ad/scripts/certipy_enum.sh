#!/bin/bash
# Certipy ADCS enumeration — find vulnerable certificate templates
# Usage: certipy_enum.sh <TARGET_IP>
# required_tools: certipy, certipy-ad
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "{\"type\":\"status\",\"data\":{\"action\":\"certipy_enum\",\"target\":\"$TARGET_IP\"}}"

if [ -f /tmp/known_creds_b64 ]; then
  CRED=$(head -1 /tmp/known_creds_b64 | base64 -d 2>/dev/null || head -1 /tmp/known_creds_b64)
else
  CRED=""
fi

if [ -z "$CRED" ]; then
  echo "{\"type\":\"result\",\"data\":{\"action\":\"certipy_enum\",\"status\":\"skipped\",\"reason\":\"no credentials available\"}}"
  exit 0
fi

USERNAME=$(echo "$CRED" | cut -d: -f1 2>/dev/null || echo "")
PASSWORD=$(echo "$CRED" | cut -d: -f2- 2>/dev/null || echo "")

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
  echo "{\"type\":\"result\",\"data\":{\"action\":\"certipy_enum\",\"status\":\"error\",\"reason\":\"invalid credential format\"}}"
  exit 1
fi

DOMAIN="${DOMAIN:-domain.local}"

echo "{\"type\":\"status\",\"data\":{\"message\":\"Running certipy find -vulnerable\",\"user\":\"$USERNAME\"}}"

FIND_OUTPUT=$(certipy find -u "${USERNAME}@${DOMAIN}" -p "$PASSWORD" -dc-ip "$TARGET_IP" -vulnerable -stdout 2>&1 || true)

if [ -z "$FIND_OUTPUT" ] || ! echo "$FIND_OUTPUT" | grep -q "."; then
  echo "{\"type\":\"result\",\"data\":{\"action\":\"certipy_enum\",\"status\":\"error\",\"reason\":\"certipy find returned empty output\",\"target\":\"$TARGET_IP\"}}"
  exit 0
fi

CA_NAME=""
IN_VULNERABLE=0
CURRENT_TEMPLATE=""

while IFS= read -r line; do
  if echo "$line" | grep -qi "Certificate Authorities"; then
    CA_NAME=$(echo "$line" | grep -oP 'CA Name\s*:\s*\K\S+' | head -1)
    echo "{\"type\":\"ca_info\",\"data\":{\"ca_name\":\"$CA_NAME\",\"target\":\"$TARGET_IP\"}}"
  fi

  if echo "$line" | grep -qiE "^\s*Vulnerable Certificates|Vulnerable$|Certificate Templates"; then
    echo "{\"type\":\"status\",\"data\":{\"message\":\"Found vulnerable templates section\"}}"
    IN_VULNERABLE=1

    CURRENT_TEMPLATE=$(echo "$line" | grep -oP 'Template Name\s*:\s*\K[^\n]+' | head -1)
    if [ -n "$CURRENT_TEMPLATE" ]; then
      echo "{\"type\":\"template\",\"data\":{\"name\":\"$CURRENT_TEMPLATE\",\"target\":\"$TARGET_IP\"}}"
    fi
  fi

  VULN_FLAG=""
  if echo "$line" | grep -qi "ESC1\|ENROLLEE_SUPPLIES_SUBJECT\|Subject Alternative Name"; then
    VULN_FLAG="ESC1"
  elif echo "$line" | grep -qi "ESC4\|GenericWrite\|WriteDacl\|WriteOwner\|GenericAll"; then
    VULN_FLAG="ESC4"
  elif echo "$line" | grep -qi "ESC6\|EDITF_ATTRIBUTESUBJECTALTNAME2"; then
    VULN_FLAG="ESC6"
  elif echo "$line" | grep -qi "ESC8\|Web Enrollment\|HTTP.*enroll"; then
    VULN_FLAG="ESC8"
  elif echo "$line" | grep -qi "ESC2\|Any Purpose\|2.5.29.37.0"; then
    VULN_FLAG="ESC2"
  elif echo "$line" | grep -qi "ESC3\|Enrollment Agent\|Certificate Request Agent"; then
    VULN_FLAG="ESC3"
  elif echo "$line" | grep -qi "ESC9\|No Security Extension\|CT_FLAG_NO_SECURITY"; then
    VULN_FLAG="ESC9"
  elif echo "$line" | grep -qi "ESC11\|ENCRYPTICERTREQUEST"; then
    VULN_FLAG="ESC11"
  elif echo "$line" | grep -qi "ESC13\|OID Group Link\|issuance policy"; then
    VULN_FLAG="ESC13"
  fi

  if [ -n "$VULN_FLAG" ]; then
    echo "{\"type\":\"vulnerability\",\"data\":{\"esc\":\"$VULN_FLAG\",\"template\":\"$CURRENT_TEMPLATE\",\"detail\":\"$line\",\"target\":\"$TARGET_IP\"}}"
  fi

  ENABLED=$(echo "$line" | grep -oP 'Enrollment Services\s*:\s*\K[^\n]+' | head -1 || true)
  CLIENTS=$(echo "$line" | grep -oP 'Enrollable Client\s*:\s*\K[^\n]+' | head -1 || true)
done <<< "$FIND_OUTPUT"

echo "{\"type\":\"status\",\"data\":{\"message\":\"Running certipy find full (non-vulnerable also) for CA configuration\"}}"
FULL_OUTPUT=$(certipy find -u "${USERNAME}@${DOMAIN}" -p "$PASSWORD" -dc-ip "$TARGET_IP" -stdout 2>&1 || true)

ENROLLMENT_URL=$(echo "$FULL_OUTPUT" | grep -oiP 'http[s]?://[^/]+/certsrv' | head -1 || echo "")
if [ -n "$ENROLLMENT_URL" ]; then
  echo "{\"type\":\"web_enrollment\",\"data\":{\"url\":\"$ENROLLMENT_URL\",\"target\":\"$TARGET_IP\"}}"
fi

EDIT_FLAGS=$(echo "$FULL_OUTPUT" | grep -i "EDITF_ATTRIBUTESUBJECTALTNAME2" || echo "")
if [ -n "$EDIT_FLAGS" ]; then
  echo "{\"type\":\"vulnerability\",\"data\":{\"esc\":\"ESC6\",\"detail\":\"EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA\",\"target\":\"$TARGET_IP\"}}"
fi

echo "{\"type\":\"result\",\"data\":{\"action\":\"certipy_enum\",\"status\":\"complete\",\"target\":\"$TARGET_IP\",\"ca\":\"$CA_NAME\"}}"
