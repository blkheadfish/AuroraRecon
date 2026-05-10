#!/bin/bash
# GeoServer Layer Discovery via GetCapabilities
# 用法: discover_layers.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

echo "=== GeoServer Layer Discovery ==="

# 尝试两种 URL 格式
for base in "${ENDPOINT}/geoserver" "${ENDPOINT}"; do
  resp=$(curl -s "${base}/wfs?service=WFS&request=GetCapabilities" --max-time 15 2>/dev/null)
  if echo "$resp" | grep -qi "FeatureType"; then
    # 提取 typeNames
    layer=$(echo "$resp" | grep -oP '<Name>[^<]+</Name>' | head -1 | sed 's/<[^>]*>//g')
    if [ -n "$layer" ]; then
      echo "LAYER_FOUND:${layer}"
      echo "BASE_URL:${base}"
    fi
    break
  fi
done
# 默认图层兜底
echo "DEFAULT_LAYERS:sf:archsites,topp:states,tiger:poi"
