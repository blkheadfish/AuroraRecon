#!/bin/bash
# Probe target for open credential-replay service ports
# Usage: detect_target_services.sh <TARGET_IP>
set -euo pipefail

TARGET_IP="${1:-127.0.0.1}"

echo "=== Target Service Recon ==="
for p in 22 2211 2222 21 3306 5432 6379 27017 139 445 3389; do
    if (exec 3<>/dev/tcp/"$TARGET_IP"/"$p") 2>/dev/null; then
        echo "PORT_OPEN:$p"
        exec 3>&- 3<&- 2>/dev/null || true
    fi
done
echo "PROBE_DONE"
