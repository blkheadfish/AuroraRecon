#!/bin/bash
# Check current user's sudo permissions
set -euo pipefail
sudo -l 2>/dev/null || echo "SUDO_CHECK_FAILED"
