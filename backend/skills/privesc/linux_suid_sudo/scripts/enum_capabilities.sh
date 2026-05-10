#!/bin/bash
# Enumerate files with special capabilities
set -euo pipefail
getcap -r / 2>/dev/null | head -30
