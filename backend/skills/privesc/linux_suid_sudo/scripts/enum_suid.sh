#!/bin/bash
# Enumerate all SUID binary files
set -euo pipefail
find / -perm -4000 -type f 2>/dev/null | head -50
