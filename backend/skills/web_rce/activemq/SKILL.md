---
name: activemq-jolokia-jmx-rce
description: Exploits Apache ActiveMQ Web Console Jolokia JMX RCE (CVE-2022-41678). Default credentials admin:admin allow writing JSP webshell via Log4j2 MBean / JFR MBean / fileserver PUT for RCE.
skill_type: exploit
severity: critical
tags: [activemq, jolokia, jmx, rce, java, cve-2022-41678, cve-2016-3088]
cve: [CVE-2022-41678, CVE-2016-3088]
---

# ActiveMQ Jolokia JMX RCE (CVE-2022-41678)

## Essential Principles

1. Apache ActiveMQ Web Console（默认 8161 端口）内嵌 Jolokia 代理
2. 使用默认凭据 `admin:admin` 后，可通过 Log4j2 MBean / JFR MBean / fileserver PUT 三种方式写入 JSP Webshell 实现 RCE
3. 关键: Jolokia API 需要 `Origin: http://localhost` 头绕过 CORS
4. CVE-2016-3088 (fileserver PUT) 也可配合使用

## When to Use

- 端口 8161 开放（ActiveMQ Web Console 默认端口）
- 指纹报告 ActiveMQ 或 Jolokia
- 已知 CVE: CVE-2022-41678, CVE-2016-3088

## When NOT to Use

- ActiveMQ 已修补（>= 5.16.5 / 5.17.3）
- 凭据不是默认 admin:admin 且无法获取

## Path Selection

| 条件 | 路径 | 命令 |
|------|------|------|
| 默认凭据可用 | exploit_script | activemq_exploit.py 自动利用 |
| 其他情况 | llm_freeform | LLM 自由推理 |

## Quick Start

```bash
# 确认 ActiveMQ 存在
curl -s -u admin:admin http://{TARGET_IP}:8161/admin/

# 一键利用
bash {skill_dir}/scripts/activemq_exploit.sh {TARGET_IP} {TARGET_PORT} {ENDPOINT}
```
