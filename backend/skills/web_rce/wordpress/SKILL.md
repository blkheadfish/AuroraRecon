---
name: wordpress-exploitation
description: Enumerates and exploits WordPress vulnerabilities including XML-RPC brute-force, outdated plugins/themes, and admin credential attacks. Use when target runs WordPress CMS with detectable version or plugin fingerprints.
skill_type: exploit
severity: high
tags: [wordpress, cms, xmlrpc, wpscan, nuclei, brute-force]
---

# WordPress Vulnerability Exploitation

## Essential Principles

1. **wpscan 枚举**：自动枚举 WordPress 插件、主题、用户、已知漏洞
2. **XML-RPC 暴力破解**：通过 `xmlrpc.php` 的 `system.multicall` 实现高效率密码爆破
3. **插件漏洞利用**：老旧插件/主题常用高危漏洞，nuclei 模板自动匹配
4. **检测特征**：`/wp-content/`、`/wp-login.php`、`xmlrpc.php` 等标准路径

## When to Use

- 指纹/响应含 WordPress、wp-content、wp-login 等字样
- 目标运行 WordPress CMS
- 需要获取管理员权限或利用已知插件漏洞

## When NOT to Use

- 非 WordPress 系统
- XML-RPC 已禁用且无插件漏洞
- 通过 `X-Redirect-By` 等自定义响应头确认非标准 CMS

## Rationalizations to Reject

- "wpscan 没扫到东西" -> 试 nuclei 直接打插件漏洞模板
- "XML-RPC 返回 404" -> 可能路径自定义，试 `/xmlrpc.php`、`/xmlrcp.php` 等变体
- "admin bruteforce 太久" -> 先试常见密码 `admin`、`password`、`123456`

## Path Selection

| 条件 | 路径 | 方法 |
|------|------|------|
| XML-RPC 可用 | **A: wp_admin_bruteforce** | XML-RPC multicall 暴力破解 |
| 插件漏洞已发现 | **B: wp_plugin_exploit** | nuclei 匹配插件漏洞模板 |
| 全部失败 | **C: LLM 兜底** | ReAct 自由推理 |

## Quick Start

```bash
# 1. wpscan 全量枚举
bash {skill_dir}/scripts/wpscan_enum.sh {ENDPOINT}

# 2. 检测 XML-RPC
bash {skill_dir}/scripts/check_xmlrpc.sh {ENDPOINT}

# 3. 管理员暴力破解
bash {skill_dir}/scripts/xmlrpc_brute.sh {ENDPOINT}

# 4. 插件漏洞利用
bash {skill_dir}/scripts/plugin_exploit.sh {ENDPOINT}
```
