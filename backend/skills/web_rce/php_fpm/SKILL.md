---
name: php-fpm-cve-2019-11043-rce
description: Exploits Nginx + PHP-FPM buffer underflow RCE (CVE-2019-11043) via fastcgi_split_path_info %0a path injection. Use when target runs Nginx with PHP-FPM and fastcgi_split_path_info configured.
skill_type: exploit
severity: critical
tags: [php, php-fpm, nginx, cve-2019-11043, buffer-underflow, fastcgi]
cve: [CVE-2019-11043]
---

# PHP-FPM Nginx 缓冲区溢出 RCE (CVE-2019-11043)

## Essential Principles

1. **漏洞原理**：Nginx + PHP-FPM 使用 `fastcgi_split_path_info` 时，`%0a` 路径导致 `env_path_info` 下溢，可注入 `PHP_VALUE` 覆盖 `php.ini` 配置
2. **自动利用**：`phuip-fpizdam` 工具自动完成 QSL 探测和 payload 注入
3. **检测特征**：`/index.php/%0a` 返回 502（正常返回 200）
4. **利用后**：任意 PHP 请求的 POST body 会被当 PHP 代码执行（但只影响部分 worker）

## When to Use

- Nginx + PHP-FPM 组合（响应头含 `X-Powered-By: PHP`）
- `/index.php/%0a` 返回 502/500 或 FPM 错误消息
- 扫描器报告 CVE-2019-11043

## When NOT to Use

- 非 Nginx + PHP-FPM 架构（Apache + mod_php）
- `fastcgi_split_path_info` 已移除
- PHP 版本 >= 7.1.33 / 7.2.24 / 7.3.11
- `try_files $uri =404` 配置已添加

## Rationalizations to Reject

- "%0a 返回 404 不是 502" -> 可能 try_files 拦截了，但不是 FPM 问题
- "phuip-fpizdam 没有" -> 走手动注入路径，curl 暴力 QSL
- "Need only 200 状态码" -> CVE-2019-11043 本质是 FPM 异常，502 才是特征

## Path Selection

| 条件 | 路径 | 方法 |
|------|------|------|
| 漏洞确认 + phuip 可用 | **A: phuip_confirmed** | phuip-fpizdam + 自动验证 |
| 疑似漏洞 + phuip 可用 | **B: phuip_likely** | phuip-fpizdam 探索模式 |
| 漏洞确认 + 无 phuip | **C: manual_exploit** | 手动 QSL 暴力注入 |
| 全部失败 | **D: LLM 兜底** | ReAct 自由推理 |

## Quick Start

```bash
# 1. 检测 %0a 路径异常
bash {skill_dir}/scripts/check_0a_anomaly.sh {ENDPOINT}

# 2. 检查工具可用性
bash {skill_dir}/scripts/check_phuip.sh

# 3. phuip-fpizdam 自动利用
bash {skill_dir}/scripts/run_fpizdam.sh {ENDPOINT}

# 4. 验证 RCE
bash {skill_dir}/scripts/verify_rce.sh {ENDPOINT}
```
