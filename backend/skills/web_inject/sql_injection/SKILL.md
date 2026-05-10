---
name: sql-injection-detection-and-exploitation
description: SQL injection detection and exploitation covering UNION, error-based, boolean-blind, time-blind, and stacked queries. Automates sqlmap for RCE and file read, with manual UNION fallback and LLM freeform reasoning.
skill_type: exploit
severity: critical
tags: [sql-injection, sqli, mysql, postgresql, mssql, oracle, sqlite, rce, database]
---

# SQL 注入检测与利用

## Essential Principles

SQL 注入的本质是应用将用户输入直接拼接到 SQL 语句中，导致攻击者
可以改变 SQL 语义，执行任意数据库操作。

注入类型及利用方式:

1. **联合查询注入 (UNION)**: 最直接，可在响应中看到数据
   - 前提: 注入点在 SELECT 语句中，且结果会显示在页面上
   - 步骤: ORDER BY 确定列数 → UNION SELECT 提取数据

2. **报错注入 (Error-based)**: 通过构造触发数据库错误的查询提取数据
   - MySQL: extractvalue(), updatexml()
   - MSSQL: convert(), cast()
   - PostgreSQL: ::int 类型转换错误

3. **布尔盲注 (Boolean-blind)**: 通过页面差异（有/无数据）逐字符提取
   - 效率低但可靠，sqlmap 自动化处理

4. **时间盲注 (Time-blind)**: 通过响应延迟判断条件真假
   - MySQL: SLEEP(), BENCHMARK()
   - PostgreSQL: pg_sleep()
   - MSSQL: WAITFOR DELAY

5. **堆叠查询 (Stacked)**: 分号分隔执行多条 SQL
   - 可 INSERT/UPDATE/DELETE/EXEC
   - PHP+MySQL 默认不支持（mysqli_query 不支持多语句）
   - Python+PostgreSQL/MSSQL 通常支持

### 数据库识别特征

| 数据库 | 特征 |
|--------|------|
| MySQL | \@\@version, CONCAT(), SLEEP(), `--+` 注释 |
| PostgreSQL | version(), pg_sleep(), `--` 注释 |
| MSSQL | \@\@version, WAITFOR DELAY, `--` 注释 |
| Oracle | DUAL 表, DBMS_PIPE.RECEIVE_MESSAGE |
| SQLite | sqlite_version(), typeof() |

## When to Use

- Web 应用存在用户输入参数（GET/POST）
- 扫描器报告了可能的 SQL 注入点
- 页面返回数据库错误信息

## When NOT to Use

- 目标使用了参数化查询或 ORM（无注入风险）
- WAF 严格拦截且无法绕过

## Path Selection

| 条件 | 路径 | 用途 |
|------|------|------|
| sqli_confirmed | sqlmap_auto | sqlmap 自动化检测 + 利用 |
| sqlmap 失败 | manual_union | 手工 UNION 注入 |
| 其他情况 | llm_freeform | LLM 自由推理 |

## Quick Start

```bash
# 单引号测试注入点
curl "http://target.com/page?id=1'"

# UNION 测试
curl "http://target.com/page?id=-1' UNION SELECT 1,version(),3--+-"

# sqlmap 自动化
sqlmap -u "http://target.com/page?id=1" --batch --dbs
```
