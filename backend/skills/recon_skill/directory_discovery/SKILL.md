---
name: directory-discovery
description: Recursively scans web directories to discover hidden admin panels, configuration files, backups, and information disclosure endpoints. Crawls Apache/Nginx Index of listings recursively. Toolchain: feroxbuster, dirsearch, gobuster.
skill_type: recon
severity: high
tags: [discovery, directory-scan, information-disclosure, git-exposed, env-leak, dirbusting]
---

# Web 目录/路径发现与目录列表利用

## Essential Principles
1. 递归扫描 Web 目录，发现隐藏的管理后台、配置文件、备份文件、信息泄露端点
2. 当发现 Apache/Nginx "Index of" 目录列表页时，递归爬取其中的文件和子目录
3. 工具链: feroxbuster（快速递归）-> dirsearch（全面）-> gobuster
4. 重点关注: 管理后台、.git/.env/.bak、phpinfo、目录遍历、源码文件、配置文件、数据库 dump、密钥文件

## When to Use
- 目标运行 Web 服务（HTTP/HTTPS）
- 需要发现隐藏路径、敏感文件泄露

## When NOT to Use
- 无 Web 服务
- 目标已获得 shell（优先进行内网横向移动）

## Path Selection
| 条件 | 路径 | 方法 |
|------|------|------|
| .git 暴露 | git_dump | curl 下载 .git/HEAD, config, refs |
| .env 暴露 | env_leak | curl 下载 .env |
| 目录列表含凭据文件 | dirlist_credential_files | 下载 id_rsa, *.pem, *.key, *.ppk |
| 目录列表含敏感文件 | dirlist_interesting_files | 下载 sql, db, bak, conf, env, log |
| 以上均失败 | llm_freeform | LLM 自由推理 |

## Key Checks
```bash
# Sensitive file paths to check
/.git/HEAD
/.env
/robots.txt
/sitemap.xml
/.htaccess
/wp-config.php.bak
/config.php.bak
/backup.zip
/dump.sql
```

## Remediation
1. 删除或限制访问 .git、.env 等敏感文件
2. 配置 Web 服务器禁止目录列表（autoindex off）
3. 移除备份文件和调试端点
4. 使用 .htaccess 或 nginx deny 规则保护敏感路径
5. 敏感密钥文件不应放在 Web 可访问目录
