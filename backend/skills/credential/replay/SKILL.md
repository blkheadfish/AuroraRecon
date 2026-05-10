---
name: credential-replay
description: Reuses real credentials obtained from prior phases (LFI, config leaks, .env, phpinfo, dumps) across SSH, MySQL, SMB, FTP, RDP, PostgreSQL, and Redis services. Base64-encoded credential injection for safe shell handling.
skill_type: attack
severity: critical
tags: [credential-replay, ssh, mysql, smb, ftp, rdp, postgres, lateral-movement]
---

# 凭据复用攻击

## Essential Principles
1. 前序阶段抓到的真实凭据在多个服务上大概率复用，尤其在内部网络与运维不规范的环境
2. 本 Skill 把 confirmed_facts.creds 中的真实凭据重放到所有匹配端口
3. base64 注入是必要的：原文带换行/引号/$ 号会破坏 bash 语法
4. 匹配链路：VulnAgent -> service-level finding -> SkillEngine 解开 creds 为模板变量

## When to Use
- 前序阶段（LFI 读 wp-config.php / 配置文件泄露 / .env 泄露 / phpinfo / spring actuator / 数据库 dump）已获取真实凭据
- 目标开放 SSH/MySQL/SMB/FTP/RDP/PostgreSQL 服务

## When NOT to Use
- 无已知凭据（has_known_creds = false）
- 目标服务端口全部关闭

## Path Selection
| 条件 | 路径 | 方法 |
|------|------|------|
| SSH 开放 | ssh_replay | 精确配对 -> 运维账号 x 已知密码 -> 笛卡尔积 |
| MySQL 开放 | mysql_replay | root/admin 优先 -> 笛卡尔积 |
| FTP 开放 | ftp_replay | curl --user 验证 |
| SMB 开放 | smb_replay | smbclient + netexec |
| PostgreSQL 开放 | postgres_replay | psql 登录列库 |
| 以上均失败 | llm_freeform | LLM 自由推理 |

## Remediation
1. 严禁多服务复用同一凭据
2. 配置文件权限收紧、不对外可读
3. 数据库账户仅授予最小权限
4. 启用 fail2ban / 服务侧锁定策略防止暴力枚举
