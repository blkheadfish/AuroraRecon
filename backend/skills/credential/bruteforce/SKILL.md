---
name: credential-bruteforce
description: Attempts default credentials and common weak passwords against SSH, FTP, RDP, and HTTP authentication services when no known CVE exists. Toolchain: hydra, medusa, ncrack.
skill_type: attack
severity: high
tags: [bruteforce, credential, ssh, ftp, rdp, hydra]
---

# 凭据暴力破解 (SSH/FTP/RDP/HTTP)

## Essential Principles
1. 当目标开放 SSH/FTP/RDP/HTTP 认证服务但无已知 CVE 时，尝试默认凭据和常见弱口令
2. 工具链: hydra -> medusa -> ncrack
3. 优先测试默认凭据（admin:admin, root:root 等），再小字典爆破
4. 如果 LFI 已确认，应优先走日志投毒链而非凭据爆破

## When to Use
- 目标开放 SSH/FTP/RDP/HTTP 认证服务
- 无已知 CVE 可供利用
- 目标端口匹配（SSH: 22/2222/2211, FTP: 21, RDP: 3389）

## When NOT to Use
- LFI 已确认（lfi_confirmed = true），应优先使用日志投毒链
- 凭据已通过其他手段获取（应使用 credential/replay）
- 目标已通过其他方式获得 shell

## Path Selection
| 条件 | 路径 | 方法 |
|------|------|------|
| SSH 开放 | ssh_default_creds | 默认凭据 + hydra 小字典 |
| FTP 开放且非匿名 | ftp_default_creds | hydra 默认凭据测试 |
| 以上均失败 | llm_freeform | LLM 自由推理 |

## Remediation
1. 禁用默认凭据，强制使用强密码策略
2. 启用账户锁定机制（fail2ban 等）
3. 使用 SSH 密钥认证替代密码
4. 限制认证服务的访问 IP
