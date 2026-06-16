---
name: hash-cracking
description: Password hash cracking using John the Ripper and hashcat. Supports NTLM (-m 1000), NetNTLMv2 (-m 5600), Kerberos TGS (-m 13100), SHA512crypt (-m 1800), and auto-format detection via hashid.
skill_type: attack
severity: high
tags: [hash-cracking, john, hashcat, ntlm, kerberos, credential, password-recovery]
---

# Hash 破解 (John/Hashcat)

## Essential Principles
1. 离线密码破解是 AD 渗透和凭证重用的核心环节 — 破解的明文密码可用于横向移动和提权
2. John the Ripper 擅长 auto-detect 和 CPU 破解；hashcat 擅长 GPU 加速和 mask 攻击
3. 破解前必须正确识别 hash 类型：hashid、hash-identifier 或手动匹配正则
4. NTLM (mode 1000) 是最常见的 Windows hash 类型；NetNTLMv2 (mode 5600) 来自 Responder；Kerberos TGS (mode 13100) 来自 Kerberoast
5. 优先跑 rockyou.txt 快速字典 → 再跑 rules → 最后 mask/brute force

## When to Use
- 已获取 NTLM hash（secretsdump、samdump）
- Responder 捕获 NetNTLMv2 响应
- Kerberoast 获取 TGS-REP hash
- Linux /etc/shadow 获取 SHA512crypt
- 任何需要离线破解的 hash

## When NOT to Use
- hash 为 NTLM hash 但可以直接 Pass-the-Hash（无需破解明文）
- 目标系统支持在线密码喷射（应路由到 credential/bruteforce）
- 已知所有密码或无需明文密码

## Path Selection
| 条件 | 路径 | 命令 |
|------|------|------|
| 任意 hash 文件 + 快速破解 | john_quick | `john --wordlist=rockyou.txt hashes.txt` |
| NTLM hash + GPU 可用 | hashcat_ntlm | `hashcat -m 1000 -a 0 hashes.txt rockyou.txt` |
| NetNTLMv2 + GPU 可用 | hashcat_netntlm | `hashcat -m 5600 -a 0 hashes.txt rockyou.txt` |
| Kerberos TGS + 字典 | hashcat_kirbi | `hashcat -m 13100 -a 0 hashes.txt rockyou.txt` |
| Linux shadow | john_shadow | `john --format=sha512crypt hashes.txt --wordlist=rockyou.txt` |
| 未知 hash 类型 | auto_detect | `hashid -m hashes.txt && john hashes.txt` |

## Quick Start
```bash
# 识别 hash 类型
hashid -m hashes.txt
hash-identifier < hashes.txt

# John auto-detect + rockyou
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 查看已破解的密码
john --show hashes.txt

# hashcat NTLM 字典攻击
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force

# hashcat 应用规则
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# hashcat mask 攻击 (8位小写字母)
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l?l?l
```

## Remediation
1. 使用长密码（>14 字符）增加爆破难度
2. 禁用 NTLM，强制 Kerberos
3. 定期轮换 KRBTGT 和 服务账户密码
4. 部署 LAPS 管理本地管理员密码
5. 监控异常的高频认证失败事件
