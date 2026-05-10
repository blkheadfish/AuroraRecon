---
name: log-poisoning-via-lfi
description: Achieves RCE via log poisoning through LFI. Uses SSH auth.log, HTTP User-Agent access.log, or SMTP mail.log injection vectors with a four-phase process (confirm, canary, deliver, trigger).
skill_type: exploit
severity: critical
tags: [lfi, log-poisoning, rce, ssh, smtp, user-agent, php, jsp, aspx]
---

# 日志投毒 RCE (Log Poisoning via LFI)

## Essential Principles

1. 日志投毒是利用"可控写入点 + 文件包含"实现 RCE 的攻击链
2. 前置条件: 已确认 LFI（param/depth/style 已锁定）且至少一个日志文件可读
3. 四阶段流程:
   - Phase 0 - 前置确认: LFI 参数已确认, 日志文件可通过 LFI 读取
   - Phase 1 - Canary 探针: 通过注入向量写入无害标记, 用 LFI 读日志验证回显
   - Phase 2 - 载荷投递: 用已验证的注入向量写入 webshell payload
   - Phase 3 - 触发 RCE: 通过 LFI 包含已投毒日志, 附带命令参数触发执行

## When to Use

- LFI 已确认且日志文件可读（auth.log / access.log / mail.log）
- SSH 端口开放（auth.log 投毒）
- Web 服务存在（User-Agent access.log 投毒）

## When NOT to Use

- LFI 未确认或无日志可读
- 所有注入向量不可达（SSH/SMTP 均关闭）

## Injection Vectors

| 向量 | 日志文件 | 可靠性 |
|------|----------|--------|
| SSH auth.log | /var/log/auth.log, /var/log/secure | 高 |
| HTTP User-Agent | Apache/Nginx access.log | 中 |
| SMTP mail.log | /var/log/mail.log | 低 |

## Quick Start

```bash
# Phase 1: SSH canary probe
bash {skill_dir}/scripts/canary_ssh.sh {ENDPOINT} {TARGET_IP}

# Phase 2 + 3: Deliver payload and trigger
bash {skill_dir}/scripts/deliver_ssh.sh {ENDPOINT} {TARGET_IP}
bash {skill_dir}/scripts/trigger_ssh.sh {ENDPOINT} {TARGET_IP}
```
