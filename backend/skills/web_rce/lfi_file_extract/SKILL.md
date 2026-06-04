---
name: lfi-file-extraction
description: Extracts sensitive files (shadow, SSH keys, logs, configs) via confirmed Local File Inclusion. Publishes credential and file events for credential_replay and log_poisoning skills.
skill_type: attack
severity: high
tags: [lfi, file-read, credential-theft, shadow, ssh-keys, information-disclosure]
---

# LFI 敏感文件提取

## Essential Principles
1. 只做文件提取，不做凭据破解（破解交给 credential_replay）
2. 三步管线：验证遍历路径 → 批量读敏感文件 → 枚举用户文件
3. 成功后通过 SkillEvent 链式触发 credential_replay / log_poisoning
4. 不在本 skill 内执行 SSH 登录或 john 破解

## When to Use
- LFI 已确认且可读文件
- 需要获取凭据/哈希/密钥供下游 skill 使用
- 作为 LFI 探测的后续步骤

## When NOT to Use
- LFI 未确认
- 仅需代码执行（使用 lfi_wrapper_rce）

## Path Selection
| 条件 | 路径 | 说明 |
|------|------|------|
| LFI 已确认 | lfi_extract_files | 读 passwd → 批量敏感文件 → 用户文件枚举 |
| 以上均失败 | llm_freeform | LLM 自由推理 |

## Event Chain
成功发布 `file_extracted` 事件：
- 目标：credential_replay, credential_bruteforce, log_poisoning
- 携带：shadow_readable, ssh_key_found, readable_files 等
