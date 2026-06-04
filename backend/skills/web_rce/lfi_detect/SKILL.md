---
name: lfi-detection
description: Pure LFI detection probe that confirms Local File Inclusion vulnerabilities through absolute path, relative traversal, and encoding bypass. Publishes events for downstream exploit skills.
skill_type: probe
severity: high
tags: [lfi, file-inclusion, path-traversal, probe, detection]
---

# LFI 探测

## Essential Principles
1. 纯探测阶段，只确认漏洞存在，不做利用
2. 三层探测策略：绝对路径 → 相对深度遍历(1-10) → 编码绕过
3. 确认后自动枚举可读文件（shadow/SSH密钥/日志）
4. 探测结果通过 SkillEvent 发布给下游 exploit skill

## When to Use
- 目标应用有文件包含迹象（page/file/include/path 等参数）
- VulnAgent 报告了 file inclusion / path traversal / LFI
- 需要确认 LFI 可用性后再分派给专用 exploit skill

## When NOT to Use
- lfi_confirmed 已存在（直接使用 lfi_wrapper_rce 或 lfi_file_extract）

## Path Selection
| 条件 | 路径 | 说明 |
|------|------|------|
| LFI 已确认 | lfi_detect_done | 发布事件，链式触发下游 |
