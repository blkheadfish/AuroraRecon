---
name: lfi-wrapper-rce
description: Exploits PHP wrapper protocols (data://, php://input, expect://, phar://) for direct Remote Code Execution through confirmed Local File Inclusion.
skill_type: exploit
severity: critical
tags: [lfi, rce, php, data-wrapper, php-input, expect, phar]
---

# LFI PHP Wrapper RCE

## Essential Principles
1. PHP wrapper 直接命令执行，无需文件上传或日志投毒
2. 优先级：data:// → php://input → expect:// → phar:///zip://
3. data:// 需要 allow_url_fopen=On，php://input 需要 allow_url_include=On
4. 有 WAF 时自动启用 php://filter 链绕过

## When to Use
- lfi_confirmed=true 且有可用参数
- 目标为 PHP 应用
- lfi_detect 完成后的事件触发

## When NOT to Use
- 非 PHP 应用（wrapper 不可用）
- lfi_confirmed=false

## Path Selection
| 条件 | 路径 | 说明 |
|------|------|------|
| LFI 已确认 | lfi_wrapper_rce | data → input → expect → phar → filter chain |
| 以上均失败 | llm_freeform | LLM 自由推理 |
