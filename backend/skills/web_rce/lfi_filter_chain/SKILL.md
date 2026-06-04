---
name: lfi-filter-chain
description: Reads PHP source code through php://filter base64 encoding chains. Uses filter chain techniques for WAF bypass and code extraction.
skill_type: exploit
severity: medium
tags: [lfi, php-filter, source-code-read, waf-bypass, filter-chain]
---

# LFI PHP Filter 链源码读取

## Essential Principles
1. php://filter/convert.base64-encode 读取任意 PHP 文件源码
2. 可配合 zlib.deflate 等中间过滤器绕过 WAF 关键字检测
3. 独立 skill，不依赖 wrapper RCE 或文件提取

## When to Use
- LFI 探测发现 php_filter 风格
- 需要读取 PHP 源码（不要求 RCE）
- WAF 存在但 php://filter 可用

## When NOT to Use
- 需要 RCE（使用 lfi_wrapper_rce）
- 非 PHP 应用

## Path Selection
| 条件 | 路径 | 说明 |
|------|------|------|
| php_filter 可用 | php_filter_chain | base64 读 + de-base64 |
| 以上均失败 | llm_freeform | LLM 自由推理 |
