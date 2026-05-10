---
name: lfi-rfi-exploitation
description: Exploits Local File Inclusion and Remote File Inclusion vulnerabilities for file read, RCE via PHP wrappers, credential theft, and log poisoning coordination. Covers absolute/relative path traversal, encoding bypass, PHP filter chains, and RFI.
skill_type: exploit
severity: critical
tags: [lfi, rfi, php, file-inclusion, path-traversal, rce, wrapper, php-filter]
cve: [CVE-2021-41773, CVE-2021-42013]
---

# 本地/远程文件包含 (LFI/RFI)

## Essential Principles

1. 文件包含漏洞允许攻击者读取服务器文件或执行代码
2. 路径解析策略:
   - 绝对路径优先: 先尝试 /etc/passwd（无 ../ 前缀）
   - 相对路径回退: 使用 ../ 深度递增（1-10级），确认后记忆深度
   - 编码绕过 (Linux): %00截断、双编码、Unicode绕过、/./路径归一化
   - Windows路径: ..\\、....\\、Unicode斜杠绕过（IIS/Tomcat）
3. PHP wrappers: php://filter base64读源码
4. RFI 远程文件包含: 测试 http:// https:// ftp:// 远程包含
5. PHP wrappers 可直接 RCE: php://input + POST、data://、expect://id

## When to Use

- 应用包含参数可见（page, file, include, path, doc 等）
- 指纹识别到 PHP
- 已知 CVE-2021-41773 / CVE-2021-42013
- 报告存在 file inclusion / path traversal

## When NOT to Use

- 应用非 PHP（LFI 仍可读文件但无法 wrapper RCE）
- 无任何包含参数

## Path Selection

| 条件 | 路径 | 说明 |
|------|------|------|
| LFI 已确认 | lfi_wrapper_rce | PHP wrapper RCE (data/input/expect/phar) |
| SSH 端口开放 | lfi_cred_reuse | 偷取 SSH 私钥 / shadow 破解 |
| 文件读取 | lfi_sensitive_read | 批量敏感文件深度探测 |
| LFI 已确认 + PHP | php_filter_chain | Filter 链读源码 |

## Quick Start

```bash
# 三层 LFI 探测
bash {skill_dir}/scripts/detect_lfi.sh {ENDPOINT}

# PHP wrapper RCE (data://)
bash {skill_dir}/scripts/exploit_wrapper_data.sh {ENDPOINT}

# 枚举敏感文件
bash {skill_dir}/scripts/enumerate_files.sh {ENDPOINT}
```
