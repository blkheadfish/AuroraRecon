---
name: xss-detection
description: Cross-Site Scripting (XSS) detection using dalfox for automated reflected/stored XSS scanning with DOM analysis, katana for URL discovery, and manual parameter testing for reflected XSS confirmation.
skill_type: scan
severity: high
tags: [xss, cross-site-scripting, dalfox, katana, web-security, reflected-xss, stored-xss]
---

# XSS (Cross-Site Scripting) Detection

## Essential Principles

XSS vulnerabilities allow injecting client-side scripts into web pages.
dalfox provides automated reflected/stored XSS detection with DOM analysis.
Combined with katana for URL discovery and parameter extraction.

Types of XSS:

1. **Reflected XSS**: Payload is reflected immediately in the response
2. **Stored XSS**: Payload is stored on the server and served to other users
3. **DOM-based XSS**: Payload is executed client-side via DOM manipulation

## When to Use

- Web application accepts user input that is reflected in responses
- Forms, search fields, URL parameters exist on the target
- Target uses PHP, ASP, or other server-side technologies

## When NOT to Use

- Target has strong Content-Security-Policy headers
- All user output is properly encoded

## Path Selection

| 条件 | 路径 | 用途 |
|------|------|------|
| Any target | dalfox_scan | dalfox automated XSS scan |
| URLs with params | manual_xss | Manual parameter testing |
| Other | llm_freeform | LLM freeform reasoning |

## Quick Start

```bash
# Katana crawl
katana -u http://target.com -d 2 -silent -jc

# dalfox XSS scan
echo "http://target.com" | dalfox pipe --silence --only-poc

# Manual parameter test
curl "http://target.com/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```
