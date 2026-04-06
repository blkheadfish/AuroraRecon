"""
report/generator.py
渗透测试报告生成器（Markdown + MinIO 存储）
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Any

from jinja2 import BaseLoader, Environment

logger = logging.getLogger(__name__)

REPORTS_DIR = os.getenv("REPORTS_DIR", "/tmp/pentest_reports")
REPORT_BLOCK_MAX_CHARS = max(1200, int(os.getenv("REPORT_BLOCK_MAX_CHARS", "12000")))


def _clean_html_body(body: str) -> str:
    """清理 HTML body：去除 style/script 内容块但保留结构与关键文本。"""
    cleaned = re.sub(r"<style[^>]*>.*?</style>", "<!-- style removed -->", body, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<script[^>]*>.*?</script>", "<!-- script removed -->", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'src="data:image/[^"]{100,}"', 'src="[base64 image removed]"', cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _detect_text_lang(text: str) -> str:
    raw = (text or "").strip()
    if not raw:
        return "text"
    if re.search(r"^(HTTP/\d\.\d\s+\d{3}|GET\s+/|POST\s+/|PUT\s+/|DELETE\s+/|PATCH\s+/|HEAD\s+/|OPTIONS\s+/)", raw, re.MULTILINE):
        return "http"
    if re.match(r"^\s*[\[{].*[\]}]\s*$", raw, re.DOTALL):
        return "json"
    if re.match(r"^\s*<\?xml|^\s*</?[a-zA-Z][\w:-]*[\s>]", raw):
        return "html"
    return "text"


def truncate_block(text: str, max_len: int = REPORT_BLOCK_MAX_CHARS) -> str:
    raw = str(text or "")
    if len(raw) <= max_len:
        return raw
    omitted = len(raw) - max_len
    keep = max_len // 2
    return (
        raw[:keep]
        + f"\n\n... [中间省略 {omitted} 字符] ...\n\n"
        + raw[-keep:]
    )


def split_evidence_sections(raw_evidence: str) -> list[dict[str, str]]:
    """将混合证据拆分为结构化块，供模板按块渲染。"""
    if not raw_evidence or not raw_evidence.strip():
        return []

    text = raw_evidence.strip()
    if text.startswith("HTTP/"):
        sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
        headers, body = (text.split(sep, 1) + [""])[:2]
        sections = [{
            "title": "响应头",
            "lang": "http",
            "content": headers.strip() or "(无)",
        }]
        body_text = _clean_html_body(body.strip())
        if body_text:
            sections.append({
                "title": "响应体",
                "lang": "html",
                "content": body_text,
            })
        return sections

    section_alias = {
        "command": ("Payload", "bash"),
        "cmd": ("Payload", "bash"),
        "payload": ("Payload", "bash"),
        "stdout": ("Output", "text"),
        "output": ("Output", "text"),
        "response": ("Output", "text"),
        "result": ("Output", "text"),
        "stderr": ("Error Output", "text"),
        "error": ("Error Output", "text"),
        "errors": ("Error Output", "text"),
        "命令": ("Payload", "bash"),
        "输出": ("Output", "text"),
        "响应": ("Output", "text"),
        "回显": ("Output", "text"),
        "错误": ("Error Output", "text"),
    }
    section_header = re.compile(
        r"^\s*(?:#{1,6}\s*|[-*]\s*)?(command|cmd|payload|stdout|stderr|response|output|result|error|errors|命令|输出|响应|回显|错误)\s*[:：]?\s*$",
        re.IGNORECASE,
    )
    inline_header = re.compile(
        r"^\s*(command|cmd|payload|stdout|stderr|response|output|result|error|errors|命令|输出|响应|回显|错误)\s*[:：]\s*(.*)$",
        re.IGNORECASE,
    )

    def _label_to_title_lang(label: str, content: str) -> tuple[str, str]:
        key = str(label or "").strip().lower()
        title, lang = section_alias.get(key, ("Evidence", "text"))
        if title == "Output":
            lang = _detect_text_lang(content)
        return title, lang

    sections: list[dict[str, str]] = []
    current_label = ""
    buffer: list[str] = []
    lines = text.splitlines()

    def flush() -> None:
        nonlocal buffer, current_label
        content = "\n".join(buffer).strip()
        if not content:
            buffer = []
            return
        title, lang = _label_to_title_lang(current_label, content)
        sections.append({
            "title": title,
            "lang": lang,
            "content": content,
        })
        buffer = []

    for line in lines:
        inline = inline_header.match(line)
        if inline:
            flush()
            current_label = str(inline.group(1) or "")
            tail = str(inline.group(2) or "").strip()
            if tail:
                buffer.append(tail)
            continue

        header = section_header.match(line)
        if header:
            flush()
            current_label = str(header.group(1) or "")
            continue

        buffer.append(line)

    flush()

    if not sections:
        sections.append({
            "title": "Evidence",
            "lang": _detect_text_lang(text),
            "content": text,
        })
    return sections


def format_evidence(raw_evidence: str) -> str:
    """兼容旧调用：返回 Markdown 格式证据文本。"""
    sections = split_evidence_sections(raw_evidence)
    if not sections:
        return "无"
    parts: list[str] = []
    for sec in sections:
        parts.append(f"**{sec['title']}：**")
        parts.append("")
        parts.append(f"```{sec['lang']}")
        parts.append(truncate_block(sec["content"]))
        parts.append("```")
        parts.append("")
    return "\n".join(parts).strip()


def severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "⚪")


def severity_label(severity: str) -> str:
    return {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}.get(severity, severity)


def _get_attr(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def command_count(result) -> int:
    command_results = _get_attr(result, "command_results", None)
    if command_results:
        return len(command_results)
    commands_run = _get_attr(result, "commands_run", None)
    if commands_run:
        return len(commands_run)
    return 0


def safe_val(val, default: str = "-") -> str:
    if val is None:
        return default
    text = str(val).strip()
    return text if text else default


def table_text(raw: str | None, limit: int = 72) -> str:
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not text:
        return "无"
    text = text.replace("|", " / ").replace("`", "'")
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def normalize_round(round_val: Any, fallback_index: int) -> int:
    """修复 round=None / round='None' / 非法值导致的“第None轮迭代”。"""
    if round_val is None:
        return fallback_index
    text = str(round_val).strip()
    if not text or text.lower() == "none":
        return fallback_index
    try:
        val = int(float(text))
    except Exception:
        return fallback_index
    return val if val > 0 else fallback_index


def pretty_json(value: Any) -> str:
    if value in (None, "", [], {}):
        return "无"
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


def format_elapsed(value: Any) -> str:
    try:
        if value is None:
            return "-"
        return f"{float(value):.2f}s"
    except Exception:
        return "-"


def normalize_markdown_whitespace(content: str) -> str:
    if not content:
        return ""

    lines = content.replace("\r\n", "\n").split("\n")
    output: list[str] = []
    in_fence = False
    blank_count = 0

    for raw_line in lines:
        line = raw_line.rstrip()
        if line.startswith("```"):
            in_fence = not in_fence
            blank_count = 0
            output.append(line)
            continue

        if in_fence:
            output.append(line)
            continue

        if not line:
            blank_count += 1
            if blank_count <= 1:
                output.append("")
            continue

        blank_count = 0
        output.append(line)

    while output and output[0] == "":
        output.pop(0)
    while output and output[-1] == "":
        output.pop()

    return "\n".join(output) + "\n"


MD_TEMPLATE = """# 渗透测试报告

| 项目 | 信息 |
|------|------|
| **任务 ID** | `{{ state.task_id }}` |
| **目标** | `{{ state.target }}` |
| **测试时间** | {{ safe_val(state.created_at, "未知") }} |
| **操作系统** | {{ safe_val(state.target_os, "未知") }} |
| **最终权限** | {{ safe_val(state.privilege_level, "未获得") }} |
| **授权说明** | {{ safe_val(state.scope_note, "未填写") }} |

## 一、执行摘要

{% set critical_count = state.findings | selectattr('severity','eq','critical') | list | length %}
{% set high_count = state.findings | selectattr('severity','eq','high') | list | length %}
{% set medium_count = state.findings | selectattr('severity','eq','medium') | list | length %}

本次测试共发现 **{{ state.findings | length }}** 个漏洞/信息项，其中严重/高危/中危共 **{{ critical_count + high_count + medium_count }}** 个。

| 严重程度 | 数量 |
|----------|------|
| 🔴 严重 | {{ critical_count }} |
| 🟠 高危 | {{ high_count }} |
| 🟡 中危 | {{ medium_count }} |

{% if state.got_shell %}
> ✅ 已获得目标访问能力，当前权限：**{{ safe_val(state.privilege_level, "unknown") }}**
{% else %}
> ❌ 本次测试未获得目标交互式访问权限。
{% endif %}

### 攻链状态

| 字段 | 值 |
|------|-----|
| **foothold_status** | {{ safe_val(state.foothold_status, "none") }} |
| **privesc_attempt_count** | {{ state.privesc_attempt_count if state.privesc_attempt_count is not none else 0 }} / {{ state.max_privesc_rounds if state.max_privesc_rounds is not none else "-" }} |
| **chain_visited** | {{ (state.chain_visited | join(" -> ")) if state.chain_visited else "无" }} |

{% if state.chain_summary %}
**攻链总结：** {{ state.chain_summary }}
{% endif %}

{% if state.objective_status %}
**目标完成度（objective_status）：**
```json
{{ pretty_json(state.objective_status) }}
```
{% endif %}

{% if state.credential_store %}
**凭据资产（credential_store）：**
```json
{{ pretty_json(state.credential_store) }}
```
{% endif %}

{% if state.loot_store %}
**战利品（loot_store）：**
```json
{{ pretty_json(state.loot_store) }}
```
{% endif %}

## 二、侦察结果

### 开放端口

| 端口 | 协议 | 服务 | 版本 |
|------|------|------|------|
{% for p in state.open_ports %}
| {{ p.port }} | {{ safe_val(p.protocol, "tcp") }} | {{ safe_val(p.service, "-") }} | {{ table_text(p.version, 60) }} |
{% else %}
| - | - | - | 未发现开放端口 |
{% endfor %}

{% if state.web_paths %}
### Web 路径发现
{% for path in state.web_paths %}
- `{{ path }}`
{% endfor %}
{% endif %}

{% if state.subdomains %}
### 子域名发现
{% for sub in state.subdomains %}
- `{{ sub }}`
{% endfor %}
{% endif %}

## 三、漏洞发现

{% set real_vulns = [] %}
{% set info_items = [] %}
{% for f in state.findings %}
{% if f.severity in ('critical', 'high', 'medium', 'low') and f.exploitable %}
{% set _ = real_vulns.append(f) %}
{% else %}
{% set _ = info_items.append(f) %}
{% endif %}
{% endfor %}

{% if real_vulns %}
### 可利用漏洞
{% for f in real_vulns %}
#### {{ loop.index }}. {{ sev_emoji(f.severity) }} {{ f.name }}

| 属性 | 值 |
|------|-----|
| **严重程度** | {{ sev_emoji(f.severity) }} {{ sev_label(f.severity) }} |
| **CVE** | {{ f.cve or "N/A" }} |
| **目标** | `{{ safe_val(f.target, "-") }}` |
| **端口** | {{ safe_val(f.port, "N/A") }} |
| **发现工具** | {{ safe_val(f.tool, "unknown") }} |

**描述：** {{ safe_val(f.description, "无") }}

{% set sections = split_evidence(f.evidence) %}
{% if sections %}
**证据：**
{% for sec in sections %}
**{{ sec.title }}**
```{{ sec.lang }}
{{ truncate_block(sec.content) }}
```
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}

{% if info_items %}
### 信息类发现
<details>
<summary>共 {{ info_items | length }} 项信息类发现（点击展开）</summary>
{% for f in info_items %}
- **{{ table_text(f.name, 80) }}** — {{ safe_val(f.tool, "unknown") }}{% if f.cve %} ({{ f.cve }}){% endif %}
{% endfor %}
</details>
{% endif %}

## 四、漏洞利用结果

{% if state.exploit_results %}
### 利用结果摘要

| 漏洞 ID | 状态 | Shell 类型 | 命令数 | 结论摘要 |
|---------|------|------------|--------|----------|
{% for r in state.exploit_results %}
| `{{ r.vuln_id }}` | {{ "✅ 成功" if r.success else "❌ 失败" }} | {{ safe_val(r.shell_type, "N/A") }} | {{ cmd_count(r) }} | {{ table_text(r.evidence, 78) }} |
{% endfor %}

{% for r in state.exploit_results %}
### {{ loop.index }}. 漏洞 `{{ r.vuln_id }}`

| 属性 | 值 |
|------|-----|
| **状态** | {{ "✅ 利用成功" if r.success else "❌ 利用失败" }} |
| **Shell 类型** | {{ safe_val(r.shell_type, "N/A") }} |

{% set rec_list = r.command_records if r.command_records else r.command_results %}
{% if rec_list %}
#### 命令执行过程（{{ rec_list | length }} 条）
{% for rec in rec_list %}
##### 第 {{ normalize_round(rec.round, loop.index) }} 轮迭代{% if rec.purpose %} — {{ rec.purpose }}{% endif %}

- exit: {{ rec.exit_code | default("-", true) }}
- elapsed: {{ format_elapsed(rec.elapsed | default(none, true)) }}

**Payload：**
```bash
{{ rec.command if rec.command else "(empty command)" }}
```

{% if rec.runtime_command and rec.runtime_command != rec.command %}
**Runtime Command：**
```bash
{{ rec.runtime_command }}
```
{% endif %}

**Output (stdout)：**
```text
{{ truncate_block(rec.stdout if rec.stdout else "(无输出)") }}
```

{% if rec.stderr %}
**Error (stderr)：**
```text
{{ truncate_block(rec.stderr) }}
```
{% endif %}
{% endfor %}
{% elif r.commands_run %}
#### 执行命令
{% for cmd in r.commands_run %}
```bash
{{ cmd }}
```
{% endfor %}
{% endif %}

{% if r.evidence %}
#### 最终证据
{% set sections = split_evidence(r.evidence) %}
{% for sec in sections %}
**{{ sec.title }}**
```{{ sec.lang }}
{{ truncate_block(sec.content) }}
```
{% endfor %}
{% endif %}
{% endfor %}
{% else %}
无利用尝试或所有漏洞不满足利用条件。
{% endif %}

## 五、后渗透发现

{% if state.post_findings and state.post_findings.get('findings') %}
{% for k, v in state.post_findings.get('findings', {}).items() %}
**{{ k }}：**
```text
{{ v if v else "无" }}
```
{% endfor %}
{% else %}
无后渗透数据。
{% endif %}

## 六、修复建议

{% set remediation_items = [] %}
{% for f in state.findings %}
{% if f.severity in ('critical', 'high', 'medium') %}
{% set _ = remediation_items.append(f) %}
{% endif %}
{% endfor %}

{% if remediation_items %}
| 漏洞 | 优先级 | 立即行动 | 参考 | 临时缓解 |
|------|--------|----------|------|----------|
{% for f in remediation_items %}
| {{ table_text(f.name, 44) }} | {{ sev_emoji(f.severity) }} {{ sev_label(f.severity) }} | {{ "立即升级并应用官方补丁" if f.severity in ('critical', 'high') else "维护窗口内修复并完成回归验证" }} | {{ f.cve or "厂商安全公告" }} | {{ "部署 WAF 规则并限制高风险入口暴露" if f.severity in ('critical', 'high') else "审查配置并加强访问控制策略" }} |
{% endfor %}
{% else %}
当前未发现需要立即处置的高/中危漏洞，建议保持基线巡检与补丁更新节奏。
{% endif %}

## 七、测试过程日志（最近 200 行）

```text
{% for entry in (state.phase_log[-200:] if state.phase_log else []) %}
{{ entry }}
{% endfor %}
```

## 八、测试方法论

1. 信息收集：端口发现、服务识别、目录/路径枚举
2. 漏洞扫描：模板/签名检测 + 证据回收
3. 攻链决策：基于环境信息动态编排利用路径
4. 漏洞利用：执行 payload 并验证命令执行证据
5. 后渗透：权限提升、凭据与资产收集
6. 报告生成：汇总证据与修复建议

---

*本报告由 PentestAI v2.0 自动生成，仅供授权安全测试使用。*  
*生成时间：{{ now }}*
"""


class ReportGenerator:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self._env = Environment(
            loader=BaseLoader(),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.globals["fmt_evidence"] = format_evidence
        self._env.globals["split_evidence"] = split_evidence_sections
        self._env.globals["truncate_block"] = truncate_block
        self._env.globals["normalize_round"] = normalize_round
        self._env.globals["pretty_json"] = pretty_json
        self._env.globals["format_elapsed"] = format_elapsed
        self._env.globals["sev_emoji"] = severity_emoji
        self._env.globals["sev_label"] = severity_label
        self._env.globals["cmd_count"] = command_count
        self._env.globals["table_text"] = table_text
        self._env.globals["safe_val"] = safe_val

    async def generate(self, state) -> tuple[str, str]:
        template = self._env.from_string(MD_TEMPLATE)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        rendered = template.render(state=state, now=now)
        md_content = normalize_markdown_whitespace(rendered)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{state.task_id[:8]}_{timestamp}.md"
        filepath = os.path.join(REPORTS_DIR, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"[ReportGenerator] 报告已写入: {filepath}")

        minio_path = ""
        try:
            from backend.storage.minio_client import get_storage

            storage = get_storage()
            minio_path = storage.upload_report(
                task_id=state.task_id,
                filename=filename,
                content=md_content,
            )
            logger.info(f"[ReportGenerator] 报告已上传至 MinIO: {minio_path}")
        except Exception as e:
            logger.warning(f"[ReportGenerator] MinIO 上传失败（已保存本地）: {e}")

        return md_content, minio_path or filepath
