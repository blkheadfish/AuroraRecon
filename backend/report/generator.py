"""
report/generator.py —— 渗透测试报告生成器（Markdown + MinIO 存储）

改进：
  - 证据完整展示，不截断
  - HTTP 响应头和响应体分离
  - HTML body 去除 style/script 噪音但保留完整结构
  - 漏洞分组：高危漏洞和信息类发现分开展示
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime

from jinja2 import Environment, BaseLoader

logger = logging.getLogger(__name__)

REPORTS_DIR = os.getenv("REPORTS_DIR", "/tmp/pentest_reports")

# ── Jinja2 自定义过滤器 ──────────────────────────────────

def format_evidence(raw_evidence: str) -> str:
    """格式化证据：分离 HTTP 响应头和响应体，完整展示"""
    if not raw_evidence or not raw_evidence.strip():
        return "无"

    text = raw_evidence.strip()

    # 检测 HTTP 响应格式
    if text.startswith("HTTP/"):
        # 兼容 \r\n\r\n 和 \n\n
        sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
        parts = text.split(sep, 1)
        headers = parts[0].strip()
        body = parts[1].strip() if len(parts) > 1 else ""

        result = "**响应头：**\n\n```http\n" + headers + "\n```\n"

        if body:
            clean_body = _clean_html_body(body)
            if clean_body:
                result += "\n**响应体：**\n\n```html\n" + clean_body + "\n```"

        return result

    # 非 HTTP 响应，完整展示
    return "```\n" + text + "\n```"


def _clean_html_body(body: str) -> str:
    """清理 HTML body：去除 style/script 内容块但保留 HTML 结构"""
    # 去掉 <style>...</style> 块（通常是大段 CSS，无安全意义）
    cleaned = re.sub(r'<style[^>]*>.*?</style>', '<!-- style removed -->', body, flags=re.DOTALL)
    # 去掉 <script>...</script> 块
    cleaned = re.sub(r'<script[^>]*>.*?</script>', '<!-- script removed -->', cleaned, flags=re.DOTALL)
    # 去掉内联 base64 图片数据（通常很长且无意义）
    cleaned = re.sub(r'src="data:image/[^"]{100,}"', 'src="[base64 image removed]"', cleaned)
    # 压缩连续空行
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()


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
    """Safely render a value, replacing None with a default string."""
    if val is None:
        return default
    return str(val)


def table_text(raw: str | None, limit: int = 72) -> str:
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not text:
        return "无"
    text = text.replace("|", " / ").replace("`", "'")
    if len(text) > limit:
        return text[:limit] + "..."
    return text


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


# ── 报告模板 ─────────────────────────────────────────────

MD_TEMPLATE = """# 渗透测试报告

| 项目 | 信息 |
|------|------|
| **任务 ID** | `{{ state.task_id }}` |
| **目标** | `{{ state.target }}` |
| **测试时间** | {{ state.created_at }} |
| **操作系统** | {{ state.target_os }} |
| **最终权限** | {{ state.privilege_level or "未获得" }} |
| **授权说明** | {{ state.scope_note }} |

---

## 一、执行摘要

{% set critical_count = state.findings | selectattr('severity','eq','critical') | list | length %}
{% set high_count = state.findings | selectattr('severity','eq','high') | list | length %}
{% set medium_count = state.findings | selectattr('severity','eq','medium') | list | length %}

本次测试共发现 **{{ state.findings | length }}** 个漏洞/信息项，其中：

| 严重程度 | 数量 |
|----------|------|
| 🔴 严重 | {{ critical_count }} |
| 🟠 高危 | {{ high_count }} |
| 🟡 中危 | {{ medium_count }} |

{% if state.got_shell %}
> ✅ **已成功获取目标 Shell，最终权限：{{ state.privilege_level }}**
{% else %}
> ❌ 本次测试未获得目标交互式访问权限。
{% endif %}

---

## 二、侦察结果

### 开放端口

| 端口 | 协议 | 服务 | 版本 |
|------|------|------|------|
{% for p in state.open_ports %}| {{ p.port }} | {{ p.protocol }} | {{ p.service }} | {{ p.version[:60] }} |
{% endfor %}

{% if state.web_paths %}
### Web 路径发现

{% for path in state.web_paths %}- `{{ path }}`
{% endfor %}
{% endif %}

{% if state.subdomains %}
### 子域名发现

{% for sub in state.subdomains %}- `{{ sub }}`
{% endfor %}
{% endif %}

---

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
| **目标** | `{{ f.target }}` |
| **端口** | {{ f.port or "N/A" }} |
| **发现工具** | {{ f.tool }} |

**描述：** {{ f.description }}

**证据：**

{{ fmt_evidence(f.evidence) }}

{% endfor %}
{% endif %}

{% if info_items %}
### 信息类发现

<details>
<summary>共 {{ info_items | length }} 项信息类发现（点击展开）</summary>

{% for f in info_items %}
- **{{ f.name[:70] }}** — {{ f.tool }}{% if f.cve %} ({{ f.cve }}){% endif %}

{% endfor %}
</details>
{% endif %}

---

## 四、漏洞利用结果

{% if state.exploit_results %}
### 利用结果摘要

| 漏洞 ID | 状态 | Shell 类型 | 命令数 | 结论摘要 |
|---------|------|------------|--------|----------|
{% for r in state.exploit_results %}| `{{ r.vuln_id }}` | {{ "✅ 成功" if r.success else "❌ 失败" }} | {{ r.shell_type or "N/A" }} | {{ cmd_count(r) }} | {{ table_text(r.evidence, 78) }} |
{% endfor %}

{% for r in state.exploit_results %}

---

### {{ loop.index }}. 漏洞 `{{ r.vuln_id }}`

| 属性 | 值 |
|------|-----|
| **状态** | {{ "✅ 利用成功" if r.success else "❌ 利用失败" }} |
{% if r.shell_type %}| **Shell 类型** | {{ r.shell_type }} |
{% endif %}

{% set rec_list = r.command_records if r.command_records else r.command_results %}
{% if rec_list %}
**执行过程（{{ rec_list | length }} 条命令）：**

{% for rec in rec_list %}

---

#### 步骤 {{ rec.round if rec.round is not none else loop.index }}{% if rec.purpose %} — {{ rec.purpose }}{% endif %}

**命令：**

```bash
{{ rec.command }}
```

**标准输出**（exit={{ rec.exit_code if rec.exit_code is not none else "-" }}，耗时{{ "%.1f"|format(rec.elapsed|float) if rec.elapsed is not none else "-" }}s）：

```text
{{ rec.stdout if rec.stdout else '(无输出)' }}
```

{% if rec.stderr %}
**错误输出：**

```text
{{ rec.stderr }}
```
{% endif %}

{% endfor %}
{% elif r.commands_run %}
**执行命令：**

{% for cmd in r.commands_run %}
```bash
{{ cmd }}
```
{% endfor %}
{% endif %}

{% if r.evidence %}
**最终结论：**

{{ fmt_evidence(r.evidence) }}
{% endif %}

{% endfor %}
{% else %}
无利用尝试或所有漏洞不满足利用条件。
{% endif %}

---

## 五、后渗透发现

{% if state.post_findings and state.post_findings.get('findings') %}
{% for k, v in state.post_findings.get('findings', {}).items() %}
**{{ k }}：**

```
{{ v if v else '无' }}
```

{% endfor %}
{% else %}
无后渗透数据。
{% endif %}

---

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
{% for f in remediation_items %}| {{ table_text(f.name, 44) }} | {{ sev_emoji(f.severity) }} {{ sev_label(f.severity) }} | {{ "立即升级并应用官方补丁" if f.severity in ('critical', 'high') else "维护窗口内修复并完成回归验证" }} | {{ f.cve or "厂商安全公告" }} | {{ "部署 WAF 规则并限制高风险入口暴露" if f.severity in ('critical', 'high') else "审查配置并加强访问控制策略" }} |
{% endfor %}
{% else %}
当前未发现需要立即处置的高/中危漏洞，建议保持基线巡检与补丁更新节奏。
{% endif %}

---

## 七、测试过程日志

```
{% for entry in state.phase_log %}{{ entry }}
{% endfor %}
```

---

## 八、测试方法论

1. **信息收集** — Nmap 端口扫描 + 服务识别，Gobuster Web 路径爆破
2. **漏洞扫描** — Nuclei CVE 检测，Nikto Web 安全扫描，Hydra 弱口令检测
3. **AI 决策分析** — 大语言模型分析漏洞并制定利用优先级
4. **漏洞利用** — LLM 驱动动态生成 Payload + Metasploit 快速通道
5. **后渗透** — 权限提升、信息收集、横向移动评估
6. **报告生成** — 汇总所有发现，提供修复建议

---

*本报告由 PentestAI v2.0 自动生成，仅供授权安全测试使用。*
*生成时间：{{ now }}*
"""


class ReportGenerator:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self._env = Environment(loader=BaseLoader())
        self._env.globals["fmt_evidence"] = format_evidence
        self._env.globals["sev_emoji"] = severity_emoji
        self._env.globals["sev_label"] = severity_label
        self._env.globals["cmd_count"] = command_count
        self._env.globals["table_text"] = table_text
        self._env.globals["safe_val"] = safe_val

    async def generate(self, state) -> tuple[str, str]:
        template = self._env.from_string(MD_TEMPLATE)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        md_content = normalize_markdown_whitespace(template.render(state=state, now=now))

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
                task_id=state.task_id, filename=filename, content=md_content,
            )
            logger.info(f"[ReportGenerator] 报告已上传至 MinIO: {minio_path}")
        except Exception as e:
            logger.warning(f"[ReportGenerator] MinIO 上传失败（已保存本地）: {e}")

        return md_content, minio_path or filepath