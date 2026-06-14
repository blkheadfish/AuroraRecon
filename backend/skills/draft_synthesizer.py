"""
skills/draft_synthesizer.py — 从成功执行记录生成 Skill 草案

草案格式：套 skill.yaml schema，标 status: draft, source_task_id,
generated_at。写入 skills/.drafts/<name>.skill.yaml.draft。

W4-T3: 实战跑通但库外存在的利用序列沉淀为待人工 review 的草案。
文件名用双重保险（.drafts 目录 + .draft 后缀），确保 loader 不加载。
"""
from __future__ import annotations

import hashlib
import logging
import re
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from backend.agents.models import VulnFinding, ExploitResult, CommandExecutionRecord

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent
DRAFTS_DIR = SKILLS_DIR / ".drafts"

DRAFT_TEMPLATE = """\
skill_id: {skill_id}
name: {name}
category: {category}
phase: {phase}
version: "0.1.0-draft"
status: draft
source_task_id: {source_task_id}
generated_at: {generated_at}
principle: {principle}
match:
  cves: [{cves}]
  keywords: [{keywords}]
  fingerprints: [{fingerprints}]
  evidence_keywords: [{evidence_keywords}]
probes: []
exploit_paths:
  - path_id: {path_id}
    name: "Auto-extracted exploit path"
    description: |
      Auto-generated from task {source_task_id} successful exploit steps.
      Review and adjust before promoting to production.
    priority: 5
    success_criteria:
      - type: output_contains
        expected: "{success_marker}"
    conditions: {{}}
    steps:
{steps_yaml}
remediation: "待补充"
"""


def _sanitize_id(raw: str) -> str:
    """生成安全的 skill_id：保留 alphanumeric + 下划线。"""
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw)[:64].lower()


def _extract_success_marker(evidence: str) -> str:
    """从证据中提取简短的成功标识。"""
    if not evidence:
        return "200 OK"
    for marker in ("uid=", "root:", "nt authority\\\\system", "RCE confirmed",
                   "admin", "whoami", "id="):
        if marker.lower() in evidence.lower():
            snippet = evidence.lower().split(marker.lower())[0][-20:] + marker
            return snippet[:80].replace("\n", " ").strip()
    return evidence[:80].replace("\n", " ").strip()


def _infer_category(finding: VulnFinding) -> str:
    name = (finding.name or "").lower()
    cve_str = (finding.cve or "").lower()
    ports = getattr(finding, "port", 0) or 0

    if "deserial" in name or "rce" in name or "execution" in name:
        return "web_rce"
    if "sqli" in name or "inject" in name or "xss" in name or "lfi" in name:
        return "web_inject"
    if any(p in name for p in ("smb", "ldap", "kerberos", "rdp", "ssh", "winrm")):
        return "network"
    if "misconfig" in name or "exposure" in name:
        return "server_misconfig"
    if "brute" in name or "password" in name or "credential" in name:
        return "credential"
    return "web_rce"


def generate_draft_yaml(
    finding: VulnFinding,
    result: ExploitResult,
    tool_records: list[dict],
    task_id: str,
    name: str = "",
    principle: str = "",
) -> str:
    """从成功利用结果生成 Skill draft YAML。

    Args:
        finding: 关联的漏洞发现
        result: 成功的利用结果（含 commands_run/command_records）
        tool_records: 任务的所有工具执行记录
        task_id: 来源任务 ID
        name: draft 名称（可选，默认从 finding 推断）
        principle: 漏洞原理（可选）

    Returns:
        生成的 YAML 字符串
    """
    category = _infer_category(finding)
    safe_name = name or finding.name or "unknown"
    draft_name = _sanitize_id(safe_name)
    skill_id = f"draft_{draft_name}_{hashlib.sha1(task_id.encode()).hexdigest()[:8]}"
    phase = "foothold"

    commands_run = list(result.commands_run or [])
    command_records = list(result.command_records or []) if hasattr(result, "command_records") else []

    # Build steps YAML from command_records (preferred) or commands_run
    steps_list: list[dict] = []
    if command_records:
        for i, rec in enumerate(command_records):
            cmd = ""
            if isinstance(rec, dict):
                cmd = rec.get("command", "") or rec.get("runtime_command", "")
            elif hasattr(rec, "command"):
                cmd = rec.command
            if not cmd:
                continue
            steps_list.append({
                "step_id": f"step_{i + 1}",
                "description": f"Step {i + 1} from task {task_id[:8]}",
                "command": cmd,
                "expected_stdout_contains": "",
                "timeout": 120,
            })
    elif commands_run:
        for i, cmd in enumerate(commands_run):
            if not cmd or not isinstance(cmd, str):
                continue
            steps_list.append({
                "step_id": f"step_{i + 1}",
                "description": f"Step {i + 1}: {cmd[:60]}",
                "command": cmd,
                "expected_stdout_contains": "",
                "timeout": 120,
            })

    if not steps_list:
        return ""

    # Format steps as YAML indented under the steps: key
    steps_yaml_lines: list[str] = []
    for step in steps_list:
        steps_yaml_lines.append(f"      - step_id: {step['step_id']}")
        steps_yaml_lines.append(f'        description: "{step["description"]}"')
        cmd_escaped = step["command"].replace("\\", "\\\\").replace('"', '\\"')
        if len(cmd_escaped) > 400:
            cmd_escaped = cmd_escaped[:400] + "...(truncated)"
        steps_yaml_lines.append(f'        command: "{cmd_escaped}"')
        if step["expected_stdout_contains"]:
            steps_yaml_lines.append(f'        expected_stdout_contains: "{step["expected_stdout_contains"]}"')
        steps_yaml_lines.append(f"        timeout: {step['timeout']}")

    steps_block = "\n".join(steps_yaml_lines) if steps_yaml_lines else "      []"

    success_marker = _extract_success_marker(result.evidence or "")
    cves_str = f'"{finding.cve}"' if finding.cve else ""
    keywords_str = f'"{safe_name}"' if safe_name else ""
    evidence_keywords = success_marker

    yaml_str = DRAFT_TEMPLATE.format(
        skill_id=skill_id,
        name=safe_name,
        category=category,
        phase=phase,
        source_task_id=task_id,
        generated_at=datetime.utcnow().isoformat(),
        principle=principle or finding.description or finding.name or "Auto-extracted",
        cves=cves_str,
        keywords=keywords_str,
        fingerprints="",
        evidence_keywords=f'"{evidence_keywords}"',
        path_id=f"auto_{draft_name}",
        success_marker=success_marker,
        steps_yaml=steps_block,
    )
    return yaml_str


def write_draft(yaml_str: str, skill_id: str) -> Path:
    """将 YAML 草案写入 .drafts/ 目录。"""
    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = _sanitize_id(skill_id)
    filename = f"{safe_name}.skill.yaml.draft"
    filepath = DRAFTS_DIR / filename
    filepath.write_text(yaml_str, encoding="utf-8")
    logger.info(f"[draft_synthesizer] 草案写入: {filepath}")
    return filepath


def list_drafts() -> list[dict]:
    """列出 .drafts/ 下所有草案文件。"""
    if not DRAFTS_DIR.exists():
        return []
    drafts: list[dict] = []
    for f in sorted(DRAFTS_DIR.glob("*.skill.yaml.draft")):
        try:
            raw = f.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
            if not isinstance(data, dict):
                continue
            drafts.append({
                "skill_id": data.get("skill_id", f.stem),
                "name": data.get("name", f.stem),
                "category": data.get("category", ""),
                "status": data.get("status", "draft"),
                "source_task_id": data.get("source_task_id", ""),
                "generated_at": data.get("generated_at", ""),
                "filename": f.name,
                "filepath": str(f),
                "yaml": raw,
            })
        except Exception as e:
            logger.warning(f"[draft_synthesizer] 读取草案失败 {f}: {e}")
    return drafts


def get_draft(name: str) -> Optional[dict]:
    """读取单个草案文件。"""
    drafts = list_drafts()
    for d in drafts:
        if d["skill_id"] == name or d["filename"] == name or d["filename"].startswith(f"{name}."):
            return d
    return None


def promote_draft(name: str) -> Optional[Path]:
    """将草案转正：从 .drafts/ 移到正式 skills 目录。

    复制到 skills/ 对应 category 目录下。
    """
    draft = get_draft(name)
    if not draft:
        logger.warning(f"[draft_synthesizer] 草案不存在: {name}")
        return None

    yaml_content = draft.get("yaml", "")
    category = draft.get("category", "web_rce")
    category_dir = SKILLS_DIR / category

    skill_id = draft.get("skill_id", name)
    safe_name = _sanitize_id(skill_id)
    dest_dir = category_dir / safe_name
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Strip draft-only fields and rename to skill.yaml
    try:
        data = yaml.safe_load(yaml_content)
        data.pop("status", None)
        data.pop("source_task_id", None)
        data.pop("generated_at", None)
        cleaned = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except Exception:
        cleaned = yaml_content

    dest_file = dest_dir / "skill.yaml"
    dest_file.write_text(cleaned, encoding="utf-8")

    # Delete original draft
    draft_path = Path(draft["filepath"])
    if draft_path.exists():
        draft_path.unlink()

    logger.info(f"[draft_synthesizer] 草稿转正: {name} → {dest_file}")
    return dest_file


def delete_draft(name: str) -> bool:
    """删除草案文件。"""
    draft = get_draft(name)
    if not draft:
        return False
    draft_path = Path(draft["filepath"])
    if draft_path.exists():
        draft_path.unlink()
        logger.info(f"[draft_synthesizer] 草案已删除: {name}")
        return True
    return False
