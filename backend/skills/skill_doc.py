"""
skills/skill_doc.py
SKILL.md 解析器

解析 SKILL.md 文件的 YAML frontmatter + Markdown body，
为 Skill 匹配和执行提供 AI 引导信息。

SKILL.md 格式：
    ---
    name: skill-name
    description: What it does and when to use it
    skill_type: exploit | recon | privesc
    severity: critical | high | medium | low | info
    tags: [tag1, tag2]
    ---
    # Title
    ## When to Use
    ...
    ## When NOT to Use
    ...
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SkillDoc:
    """解析后的 SKILL.md 内容"""

    name: str = ""
    description: str = ""
    skill_type: str = "exploit"
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)

    # Markdown body sections
    body: str = ""
    essential_principles: str = ""
    when_to_use: str = ""
    when_not_to_use: str = ""
    rationalizations: str = ""
    quick_start: str = ""
    path_selection: str = ""  # 路径选择表

    source_path: str = ""

    @property
    def guidance_text(self) -> str:
        """拼接可用作 LLM prompt 的引导文本"""
        parts = []
        if self.essential_principles:
            parts.append(f"## Essential Principles\n{self.essential_principles}")
        if self.when_to_use:
            parts.append(f"## When to Use\n{self.when_to_use}")
        if self.when_not_to_use:
            parts.append(f"## When NOT to Use\n{self.when_not_to_use}")
        if self.rationalizations:
            parts.append(f"## Rationalizations to Reject\n{self.rationalizations}")
        if self.path_selection:
            parts.append(f"## Path Selection\n{self.path_selection}")
        if self.quick_start:
            parts.append(f"## Quick Start\n{self.quick_start}")
        return "\n\n".join(parts)


def load_skill_doc(path: Path) -> Optional[SkillDoc]:
    """
    从 SKILL.md 文件加载解析。

    返回 None 表示文件不存在或解析失败。
    """
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        logger.warning("[SkillDoc] 读取失败: %s", path)
        return None

    frontmatter, body = _split_frontmatter(content)

    doc = SkillDoc(source_path=str(path))

    if frontmatter:
        try:
            fm = yaml.safe_load(frontmatter)
            if fm and isinstance(fm, dict):
                doc.name = str(fm.get("name", ""))
                doc.description = str(fm.get("description", ""))
                doc.skill_type = str(fm.get("skill_type", "exploit"))
                doc.severity = str(fm.get("severity", "medium"))
                doc.tags = _ensure_list(fm.get("tags", []))
                doc.cve = _ensure_list(fm.get("cve", []))
        except yaml.YAMLError:
            logger.warning("[SkillDoc] YAML 解析失败: %s", path)

    doc.body = body
    doc.essential_principles = _extract_section(body, "Essential Principles") or _extract_section(body, "漏洞原理")
    doc.when_to_use = _extract_section(body, "When to Use")
    doc.when_not_to_use = _extract_section(body, "When NOT to Use")
    doc.rationalizations = _extract_section(body, "Rationalizations to Reject")
    doc.quick_start = _extract_section(body, "Quick Start")
    doc.path_selection = _extract_section(body, "路径选择") or _extract_section(body, "Path Selection")

    return doc


def find_skill_doc(skill_dir: Path) -> Optional[Path]:
    """在 skill 目录下查找 SKILL.md"""
    candidate = skill_dir / "SKILL.md"
    if candidate.exists():
        return candidate
    return None


def _split_frontmatter(content: str) -> tuple[str, str]:
    """分离 YAML frontmatter 和 Markdown body"""
    if not content.startswith("---"):
        return "", content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return "", content

    return parts[1].strip(), parts[2].strip()


def _extract_section(body: str, heading: str) -> str:
    """提取指定 ## 标题下的内容（直到下一个 ## 标题）"""
    lines = body.split("\n")
    in_section = False
    result: list[str] = []

    for line in lines:
        if in_section and line.startswith("## "):
            break
        if in_section:
            result.append(line)
        if line.strip() == f"## {heading}":
            in_section = True

    return "\n".join(result).strip()


def _ensure_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]
