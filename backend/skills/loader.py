"""
skills/loader.py
YAML Skill 加载器

职责：
  - 扫描 skills/ 目录下所有 skill.yaml（新格式）或 *.yaml（旧格式）
  - 反序列化为 Skill 数据模型
  - 同时加载侧边 SKILL.md AI 引导文档
  - 校验必填字段

新格式（推荐）：
  skills/<category>/<skill>/
    skill.yaml    ← 匹配规则 + 路径定义
    SKILL.md      ← AI 引导文档
    scripts/      ← 执行脚本

旧格式（向后兼容）：
  skills/<category>/<skill>.yaml
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from backend.skills.models import (
    ExploitPath,
    ExploitStep,
    MatchConfig,
    MatchRule,
    ParseRule,
    Probe,
    ProbeStep,
    Skill,
    SuccessCriteria,
)
from backend.skills.skill_doc import load_skill_doc

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent

# 不扫描 YAML 的子目录
_SKIP_DIRS = {"scripts", "references", "workflows", "templates", "examples"}


def load_all_skills() -> list[Skill]:
    """扫描并加载所有 Skill YAML 文件（兼容新旧格式）"""
    skills: list[Skill] = []
    loaded_dirs: set[Path] = set()

    # 1) 新格式：扫描 */skill.yaml
    for yaml_path in SKILLS_DIR.rglob("skill.yaml"):
        parent_dir = yaml_path.parent
        if _should_skip_path(parent_dir):
            continue
        try:
            skill = load_skill(yaml_path)
            skills.append(skill)
            loaded_dirs.add(parent_dir)
            logger.info("[SkillLoader] 加载: %s (%s)", skill.skill_id, yaml_path.parent.name)
        except Exception as e:
            logger.warning("[SkillLoader] 加载失败 %s: %s", yaml_path, e)

    # 2) 旧格式：扫描剩余 *.yaml（不在已加载目录或跳过目录中）
    for yaml_path in SKILLS_DIR.rglob("*.yaml"):
        if yaml_path.name == "skill.yaml":
            continue  # 已在上面处理
        parent_dir = yaml_path.parent
        if parent_dir in loaded_dirs:
            continue  # 该目录已有新格式
        if _should_skip_path(parent_dir):
            continue
        try:
            skill = load_skill(yaml_path)
            skills.append(skill)
            logger.info("[SkillLoader] 加载(旧): %s (%s)", skill.skill_id, yaml_path.name)
        except Exception as e:
            logger.warning("[SkillLoader] 加载失败 %s: %s", yaml_path, e)

    logger.info("[SkillLoader] 共加载 %d 个 Skill", len(skills))
    return skills


def _should_skip_path(path: Path) -> bool:
    """检查路径是否属于不该扫描的目录"""
    for part in path.parts:
        if part in _SKIP_DIRS:
            return True
    return False


def load_skill(path: Path) -> Skill:
    """
    加载单个 YAML 文件为 Skill 对象。

    同时尝试加载同目录下的 SKILL.md 作为 AI 引导文档（可选）。
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        raise ValueError(f"无效的 Skill 文件: {path}")

    skill_id = raw.get("skill_id", "")
    if not skill_id:
        raise ValueError(f"缺少 skill_id: {path}")

    skill = Skill(
        skill_id=skill_id,
        name=raw.get("name", skill_id),
        category=raw.get("category", ""),
        phase=raw.get("phase", "foothold"),
        version=raw.get("version", "1.0"),
        principle=raw.get("principle", ""),
        match=_parse_match(raw.get("match", {})),
        probes=_parse_probes(raw.get("probes", [])),
        exploit_paths=_parse_paths(raw.get("exploit_paths", [])),
        remediation=raw.get("remediation", ""),
        source_file=str(path),
    )

    # 加载侧边 SKILL.md（AI 引导文档，可选）
    skill_dir = path.parent
    doc_path = skill_dir / "SKILL.md"
    if doc_path.exists():
        skill.doc = load_skill_doc(doc_path)

    _validate_variable_consistency(skill, path)
    return skill



def _parse_match(raw: dict) -> MatchConfig:
    return MatchConfig(
        rules=[_parse_match_rule(r) for r in raw.get("rules", [])],
        exclude=[_parse_match_rule(r) for r in raw.get("exclude", [])],
    )


def _parse_match_rule(raw: dict) -> MatchRule:
    return MatchRule(
        fingerprint_contains=_ensure_list(raw.get("fingerprint_contains", [])),
        cve_matches=_ensure_list(raw.get("cve_matches", [])),
        evidence_contains=_ensure_list(raw.get("evidence_contains", [])),
        json_probe_result=raw.get("json_probe_result", ""),
        service_is=raw.get("service_is", ""),
        port_is=_ensure_list(raw.get("port_is", [])),
        tool_is=raw.get("tool_is", ""),
        variable_present=_ensure_list(raw.get("variable_present", [])),
    )


def _parse_probes(raw_list: list) -> list[Probe]:
    probes = []
    for raw in raw_list:
        probe = Probe(
            id=raw.get("id", ""),
            description=raw.get("description", ""),
            command=raw.get("command", ""),
            parse_rules=[_parse_parse_rule(r) for r in raw.get("parse_rules", [])],
            timeout=raw.get("timeout", 15),
            steps=[_parse_probe_step(s) for s in raw.get("steps", [])],
            depends_on=raw.get("depends_on", {}),
            requires=raw.get("requires", {}),
            skip_if=raw.get("skip_if", {}),
        )
        probes.append(probe)
    return probes


def _parse_probe_step(raw: dict) -> ProbeStep:
    return ProbeStep(
        command=raw.get("command", ""),
        parse_rules=[_parse_parse_rule(r) for r in raw.get("parse_rules", [])],
        timeout=raw.get("timeout", 15),
    )


def _parse_parse_rule(raw: dict) -> ParseRule:
    return ParseRule(
        if_contains=_ensure_list(raw.get("if_contains", [])),
        if_not_contains=_ensure_list(raw.get("if_not_contains", [])),
        if_status_code=_ensure_list(raw.get("if_status_code", [])),
        if_regex=raw.get("if_regex", ""),
        and_body_not_empty=raw.get("and_body_not_empty", False),
        set=raw.get("set", {}),
    )


def _parse_paths(raw_list: list) -> list[ExploitPath]:
    paths = []
    for raw in raw_list:
        path = ExploitPath(
            path_id=raw.get("path_id", ""),
            name=raw.get("name", ""),
            priority=raw.get("priority", 10),
            principle=raw.get("principle", ""),
            conditions=raw.get("conditions", {}),
            conditions_any=raw.get("conditions_any", []),
            skip_if=raw.get("skip_if", {}),
            steps=[_parse_step(s) for s in raw.get("steps", [])],
            mode=raw.get("mode", ""),
            max_rounds=raw.get("max_rounds", 5),
        )
        paths.append(path)
    return paths


def _parse_step(raw: dict) -> ExploitStep:
    sc_raw = raw.get("success_criteria", {})
    success_criteria = SuccessCriteria(
        stdout_contains_any=_ensure_list(sc_raw.get("stdout_contains_any", [])),
        stdout_contains_all=_ensure_list(sc_raw.get("stdout_contains_all", [])),
        stdout_not_empty=sc_raw.get("stdout_not_empty", False),
        stdout_regex=sc_raw.get("stdout_regex", ""),
        exit_code=sc_raw.get("exit_code"),
    )

    return ExploitStep(
        id=raw.get("id", ""),
        description=raw.get("description", ""),
        command=raw.get("command", ""),
        timeout=raw.get("timeout", 30),
        publish_ports=_ensure_list(raw.get("publish_ports", [])),
        success_criteria=success_criteria,
        on_success=raw.get("on_success", "next_step"),
        on_fail=raw.get("on_fail", "next_path"),
        evidence_capture=raw.get("evidence_capture", {}),
    )


def _ensure_list(value: Any) -> list:
    """确保返回列表（YAML 中单值自动包装）"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _validate_variable_consistency(skill: Skill, path: Path) -> None:
    """Warn at load time if conditions reference variables not set by any probe."""
    produced: set[str] = set()
    for probe in skill.probes:
        for rule in probe.parse_rules:
            produced.update(rule.set.keys())
        for step in probe.steps:
            for rule in step.parse_rules:
                produced.update(rule.set.keys())

    consumed: set[str] = set()
    for probe in skill.probes:
        consumed.update(probe.depends_on.keys())
        consumed.update(probe.requires.keys())
    for ep in skill.exploit_paths:
        consumed.update(ep.conditions.keys())
        consumed.update(ep.skip_if.keys())
        for group in ep.conditions_any:
            consumed.update(group.keys())

    consumed_non_env = {v for v in consumed if not v.startswith("env.")}
    orphans = consumed_non_env - produced
    if orphans:
        logger.warning(
            "[SkillLoader] %s (%s): conditions reference variables "
            "never set by probes: %s",
            skill.skill_id, path.name, orphans,
        )