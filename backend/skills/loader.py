"""
skills/loader.py
YAML Skill 加载器

职责：
  - 扫描 skills/ 目录下所有 .yaml 文件
  - 反序列化为 Skill 数据模型
  - 校验必填字段
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

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent


def load_all_skills() -> list[Skill]:
    """扫描并加载所有 Skill YAML 文件"""
    skills: list[Skill] = []

    for yaml_path in SKILLS_DIR.rglob("*.yaml"):
        try:
            skill = load_skill(yaml_path)
            skills.append(skill)
            logger.info(f"[SkillLoader] 加载: {skill.skill_id} ({yaml_path.name})")
        except Exception as e:
            logger.warning(f"[SkillLoader] 加载失败 {yaml_path}: {e}")

    logger.info(f"[SkillLoader] 共加载 {len(skills)} 个 Skill")
    return skills


def load_skill(path: Path) -> Skill:
    """加载单个 YAML 文件为 Skill 对象"""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        raise ValueError(f"无效的 Skill 文件: {path}")

    skill_id = raw.get("skill_id", "")
    if not skill_id:
        raise ValueError(f"缺少 skill_id: {path}")

    return Skill(
        skill_id=skill_id,
        name=raw.get("name", skill_id),
        category=raw.get("category", ""),
        version=raw.get("version", "1.0"),
        principle=raw.get("principle", ""),
        match=_parse_match(raw.get("match", {})),
        probes=_parse_probes(raw.get("probes", [])),
        exploit_paths=_parse_paths(raw.get("exploit_paths", [])),
        remediation=raw.get("remediation", ""),
        source_file=str(path),
    )


# ─────────────────────────────────────────────────────────
# 内部解析函数
# ─────────────────────────────────────────────────────────

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
