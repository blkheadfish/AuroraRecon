"""
skills/loader.py
YAML Skill 加载器 — 渐进式加载（Progressive Disclosure）

职责：
  - 启动时只加载 metadata（~50 tokens/skill）用于匹配
  - 执行时按需加载完整 Skill + references/*.md
  - 同时加载侧边 SKILL.md AI 引导文档
  - 校验必填字段

新格式（推荐）：
  skills/<category>/<skill>/
    skill.yaml    ← 匹配规则 + 路径定义
    SKILL.md      ← AI 引导文档
    scripts/      ← 执行脚本
    references/   ← 参考资料（按需加载）

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
    LlmConfig,
    MatchConfig,
    MatchRule,
    ParseRule,
    Probe,
    ProbeStep,
    Skill,
    SkillMeta,
    SuccessCriteria,
)
from backend.skills.skill_doc import load_skill_doc

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent

# 不扫描 YAML 的子目录（references 可在执行时加载）
# W4-T3: .drafts 目录包含待审核草案，不自动加载
_SKIP_DIRS = {"scripts", "workflows", "templates", "examples", ".drafts"}


def load_skills_metadata() -> list[SkillMeta]:
    """启动时加载：只提取匹配和路由所需的轻量元数据（~50 tokens/skill）。"""
    metas: list[SkillMeta] = []
    loaded_dirs: set[Path] = set()

    # 1) 新格式：扫描 */skill.yaml
    for yaml_path in SKILLS_DIR.rglob("skill.yaml"):
        parent_dir = yaml_path.parent
        if _should_skip_path(parent_dir):
            continue
        try:
            meta = _load_skill_meta(yaml_path)
            metas.append(meta)
            loaded_dirs.add(parent_dir)
        except Exception as e:
            logger.warning("[SkillLoader] Metadata 加载失败 %s: %s", yaml_path, e)

    # 2) 旧格式：扫描剩余 *.yaml（不在已加载目录中）
    for yaml_path in SKILLS_DIR.rglob("*.yaml"):
        if yaml_path.name == "skill.yaml":
            continue
        parent_dir = yaml_path.parent
        if parent_dir in loaded_dirs:
            continue
        if _should_skip_path(parent_dir):
            continue
        try:
            meta = _load_skill_meta(yaml_path)
            metas.append(meta)
        except Exception as e:
            logger.warning("[SkillLoader] Metadata 加载失败 %s: %s", yaml_path, e)

    logger.info("[SkillLoader] Metadata: 加载 %d 个 Skill", len(metas))
    return metas


def _load_skill_meta(path: Path) -> SkillMeta:
    """只解析 YAML frontmatter 中的路由信息，不加载 probes/paths 详情。"""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not raw or not isinstance(raw, dict):
        raise ValueError(f"无效的 Skill 文件: {path}")

    skill_id = raw.get("skill_id", "")
    if not skill_id:
        raise ValueError(f"缺少 skill_id: {path}")

    return SkillMeta(
        skill_id=skill_id,
        name=raw.get("name", skill_id),
        description=raw.get("description", raw.get("principle", ""))[:200],
        category=raw.get("category", ""),
        phase=raw.get("phase", "foothold"),
        match=_parse_match(raw.get("match", {})),
        source_file=str(path),
    )


def load_skill_full(skill_id_or_path: str) -> Skill | None:
    """
    按需加载完整 Skill（含 probes、exploit_paths、SKILL.md、references）。

    支持按 skill_id 或 source_file 路径查找。
    """
    # 尝试按路径查找
    path = Path(skill_id_or_path)
    if path.exists() and path.suffix in (".yaml", ".yml"):
        return _load_skill_full_from_path(path)

    # 按 skill_id 搜索
    for yaml_path in SKILLS_DIR.rglob("skill.yaml"):
        if _should_skip_path(yaml_path.parent):
            continue
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if raw and raw.get("skill_id") == skill_id_or_path:
                return _load_skill_full_from_path(yaml_path)
        except Exception:
            continue

    # 旧格式 fallback
    for yaml_path in SKILLS_DIR.rglob("*.yaml"):
        if yaml_path.name == "skill.yaml":
            continue
        if _should_skip_path(yaml_path.parent):
            continue
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if raw and raw.get("skill_id") == skill_id_or_path:
                return _load_skill_full_from_path(yaml_path)
        except Exception:
            continue

    logger.warning("[SkillLoader] 未找到 Skill: %s", skill_id_or_path)
    return None


def _load_skill_full_from_path(path: Path) -> Skill | None:
    """从 YAML 路径加载完整 Skill（含 probes/paths/doc/references）。"""
    try:
        skill = load_skill(path)
        # 加载 references
        skill_dir = path.parent
        skill.references = load_skill_references(skill_dir)
        if skill.references:
            logger.info(
                "[SkillLoader] %s: 加载 %d 个 references",
                skill.skill_id, len(skill.references),
            )
        return skill
    except Exception as e:
        logger.warning("[SkillLoader] 完整加载失败 %s: %s", path, e)
        return None


def load_skill_references(skill_dir: Path) -> dict[str, str]:
    """
    扫描 skill_dir/references/*.md，返回 {filename: content}。

    用于注入 _react_freeform LLM context。
    """
    refs_dir = skill_dir / "references"
    if not refs_dir.is_dir():
        return {}

    refs: dict[str, str] = {}
    for md_path in sorted(refs_dir.glob("*.md")):
        try:
            content = md_path.read_text(encoding="utf-8").strip()
            if content:
                refs[md_path.name] = content
        except Exception as e:
            logger.warning("[SkillLoader] 读取 reference 失败 %s: %s", md_path, e)

    return refs


def load_all_skills() -> list[Skill]:
    """全量加载所有 Skill（保留向后兼容，内部使用渐进式加载的 metadata 路径）。"""
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
            continue
        parent_dir = yaml_path.parent
        if parent_dir in loaded_dirs:
            continue
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
        selector=raw.get("selector"),
        llm_config=_parse_llm_config(raw.get("llm", {})),
    )

    # 加载侧边 SKILL.md（AI 引导文档，可选）
    skill_dir = path.parent
    doc_path = skill_dir / "SKILL.md"
    if doc_path.exists():
        skill.doc = load_skill_doc(doc_path)

    schema_warnings = validate_skill_schema(raw, path)
    for w in schema_warnings:
        logger.warning("[SkillLoader] Schema 警告 — %s: %s", skill.skill_id, w)

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
            on_success=raw.get("on_success", {}),
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


def _parse_llm_config(raw: dict) -> LlmConfig:
    """解析 skill.yaml 中可选的 llm: 节"""
    if not raw or not isinstance(raw, dict):
        return LlmConfig()
    return LlmConfig(
        freeform_system_prompt=raw.get("freeform_system_prompt", ""),
        max_rounds=int(raw.get("max_rounds", 5)),
    )


_REQUIRED_FIELDS = ["skill_id", "name", "category", "phase"]
_CATEGORIES = {
    "credential", "java_deserialization", "network", "persistence",
    "privesc", "recon", "server_misconfig", "web_inject", "web_rce",
}
_PHASES = {"foothold", "privesc", "recon", "persistence", "post_exploit"}


def validate_skill_schema(raw: dict, path: Path) -> list[str]:
    """校验 skill.yaml 结构完整性，返回 warning 列表。

    - 缺失必填字段 → 抛 ValueError
    - 字段类型不对 / 建议值不在已知集合中 → warning
    """
    warnings: list[str] = []
    if not raw or not isinstance(raw, dict):
        raise ValueError(f"无效的 Skill YAML（不是字典）: {path}")

    for field in _REQUIRED_FIELDS:
        if not raw.get(field):
            raise ValueError(f"缺失必填字段 '{field}': {path}")

    category = raw.get("category", "")
    if category not in _CATEGORIES:
        warnings.append(
            f"category '{category}' 不在已知分类中（{sorted(_CATEGORIES)}）"
        )

    phase = raw.get("phase", "")
    if phase not in _PHASES:
        warnings.append(
            f"phase '{phase}' 不在已知阶段中（{sorted(_PHASES)}）"
        )

    match = raw.get("match")
    if not match or not isinstance(match, dict):
        warnings.append("未定义 match 节 — skill 将永远不会被自动匹配")
    else:
        rules = match.get("rules", [])
        if not isinstance(rules, list) or len(rules) == 0:
            warnings.append("match.rules 为空 — skill 将永远不会被自动匹配")

    probes = raw.get("probes", [])
    if not isinstance(probes, list) or len(probes) == 0:
        warnings.append("未定义 probes — 没有探测阶段")

    paths = raw.get("exploit_paths", [])
    if not isinstance(paths, list) or len(paths) == 0:
        warnings.append("未定义 exploit_paths — 没有利用路径")

    if isinstance(paths, list):
        for ep in paths:
            if not isinstance(ep, dict):
                continue
            steps = ep.get("steps", [])
            if not isinstance(steps, list) or len(steps) == 0:
                mode = ep.get("mode", "")
                if mode != "react_freeform":
                    warnings.append(
                        f"exploit_path '{ep.get('path_id', '?')}' 未定义 steps "
                        f"且 mode 不是 react_freeform"
                    )

    return warnings


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
