"""
解耦后 skill 结构联调单测。

覆盖内容：
  * D1: log_poisoning skill 正确加载, 包含 check_ssh_port / probe_webshell_lang probes
  * D2: log_poisoning 按注入向量分叉为 3 条 ExploitPath (poison_via_ssh/ua/smtp),
        conditions 分别由各自的 canary 标志门控
  * D3: lfi_rfi_exploit 不再包含 log poisoning 相关 probes 和 exploit paths
  * D4: engine._exploit_level_map 覆盖新的 vector-based shell_types
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from backend.skills import engine as engine_module
from backend.skills.loader import load_all_skills
from backend.skills.models import Skill, SkillContext


LFI_SKILL_ID = "lfi_rfi_exploit"
LOG_POISON_SKILL_ID = "log_poisoning"
VECTOR_PATH_IDS = {
    "poison_via_ssh": "ssh_canary_confirmed",
    "poison_via_ua": "ua_canary_confirmed",
    "poison_via_smtp": "smtp_canary_confirmed",
}


@pytest.fixture(scope="module")
def all_skills() -> list[Skill]:
    return load_all_skills()


@pytest.fixture(scope="module")
def lfi_skill(all_skills: list[Skill]) -> Skill:
    for sk in all_skills:
        if sk.skill_id == LFI_SKILL_ID:
            return sk
    pytest.fail(f"Skill {LFI_SKILL_ID} not found in loaded skills")


@pytest.fixture(scope="module")
def log_poison_skill(all_skills: list[Skill]) -> Skill:
    for sk in all_skills:
        if sk.skill_id == LOG_POISON_SKILL_ID:
            return sk
    pytest.fail(f"Skill {LOG_POISON_SKILL_ID} not found in loaded skills")



def test_log_poison_has_check_ssh_port(log_poison_skill: Skill) -> None:
    probes_by_id = {p.id: p for p in log_poison_skill.probes}
    assert "check_ssh_port" in probes_by_id, (
        f"check_ssh_port missing from log_poisoning; probes={list(probes_by_id)}"
    )


def test_log_poison_has_probe_webshell_lang(log_poison_skill: Skill) -> None:
    probes_by_id = {p.id: p for p in log_poison_skill.probes}
    assert "probe_webshell_lang" in probes_by_id, (
        f"probe_webshell_lang missing from log_poisoning; probes={list(probes_by_id)}"
    )


def test_probe_webshell_lang_sets_variable(log_poison_skill: Skill) -> None:
    probe = next(p for p in log_poison_skill.probes if p.id == "probe_webshell_lang")
    assert probe.command, "probe_webshell_lang must have a command"
    assert probe.parse_rules, "probe_webshell_lang must declare parse_rules"

    setting_rule = next(
        (r for r in probe.parse_rules if "webshell_lang" in r.set),
        None,
    )
    assert setting_rule is not None, (
        "parse_rules should set webshell_lang from probe output"
    )


def test_log_poison_has_canary_probes(log_poison_skill: Skill) -> None:
    probes_by_id = {p.id: p for p in log_poison_skill.probes}
    for canary_id in ("canary_probe_ssh", "canary_probe_ua", "canary_probe_smtp"):
        assert canary_id in probes_by_id, (
            f"{canary_id} missing from log_poisoning; probes={list(probes_by_id)}"
        )



def test_log_poison_paths_by_vector(log_poison_skill: Skill) -> None:
    paths_by_id = {p.path_id: p for p in log_poison_skill.exploit_paths}
    for path_id, gate_var in VECTOR_PATH_IDS.items():
        assert path_id in paths_by_id, (
            f"Expected path {path_id}, available={list(paths_by_id)}"
        )
        path = paths_by_id[path_id]
        assert path.conditions.get(gate_var) is True, (
            f"{path_id} must gate on {gate_var}=true, got {path.conditions}"
        )


@pytest.mark.parametrize("path_id,gate_var", list(VECTOR_PATH_IDS.items()))
def test_context_activates_only_matching_vector(
    log_poison_skill: Skill,
    path_id: str,
    gate_var: str,
) -> None:
    """Only the ExploitPath whose canary flag is set should pass .check()."""
    ctx = SkillContext()
    ctx.set_var(gate_var, True)

    passing = {
        p.path_id
        for p in log_poison_skill.exploit_paths
        if p.conditions and any(k in VECTOR_PATH_IDS.values() for k in p.conditions)
        and ctx.check(p.conditions)
    }

    assert passing == {path_id}, (
        f"Setting {gate_var}=true should only activate {path_id}, but got {passing}"
    )


def test_log_poison_paths_have_deliver_and_trigger_steps(log_poison_skill: Skill) -> None:
    paths_by_id = {p.path_id: p for p in log_poison_skill.exploit_paths}
    for path_id in VECTOR_PATH_IDS:
        path = paths_by_id[path_id]
        step_ids = [s.id for s in path.steps]
        has_deliver = any("deliver" in sid for sid in step_ids)
        has_trigger = any("trigger" in sid for sid in step_ids)
        assert has_deliver, f"{path_id} missing deliver step; got {step_ids}"
        assert has_trigger, f"{path_id} missing trigger step; got {step_ids}"



def test_lfi_skill_has_no_log_poison_probes(lfi_skill: Skill) -> None:
    removed_probes = {"check_ssh_port", "probe_webshell_lang"}
    probes_by_id = {p.id: p for p in lfi_skill.probes}
    overlap = removed_probes & set(probes_by_id.keys())
    assert not overlap, (
        f"lfi_rfi_exploit should not contain {overlap} after decoupling"
    )


def test_lfi_skill_has_no_log_poison_paths(lfi_skill: Skill) -> None:
    paths_by_id = {p.path_id: p for p in lfi_skill.exploit_paths}
    old_poison_paths = {
        "lfi_log_poison_php", "lfi_log_poison_jsp", "lfi_log_poison_aspx",
    }
    overlap = old_poison_paths & set(paths_by_id.keys())
    assert not overlap, (
        f"lfi_rfi_exploit should not contain {overlap} after decoupling"
    )


def test_lfi_paths_not_gated_by_webshell_lang(lfi_skill: Skill) -> None:
    """All remaining LFI paths should be language-agnostic."""
    for path in lfi_skill.exploit_paths:
        if path.conditions:
            assert "webshell_lang" not in path.conditions, (
                f"{path.path_id} should not depend on webshell_lang"
            )



def test_engine_exploit_level_map_covers_vector_shell_types() -> None:
    """engine.py's _exploit_level_map must cover the new vector-based shell_types."""
    source = Path(inspect.getfile(engine_module)).read_text(encoding="utf-8")
    required_keys = [
        "rce_ssh_log_poison",
        "rce_access_log_poison",
        "rce_smtp_log_poison",
    ]
    missing = [k for k in required_keys if f'"{k}"' not in source]
    assert not missing, (
        f"engine._exploit_level_map missing shell_type mappings: {missing}"
    )
