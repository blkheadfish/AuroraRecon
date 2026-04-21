"""
C 组（log poisoning language dispatcher）联调单测。

覆盖内容：
  * C1: probe_webshell_lang 被正确加载到 lfi_rfi_exploit 的 probes 中，
        且 parse_rules 能把 WEBSHELL_LANG:* 写入 context.variables["webshell_lang"]
  * C2 / C5 / C6: log poisoning 按 webshell_lang 分叉为 3 条 ExploitPath，
        conditions 只在目标语言命中时通过
  * C7: engine.py 的 _exploit_level_map 含 6 个新的 rce_*_log_poison_{php,jsp,aspx}
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from backend.skills import engine as engine_module
from backend.skills.loader import load_all_skills
from backend.skills.models import Skill, SkillContext


LFI_SKILL_ID = "lfi_rfi_exploit"
LANG_PATH_IDS = {
    "php": "lfi_log_poison_php",
    "jsp": "lfi_log_poison_jsp",
    "aspx": "lfi_log_poison_aspx",
}


@pytest.fixture(scope="module")
def lfi_skill() -> Skill:
    skills = load_all_skills()
    for sk in skills:
        if sk.skill_id == LFI_SKILL_ID:
            return sk
    pytest.fail(f"Skill {LFI_SKILL_ID} not found in loaded skills")


# ─────────────────────────────────────────────────────────────────
# C1 · probe_webshell_lang
# ─────────────────────────────────────────────────────────────────

def test_probe_webshell_lang_present(lfi_skill: Skill) -> None:
    probes_by_id = {p.id: p for p in lfi_skill.probes}
    assert "probe_webshell_lang" in probes_by_id, (
        f"probe_webshell_lang missing; probes={list(probes_by_id)}"
    )


def test_probe_webshell_lang_parse_rule_sets_variable(lfi_skill: Skill) -> None:
    probe = next(p for p in lfi_skill.probes if p.id == "probe_webshell_lang")
    assert probe.command, "probe_webshell_lang must have a command"
    assert probe.parse_rules, "probe_webshell_lang must declare parse_rules"

    setting_rule = next(
        (r for r in probe.parse_rules if "webshell_lang" in r.set),
        None,
    )
    assert setting_rule is not None, (
        "parse_rules should set webshell_lang from probe output"
    )
    assert setting_rule.if_regex, (
        "parse_rule should gate on an if_regex matching WEBSHELL_LANG:<lang>"
    )


# ─────────────────────────────────────────────────────────────────
# C2 / C5 / C6 · exploit paths forked by webshell_lang
# ─────────────────────────────────────────────────────────────────

def test_log_poison_paths_forked_by_lang(lfi_skill: Skill) -> None:
    paths_by_id = {p.path_id: p for p in lfi_skill.exploit_paths}

    for lang, path_id in LANG_PATH_IDS.items():
        assert path_id in paths_by_id, (
            f"Expected path {path_id} for lang={lang}, available={list(paths_by_id)}"
        )
        path = paths_by_id[path_id]
        assert path.conditions.get("lfi_confirmed") is True, (
            f"{path_id} must gate on lfi_confirmed=true"
        )
        assert path.conditions.get("webshell_lang") == lang, (
            f"{path_id} must gate on webshell_lang={lang}, got {path.conditions}"
        )


def test_log_poison_steps_named_per_lang(lfi_skill: Skill) -> None:
    paths_by_id = {p.path_id: p for p in lfi_skill.exploit_paths}

    for lang, path_id in LANG_PATH_IDS.items():
        path = paths_by_id[path_id]
        step_ids = [s.id for s in path.steps]
        assert f"log_poison_ssh_{lang}" in step_ids, (
            f"{path_id} missing log_poison_ssh_{lang} step; got {step_ids}"
        )
        assert f"log_poison_access_log_{lang}" in step_ids, (
            f"{path_id} missing log_poison_access_log_{lang} step; got {step_ids}"
        )


@pytest.mark.parametrize("active_lang", ["php", "jsp", "aspx"])
def test_context_picks_only_matching_lang_path(
    lfi_skill: Skill,
    active_lang: str,
) -> None:
    """Only the ExploitPath whose webshell_lang matches ctx should pass .check()."""
    ctx = SkillContext()
    ctx.set_var("lfi_confirmed", True)
    ctx.set_var("webshell_lang", active_lang)

    passing = {
        p.path_id
        for p in lfi_skill.exploit_paths
        if p.conditions.get("webshell_lang") in LANG_PATH_IDS
        and ctx.check(p.conditions)
    }

    expected = {LANG_PATH_IDS[active_lang]}
    assert passing == expected, (
        f"webshell_lang={active_lang} should only activate {expected}, "
        f"but got {passing}"
    )


def test_other_lfi_paths_not_gated_by_webshell_lang(lfi_skill: Skill) -> None:
    """Non-log-poison paths (wrapper RCE, cred reuse, etc.) must stay language-agnostic."""
    lang_path_ids = set(LANG_PATH_IDS.values())
    for path in lfi_skill.exploit_paths:
        if path.path_id in lang_path_ids:
            continue
        assert "webshell_lang" not in path.conditions, (
            f"{path.path_id} should not depend on webshell_lang but has {path.conditions}"
        )


# ─────────────────────────────────────────────────────────────────
# C7 · engine._exploit_level_map coverage
# ─────────────────────────────────────────────────────────────────

def test_engine_exploit_level_map_covers_language_variants() -> None:
    """engine.py's local _exploit_level_map must declare the 6 new shell_types.

    _exploit_level_map is a local dict inside a method, so we inspect the
    engine source text rather than binding to a runtime object.
    """
    source = Path(inspect.getfile(engine_module)).read_text(encoding="utf-8")
    required_keys = [
        "rce_ssh_log_poison_php",
        "rce_ssh_log_poison_jsp",
        "rce_ssh_log_poison_aspx",
        "rce_access_log_poison_php",
        "rce_access_log_poison_jsp",
        "rce_access_log_poison_aspx",
    ]
    missing = [k for k in required_keys if f'"{k}"' not in source]
    assert not missing, (
        f"engine._exploit_level_map missing shell_type mappings: {missing}"
    )
