"""
E3 · exploit_agent 链式偏置单测。

验证 `ExploitAgent._apply_log_poison_chain_bias` 在
"LFI 已确认 + 日志可读" 时：
  - 把 credential_bruteforce 替换为 log_poisoning
  - 把 category=credential 的 SSH 端口候选替换掉
  - 不影响 web_rce / java_deserialization 等其它正常 skill
  - 未触发条件时保持原样
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest

from backend.agents.exploit_agent import ExploitAgent



@dataclass
class _FakeSkill:
    skill_id: str
    category: str = ""
    name: str = ""


class _FakeRegistry:
    def __init__(self, by_id: dict[str, _FakeSkill]) -> None:
        self._by_id = by_id

    def get_by_id(self, skill_id: str) -> Optional[_FakeSkill]:
        return self._by_id.get(skill_id)


def _make_agent(with_log_poison_skill: bool = True) -> ExploitAgent:
    agent = object.__new__(ExploitAgent)
    by_id = {
        "credential_bruteforce": _FakeSkill(
            skill_id="credential_bruteforce", category="credential",
        ),
    }
    if with_log_poison_skill:
        by_id["log_poisoning"] = _FakeSkill(
            skill_id="log_poisoning", category="web_rce",
        )
    agent.skill_registry = _FakeRegistry(by_id)
    return agent



def test_bias_replaces_credential_bruteforce_when_log_readable():
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "file", "depth": "5"},
            "services": {"log_readable": ["auth.log"]},
        },
    }
    skill = _FakeSkill("credential_bruteforce", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=22, context=ctx, origin="match",
    )
    assert out is not None
    assert out.skill_id == "log_poisoning"


def test_bias_accepts_readable_files_fallback_for_log_detection():
    """services.log_readable 为空，但 lfi.readable_files 含日志文件 → 依然触发偏置."""
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {
                "param": "file",
                "readable_files": ["/etc/passwd", "/var/log/auth.log"],
            },
            "services": {},
        },
    }
    skill = _FakeSkill("credential_bruteforce", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=22, context=ctx, origin="freeform_port",
    )
    assert out.skill_id == "log_poisoning"


@pytest.mark.parametrize("ssh_port", [22, 2222, 2211])
def test_bias_catches_generic_credential_category_on_ssh_ports(ssh_port):
    """连 skill_id 叫别的（如 custom_ssh_brute）只要 category==credential 且端口是 SSH 也拦."""
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "page"},
            "services": {"log_readable": ["secure"]},
        },
    }
    skill = _FakeSkill("some_other_ssh_brute", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=ssh_port, context=ctx, origin="match_by_port",
    )
    assert out.skill_id == "log_poisoning"



def test_bias_passthrough_when_no_lfi_confirmed():
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {},
            "services": {"log_readable": ["auth.log"]},
        },
    }
    skill = _FakeSkill("credential_bruteforce", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=22, context=ctx, origin="match",
    )
    assert out is skill


def test_bias_passthrough_when_no_log_readable():
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "file"},
            "services": {"log_readable": []},
        },
    }
    skill = _FakeSkill("credential_bruteforce", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=22, context=ctx, origin="match",
    )
    assert out is skill


def test_bias_does_not_touch_web_rce_skills():
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "file"},
            "services": {"log_readable": ["auth.log"]},
        },
    }
    skill = _FakeSkill("shiro_exploit", category="java_deserialization")
    out = agent._apply_log_poison_chain_bias(
        skill, port=8080, context=ctx, origin="match",
    )
    assert out is skill


def test_bias_keeps_credential_skill_on_non_ssh_port():
    """非 SSH 端口上的 credential category skill 不需要被 E3 拦截."""
    agent = _make_agent()
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "file"},
            "services": {"log_readable": ["auth.log"]},
        },
    }
    skill = _FakeSkill("ftp_brute", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=21, context=ctx, origin="match",
    )
    assert out is skill


def test_bias_handles_none_skill_and_missing_alt():
    agent = _make_agent(with_log_poison_skill=False)
    ctx = {
        "confirmed_facts": {
            "lfi": {"param": "file"},
            "services": {"log_readable": ["auth.log"]},
        },
    }
    out = agent._apply_log_poison_chain_bias(
        None, port=22, context=ctx, origin="match_by_port",
    )
    assert out is None

    skill = _FakeSkill("credential_bruteforce", category="credential")
    out = agent._apply_log_poison_chain_bias(
        skill, port=22, context=ctx, origin="match",
    )
    assert out is skill


def test_bias_handles_empty_context():
    agent = _make_agent()
    skill = _FakeSkill("credential_bruteforce", category="credential")
    assert agent._apply_log_poison_chain_bias(
        skill, port=22, context=None, origin="match",
    ) is skill
    assert agent._apply_log_poison_chain_bias(
        skill, port=22, context={}, origin="match",
    ) is skill
