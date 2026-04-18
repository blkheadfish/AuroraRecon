"""Regression tests for the serial LFI depth/param/style confirmation gate."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from backend.agents.lfi_probe import (
    LfiProbeResult,
    _depth_order_from_doc_root,
    is_lfi_finding,
    probe_lfi_depth,
)
from backend.agents.models import VulnFinding


PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)


@dataclass
class _FakeExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed: float = 0.01


class _FakeExecutor:
    def __init__(self, responder):
        self._responder = responder
        self.calls: list[str] = []

    async def run(self, *, tool: str, args: list[str], timeout: int, **_: Any):
        cmd = args[1] if len(args) >= 2 else ""
        self.calls.append(cmd)
        body = self._responder(cmd)
        return _FakeExecResult(stdout=body)


def _finding(url="http://t.test/include.php") -> VulnFinding:
    return VulnFinding(
        name="LFI via include", severity="high",
        target=url, port=80,
        description="Local File Inclusion", evidence="",
        exploitable=True,
    )


@pytest.mark.asyncio
async def test_probe_confirms_on_image_depth_5():
    def responder(cmd: str) -> str:
        if "image=" in cmd and ("../" * 5) in cmd:
            return PASSWD
        return "<html>dummy</html>"

    ex = _FakeExecutor(responder)
    result = await probe_lfi_depth(_finding(), {}, executor=ex)
    assert result.status == "confirmed"
    assert result.param == "image"
    assert result.depth == "5"
    assert result.style == "relative"
    assert result.probed_count < 40


@pytest.mark.asyncio
async def test_probe_uses_doc_root_hint():
    def responder(cmd: str) -> str:
        if "file=" in cmd and ("../" * 5) in cmd:
            return PASSWD
        return "<html>no</html>"

    ex = _FakeExecutor(responder)
    context = {"php_runtime": {"doc_root": "/var/www/html/antibot_image/antibots"}}
    result = await probe_lfi_depth(_finding(), context, executor=ex)
    assert result.status == "confirmed"
    assert result.depth == "5"


@pytest.mark.asyncio
async def test_probe_unconfirmed_when_no_hit():
    def responder(cmd: str) -> str:
        return "<html>Welcome</html>"

    ex = _FakeExecutor(responder)
    result = await probe_lfi_depth(_finding(), {}, executor=ex, max_probes=8)
    assert result.status == "unconfirmed"
    assert result.probed_count <= 8


@pytest.mark.asyncio
async def test_probe_absolute_path_hit():
    def responder(cmd: str) -> str:
        if "=/etc/passwd" in cmd and "../" not in cmd:
            return PASSWD
        return "<html>no</html>"

    ex = _FakeExecutor(responder)
    result = await probe_lfi_depth(_finding(), {}, executor=ex)
    assert result.status == "confirmed"
    assert result.style == "absolute"
    assert result.depth == "0"


def test_is_lfi_finding_heuristic():
    assert is_lfi_finding(_finding())
    non = VulnFinding(name="SQL Injection", severity="high",
                     description="SQLi in /users", target="http://x", port=80)
    assert not is_lfi_finding(non)


def test_depth_order_from_doc_root():
    order = _depth_order_from_doc_root("/var/www/html/a/b")
    assert order[0] == 4  # theory-1=4 when theory=5


@pytest.mark.asyncio
async def test_exploit_agent_skips_probe_when_fact_present(monkeypatch):
    """When confirmed_facts already contains lfi.param and lfi.depth, the
    agent must NOT call probe_lfi_depth."""
    pytest.importorskip("openai")
    from backend.agents.exploit_agent import ExploitAgent

    called = {"count": 0}

    async def _fake_probe(*args, **kwargs):
        called["count"] += 1
        return LfiProbeResult(status="confirmed", param="image", depth="5",
                              style="relative", probed_count=1)

    monkeypatch.setattr("backend.agents.lfi_probe.probe_lfi_depth", _fake_probe)

    agent = ExploitAgent()
    context = {
        "confirmed_facts": {
            "lfi": {"param": "image", "depth": "5", "style": "relative"}
        }
    }
    await agent._run_lfi_gate(_finding(), context)
    assert called["count"] == 0


@pytest.mark.asyncio
async def test_exploit_agent_runs_probe_when_lfi_not_locked(monkeypatch):
    pytest.importorskip("openai")
    from backend.agents.exploit_agent import ExploitAgent

    called = {"count": 0}

    async def _fake_probe(*args, **kwargs):
        called["count"] += 1
        return LfiProbeResult(status="confirmed", param="image", depth="7",
                              style="relative", probed_count=3)

    monkeypatch.setattr("backend.agents.lfi_probe.probe_lfi_depth", _fake_probe)

    agent = ExploitAgent()
    context: dict = {}
    await agent._run_lfi_gate(_finding(), context)
    assert called["count"] == 1
    locked = context["confirmed_facts"]["lfi"]
    assert locked["param"] == "image"
    assert locked["depth"] == "7"


def test_react_guard_blocks_reprobe_command():
    from backend.agents.fact_hooks import is_lfi_reprobe_command as _is_lfi_reprobe_command

    assert _is_lfi_reprobe_command(
        "for d in $(seq 1 10); do T=$(printf '../%.0s' $(seq 1 $d)); "
        "curl \"http://x?image=${T}etc/passwd\"; done"
    )
    assert _is_lfi_reprobe_command(
        "for p in page file include path; do for d in {1..10}; do "
        "curl \"http://x?$p=../../../../etc/passwd\"; done; done"
    )
    assert not _is_lfi_reprobe_command(
        "curl -s 'http://x?image=../../../../../etc/passwd'"
    )
    assert not _is_lfi_reprobe_command(
        "curl -s 'http://x?image=php://filter/convert.base64-encode/resource=/var/log/auth.log'"
    )
