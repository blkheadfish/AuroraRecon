"""Verify that node_secondary_attack transports confirmed_facts/prior_* into context."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from backend.agents.models import ExploitResult, PentestState, VulnFinding


@pytest.mark.asyncio
async def test_secondary_attack_injects_confirmed_facts(monkeypatch):
    pytest.importorskip("langgraph")
    pytest.importorskip("openai")
    state = PentestState(target="http://x")
    state.target_host = "x.test"
    state.got_shell = False
    state.foothold_status = "file_read"

    finding = VulnFinding(
        name="LFI in include.php", severity="high",
        target="http://x.test/include.php", port=80,
        description="Local File Inclusion via include param",
        evidence="proof", exploitable=True,
    )
    state.findings.append(finding)
    state.exploit_results.append(
        ExploitResult(vuln_id=finding.vuln_id, success=False,
                      evidence="failed")
    )
    state.confirmed_facts = {
        "lfi": {"param": "image", "depth": "5", "style": "relative",
                "readable_files": ["/etc/passwd", "/var/log/auth.log"]},
    }
    state.exploit_probe_variables = {
        finding.vuln_id: {"lfi_param": "image", "lfi_depth": "5", "lfi_style": "relative"},
    }
    state.failed_commands_by_vuln = {finding.vuln_id: ["curl bogus"]}
    state.php_runtime = {
        "allow_url_include": True, "doc_root": "/var/www/html/x",
    }

    captured = {}

    async def _fake_run(**kwargs):
        captured.update(kwargs)
        return []

    fake = AsyncMock(side_effect=_fake_run)
    with patch("backend.agents.exploit_agent.ExploitAgent.run", new=fake):
        from backend.agents.orchestrator import node_secondary_attack
        await node_secondary_attack(state)

    ctx = captured.get("context") or {}
    assert ctx.get("secondary_pass") is True
    assert ctx.get("confirmed_facts", {}).get("lfi", {}).get("param") == "image"
    assert ctx.get("prior_probe_variables", {}).get(finding.vuln_id, {}).get("lfi_depth") == "5"
    assert "curl bogus" in ctx.get("prior_failed_commands", {}).get(finding.vuln_id, [])
    assert ctx.get("php_runtime", {}).get("allow_url_include") is True
    assert captured.get("fact_sink") is not None
