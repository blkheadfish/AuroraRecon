"""Regression tests for ExploitAgent._extract_facts + fact_sink merging."""
from __future__ import annotations

from backend.agents.fact_hooks import extract_facts, make_fact_sink as _make_fact_sink
from backend.agents.models import ExploitResult, PentestState, VulnFinding


PASSWD_SAMPLE = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)


def _finding(**kw) -> VulnFinding:
    return VulnFinding(
        name=kw.get("name", "LFI via include"),
        severity=kw.get("severity", "high"),
        target=kw.get("target", "http://x/include.php"),
        port=80,
        description=kw.get("description", "Local File Inclusion"),
        evidence=kw.get("evidence", ""),
        exploitable=True,
    )


def test_extract_facts_from_lfi_hit_marker():
    finding = _finding()
    result = ExploitResult(
        vuln_id=finding.vuln_id,
        success=True,
        exploit_level="file_read",
        session_info={"probe_variables": {"lfi_param": "image", "lfi_depth": "5", "lfi_style": "relative"}},
        commands_run=["curl -s http://x/info.php?image=../../../../../etc/passwd"],
        command_records=[{
            "round": 1,
            "command": "curl -s 'http://x/info.php?image=../../../../../etc/passwd'",
            "stdout": PASSWD_SAMPLE,
            "exit_code": 0,
        }],
    )
    facts = extract_facts(result, finding)
    assert facts["vuln_id"] == finding.vuln_id
    assert facts["probe_variables"]["lfi_param"] == "image"
    assert facts["probe_variables"]["lfi_depth"] == "5"
    lfi = facts["confirmed"]["lfi"]
    assert lfi["param"] == "image"
    assert lfi["depth"] == "5"
    assert lfi["style"] == "relative"
    assert "/etc/passwd" in lfi["readable_files"]


def test_extract_facts_captures_failed_commands():
    finding = _finding()
    result = ExploitResult(
        vuln_id=finding.vuln_id,
        success=False,
        exploit_level="",
        commands_run=["curl fail-cmd"],
        command_records=[{
            "round": 1,
            "command": "curl -s http://x/include.php?bogus=yes",
            "stdout": "",
            "exit_code": 7,
        }],
    )
    facts = extract_facts(result, finding)
    assert "curl -s http://x/include.php?bogus=yes" in facts.get("failed_commands", [])


def test_fact_sink_merges_into_state():
    state = PentestState(target="http://x")
    sink = _make_fact_sink(state)
    sink({
        "vuln_id": "vuln-1",
        "probe_variables": {"lfi_param": "image", "lfi_depth": "5"},
        "confirmed": {"lfi": {"param": "image", "depth": "5", "style": "relative",
                              "readable_files": ["/etc/passwd"]}},
        "failed_commands": ["curl bad"],
    })
    sink({
        "vuln_id": "vuln-1",
        "confirmed": {"lfi": {"readable_files": ["/var/log/auth.log"]}},
        "failed_commands": ["curl bad"],
    })
    assert state.confirmed_facts["lfi"]["param"] == "image"
    assert state.confirmed_facts["lfi"]["depth"] == "5"
    assert set(state.confirmed_facts["lfi"]["readable_files"]) == {
        "/etc/passwd", "/var/log/auth.log",
    }
    assert state.exploit_probe_variables["vuln-1"]["lfi_param"] == "image"
    assert state.failed_commands_by_vuln["vuln-1"] == ["curl bad"]


def test_fact_sink_preserves_first_confirmed_value():
    state = PentestState(target="http://x")
    sink = _make_fact_sink(state)
    sink({"vuln_id": "v", "confirmed": {"lfi": {"depth": "5"}}})
    sink({"vuln_id": "v", "confirmed": {"lfi": {"depth": "3"}}})
    assert state.confirmed_facts["lfi"]["depth"] == "5"
