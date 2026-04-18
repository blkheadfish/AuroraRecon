"""Tests for the generalised ``apply_service_info_extraction`` hook.

These exercise the full end-to-end pipe: harvested pages ➜ dispatcher ➜
per-service buckets on ``state.runtime_facts`` ➜ auto-generated
``VulnFinding``/log emissions, all without any LLM or network dependency.
"""
from __future__ import annotations

from backend.agents.fact_hooks import apply_service_info_extraction
from backend.agents.models import PentestState


APACHE_HTML = (
    '<html><title>Apache Status</title>\n'
    'Server Version: Apache/2.4.49 (Debian)\n'
    'Server MPM: event\n'
    '<tt>mod_cgi</tt> <tt>mod_dav</tt>\n'
)

TOMCAT_MANAGER = (
    '<html><title>/manager</title>\n'
    '<h1>Tomcat Web Application Manager</h1>\n'
    'Tomcat Version=Apache Tomcat/8.5.40\n'
    '<Connector name="AJP/1.3-8009" />\n'
)

ACTUATOR_ENV = (
    '{"activeProfiles":["prod"],"propertySources":[{'
    '"name":"applicationProperties","properties":{'
    '"spring.datasource.password":{"value":"SuperSecret"}}}]}'
)

ENV_LARAVEL = (
    "APP_KEY=base64:abc==\nAPP_ENV=production\nAPP_DEBUG=true\n"
    "DB_PASSWORD=p@ssw0rd\n"
)


def _state() -> PentestState:
    return PentestState(task_id="t1", target="192.0.2.10")


def test_apply_populates_all_buckets():
    state = _state()
    harvested = [
        {"path": "/server-status",  "body": APACHE_HTML,   "headers": ""},
        {"path": "/manager/status", "body": TOMCAT_MANAGER,"headers": ""},
        {"path": "/actuator/env",   "body": ACTUATOR_ENV,  "headers": ""},
        {"path": "/.env",           "body": ENV_LARAVEL,   "headers": ""},
    ]

    apply_service_info_extraction(state, harvested, "http://192.0.2.10:80", 80)

    rf = state.runtime_facts
    assert set(rf.keys()) == {"apache", "tomcat", "spring", "env_file"}

    assert rf["apache"]["server_version"].startswith("Apache/2.4.49")
    assert rf["apache"]["_attack_surface"]["cve_2021_41773_candidate"] is True

    assert rf["tomcat"]["tomcat_version"].startswith("Apache Tomcat/8.5.40")
    assert rf["tomcat"]["_attack_surface"]["manager_reachable"] is True

    assert rf["spring"]["env_entry_count"] == 1
    assert rf["spring"]["_attack_surface"]["credential_leak"] is True

    assert rf["env_file"]["_attack_surface"]["prod_credential_leak"] is True


def test_apply_emits_high_severity_findings():
    state = _state()
    harvested = [
        {"path": "/server-status",  "body": APACHE_HTML,   "headers": ""},
        {"path": "/manager/status", "body": TOMCAT_MANAGER,"headers": ""},
        {"path": "/actuator/env",   "body": ACTUATOR_ENV,  "headers": ""},
        {"path": "/.env",           "body": ENV_LARAVEL,   "headers": ""},
    ]
    apply_service_info_extraction(state, harvested, "http://x", 80)

    names = [f.name for f in state.findings]
    assert any("CVE-2021-41773" in n for n in names)
    assert any("Ghostcat" in n for n in names)
    assert any("Manager" in n for n in names)
    assert any("Actuator" in n for n in names)
    assert any(".env" in n for n in names)

    # All of them should be high severity
    for f in state.findings:
        assert f.severity == "high"
        assert f.exploitable is True


def test_php_runtime_backcompat_alias_still_written():
    """When phpinfo is present, ``state.php_runtime`` must mirror runtime_facts['php']."""
    state = _state()
    phpinfo_html = (
        "<html><body>\n"
        '<tr><td class="e">PHP Version</td><td class="v">7.4.33</td></tr>\n'
        '<tr><td class="e">allow_url_include</td><td class="v">On</td></tr>\n'
        '<tr><td class="e">disable_functions</td><td class="v">no value</td></tr>\n'
        '<tr><td class="e">System</td><td class="v">Linux x 5.4</td></tr>\n'
        "</body></html>"
    )
    apply_service_info_extraction(
        state,
        [{"path": "/info.php", "body": phpinfo_html, "headers": ""}],
        "http://x", 80,
    )
    assert state.runtime_facts.get("php", {}).get("allow_url_include") is True
    # back-compat alias
    assert state.php_runtime.get("allow_url_include") is True
    assert state.php_runtime is state.runtime_facts["php"] or \
           state.php_runtime == state.runtime_facts["php"]


def test_apply_is_noop_when_nothing_matches():
    state = _state()
    apply_service_info_extraction(
        state,
        [{"path": "/random.html", "body": "<h1>nothing interesting</h1>", "headers": ""}],
        "http://x", 80,
    )
    assert state.runtime_facts == {}
    assert state.findings == []
