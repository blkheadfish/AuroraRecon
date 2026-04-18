"""Regression tests for the generalised service-info parser stack.

Covers:
  - apache_status_parser   (mod_status / mod_info HTML + auto text)
  - nginx_parser           (stub_status + Server header)
  - tomcat_status_parser   (manager status + connectors + Ghostcat version gate)
  - spring_actuator_parser (/env, /configprops, /mappings, /heapdump)
  - env_file_parser        (.env credential + framework detection)
  - service_info_dispatcher (path routing + fallback content detection)

These tests are pure-Python — no asyncio, no LLM, no network.
"""
from __future__ import annotations

from backend.tools.parsers import (
    apache_status_parser as A,
    nginx_parser as N,
    tomcat_status_parser as T,
    spring_actuator_parser as S,
    env_file_parser as E,
    service_info_dispatcher as D,
)


# ── Apache ──────────────────────────────────────────────────────

APACHE_HTML = (
    '<html><title>Apache Status</title>\n'
    '<dl><dt>Server Version: Apache/2.4.49 (Debian)</dt>\n'
    '<dt>Server MPM: event</dt>\n'
    '<dt>Server Built: 2021-09-15 00:00:00</dt></dl>\n'
    '<tt>mod_status</tt> <tt>mod_cgi</tt> <tt>mod_dav</tt> <tt>mod_proxy</tt>\n'
    'BusyWorkers: 5\n'
    'IdleWorkers: 20\n'
)

APACHE_AUTO = (
    "Total Accesses: 12345\n"
    "Total kBytes: 678\n"
    "Uptime: 10000\n"
    "BusyWorkers: 3\n"
    "IdleWorkers: 47\n"
    "Scoreboard: ___W__K.\n"
)


def test_apache_parse_html_basic():
    facts = A.parse_apache_status(APACHE_HTML)
    assert facts["server_version"] == "Apache/2.4.49 (Debian)"
    assert facts["server_mpm"] == "event"
    assert facts["busy_workers"] == 5
    assert facts["idle_workers"] == 20
    assert "mod_cgi" in facts["modules"]
    assert "mod_dav" in facts["modules"]
    assert facts["loaded_module_count"] == 4


def test_apache_parse_auto_block():
    facts = A.parse_apache_status(APACHE_AUTO)
    assert facts.get("total_accesses") == 12345
    assert facts.get("total_kbytes") == 678
    assert facts.get("busy_workers") == 3
    assert facts.get("idle_workers") == 47


def test_apache_surface_cve_2021_41773():
    facts = A.parse_apache_status(APACHE_HTML)
    surface = A.derive_attack_surface(facts)
    assert surface["cgi_enabled"] is True
    assert surface["webdav_enabled"] is True
    assert surface["cve_2021_41773_candidate"] is True
    assert surface["version"] == "2.4.49"


def test_apache_is_apache_content_negative():
    assert A.is_apache_status_content(APACHE_HTML) is True
    assert A.is_apache_status_content("<h1>nothing</h1>") is False


# ── Nginx ───────────────────────────────────────────────────────

NGINX_STUB = (
    "Active connections: 291\n"
    "server accepts handled requests\n"
    " 16630948 16630948 31070465\n"
    "Reading: 6 Writing: 179 Waiting: 106\n"
)


def test_nginx_parse_stub_status():
    facts = N.parse_nginx_status(NGINX_STUB, headers="Server: nginx/1.18.0\n")
    assert facts["active_connections"] == 291
    assert facts["accepts"] == 16630948
    assert facts["total_requests"] == 31070465
    assert facts["reading"] == 6
    assert facts["nginx_version"] == "1.18.0"
    assert facts["server_banner"].startswith("nginx/1.18.0")


def test_nginx_surface_version_disclosure():
    facts = N.parse_nginx_status(NGINX_STUB, headers="Server: nginx/1.18.0")
    surface = N.derive_attack_surface(facts)
    assert surface["version"] == "1.18.0"
    assert surface["version_disclosure"] is True
    assert surface["production_traffic"] is True


def test_nginx_signature_from_welcome_page():
    html = "<html><body><h1>Welcome to nginx!</h1></body></html>"
    assert N.is_nginx_status_content(html) is True


# ── Tomcat ──────────────────────────────────────────────────────

TOMCAT_MANAGER = (
    '<html><title>/manager</title>\n'
    '<h1>Tomcat Web Application Manager</h1>\n'
    'Tomcat Version=Apache Tomcat/8.5.40\n'
    'JVM Version=1.8.0_222-b10\n'
    'OS Name=Linux\n'
    '<Connector name="HTTP/1.1-nio-8080" />\n'
    '<Connector name="AJP/1.3-8009" />\n'
)


def test_tomcat_parse_basic():
    facts = T.parse_tomcat(TOMCAT_MANAGER)
    assert facts["tomcat_version"] == "Apache Tomcat/8.5.40"
    assert facts["jvm_version"] == "1.8.0_222-b10"
    assert 8080 in facts["connector_ports"]
    assert 8009 in facts["connector_ports"]
    assert "AJP" in facts["connector_protocols"] or "AJP/1.3" in facts["connector_protocols"]
    assert facts["manager_accessible"] is True


def test_tomcat_surface_ghostcat_flagged():
    facts = T.parse_tomcat(TOMCAT_MANAGER)
    surface = T.derive_attack_surface(facts)
    assert surface["manager_reachable"] is True
    assert surface["ajp_connector"] is True
    assert surface["ghostcat_risk"] is True
    assert surface["cve_2020_1938_ghostcat_candidate"] is True


def test_tomcat_error_page_version_leak():
    body = (
        "<html><body><h1>HTTP Status 404</h1>"
        "<hr/><h3>Apache Tomcat/9.0.30</h3></body></html>"
    )
    facts = T.parse_tomcat(body)
    assert facts["tomcat_version"].startswith("9.0.30")


# ── Spring Actuator ─────────────────────────────────────────────

ACTUATOR_ENV = (
    '{"activeProfiles":["prod"],"propertySources":[{'
    '"name":"systemProperties","properties":{'
    '"spring.datasource.password":{"value":"SuperSecret123"},'
    '"JAVA_HOME":{"value":"/usr/lib/jvm/java-11"}'
    '}}]}'
)

ACTUATOR_CONFIGPROPS = (
    '{"contexts":{"app":{"beans":{"dataSource":{"properties":{'
    '"username":"root","password":"hidden_pwd","url":"jdbc:mysql://x"'
    '}}}}}}'
)

ACTUATOR_INDEX = (
    '{"_links":{"self":{"href":"http://x/actuator"},'
    '"env":{"href":"http://x/actuator/env"},'
    '"heapdump":{"href":"http://x/actuator/heapdump"}}}'
)


def test_actuator_env_extracts_sensitive():
    facts = S.parse_actuator("/actuator/env", ACTUATOR_ENV)
    assert facts["endpoint_kind"] == "env"
    assert facts["env_entry_count"] == 2
    assert "prod" in facts["active_profiles"]
    keys = {e["key"] for e in facts["sensitive_env"]}
    assert "spring.datasource.password" in keys


def test_actuator_configprops_walks_tree():
    facts = S.parse_actuator("/actuator/configprops", ACTUATOR_CONFIGPROPS)
    assert facts["endpoint_kind"] == "configprops"
    keys = {e["key"] for e in facts.get("sensitive_configprops", [])}
    assert any("password" in k for k in keys)


def test_actuator_index_extracts_links():
    facts = S.parse_actuator("/actuator", ACTUATOR_INDEX)
    assert facts["endpoint_kind"] == "index"
    joined = "\n".join(facts.get("available_endpoints", []))
    assert "env" in joined and "heapdump" in joined


def test_actuator_merge_and_surface():
    env_facts = S.parse_actuator("/actuator/env", ACTUATOR_ENV)
    cp_facts = S.parse_actuator("/actuator/configprops", ACTUATOR_CONFIGPROPS)
    merged = S.merge_actuator_facts([env_facts, cp_facts])
    assert "env" in merged["endpoints_seen"]
    assert "configprops" in merged["endpoints_seen"]
    surface = S.derive_attack_surface(merged)
    assert surface["credential_leak"] is True
    assert surface["env_exposed"] is True


# ── .env ────────────────────────────────────────────────────────

ENV_LARAVEL = (
    "APP_NAME=Laravel\n"
    "APP_KEY=base64:abc123def456==\n"
    "APP_DEBUG=true\n"
    "APP_ENV=production\n"
    "DB_CONNECTION=mysql\n"
    "DB_PASSWORD=p@ssw0rd\n"
    "DATABASE_URL=mysql://root:superpwd@db:3306/app\n"
    "# comment line here\n"
    "MAIL_PASSWORD=\"quoted secret\"\n"
)


def test_env_file_parse_and_detect():
    facts = E.parse_env_file(ENV_LARAVEL)
    assert facts["entry_count"] >= 7
    assert facts["debug_enabled"] is True
    assert facts["deployment_env"] == "production"
    sens_keys = {e["key"] for e in facts["sensitive"]}
    assert "APP_KEY" in sens_keys
    assert "DB_PASSWORD" in sens_keys
    assert "MAIL_PASSWORD" in sens_keys
    creds = facts["url_credentials"]
    assert creds and creds[0]["user"] == "root" and creds[0]["password"] == "superpwd"
    assert "laravel" in facts["frameworks"]


def test_env_file_surface_flags_prod_leak():
    facts = E.parse_env_file(ENV_LARAVEL)
    surface = E.derive_attack_surface(facts)
    assert surface["credential_leak"] is True
    assert surface["prod_credential_leak"] is True
    assert surface["debug_mode"] is True


def test_env_file_sniff_by_content_shape():
    body = "NODE_ENV=production\nPORT=3000\nDB_URL=postgres://u:p@h/db\nREDIS_URL=redis://r\n"
    assert E.is_env_file_content(body, path="/config/dotenv") is True


# ── Dispatcher ──────────────────────────────────────────────────

def test_dispatcher_routes_all_kinds():
    harvested = [
        {"path": "/server-status",  "body": APACHE_HTML,   "headers": ""},
        {"path": "/nginx_status",   "body": NGINX_STUB,    "headers": "Server: nginx/1.18.0"},
        {"path": "/manager/status", "body": TOMCAT_MANAGER,"headers": ""},
        {"path": "/actuator/env",   "body": ACTUATOR_ENV,  "headers": ""},
        {"path": "/.env",           "body": ENV_LARAVEL,   "headers": ""},
    ]
    matches = D.parse_harvested(harvested)
    kinds = [m.kind for m in matches]
    # All five must appear, order does not matter
    assert set(kinds) == {"apache", "nginx", "tomcat", "spring", "env_file"}


def test_dispatcher_manager_status_does_not_match_nginx():
    """Regression: /manager/status used to be mis-routed to nginx because of
    the generic "status" alt in the nginx hint. Make sure the order fix holds."""
    m = D.parse_entry("/manager/status", TOMCAT_MANAGER)
    assert m is not None
    assert m.kind == "tomcat"


def test_dispatcher_content_fallback_when_path_unknown():
    """A crawler might harvest an Apache status page at /dashboard."""
    m = D.parse_entry("/dashboard", APACHE_HTML)
    assert m is not None
    assert m.kind == "apache"


def test_dispatcher_env_attack_surface_attached():
    m = D.parse_entry("/.env", ENV_LARAVEL)
    assert m is not None
    assert m.kind == "env_file"
    surface = m.facts.get("_attack_surface") or {}
    assert surface.get("prod_credential_leak") is True


def test_summarise_runtime_facts_includes_alerts():
    harvested = [
        {"path": "/server-status",  "body": APACHE_HTML,    "headers": ""},
        {"path": "/manager/status", "body": TOMCAT_MANAGER, "headers": ""},
        {"path": "/actuator/env",   "body": ACTUATOR_ENV,   "headers": ""},
    ]
    rf: dict = {}
    for m in D.parse_harvested(harvested):
        rf.setdefault(m.kind, {}).update(m.facts)
    summary = D.summarise_runtime_facts(rf, max_chars=4000)
    assert "Apache" in summary
    assert "Tomcat" in summary
    assert "Actuator" in summary
