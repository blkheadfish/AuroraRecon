"""
tomcat_status_parser.py
Extract facts from Tomcat management endpoints:

  - ``/manager/status``              HTML dashboard with connector/JVM info
  - ``/manager/status?XML=true``     Pure XML variant (more reliable)
  - ``/manager/serverinfo``          key=value plain text
  - ``/manager/html``                index: deployed apps + sessions
  - Default Tomcat 404 / JSP error pages that leak ``Apache Tomcat/<ver>``

Output ``TomcatFacts``:
  - tomcat_version, server_built, server_number, jvm_version, jvm_vendor
  - os_name, os_version, os_architecture
  - connector_ports      : list[int]
  - connector_protocols  : list[str]
  - deployed_apps        : list[{"path","sessions","running"}]
  - manager_accessible   : bool     (derived)
"""
from __future__ import annotations

import html as _html
import re
from typing import Any

_TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _strip(value: str) -> str:
    if not value:
        return ""
    return _html.unescape(_TAG_STRIP_RE.sub(" ", value)).strip()


_TOMCAT_SIG_RE = re.compile(
    r"Apache Tomcat/|"
    r"<title>/manager</title>|"
    r"<title>Server Status</title>|"
    r"<h1>Tomcat Web Application Manager</h1>|"
    r"<status>\s*<jvm>|"
    r"Tomcat Server Information",
    re.IGNORECASE,
)


def is_tomcat_content(text: str) -> bool:
    if not text:
        return False
    return bool(_TOMCAT_SIG_RE.search(text))


_SERVERINFO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("tomcat_version",  re.compile(r"Tomcat Version[:=]\s*([^\n<]+)", re.IGNORECASE)),
    ("server_built",    re.compile(r"Server Built[:=]\s*([^\n<]+)",   re.IGNORECASE)),
    ("server_number",   re.compile(r"Server Number[:=]\s*([^\n<]+)",  re.IGNORECASE)),
    ("os_name",         re.compile(r"OS Name[:=]\s*([^\n<]+)",        re.IGNORECASE)),
    ("os_version",      re.compile(r"OS Version[:=]\s*([^\n<]+)",     re.IGNORECASE)),
    ("os_architecture", re.compile(r"OS Architecture[:=]\s*([^\n<]+)",re.IGNORECASE)),
    ("jvm_version",     re.compile(r"JVM Version[:=]\s*([^\n<]+)",    re.IGNORECASE)),
    ("jvm_vendor",      re.compile(r"JVM Vendor[:=]\s*([^\n<]+)",     re.IGNORECASE)),
]


_VERSION_INLINE_RE = re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+(?:[-.]\w+)?)", re.IGNORECASE)


_CONNECTOR_XML_RE = re.compile(
    r'<connector[^>]*name="([^"]+)"[^>]*>',
    re.IGNORECASE,
)

_CONNECTOR_DASH_RE = re.compile(
    r'(HTTP|AJP)/?[\w.]*-(?:nio|apr|bio|nio2)?-?(\d{2,5})',
    re.IGNORECASE,
)


_DEPLOYED_APP_RE = re.compile(
    r'<tr[^>]*>\s*<td[^>]*>\s*<(?:small|code)?[^>]*>\s*'
    r'(/[\w.\-/]*)\s*</(?:small|code)?[^>]*>\s*</td>',
    re.IGNORECASE,
)


def parse_tomcat(text: str) -> dict[str, Any]:
    if not text:
        return {}
    facts: dict[str, Any] = {}

    for key, pat in _SERVERINFO_PATTERNS:
        m = pat.search(text)
        if m:
            facts[key] = _strip(m.group(1))

    if "tomcat_version" not in facts:
        m = _VERSION_INLINE_RE.search(text)
        if m:
            facts["tomcat_version"] = m.group(1).strip()

    protocols: set[str] = set()
    ports: set[int] = set()
    for m in _CONNECTOR_XML_RE.finditer(text):
        name = m.group(1)
        pm = re.search(r"-(\d{2,5})$", name)
        if pm:
            try:
                ports.add(int(pm.group(1)))
            except ValueError:
                pass
        if name.startswith(("HTTP", "AJP", "http", "ajp")):
            protocols.add(name.split("-")[0].upper())
    for m in _CONNECTOR_DASH_RE.finditer(text):
        protocols.add(m.group(1).upper())
        try:
            ports.add(int(m.group(2)))
        except ValueError:
            pass
    if protocols:
        facts["connector_protocols"] = sorted(protocols)
    if ports:
        facts["connector_ports"] = sorted(ports)

    apps: list[dict[str, Any]] = []
    for m in _DEPLOYED_APP_RE.finditer(text):
        path = m.group(1).strip()
        if path and path not in ("/manager", "/host-manager") and len(apps) < 40:
            apps.append({"path": path})
    if apps:
        facts["deployed_apps"] = apps

    facts["manager_accessible"] = (
        "Tomcat Web Application Manager" in text
        or "/manager/status" in text
        or "manager-gui" in text
    )

    return facts


def _parse_ver(v: str) -> tuple[int, int, int]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    ver = facts.get("tomcat_version") or ""
    parsed = _parse_ver(ver)
    if ver:
        surface["version"] = ver
        major, minor, patch = parsed
        if major == 9 and (minor, patch) < (0, 31):
            surface["cve_2020_1938_ghostcat_candidate"] = True
        if major == 8 and (minor, patch) < (5, 51):
            surface["cve_2020_1938_ghostcat_candidate"] = True
        if major == 7 and (minor, patch) < (0, 100):
            surface["cve_2020_1938_ghostcat_candidate"] = True
        if major in (7, 8, 9) and (major, minor, patch) < (9, 0, 75):
            surface["cve_2022_34305_xss_candidate"] = True

    if facts.get("manager_accessible"):
        surface["manager_reachable"] = True
        surface["manager_deploy_rce_path"] = "/manager/html/upload"

    protos = facts.get("connector_protocols") or []
    if "AJP" in protos:
        surface["ajp_connector"] = True
        surface["ghostcat_risk"] = True
    ports = facts.get("connector_ports") or []
    if 8009 in ports or any(str(p).endswith("09") for p in ports):
        surface["ajp_port_hint"] = True

    return surface


def summarise_for_context(facts: dict[str, Any], max_chars: int = 600) -> str:
    if not facts:
        return ""
    lines = ["Tomcat 运行时约束摘要:"]
    if facts.get("tomcat_version"):
        lines.append(f"- 版本: Apache Tomcat/{facts['tomcat_version']}")
    if facts.get("jvm_version"):
        lines.append(f"- JVM: {facts.get('jvm_vendor', '')} {facts['jvm_version']}")
    if facts.get("os_name"):
        os_line = facts["os_name"]
        if facts.get("os_version"):
            os_line += f" {facts['os_version']}"
        if facts.get("os_architecture"):
            os_line += f" ({facts['os_architecture']})"
        lines.append(f"- OS: {os_line}")
    if facts.get("connector_ports"):
        lines.append(
            f"- Connector: protos={','.join(facts.get('connector_protocols', []))} "
            f"ports={facts['connector_ports']}"
        )
    if facts.get("deployed_apps"):
        paths = [a["path"] for a in facts["deployed_apps"][:8]]
        lines.append(f"- 已部署应用: {', '.join(paths)}")
    return "\n".join(lines)[:max_chars]
