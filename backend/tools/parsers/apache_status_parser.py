"""
apache_status_parser.py
Deterministic extraction from Apache ``mod_status`` and ``mod_info`` pages.

Endpoints typically exposed:
  - ``/server-status``       — runtime stats + per-worker table
  - ``/server-status?refresh=N`` / ``?auto``  — plain-text variant
  - ``/server-info``         — loaded module list, server config, MPM info

Output ``ApacheFacts`` (flat dict):
  - server_version         : str  (e.g. "Apache/2.4.41 (Ubuntu)")
  - server_mpm             : str  (prefork / worker / event)
  - openssl_version        : str
  - php_sapi               : str  (if mod_php present)
  - server_built           : str
  - current_time           : str
  - total_accesses         : int
  - total_kbytes           : int
  - busy_workers           : int
  - idle_workers           : int
  - modules                : list[str]   (server-info)
  - loaded_module_count    : int
  - virtual_hosts          : list[str]   (server-info)
  - config_files           : list[str]   (server-info)
  - request_samples        : list[str]   ( URIs from per-worker scoreboard )
"""
from __future__ import annotations

import html as _html
import re
from typing import Any

_TAG_STRIP_RE = re.compile(r"<[^>]+>")


def _strip(text: str) -> str:
    return _html.unescape(_TAG_STRIP_RE.sub(" ", text or "")).strip()



_APACHE_SIG_RE = re.compile(
    r"(?:Apache Server Status|Apache Server Information|"
    r"Server Version:\s*Apache/|<title>\s*Apache Status\b|"
    r"ScoreBoard Key:|"
    r"<h1>Apache Server Information</h1>)",
    re.IGNORECASE,
)


def is_apache_status_content(text: str) -> bool:
    if not text:
        return False
    return bool(_APACHE_SIG_RE.search(text))



_FIELD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("server_version",  re.compile(r"Server Version:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("server_mpm",      re.compile(r"Server MPM:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("server_built",    re.compile(r"Server Built:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("current_time",    re.compile(r"Current Time:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("restart_time",    re.compile(r"Restart Time:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("parent_pid",      re.compile(r"Parent Server (?:Generation|PID):\s*(\d+)", re.IGNORECASE)),
    ("cpu_usage",       re.compile(r"CPU Usage:\s*([^\n<]+?)(?:<|\n)", re.IGNORECASE)),
    ("total_accesses",  re.compile(r"(\d+)\s+requests currently being processed", re.IGNORECASE)),
    ("busy_workers",    re.compile(r"BusyWorkers:\s*(\d+)", re.IGNORECASE)),
    ("idle_workers",    re.compile(r"IdleWorkers:\s*(\d+)", re.IGNORECASE)),
]


_AUTO_FIELD_RE = re.compile(
    r"^\s*(Total Accesses|Total kBytes|CPULoad|Uptime|ReqPerSec|BytesPerSec|"
    r"BytesPerReq|BusyWorkers|IdleWorkers|ConnsTotal|ConnsAsyncWriting|"
    r"ConnsAsyncKeepAlive|ConnsAsyncClosing|Scoreboard):\s*(.+?)\s*$",
    re.MULTILINE,
)


def _parse_auto_block(text: str, out: dict[str, Any]) -> None:
    for m in _AUTO_FIELD_RE.finditer(text):
        key = m.group(1).strip().lower().replace(" ", "_")
        val = m.group(2).strip()
        if key in ("busyworkers", "busy_workers"):
            try:
                out["busy_workers"] = int(val)
            except ValueError:
                pass
        elif key in ("idleworkers", "idle_workers"):
            try:
                out["idle_workers"] = int(val)
            except ValueError:
                pass
        elif key == "total_accesses":
            try:
                out["total_accesses"] = int(val)
            except ValueError:
                pass
        elif key == "total_kbytes":
            try:
                out["total_kbytes"] = int(val)
            except ValueError:
                pass
        else:
            out[key] = val



_MODULE_HEADER_RE = re.compile(
    r"Module Name:\s*<?/?[a-z]*?>?\s*([A-Za-z0-9_./-]+)", re.IGNORECASE
)
_SIMPLE_MODULE_RE = re.compile(
    r"<tt>\s*(mod_[a-z0-9_]+)\s*</tt>", re.IGNORECASE
)

_VHOST_RE = re.compile(
    r"(?:Server|ServerName|name)\s*[:=]?\s*([a-zA-Z0-9_.\-]+\.[a-zA-Z]{2,}(?:\:\d+)?)",
    re.IGNORECASE,
)

_CONFIG_FILE_RE = re.compile(
    r"(/etc/(?:apache2|httpd)[A-Za-z0-9_./-]+\.conf|"
    r"[A-Za-z]:[\\/][\w\.\-\\/ ]+?\.conf)",
    re.IGNORECASE,
)


_SCOREBOARD_REQ_RE = re.compile(
    r"<td[^>]*>\s*(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)\s+HTTP",
    re.IGNORECASE,
)


def parse_apache_status(text: str) -> dict[str, Any]:
    """Parse Apache ``server-status`` / ``server-info`` body and return facts."""
    if not text:
        return {}
    facts: dict[str, Any] = {}

    for key, pat in _FIELD_PATTERNS:
        m = pat.search(text)
        if m:
            raw = _strip(m.group(1))
            if key in ("busy_workers", "idle_workers"):
                try:
                    facts[key] = int(raw)
                except ValueError:
                    facts[key] = raw
            else:
                facts[key] = raw

    _parse_auto_block(text, facts)

    modules: set[str] = set()
    for m in _MODULE_HEADER_RE.finditer(text):
        modules.add(m.group(1).strip())
    for m in _SIMPLE_MODULE_RE.finditer(text):
        modules.add(m.group(1).strip())
    if modules:
        facts["modules"] = sorted(modules, key=str.lower)
        facts["loaded_module_count"] = len(modules)

    vhosts: set[str] = set()
    for m in _VHOST_RE.finditer(text):
        name = m.group(1).strip()
        if "." in name and not name.startswith("Apache"):
            vhosts.add(name)
    if vhosts:
        facts["virtual_hosts"] = sorted(vhosts)[:25]

    configs: set[str] = set()
    for m in _CONFIG_FILE_RE.finditer(text):
        configs.add(m.group(1).strip())
    if configs:
        facts["config_files"] = sorted(configs)[:15]

    requests: set[str] = set()
    for m in _SCOREBOARD_REQ_RE.finditer(text):
        uri = m.group(2).strip()
        if uri and len(uri) < 200:
            requests.add(uri)
    if requests:
        facts["request_samples"] = sorted(requests)[:20]

    return facts


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    """Convert Apache facts into attack-surface hints."""
    surface: dict[str, Any] = {}
    modules: list[str] = facts.get("modules") or []

    if "mod_cgi" in modules or "mod_cgid" in modules:
        surface["cgi_enabled"] = True
    if any(m.startswith("mod_php") for m in modules):
        surface["mod_php"] = True
    if "mod_status" in modules:
        surface["status_exposed"] = True
    if "mod_info" in modules:
        surface["info_exposed"] = True
    if "mod_userdir" in modules:
        surface["userdir_enabled"] = True
    if any(m in modules for m in ("mod_dav", "mod_dav_fs")):
        surface["webdav_enabled"] = True
    if "mod_proxy" in modules:
        surface["proxy_enabled"] = True
        surface["proxy_ssrf_risk"] = True

    version = facts.get("server_version") or ""
    m = re.search(r"Apache/(\d+\.\d+\.\d+)", version)
    if m:
        ver = m.group(1)
        surface["version"] = ver
        try:
            major, minor, patch = [int(x) for x in ver.split(".")]
            if major == 2 and minor == 4 and patch < 50:
                surface["cve_2021_42013_candidate"] = True
            if major == 2 and minor == 4 and patch in (49, 50):
                surface["cve_2021_41773_candidate"] = True
        except ValueError:
            pass

    if facts.get("request_samples"):
        surface["live_uri_samples"] = facts["request_samples"]

    return surface


def summarise_for_context(facts: dict[str, Any], max_chars: int = 600) -> str:
    if not facts:
        return ""
    lines = ["Apache 运行时约束摘要:"]
    if facts.get("server_version"):
        lines.append(f"- 版本: {facts['server_version']}")
    if facts.get("server_mpm"):
        lines.append(f"- MPM: {facts['server_mpm']}")
    if facts.get("loaded_module_count"):
        lines.append(f"- 已加载模块: {facts['loaded_module_count']} 个")
    if facts.get("virtual_hosts"):
        vh = ", ".join(facts["virtual_hosts"][:6])
        lines.append(f"- VirtualHost: {vh}")
    if facts.get("request_samples"):
        samples = ", ".join(facts["request_samples"][:5])
        lines.append(f"- 当前请求样本: {samples}")
    return "\n".join(lines)[:max_chars]
