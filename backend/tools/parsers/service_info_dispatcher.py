"""
service_info_dispatcher.py
Look at (path, body, headers) tuples and pick the right structured parser.

Returns a list of ``DisclosureMatch`` records, one per harvested entry that
looked like a service-info / config-disclosure endpoint. Each match carries
the ``kind`` bucket (``php``, ``apache``, ``nginx``, ``tomcat``, ``spring``,
``env_file``) and the extracted ``facts`` so the orchestrator can merge them
into ``state.runtime_facts[kind]``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from backend.tools.parsers import phpinfo_parser
from backend.tools.parsers import apache_status_parser
from backend.tools.parsers import nginx_parser
from backend.tools.parsers import tomcat_status_parser
from backend.tools.parsers import spring_actuator_parser
from backend.tools.parsers import env_file_parser

logger = logging.getLogger(__name__)


@dataclass
class DisclosureMatch:
    kind: str
    path: str
    facts: dict[str, Any]


_PATH_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("php",      re.compile(r"(?:^|/)(?:phpinfo|info)(?:\.php)?(?:[?#]|$)", re.IGNORECASE)),
    ("apache",   re.compile(r"(?:^|/)(?:server-status|server-info)(?:[?#]|$)", re.IGNORECASE)),
    ("tomcat",   re.compile(r"(?:^|/)(?:manager|host-manager)(?:/|$)", re.IGNORECASE)),
    ("spring",   re.compile(r"(?:^|/)actuator(?:/|$)", re.IGNORECASE)),
    ("spring",   re.compile(r"^/(?:env|mappings|configprops|trace|heapdump|beans|health|autoconfig|dump)(?:[?#]|$)", re.IGNORECASE)),
    ("nginx",    re.compile(r"(?:^|/)(?:nginx_?status|stub_?status)(?:[?#]|$)", re.IGNORECASE)),
    ("env_file", re.compile(r"(?:^|/)\.env(?:\.[\w.-]+)?(?:[?#]|$)", re.IGNORECASE)),
    ("nginx",    re.compile(r"^/status(?:\.html)?(?:[?#]|$)", re.IGNORECASE)),
]


def _match_by_content(body: str, headers: str) -> str | None:
    """Fallback content-based detection when the path is ambiguous."""
    if not body:
        return None
    if phpinfo_parser.is_phpinfo_content(body):
        return "php"
    if apache_status_parser.is_apache_status_content(body):
        return "apache"
    if nginx_parser.is_nginx_status_content(body, headers):
        return "nginx"
    if tomcat_status_parser.is_tomcat_content(body):
        return "tomcat"
    if spring_actuator_parser.is_actuator_content(body):
        return "spring"
    if env_file_parser.is_env_file_content(body):
        return "env_file"
    return None


_PARSE_DISPATCH: dict[str, Callable[[str, str, str], dict[str, Any]]] = {
    "php":      lambda path, body, headers: phpinfo_parser.parse_phpinfo(body),
    "apache":   lambda path, body, headers: apache_status_parser.parse_apache_status(body),
    "nginx":    lambda path, body, headers: nginx_parser.parse_nginx_status(body, headers),
    "tomcat":   lambda path, body, headers: tomcat_status_parser.parse_tomcat(body),
    "spring":   lambda path, body, headers: spring_actuator_parser.parse_actuator(path, body),
    "env_file": lambda path, body, headers: env_file_parser.parse_env_file(body),
}


def _derive_surface(kind: str, facts: dict[str, Any]) -> dict[str, Any]:
    try:
        if kind == "php":
            return phpinfo_parser.derive_attack_surface(facts)
        if kind == "apache":
            return apache_status_parser.derive_attack_surface(facts)
        if kind == "nginx":
            return nginx_parser.derive_attack_surface(facts)
        if kind == "tomcat":
            return tomcat_status_parser.derive_attack_surface(facts)
        if kind == "spring":
            return spring_actuator_parser.derive_attack_surface(facts)
        if kind == "env_file":
            return env_file_parser.derive_attack_surface(facts)
    except Exception as exc:
        logger.debug(f"[service_info_dispatcher] derive_attack_surface({kind}) failed: {exc}")
    return {}


def _summarise(kind: str, facts: dict[str, Any]) -> str:
    try:
        if kind == "php":
            return phpinfo_parser.summarise_for_context(facts)
        if kind == "apache":
            return apache_status_parser.summarise_for_context(facts)
        if kind == "nginx":
            return nginx_parser.summarise_for_context(facts)
        if kind == "tomcat":
            return tomcat_status_parser.summarise_for_context(facts)
        if kind == "spring":
            return spring_actuator_parser.summarise_for_context(facts)
        if kind == "env_file":
            return env_file_parser.summarise_for_context(facts)
    except Exception as exc:
        logger.debug(f"[service_info_dispatcher] summarise_for_context({kind}) failed: {exc}")
    return ""


def detect_kind(path: str, body: str, headers: str = "") -> str | None:
    """Return service bucket key for the given entry, or ``None``."""
    lp = path or ""
    for kind, pat in _PATH_HINTS:
        if pat.search(lp):
            return kind
    return _match_by_content(body or "", headers or "")


def parse_entry(path: str, body: str, headers: str = "") -> DisclosureMatch | None:
    kind = detect_kind(path, body, headers)
    if not kind:
        return None
    parser = _PARSE_DISPATCH.get(kind)
    if parser is None:
        return None
    try:
        facts = parser(path, body, headers)
    except Exception as exc:
        logger.warning(f"[service_info_dispatcher] parse({kind}, {path}) failed: {exc}")
        return None
    if not facts:
        return None
    surface = _derive_surface(kind, facts)
    if surface:
        facts["_attack_surface"] = surface
    return DisclosureMatch(kind=kind, path=path, facts=facts)


def parse_harvested(harvested: list[dict[str, Any]]) -> list[DisclosureMatch]:
    """Dispatch over a list of harvested entries.

    Each entry is expected to look like::
        {"path": "/info.php", "body": "...", "headers": "...", "code": "200", ...}
    Entries that don't match any known kind are ignored.
    """
    out: list[DisclosureMatch] = []
    for entry in harvested or []:
        body = entry.get("body") or ""
        path = entry.get("path") or ""
        headers = entry.get("headers") or ""
        if not body:
            continue
        match = parse_entry(path, body, headers)
        if match:
            out.append(match)
    return out


def summarise_runtime_facts(runtime_facts: dict[str, dict[str, Any]], max_chars: int = 2400) -> str:
    """Build a compact, multi-service summary block for LLM prompt injection."""
    if not runtime_facts:
        return ""
    sections: list[str] = []
    for kind, facts in runtime_facts.items():
        if not facts:
            continue
        block = _summarise(kind, facts)
        if block:
            sections.append(block)
    if not sections:
        return ""
    out = "\n\n".join(sections)
    return out[:max_chars]
