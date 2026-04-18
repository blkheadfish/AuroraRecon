"""
spring_actuator_parser.py
Extract facts from Spring Boot Actuator endpoints.

Supported endpoints (anything the crawler may hand us):
  - ``/actuator``         endpoint discovery (HAL/JSON index)
  - ``/actuator/env``     application + system properties; often leaks creds
  - ``/actuator/info``    app metadata
  - ``/actuator/mappings`` routing table
  - ``/actuator/beans``   bean graph (size only — content is noisy)
  - ``/actuator/health``  status + component details
  - ``/actuator/configprops`` bound properties (can leak creds)
  - ``/actuator/heapdump`` binary; we merely flag presence
  - ``/actuator/loggers``, ``/actuator/metrics``

Legacy (Spring Boot 1.x) flat paths also handled:
  ``/env``, ``/mappings``, ``/configprops``, ``/trace``, ``/dump``
"""
from __future__ import annotations

import json
import re
from typing import Any


_HAL_LINKS_RE = re.compile(r'"(?P<name>[a-z][\w\-.]*?)"\s*:\s*\{\s*"href"\s*:\s*"(?P<href>[^"]+)"',
                            re.IGNORECASE)


_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"credential|client[_-]?secret|private[_-]?key|datasource\.password|"
    r"spring\.datasource\.password|jdbc\.password|redis\.password|"
    r"mongodb\.password|aws\.accesskey|aws\.secretkey)",
    re.IGNORECASE,
)


_ACTUATOR_SIG_RE = re.compile(
    r'"_links"\s*:\s*\{|'
    r'"propertySources"\s*:\s*\[|'
    r'"contexts"\s*:\s*\{|'
    r'"handler"\s*:\s*"[^"]*springframework|'
    r'"healthEndpoint"\s*:|'
    r'spring\.boot',
    re.IGNORECASE,
)


def is_actuator_content(text: str) -> bool:
    if not text:
        return False
    if _ACTUATOR_SIG_RE.search(text):
        return True
    tl = text.lower().lstrip()
    if tl.startswith("{") and ("actuator" in tl or "propertysources" in tl):
        return True
    return False


def _detect_endpoint_kind(path: str, payload: Any) -> str:
    p = (path or "").lower()
    if "/env" in p:
        return "env"
    if "/mappings" in p:
        return "mappings"
    if "/info" in p:
        return "info"
    if "/health" in p:
        return "health"
    if "/configprops" in p:
        return "configprops"
    if "/beans" in p:
        return "beans"
    if "/heapdump" in p:
        return "heapdump"
    if "/loggers" in p:
        return "loggers"
    if "/metrics" in p:
        return "metrics"
    if "/trace" in p:
        return "trace"
    if isinstance(payload, dict):
        if "propertySources" in payload:
            return "env"
        if "components" in payload and "status" in payload:
            return "health"
        if "contexts" in payload:
            return "mappings"
        if "_links" in payload:
            return "index"
    return "unknown"


def _collect_env_entries(payload: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    """Return (all_entries, sensitive_entries) from /actuator/env JSON."""
    all_entries: list[dict] = []
    sensitive: list[dict] = []
    for src in payload.get("propertySources", []) or []:
        src_name = str(src.get("name", ""))
        props = src.get("properties") or {}
        if not isinstance(props, dict):
            continue
        for key, val_wrap in props.items():
            val: Any = val_wrap
            if isinstance(val_wrap, dict):
                val = val_wrap.get("value", "")
            entry = {"source": src_name, "key": str(key), "value": str(val)[:200]}
            all_entries.append(entry)
            if _SENSITIVE_KEY_RE.search(str(key)):
                sensitive.append(entry)
    return all_entries, sensitive


def _collect_configprops(payload: dict[str, Any]) -> list[dict]:
    """Recursively walk /actuator/configprops JSON for sensitive keys."""
    hits: list[dict] = []

    def _walk(prefix: str, node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                full = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    _walk(full, v)
                else:
                    if _SENSITIVE_KEY_RE.search(full):
                        hits.append({"key": full, "value": str(v)[:200]})
        elif isinstance(node, list):
            for idx, v in enumerate(node):
                _walk(f"{prefix}[{idx}]", v)

    _walk("", payload)
    return hits


def _collect_mappings(payload: dict[str, Any]) -> list[str]:
    mappings: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and "predicate" in v:
                    pred = str(v.get("predicate", ""))
                    m = re.search(r"\{([A-Z]+\s*)?(/[^\s\}]+)", pred)
                    if m:
                        mappings.append(m.group(2))
                else:
                    _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(payload)
    return sorted(set(mappings))[:100]


def parse_actuator(path: str, body: str) -> dict[str, Any]:
    """Parse a single actuator endpoint body. Returns per-endpoint facts + kind."""
    if not body:
        return {}
    facts: dict[str, Any] = {}

    try:
        payload = json.loads(body)
    except Exception:
        payload = None

    kind = _detect_endpoint_kind(path, payload)
    facts["endpoint_kind"] = kind

    if payload is None:
        if kind == "heapdump":
            facts["heapdump_available"] = True
        return facts

    if kind == "env":
        all_e, sens = _collect_env_entries(payload)
        facts["env_entry_count"] = len(all_e)
        if sens:
            facts["sensitive_env"] = sens[:50]
        active = payload.get("activeProfiles") or []
        if active:
            facts["active_profiles"] = list(active)

    elif kind == "configprops":
        sens = _collect_configprops(payload)
        if sens:
            facts["sensitive_configprops"] = sens[:50]

    elif kind == "mappings":
        routes = _collect_mappings(payload)
        if routes:
            facts["routes"] = routes

    elif kind == "health":
        status = payload.get("status") if isinstance(payload, dict) else None
        if status:
            facts["health_status"] = str(status)
        components = payload.get("components") or payload.get("details") or {}
        if isinstance(components, dict):
            facts["health_components"] = sorted(components.keys())[:30]

    elif kind == "info":
        app = (payload.get("app") if isinstance(payload, dict) else None) or {}
        if isinstance(app, dict):
            if app.get("version"):
                facts["app_version"] = str(app["version"])
            if app.get("name"):
                facts["app_name"] = str(app["name"])
        build = (payload.get("build") if isinstance(payload, dict) else None) or {}
        if isinstance(build, dict) and build.get("version"):
            facts["build_version"] = str(build["version"])

    elif kind == "index":
        links: list[str] = []
        for m in _HAL_LINKS_RE.finditer(body):
            name = m.group("name")
            href = m.group("href")
            if name != "self":
                links.append(f"{name} -> {href}")
        if links:
            facts["available_endpoints"] = links[:40]

    elif kind == "beans":
        contexts = payload.get("contexts") if isinstance(payload, dict) else None
        if isinstance(contexts, dict):
            total = 0
            for ctx in contexts.values():
                beans = ctx.get("beans") if isinstance(ctx, dict) else None
                if isinstance(beans, dict):
                    total += len(beans)
            if total:
                facts["bean_count"] = total

    return facts


def merge_actuator_facts(facts_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge facts extracted from multiple actuator endpoints into one dict."""
    merged: dict[str, Any] = {"endpoints_seen": []}
    for f in facts_list:
        kind = f.get("endpoint_kind")
        if kind:
            merged["endpoints_seen"].append(kind)
        for k, v in f.items():
            if k == "endpoint_kind":
                continue
            if k not in merged:
                merged[k] = v
            elif isinstance(v, list) and isinstance(merged[k], list):
                seen = {str(x) for x in merged[k]}
                for item in v:
                    if str(item) not in seen:
                        merged[k].append(item)
                        seen.add(str(item))
    merged["endpoints_seen"] = sorted(set(merged["endpoints_seen"]))
    return merged


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    endpoints = facts.get("endpoints_seen") or []
    if "env" in endpoints:
        surface["env_exposed"] = True
    if "heapdump" in endpoints or facts.get("heapdump_available"):
        surface["heapdump_exposed"] = True
        surface["heapdump_scan_cmd"] = "python3 JDumpSpider.jar heapdump.hprof"
    if facts.get("sensitive_env") or facts.get("sensitive_configprops"):
        surface["credential_leak"] = True
    if "mappings" in endpoints and facts.get("routes"):
        if any("/admin" in r or "/internal" in r for r in facts.get("routes", [])):
            surface["admin_routes_exposed"] = True
    if facts.get("available_endpoints"):
        surface["discovery_index"] = facts["available_endpoints"]
    active = facts.get("active_profiles") or []
    if "dev" in active or "development" in active:
        surface["dev_profile_active"] = True

    return surface


def _mask(value: str) -> str:
    if not value or len(value) <= 4:
        return "***"
    return value[:2] + "…" + value[-2:]


def summarise_for_context(facts: dict[str, Any], max_chars: int = 700) -> str:
    if not facts:
        return ""
    lines = ["Spring Actuator 运行时约束摘要:"]
    if facts.get("app_name") or facts.get("app_version"):
        lines.append(f"- App: {facts.get('app_name', '')} {facts.get('app_version', '')}".rstrip())
    if facts.get("active_profiles"):
        lines.append(f"- ActiveProfiles: {', '.join(facts['active_profiles'])}")
    endpoints = facts.get("endpoints_seen") or []
    if endpoints:
        lines.append(f"- 已暴露 endpoint: {', '.join(endpoints)}")
    if facts.get("sensitive_env"):
        masked = [f"{e['key']}={_mask(str(e['value']))}" for e in facts["sensitive_env"][:5]]
        lines.append(f"- /env 凭据泄露 (脱敏): {'; '.join(masked)}")
    if facts.get("sensitive_configprops"):
        masked = [f"{e['key']}={_mask(str(e['value']))}" for e in facts["sensitive_configprops"][:5]]
        lines.append(f"- /configprops 凭据泄露 (脱敏): {'; '.join(masked)}")
    if facts.get("heapdump_available") or "heapdump" in endpoints:
        lines.append("- /actuator/heapdump 可下载 → JVM 内存转储，可用 JDumpSpider 提取密码")
    if facts.get("routes"):
        lines.append(f"- 路由数: {len(facts['routes'])} (含 admin/internal: "
                     f"{'是' if any('/admin' in r or '/internal' in r for r in facts['routes']) else '否'})")
    return "\n".join(lines)[:max_chars]
