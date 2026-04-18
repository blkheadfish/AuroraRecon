"""
nginx_parser.py
Deterministic extraction from Nginx disclosure surfaces:

  - ``/nginx_status`` / ``/status`` (ngx_http_stub_status_module)
        Active connections: 291
        server accepts handled requests
         16630948 16630948 31070465
        Reading: 6 Writing: 179 Waiting: 106

  - Default Nginx error / welcome pages exposing version via ``Server`` header
  - Custom ``/server_status`` from ngx_status / Nginx Plus JSON endpoint
"""
from __future__ import annotations

import json
import re
from typing import Any

_STUB_SIG_RE = re.compile(
    r"Active connections:\s*\d+|"
    r"server accepts handled requests|"
    r"<h1>\s*Welcome to nginx!\s*</h1>",
    re.IGNORECASE,
)

_STUB_BLOCK_RE = re.compile(
    r"Active connections:\s*(?P<active>\d+).*?"
    r"(?P<accepts>\d+)\s+(?P<handled>\d+)\s+(?P<requests>\d+).*?"
    r"Reading:\s*(?P<reading>\d+)\s+Writing:\s*(?P<writing>\d+)\s+Waiting:\s*(?P<waiting>\d+)",
    re.IGNORECASE | re.DOTALL,
)

_SERVER_HEADER_RE = re.compile(
    r"(?:^|\n)Server:\s*(nginx[^\r\n]*)",
    re.IGNORECASE,
)

_VERSION_INLINE_RE = re.compile(
    r"nginx/(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def is_nginx_status_content(text: str, headers: str = "") -> bool:
    if not text and not headers:
        return False
    if text and _STUB_SIG_RE.search(text):
        return True
    if headers and re.search(r"^Server:\s*nginx", headers, re.IGNORECASE | re.MULTILINE):
        return True
    return False


def parse_nginx_status(text: str, headers: str = "") -> dict[str, Any]:
    facts: dict[str, Any] = {}

    m = _STUB_BLOCK_RE.search(text or "")
    if m:
        facts["active_connections"] = int(m.group("active"))
        facts["accepts"] = int(m.group("accepts"))
        facts["handled"] = int(m.group("handled"))
        facts["total_requests"] = int(m.group("requests"))
        facts["reading"] = int(m.group("reading"))
        facts["writing"] = int(m.group("writing"))
        facts["waiting"] = int(m.group("waiting"))
        dropped = facts["accepts"] - facts["handled"]
        if dropped > 0:
            facts["dropped_connections"] = dropped

    hdr_src = headers or text or ""
    sm = _SERVER_HEADER_RE.search(hdr_src)
    if sm:
        facts["server_banner"] = sm.group(1).strip()
    vm = _VERSION_INLINE_RE.search(hdr_src)
    if vm:
        facts["nginx_version"] = vm.group(1)

    if text and text.strip().startswith("{"):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict) and "version" in payload:
                facts["nginx_version"] = str(payload["version"])
            if isinstance(payload, dict) and "nginx_version" in payload:
                facts["nginx_version"] = str(payload["nginx_version"])
        except Exception:
            pass

    return facts


_CVE_VERSION_TABLE = [
    ("1.20.0",  "cve_2021_23017_candidate",
     "resolver off-by-one (CVE-2021-23017) when DNS 配置启用"),
    ("1.15.5",  "cve_2019_9513_candidate",
     "HTTP/2 DoS (CVE-2019-9511 ~ 9516) 候选"),
    ("1.4.0",   "ancient_version",
     "极老版本，完整 CVE 列表过长，建议直接对 CVE DB 查询"),
]


def _vercmp(a: str, b: str) -> int:
    pa = [int(x) for x in a.split(".") if x.isdigit()]
    pb = [int(x) for x in b.split(".") if x.isdigit()]
    while len(pa) < 3:
        pa.append(0)
    while len(pb) < 3:
        pb.append(0)
    return (pa > pb) - (pa < pb)


def derive_attack_surface(facts: dict[str, Any]) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    ver = facts.get("nginx_version") or ""
    if ver:
        surface["version"] = ver
        for threshold, key, desc in _CVE_VERSION_TABLE:
            try:
                if _vercmp(ver, threshold) < 0:
                    surface[key] = desc
            except Exception:
                pass

    if facts.get("server_banner") and "nginx/" in facts["server_banner"].lower():
        surface["version_disclosure"] = True

    if facts.get("total_requests", 0) > 1_000_000:
        surface["production_traffic"] = True

    return surface


def summarise_for_context(facts: dict[str, Any], max_chars: int = 400) -> str:
    if not facts:
        return ""
    lines = ["Nginx 运行时约束摘要:"]
    if facts.get("nginx_version"):
        lines.append(f"- 版本: nginx/{facts['nginx_version']}")
    elif facts.get("server_banner"):
        lines.append(f"- Server: {facts['server_banner']}")
    if "active_connections" in facts:
        lines.append(
            f"- 活动连接: {facts['active_connections']} "
            f"(reading={facts.get('reading', 0)}/writing={facts.get('writing', 0)}"
            f"/waiting={facts.get('waiting', 0)})"
        )
    if facts.get("total_requests"):
        lines.append(f"- 累计请求数: {facts['total_requests']}")
    return "\n".join(lines)[:max_chars]
