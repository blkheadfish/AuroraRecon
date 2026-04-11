"""
tools/parsers/path_aggregator.py
Unified path/route evidence aggregator.

Normalizes output from heterogeneous directory/fuzzing scanners
(feroxbuster, dirsearch, gobuster, dirb, dirmap, ffuf, wfuzz, katana, nikto)
into one de-duplicated path inventory with confidence scoring.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


class PathEntry:
    __slots__ = ("path", "status", "source_tools", "confidence", "hints")

    def __init__(
        self,
        path: str,
        status: int = 0,
        source_tool: str = "",
        confidence: float = 0.5,
    ):
        self.path = path
        self.status = status
        self.source_tools: list[str] = [source_tool] if source_tool else []
        self.confidence = confidence
        self.hints: list[str] = _classify_path(path)

    def merge(self, other: "PathEntry") -> None:
        for t in other.source_tools:
            if t and t not in self.source_tools:
                self.source_tools.append(t)
        if other.status and not self.status:
            self.status = other.status
        self.confidence = min(1.0, self.confidence + 0.15 * len(other.source_tools))
        for h in other.hints:
            if h not in self.hints:
                self.hints.append(h)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "source_tools": self.source_tools,
            "confidence": round(self.confidence, 2),
            "hints": self.hints,
        }


def _classify_path(path: str) -> list[str]:
    hints: list[str] = []
    p = path.lower()
    if any(k in p for k in ("/admin", "/manager", "/dashboard", "/console", "/panel")):
        hints.append("admin")
    if any(k in p for k in ("/login", "/signin", "/auth", "/sso")):
        hints.append("login")
    if any(k in p for k in (".conf", ".cfg", ".ini", ".yaml", ".yml", ".xml", "web.config")):
        hints.append("config")
    if any(k in p for k in (".bak", ".old", ".backup", ".swp", ".save", ".orig", ".copy")):
        hints.append("backup")
    if any(k in p for k in ("/api", "/v1", "/v2", "/graphql", "/rest", "/swagger")):
        hints.append("api")
    if any(k in p for k in (".git", ".svn", ".env", ".htaccess", ".DS_Store")):
        hints.append("leak")
    if any(k in p for k in ("/static", "/assets", "/css", "/js", "/img", "/images")):
        hints.append("static")
    if any(k in p for k in ("/upload", "/uploads", "/file", "/files", "/attachment")):
        hints.append("upload")
    if any(k in p for k in ("phpinfo", "server-status", "server-info", "/info")):
        hints.append("info_disclosure")
    if any(k in p for k in ("wp-content", "wp-admin", "wp-login", "wp-includes")):
        hints.append("wordpress")
    return hints


_URL_RE = re.compile(r'(https?://[^\s\]\)]+)')
_STATUS_CODE_RE = re.compile(r'\b([1-5]\d{2})\b')
_FEROX_LINE_RE = re.compile(r'^\s*(\d{3})\s+\S+\s+\S+\s+\S+\s+(https?://\S+)')
_GOBUSTER_RE = re.compile(r'^(/\S+)\s+\(Status:\s*(\d{3})\)')
_DIRB_RE = re.compile(r'^\+\s+(https?://\S+)\s+\(CODE:(\d{3})')
_DIRB_DIRECTORY_RE = re.compile(r'^\s*==>\s*DIRECTORY:\s*(https?://\S+)', re.IGNORECASE)
_FFUF_RE = re.compile(r'^\s*(\S+)\s+\[Status:\s*(\d{3})')
_DIRSEARCH_RE = re.compile(r'^\s*(\d{3})\s+\S+\s+\S+\s+(\S+)')
_WFUZZ_RE = re.compile(r'^\d+\s+\d+\s+\d+\s+\d+\s+(\d{3})\s+\d+\s+\w+\s+\d+\s+"([^"]+)"')


class PathAggregator:
    """Collects paths from multiple tool outputs and produces a unified inventory."""

    def __init__(self) -> None:
        self._entries: dict[str, PathEntry] = {}

    @property
    def count(self) -> int:
        return len(self._entries)

    def ingest(self, tool_name: str, raw_output: str, base_url: str = "") -> int:
        """Parse raw output from a tool and add discovered paths. Returns count of new paths."""
        parser = _TOOL_PARSERS.get(tool_name, _parse_generic)
        results = parser(raw_output, base_url)
        added = 0
        for path, status in results:
            path = _normalize_path(path)
            if not path:
                continue
            if path in self._entries:
                self._entries[path].merge(
                    PathEntry(path, status, tool_name)
                )
            else:
                conf = _base_confidence(status, tool_name)
                self._entries[path] = PathEntry(path, status, tool_name, conf)
                added += 1
        return added

    def add_paths(self, paths: list[str], source: str = "manual", status: int = 200) -> None:
        for p in paths:
            p = _normalize_path(p)
            if not p:
                continue
            if p in self._entries:
                self._entries[p].merge(PathEntry(p, status, source))
            else:
                self._entries[p] = PathEntry(p, status, source, 0.5)

    def get_inventory(self, min_confidence: float = 0.0) -> list[dict]:
        items = [
            e.to_dict() for e in self._entries.values()
            if e.confidence >= min_confidence
        ]
        items.sort(key=lambda x: (-x["confidence"], x["path"]))
        return items

    def get_paths(self) -> list[str]:
        return sorted(self._entries.keys())

    def get_actionable_paths(self) -> list[str]:
        """Return non-static paths sorted by confidence descending."""
        return [
            e.path for e in sorted(
                self._entries.values(), key=lambda x: -x.confidence
            )
            if "static" not in e.hints
        ]

    def summary(self) -> dict:
        hint_counts: dict[str, int] = {}
        for e in self._entries.values():
            for h in e.hints:
                hint_counts[h] = hint_counts.get(h, 0) + 1
        sources: set[str] = set()
        for e in self._entries.values():
            sources.update(e.source_tools)
        return {
            "total_paths": len(self._entries),
            "source_tools": sorted(sources),
            "hint_distribution": hint_counts,
            "high_value": sum(
                1 for e in self._entries.values()
                if any(h in e.hints for h in ("admin", "login", "leak", "upload", "api", "config", "backup"))
            ),
        }


def _normalize_path(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        raw = parsed.path
    path = raw.rstrip("/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _base_confidence(status: int, tool: str) -> float:
    if status == 200:
        return 0.7
    if status in (301, 302):
        return 0.5
    if status == 403:
        return 0.6
    if status == 500:
        return 0.4
    return 0.5


def _parse_feroxbuster(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _FEROX_LINE_RE.match(line)
        if m:
            results.append((m.group(2), int(m.group(1))))
            continue
        m = _URL_RE.search(line)
        if m:
            sc = _STATUS_CODE_RE.search(line)
            results.append((m.group(1), int(sc.group(1)) if sc else 0))
    return results


def _parse_gobuster(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        m = _GOBUSTER_RE.match(line.strip())
        if m:
            results.append((m.group(1), int(m.group(2))))
    return results


def _parse_dirsearch(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        m = _DIRSEARCH_RE.match(line.strip())
        if m:
            results.append((m.group(2), int(m.group(1))))
    return results


def _parse_dirb(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        m = _DIRB_RE.match(stripped)
        if m:
            results.append((m.group(1), int(m.group(2))))
            continue
        # dirb sometimes reports directory hits in this form:
        # ==> DIRECTORY: http://target/admin/
        d = _DIRB_DIRECTORY_RE.match(stripped)
        if d:
            results.append((d.group(1), 200))
    return results


def _parse_ffuf(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _FFUF_RE.match(line)
        if m:
            path = m.group(1)
            if not path.startswith("/"):
                path = "/" + path
            results.append((path, int(m.group(2))))
            continue
        if line.startswith("/") or line.startswith("http"):
            results.append((line.split()[0], 0))
    return results


def _parse_wfuzz(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        m = _WFUZZ_RE.match(line.strip())
        if m:
            results.append((m.group(2), int(m.group(1))))
    return results


def _parse_katana(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _URL_RE.match(line)
        if m:
            results.append((m.group(1), 200))
    return results


def _parse_nikto(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for line in raw.splitlines():
        m = re.search(r'(?:OSVDB-\d+|Server).*?((?:/[\w./\-]+)+)', line)
        if m:
            results.append((m.group(1), 0))
    return results


def _parse_dirmap(raw: str, base_url: str) -> list[tuple[str, int]]:
    return _parse_generic(raw, base_url)


def _parse_generic(raw: str, base_url: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _URL_RE.search(line)
        if m:
            url = m.group(1)
            if url not in seen:
                seen.add(url)
                sc = _STATUS_CODE_RE.search(line)
                results.append((url, int(sc.group(1)) if sc else 0))
            continue
        if line.startswith("/"):
            path = line.split()[0]
            if path not in seen:
                seen.add(path)
                sc = _STATUS_CODE_RE.search(line)
                results.append((path, int(sc.group(1)) if sc else 0))
    return results


_TOOL_PARSERS = {
    "feroxbuster": _parse_feroxbuster,
    "dirsearch": _parse_dirsearch,
    "gobuster": _parse_gobuster,
    "dirb": _parse_dirb,
    "ffuf": _parse_ffuf,
    "wfuzz": _parse_wfuzz,
    "katana": _parse_katana,
    "nikto": _parse_nikto,
    "dirmap": _parse_dirmap,
}
