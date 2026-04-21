"""
tools/deep_scan_coordinator.py

Shared deep-scan queue + budget across:
  - Phase 2: DirScanOrchestrator._execute_deep_scans  (per-port)
  - Phase 3: ReconAgent._deep_recursive_scan          (LLM-guided)
  - Phase 3-drain: ReconAgent._drain_deep_scan_queue  (new)

Problem this solves (pre-refactor):
  - Orchestrator kept its own local _deep_scan_queue.
  - _deep_recursive_scan in ReconAgent was one-shot — new directories it
    discovered were ingested into the aggregator but never re-queued.
  - The two kept separate state, so Phase 3 could not benefit from the
    orchestrator's duplicate-tracking nor vice versa.

Contract:
  - enqueue(target)        dedupes by normalised path + scanned set
  - pop_batch(n)           pops up to n items by priority desc (respects budget)
  - mark_scanned(path, s)  records completion + elapsed cost
  - can_scan()             false once scan count or wall-time budget exhausts
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


# Mirror of DirScanOrchestrator._HIGH_VALUE_HINTS / _DEEP_KEYWORDS so that
# pick_followups produces identical scoring regardless of who calls it
# (orchestrator-internal vs Phase 3 _deep_recursive_scan回流).
_HIGH_VALUE_HINTS = frozenset({
    "admin", "login", "backup", "config", "upload", "api",
    "leak", "info_disclosure",
})

_DEEP_KEYWORDS = frozenset({
    "admin", "api", "backup", "config", "upload", "manager",
    "console", "debug", "internal", "private", "portal", "panel",
    "cgi-bin", "includes", "modules", "plugins", "data",
    "user", "users", "account", "dashboard", "test", "staging", "dev",
    "tmp", "temp", "assets", "static", "vendor", "files", "docs", "help",
    "system", "settings", "secret", "secrets", "manage", "cms",
    "wp-admin", "phpmyadmin", "install", "setup",
})


def _norm(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def pick_followups(
    new_paths: Iterable[str],
    aggregator: Any,
    scanned: Iterable[str],
    *,
    cap: int = 10,
    threshold: int = 3,
) -> list[str]:
    """Score new paths and return the top candidates worth re-scanning.

    Shared by DirScanOrchestrator (Phase 2) and ReconAgent._deep_recursive_scan
    回流 (Phase 3). Both should agree on which directories deserve another
    ferox pass so that the coordinator sees a consistent queue.

    Scoring (threshold >= 3 by default):
      is_dir_like                      +2
      keyword hit (substring)          +3
      aggregator hint in HIGH_VALUE    +2
      aggregator confidence >= 0.7     +1
    """
    scanned_set = {_norm(s) for s in scanned} if scanned else set()
    scored: list[tuple[int, str]] = []
    entries = getattr(aggregator, "_entries", None) if aggregator else None

    for p in new_paths:
        if not p:
            continue
        if _norm(p) in scanned_set:
            continue
        lower = p.lower().rstrip("/")
        if not lower:
            continue
        basename = lower.rsplit("/", 1)[-1] if "/" in lower else lower
        score = 0
        is_dir_like = p.endswith("/") or "." not in basename
        if is_dir_like and basename:
            score += 2
        if any(kw in lower for kw in _DEEP_KEYWORDS):
            score += 3
        entry = entries.get(p) if isinstance(entries, dict) else None
        if entry is not None:
            hints = getattr(entry, "hints", None) or set()
            if hints and (set(hints) & _HIGH_VALUE_HINTS):
                score += 2
            confidence = getattr(entry, "confidence", 0.0) or 0.0
            if confidence >= 0.7:
                score += 1
        if score >= threshold:
            scored.append((score, p))

    scored.sort(key=lambda x: -x[0])
    return [p for _, p in scored[:cap]]


@dataclass
class DeepScanTarget:
    path: str
    reason: str = ""
    wordlist: str = "small"
    priority: int = 0
    # Optional per-target base URL override. When unset, the drain caller
    # decides the base (typically the primary Web port).
    base_url: str = ""


@dataclass
class DeepScanStats:
    enqueued: int = 0
    scanned: int = 0
    queued: int = 0
    elapsed_s: float = 0.0
    budget_s: float = 0.0
    max_total: int = 0

    def to_dict(self) -> dict:
        return {
            "enqueued": self.enqueued,
            "scanned": self.scanned,
            "queued": self.queued,
            "elapsed_s": round(self.elapsed_s, 1),
            "budget_s": round(self.budget_s, 1),
            "max_total": self.max_total,
        }


class DeepScanCoordinator:
    """Deduplicated priority queue + soft budget for cross-phase deep scans."""

    def __init__(
        self,
        *,
        max_total_scans: int = 30,
        budget_seconds: float = 900.0,
    ) -> None:
        self._queue: dict[str, DeepScanTarget] = {}
        self._scanned: set[str] = set()
        self._max_total_scans = max(1, int(max_total_scans))
        self._budget_seconds = max(1.0, float(budget_seconds))
        self._elapsed = 0.0
        self._enqueued_total = 0

    # ─── enqueue / dedup ──────────────────────────────────────────
    def enqueue(self, target: DeepScanTarget) -> bool:
        """Add target if new. Returns True if actually enqueued."""
        norm = _norm(target.path)
        if not norm:
            return False
        if norm in self._scanned:
            return False
        existing = self._queue.get(norm)
        if existing is not None:
            # Upgrade priority if new entry says it's more interesting
            if target.priority > existing.priority:
                existing.priority = target.priority
                existing.reason = target.reason or existing.reason
            return False
        self._queue[norm] = target
        self._enqueued_total += 1
        return True

    def enqueue_many(self, targets: Iterable[DeepScanTarget]) -> int:
        count = 0
        for t in targets:
            if self.enqueue(t):
                count += 1
        return count

    # ─── pop / scheduling ────────────────────────────────────────
    def pop_batch(self, n: int = 5) -> list[DeepScanTarget]:
        """Pop up to n highest-priority items. Returns [] when budget exhausted."""
        if not self.can_scan() or not self._queue:
            return []
        items = list(self._queue.values())
        items.sort(key=lambda t: (-int(t.priority), t.path))
        cap = max(1, int(n))
        # also respect remaining scan budget
        remaining = self._max_total_scans - len(self._scanned)
        cap = min(cap, max(0, remaining))
        batch = items[:cap]
        for t in batch:
            self._queue.pop(_norm(t.path), None)
        return batch

    def mark_scanned(self, path: str, *, elapsed_s: float = 0.0) -> None:
        norm = _norm(path)
        if not norm:
            return
        self._scanned.add(norm)
        self._queue.pop(norm, None)
        try:
            self._elapsed += float(elapsed_s)
        except (TypeError, ValueError):
            pass

    # ─── budget / state ──────────────────────────────────────────
    def can_scan(self) -> bool:
        return (
            len(self._scanned) < self._max_total_scans
            and self._elapsed < self._budget_seconds
        )

    def has_pending(self) -> bool:
        return bool(self._queue)

    def pending_count(self) -> int:
        return len(self._queue)

    def scanned_count(self) -> int:
        return len(self._scanned)

    def has_been_scanned(self, path: str) -> bool:
        return _norm(path) in self._scanned

    def scanned_summary(self, limit: int = 20) -> list[str]:
        """Return a deterministic (sorted) snapshot of already-scanned paths.

        Used by DIR_MID_SCAN_EVAL prompt (A5) to suppress duplicate LLM
        recommendations. Paths are deduplicated + normalized via ``_norm``
        already, we just sort them for stable ordering.
        """
        if limit <= 0:
            return []
        return sorted(self._scanned)[:limit]

    def stats(self) -> DeepScanStats:
        return DeepScanStats(
            enqueued=self._enqueued_total,
            scanned=len(self._scanned),
            queued=len(self._queue),
            elapsed_s=self._elapsed,
            budget_s=self._budget_seconds,
            max_total=self._max_total_scans,
        )

    def budget_report(self) -> str:
        s = self.stats()
        return (
            f"deep-scan budget: scanned={s.scanned}/{s.max_total}, "
            f"queued={s.queued}, elapsed={s.elapsed_s:.1f}s/{s.budget_s:.0f}s"
        )
