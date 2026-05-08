"""
collector.py
Lightweight in-process metrics for LLM calls and tool executions.
No external dependencies — all data lives in memory, reset on restart.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMCallRecord:
    timestamp: str
    phase: str
    method: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    duration_ms: float
    status: str
    caller: str


@dataclass
class ToolExecRecord:
    timestamp: str
    tool_name: str
    phase: str
    success: bool
    elapsed_ms: float
    timed_out: bool


@dataclass
class ToolAggregate:
    calls: int = 0
    success: int = 0
    fail: int = 0
    timeout: int = 0
    total_elapsed_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.calls == 0:
            return 0.0
        return round(self.success / self.calls, 4)

    @property
    def avg_elapsed_ms(self) -> float:
        if self.calls == 0:
            return 0.0
        return round(self.total_elapsed_ms / self.calls, 1)


class MetricsCollector:
    """Singleton metrics store for LLM + tool observability."""

    LLM_MAXLEN = 500
    TOOL_MAXLEN = 500

    def __init__(self):
        self._lock = threading.Lock()
        self._llm_calls: deque[LLMCallRecord] = deque(maxlen=self.LLM_MAXLEN)
        self._tool_calls: deque[ToolExecRecord] = deque(maxlen=self.TOOL_MAXLEN)
        self._tool_agg: dict[str, ToolAggregate] = {}

    # ── LLM metrics ────────────────────────────────────────────────

    def collect_llm_call(
        self,
        *,
        phase: str = "",
        method: str = "",
        duration_ms: float = 0.0,
        usage: Optional[Any] = None,
        status: str = "ok",
        caller: str = "",
        provider: str = "",
        model: str = "",
    ) -> None:
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        if usage is not None:
            try:
                prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                total_tokens = getattr(usage, "total_tokens", 0) or 0
            except Exception:
                pass

        record = LLMCallRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase or "",
            method=method or "",
            provider=provider or "",
            model=model or "",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            duration_ms=round(duration_ms, 1),
            status=status,
            caller=caller or "",
        )
        with self._lock:
            self._llm_calls.append(record)

    def get_llm_summary(self) -> dict[str, Any]:
        with self._lock:
            calls = list(self._llm_calls)

        by_phase: dict[str, dict] = {}
        for r in calls:
            key = r.phase or "(unknown)"
            if key not in by_phase:
                by_phase[key] = {"count": 0, "total_tokens": 0, "total_ms": 0.0}
            by_phase[key]["count"] += 1
            by_phase[key]["total_tokens"] += r.total_tokens
            by_phase[key]["total_ms"] += r.duration_ms

        for v in by_phase.values():
            v["avg_tokens"] = round(v["total_tokens"] / v["count"], 1) if v["count"] else 0
            v["avg_ms"] = round(v["total_ms"] / v["count"], 1) if v["count"] else 0

        return {
            "calls_total": len(calls),
            "tokens_total": sum(r.total_tokens for r in calls),
            "by_phase": by_phase,
            "recent_calls": [self._record_to_dict(r) for r in calls[-50:]],
        }

    def get_llm_raw_calls(self, limit: int = 100) -> list[dict]:
        with self._lock:
            calls = list(self._llm_calls)
        return [self._record_to_dict(r) for r in calls[-limit:]]

    @staticmethod
    def _record_to_dict(r: LLMCallRecord) -> dict:
        return {
            "timestamp": r.timestamp,
            "phase": r.phase,
            "method": r.method,
            "provider": r.provider,
            "model": r.model,
            "prompt_tokens": r.prompt_tokens,
            "completion_tokens": r.completion_tokens,
            "total_tokens": r.total_tokens,
            "duration_ms": r.duration_ms,
            "status": r.status,
            "caller": r.caller,
        }

    # ── Tool metrics ───────────────────────────────────────────────

    def collect_tool_exec(
        self,
        *,
        tool_name: str = "",
        phase: str = "",
        success: bool = False,
        elapsed: float = 0.0,
        timed_out: bool = False,
    ) -> None:
        name = tool_name or "unknown"
        record = ToolExecRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name=name,
            phase=phase or "",
            success=success,
            elapsed_ms=round(elapsed * 1000, 1),
            timed_out=timed_out,
        )
        with self._lock:
            self._tool_calls.append(record)
            agg = self._tool_agg.setdefault(name, ToolAggregate())
            agg.calls += 1
            if success:
                agg.success += 1
            else:
                agg.fail += 1
            if timed_out:
                agg.timeout += 1
            agg.total_elapsed_ms += elapsed * 1000

    def get_tool_summary(self) -> dict[str, Any]:
        with self._lock:
            agg_snapshot = {k: v.__dict__.copy() for k, v in self._tool_agg.items()}
            recent = list(self._tool_calls)[-50:]

        tools = []
        for name, a in agg_snapshot.items():
            tools.append({
                "name": name,
                "calls": a["calls"],
                "success": a["success"],
                "fail": a["fail"],
                "timeout": a["timeout"],
                "success_rate": (
                    round(a["success"] / a["calls"], 4) if a["calls"] else 0
                ),
                "avg_elapsed_ms": (
                    round(a["total_elapsed_ms"] / a["calls"], 1) if a["calls"] else 0
                ),
            })
        tools.sort(key=lambda x: x["calls"], reverse=True)

        return {
            "tools_total": len(tools),
            "calls_total": sum(t["calls"] for t in tools),
            "tools": tools,
            "recent_calls": [
                {
                    "timestamp": r.timestamp,
                    "tool_name": r.tool_name,
                    "phase": r.phase,
                    "success": r.success,
                    "elapsed_ms": r.elapsed_ms,
                    "timed_out": r.timed_out,
                }
                for r in recent
            ],
        }


# ── Module-level singleton ────────────────────────────────────────

_collector: Optional[MetricsCollector] = None
_collector_lock = threading.Lock()


def get_collector() -> MetricsCollector:
    global _collector
    if _collector is None:
        with _collector_lock:
            if _collector is None:
                _collector = MetricsCollector()
                logger.info("[Metrics] Collector initialized")
    return _collector
