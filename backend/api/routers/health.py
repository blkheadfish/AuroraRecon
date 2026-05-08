"""
routers/health.py —— 健康检查 + 指标概览
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Request

from backend.agents.models import PentestState, TaskStatus
from backend.api.state import get_state_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


def _safe_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def _parse_iso_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _build_system_overview(tasks: list[PentestState], sm) -> dict:
    def _is_root_priv(s: PentestState) -> bool:
        return (s.privilege_level or "").lower() == "root" or bool(
            (s.objective_status or {}).get("root_reached")
        )

    return {
        "api_status": "ok",
        "database": "connected" if sm.db_available else "unavailable",
        "redis": "connected" if sm.redis_available else "unavailable",
        "msf": "connected" if sm.msf_available else "unavailable",
        "version": "2.0.0",
        "total_tasks": len(tasks),
        "running_tasks": sum(1 for t in tasks if t.status == TaskStatus.RUNNING),
        "completed_tasks": sum(1 for t in tasks if t.status == TaskStatus.COMPLETED),
        "failed_tasks": sum(1 for t in tasks if t.status == TaskStatus.FAILED),
        "active_task_ids": sm.running_count,
        "shells_obtained_tasks": sum(1 for t in tasks if t.got_shell),
        "root_reached_tasks": sum(1 for t in tasks if _is_root_priv(t)),
        "mean_privesc_rounds": round(
            sum(t.privesc_attempt_count for t in tasks) / len(tasks), 2
        ) if tasks else 0.0,
    }


async def _build_tool_overview(sm) -> dict:
    try:
        registry = sm.get_tool_registry()
        by_executor: dict[str, int] = defaultdict(int)
        tools = []
        disabled_keys: set[str] = set()
        try:
            from backend.db.database import list_overrides
            overrides = await list_overrides("tool")
            disabled_keys = {o["resource_key"] for o in overrides if not o["enabled"]}
        except Exception:
            pass
        for td in registry.list_all():
            by_executor[td.executor] += 1
            tools.append({
                "name": td.name,
                "category": td.category,
                "executor": td.executor,
                "timeout": td.timeout,
                "enabled": td.name not in disabled_keys,
            })
        tools.sort(key=lambda item: (item["category"], item["name"]))
        return {
            "total_tools": registry.size,
            "by_category": registry.summary(),
            "by_executor": dict(by_executor),
            "tools": tools,
        }
    except Exception as e:
        logger.warning(f"[Metrics] 工具概览构建失败: {e}")
        return {"total_tools": 0, "by_category": {}, "by_executor": {}, "tools": [], "error": str(e)}


def _build_tool_invocation_overview(tasks: list[PentestState]) -> dict:
    calls_by_tool: dict[str, int] = defaultdict(int)
    backend_calls: dict[str, int] = defaultdict(int)
    done_by_tool: dict[str, int] = defaultdict(int)
    success_by_tool: dict[str, int] = defaultdict(int)
    elapsed_sum_by_tool: dict[str, float] = defaultdict(float)
    backend_by_tool: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    total_calls = 0
    success_calls = 0
    failed_calls = 0
    total_elapsed = 0.0
    done_count = 0

    for state in tasks:
        for rec in state.tool_records or []:
            payload = rec.model_dump() if hasattr(rec, "model_dump") else dict(rec or {})
            tool_name = (
                str(payload.get("display_tool") or "").strip()
                or str(payload.get("tool") or "").strip()
                or "unknown"
            )
            backend = str(payload.get("backend") or "").strip() or "shell"
            calls_by_tool[tool_name] += 1
            backend_calls[backend] += 1
            backend_by_tool[tool_name][backend] += 1
            total_calls += 1

            exit_code = payload.get("exit_code")
            if exit_code is None:
                continue
            try:
                exit_code_val = int(exit_code)
            except Exception:
                continue
            elapsed = payload.get("elapsed")
            try:
                elapsed_val = float(elapsed) if elapsed is not None else 0.0
            except Exception:
                elapsed_val = 0.0
            done_by_tool[tool_name] += 1
            elapsed_sum_by_tool[tool_name] += elapsed_val
            total_elapsed += elapsed_val
            done_count += 1
            if exit_code_val == 0:
                success_by_tool[tool_name] += 1
                success_calls += 1
            else:
                failed_calls += 1

    top_tools = []
    for tool_name, calls in sorted(calls_by_tool.items(), key=lambda item: item[1], reverse=True):
        completed = done_by_tool.get(tool_name, 0)
        succeeded = success_by_tool.get(tool_name, 0)
        avg_elapsed_ms = 0.0
        if completed > 0:
            avg_elapsed_ms = round((elapsed_sum_by_tool[tool_name] / completed) * 1000.0, 2)
        top_tools.append({
            "tool": tool_name,
            "calls": calls,
            "completed_calls": completed,
            "success_rate": _safe_rate(succeeded, completed),
            "avg_elapsed_ms": avg_elapsed_ms,
            "backends": dict(backend_by_tool.get(tool_name, {})),
        })

    return {
        "total_calls": total_calls,
        "completed_calls": done_count,
        "success_calls": success_calls,
        "failed_calls": failed_calls,
        "success_rate": _safe_rate(success_calls, done_count),
        "avg_elapsed_ms": round((total_elapsed / done_count) * 1000.0, 2) if done_count > 0 else 0.0,
        "by_backend": dict(sorted(backend_calls.items(), key=lambda item: item[1], reverse=True)),
        "top_tools": top_tools[:10],
    }


def _build_guard_overview(tasks: list[PentestState]) -> dict:
    guard_totals: dict[str, int] = defaultdict(int)
    for state in tasks:
        for k, v in (state.guard_stats or {}).items():
            guard_totals[k] += int(v or 0)
    llm_rejects = sum(
        v for k, v in guard_totals.items()
        if "preflight" in k or "llm_reject" in k
    )
    return {
        "reprobe_intercept_count": sum(v for k, v in guard_totals.items() if "reprobe" in k or "enum" in k),
        "repeat_failed_command_intercept_count": sum(v for k, v in guard_totals.items() if "repeat_failed" in k),
        "llm_preflight_reject_count": llm_rejects,
        "by_guard_code": dict(guard_totals),
    }


@router.get("/health")
async def health_check(request: Request):
    sm = get_state_manager()
    admin_routes = sorted(
        {r.path for r in request.app.routes if getattr(r, "path", "").startswith("/admin")}
    )
    from backend.api import event_stream
    return {
        "status": "ok",
        "version": "2.0.0",
        "metrics_overview": True,
        "metrics_paths": ["/metrics/overview", "/api/metrics/overview"],
        "database": "connected" if sm.db_available else "unavailable",
        "redis": "connected" if sm.redis_available else "unavailable",
        "msf": "connected" if sm.msf_available else "unavailable",
        "active_tasks": sm.running_count,
        "realtime_protocol": {
            "version": event_stream.PROTOCOL_VERSION,
            "backend": "redis_stream" if event_stream.is_redis_backed() else "local_fallback",
            "stream_maxlen": event_stream.STREAM_MAXLEN,
            "stream_ttl_seconds": event_stream.STREAM_TTL_SECONDS,
            "xread_block_ms": event_stream.XREAD_BLOCK_MS,
        },
        "admin_routes_count": len(admin_routes),
        "admin_routes": admin_routes,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/metrics/overview")
@router.get("/api/metrics/overview")
async def get_metrics_overview(window_hours: int = 24):
    sm = get_state_manager()
    bounded_window = max(1, min(window_hours, 168))
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=bounded_window)

    all_tasks = sm.all_states()
    scoped_tasks = []
    for state in all_tasks:
        task_ts = _parse_iso_ts(state.created_at)
        if task_ts is None or task_ts >= cutoff:
            scoped_tasks.append(state)

    return {
        "generated_at": now.isoformat(),
        "window_hours": bounded_window,
        "system_overview": _build_system_overview(all_tasks, sm),
        "tool_overview": await _build_tool_overview(sm),
        "tool_invocation_overview": _build_tool_invocation_overview(scoped_tasks),
        "guard_overview": _build_guard_overview(scoped_tasks),
    }
