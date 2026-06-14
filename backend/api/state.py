"""
state.py —— 全局状态管理器

将散落的全局变量封装为 TaskStateManager 类，
所有 Router / Service 通过依赖注入获取同一实例。

协议 v2 之后, ``build_decision_events`` 那一套从 ``phase_log`` 字符串里
正则反推 tool/thought/log 的派生逻辑全部下线 -- 实时事件由 Redis Stream
持久化, 前端直接消费 envelope, 不再用 phase_log 重新拼一份"伪事件流"。
对应的 TOOL_START_RE / TOOL_DONE_RE / _SHELL_NAMES / _command_preview /
_infer_tool_from_command 等正则与工具推断函数也一并删掉, 减少误推断带来的
"工具名乱跳"问题。
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime
from typing import Optional

from backend.agents.models import PentestState, TaskStatus
from backend.agents.chain_templates import pipeline_steps_for

logger = logging.getLogger(__name__)


class TaskStateManager:
    """进程内任务状态容器（单例）"""

    def __init__(self):
        self._tasks: dict[str, PentestState] = {}
        self._running_tasks: set[str] = set()
        self._approval_inflight: dict[str, float] = {}
        self.APPROVAL_INFLIGHT_TIMEOUT = 600

        self.db_available = False
        self.redis_available = False
        self.msf_available = False

        self._tool_registry_cache = None
        self._tool_registry_mtime = 0.0

        self._bg_tasks: dict[str, asyncio.Task] = {}

        self._log_seq_counter: dict[str, int] = {}
        self._log_seq_lock = threading.Lock()


    def get(self, task_id: str) -> Optional[PentestState]:
        return self._tasks.get(task_id)

    def set(self, task_id: str, state: PentestState):
        self._tasks[task_id] = state

    def pop(self, task_id: str) -> Optional[PentestState]:
        self.reset_log_seq(task_id)
        return self._tasks.pop(task_id, None)

    def all_states(self) -> list[PentestState]:
        return list(self._tasks.values())

    def items(self):
        return self._tasks.items()


    def mark_running(self, task_id: str):
        self._running_tasks.add(task_id)

    def mark_stopped(self, task_id: str):
        self._running_tasks.discard(task_id)

    @property
    def running_count(self) -> int:
        return len(self._running_tasks)

    def is_running(self, task_id: str) -> bool:
        return task_id in self._running_tasks


    def set_approval_inflight(self, task_id: str, ts: float):
        self._approval_inflight[task_id] = ts

    def get_approval_inflight(self, task_id: str) -> Optional[float]:
        return self._approval_inflight.get(task_id)

    def clear_approval_inflight(self, task_id: str):
        self._approval_inflight.pop(task_id, None)


    def register_bg_task(self, task_id: str, task: asyncio.Task) -> None:
        """注册一个后台协程(若已有旧句柄则先取消,避免泄漏)。"""
        old = self._bg_tasks.get(task_id)
        if old and not old.done():
            old.cancel()
        self._bg_tasks[task_id] = task

    def unregister_bg_task(self, task_id: str) -> None:
        self._bg_tasks.pop(task_id, None)


    def next_log_seq(self, task_id: str, *, anchor: int | None = None) -> int:
        """返回 ``task_id`` 维度下一条日志的单调 seq。

        - 跨分支(fork 后两条分支各自向 phase_log 追加)仍能单调推进;
        - WS 重连 ``after_log_seq`` 用这条 seq 走 bisect, 不会再漏补;
        - ``anchor`` 给 hydrate / resume 路径用: 进程重启后第一次 log 时
          从 ``state.phase_log_seqs[-1]`` 同步起点, 避免 counter 退回 0
          以致前端重连 ``after_log_seq=K`` 时被错误地当作"全部要补"。

        线程安全: ``threading.Lock`` 保证 worker 线程 ``state.log()`` 间接
        调用时 counter 不会与主协程互相吞掉自增。
        """
        with self._log_seq_lock:
            cur = self._log_seq_counter.get(task_id, -1)
            if anchor is not None and anchor > cur:
                cur = int(anchor)
            cur += 1
            self._log_seq_counter[task_id] = cur
            return cur

    def reset_log_seq(self, task_id: str) -> None:
        with self._log_seq_lock:
            self._log_seq_counter.pop(task_id, None)

    def peek_log_seq(self, task_id: str) -> int:
        with self._log_seq_lock:
            return self._log_seq_counter.get(task_id, -1)

    def cancel_bg_task(self, task_id: str) -> bool:
        """主动取消 run_task/resume_task 协程。返回是否发起了取消。

        语义说明:
            ``run_task`` / ``resume_task`` / ``_resume_branch_bg`` 内部都用
            ``sm._bg_tasks.get(task_id) is my_task`` 判断自己是不是当前
            owner——是 owner 才走 ``stop container`` / ``publish('done')`` /
            ``clear_*_sink`` 的收尾。如果这里直接 ``pop``,``cancel`` 唤醒
            后的 finally 会把自己误判成"被分支接管",于是整个用户主动 cancel
            的语义就被吞掉了 (容器不关、done 不发、sink 不清)。所以
            ``cancel_bg_task`` 只发取消信号,真正的 unregister 由协程自己
            在 finally 里完成。
        """
        task = self._bg_tasks.get(task_id)
        if not task or task.done():
            return False
        task.cancel()
        return True


    def get_tool_registry(self):
        from pathlib import Path as _Path
        from backend.tools.tool_registry import ToolRegistry, DEFINITIONS_DIR

        latest_mtime = max(
            (f.stat().st_mtime for f in _Path(DEFINITIONS_DIR).glob("*.yaml")),
            default=0,
        )
        if self._tool_registry_cache is None or latest_mtime > self._tool_registry_mtime:
            self._tool_registry_cache = ToolRegistry()
            self._tool_registry_mtime = latest_mtime
        return self._tool_registry_cache


    def to_summary(self, state: PentestState) -> dict:
        from backend.api.schemas import TaskSummary
        tid = getattr(state, "chain_template_id", "web")
        return TaskSummary(
            task_id=state.task_id,
            target=state.target,
            status=state.status.value,
            current_phase=state.current_phase,
            findings_count=len(state.findings),
            got_shell=state.got_shell,
            report_path=state.report_path,
            privilege_level=state.privilege_level,
            created_at=state.created_at,
            updated_at=datetime.utcnow().isoformat(),
            workflow_mode=state.workflow_mode,
            auto_approve=state.auto_approve,
            chain_template_id=tid,
            chain_template={
                "id": tid,
                "pipeline_steps": pipeline_steps_for(tid),
            },
        ).model_dump()

    def to_detail(self, state: PentestState) -> dict:
        base = self.to_summary(state)
        base.update({
            "target_os": state.target_os,
            "scope_note": state.scope_note,
            "authorized_scope": state.authorized_scope,
            "scope_violations": state.scope_violations,
            "extra_hint": state.extra_hint,
            "user_prompt": state.user_prompt,
            "parsed_intent": state.parsed_intent,
            "pentest_plan": state.pentest_plan,
            "error_msg": state.error_msg,
            "open_ports": [p.model_dump() for p in state.open_ports],
            "os_info": state.os_info,
            "web_paths": state.web_paths,
            "path_contents": state.path_contents,
            "subdomains": state.subdomains,
            "findings": [f.model_dump() for f in state.findings],
            "exploit_results": [r.model_dump() for r in state.exploit_results],
            "tool_records": [r.model_dump() for r in state.tool_records],
            "decision_events": [],
            "post_findings": state.post_findings,
            "report_md": state.report_md,
            "phase_log": state.phase_log,
            "fingerprints": state.fingerprints,
            "foothold_status": state.foothold_status,
            "credential_store": state.credential_store,
            "loot_store": state.loot_store,
            "privesc_hypotheses": state.privesc_hypotheses,
            "objective_status": state.objective_status,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
            "max_privesc_rounds": state.max_privesc_rounds,
            "chain_summary": state.chain_summary,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "secondary_attack_count": state.secondary_attack_count,
            "max_secondary_attacks": state.max_secondary_attacks,
            "success_gate_level": state.success_gate_level,
            "autonomy_level": state.autonomy_level,
            "risk_budget": state.risk_budget,
            "max_react_rounds": state.max_react_rounds,
            "max_explore_rounds": state.max_explore_rounds,
            "skill_min_score": state.skill_min_score,
            "skill_weak_boost": state.skill_weak_boost,
            "pending_checkpoint": state.pending_checkpoint,
            "checkpoint_history": list(state.checkpoint_history or []),
            "pending_user_prompt": state.pending_user_prompt,
            "attack_graph": state.attack_graph.to_payload() if state.attack_graph else {"nodes": [], "edges": []},
            "phase_visit_count": dict(state.phase_visit_count or {}),
            "replan_signals": dict(state.replan_signals or {}),
            "replan_count": state.replan_count,
            "max_replan": state.max_replan,
            "supervisor_round": state.supervisor_round,
            "supervisor_history": list(state.supervisor_history or []),
            "prior_intel": state.runtime_facts.get("prior_intel"),
        })
        for rec in base.get("tool_records", []):
            for field in ("stdout", "stderr"):
                val = rec.get(field, "")
                if len(val) > 2000:
                    original_len = len(val)
                    rec[field] = val[:2000] + "\n...(truncated)"
                    rec["truncated"] = True
                    rec.setdefault(
                        "truncated_reason",
                        f"API 层截断: {field} {original_len}→2000 字符",
                    )
        return base

    DEFAULT_SNAPSHOT_LOG_TAIL = 60
    DEFAULT_SNAPSHOT_DECISION_TAIL = 120
    SNAPSHOT_PATH_SNIPPET_MAX = 400
    SNAPSHOT_EXPLOIT_OUTPUT_MAX = 1000

    def to_detail_snapshot(
        self,
        state: PentestState,
        log_tail: int = DEFAULT_SNAPSHOT_LOG_TAIL,
        decision_tail: int = DEFAULT_SNAPSHOT_DECISION_TAIL,
    ) -> dict:
        """Lightweight detail used by the running-task page首屏。

        与 ``to_detail`` 的差异:
          * ``phase_log`` 被替换为 ``phase_log_tail`` (最近 N 条) +
            ``phase_log_total`` (总数),完整日志走 ``/tasks/{id}/logs``
            的分页接口。
          * ``decision_events`` 同样仅返回 ``decision_events_tail`` +
            ``decision_events_total``。
          * ``tool_records`` 直接丢弃(前端 view 实际未消费),仅保留
            ``tool_records_count`` 用于摘要展示。
          * ``report_md`` 不再随首屏返回,前端打开「报告」Tab 时再走
            ``/tasks/{id}/report``。
          * ``exploit_results`` 内每条 stdout/stderr 截断到 1KB,
            ``path_contents`` 的 ``content_snippet`` 截断到 400 字符。

        ``decision_events`` 字段名保持向后兼容(等同于 tail),老前端
        即便没有更新仍能拿到最近的事件渲染。
        """
        base = self.to_summary(state)

        log_tail = max(0, min(log_tail, 500))
        decision_tail = max(0, min(decision_tail, 500))

        log_total = len(state.phase_log or [])
        phase_log_tail = (
            list(state.phase_log[-log_tail:]) if (log_tail and log_total) else []
        )

        decision_total = 0
        decision_tail_slice: list[dict] = []

        path_contents_snapshot: list[dict] = []
        for c in (state.path_contents or []):
            if not isinstance(c, dict):
                continue
            entry = dict(c)
            snippet = entry.get("content_snippet") or ""
            if isinstance(snippet, str) and len(snippet) > self.SNAPSHOT_PATH_SNIPPET_MAX:
                entry["content_snippet"] = (
                    snippet[: self.SNAPSHOT_PATH_SNIPPET_MAX] + "...(truncated)"
                )
                entry["content_truncated"] = True
            path_contents_snapshot.append(entry)

        exploit_results_snapshot: list[dict] = []
        for r in state.exploit_results:
            payload = r.model_dump() if hasattr(r, "model_dump") else dict(r or {})
            for field_name in ("command_results", "command_records"):
                records = payload.get(field_name) or []
                trimmed = []
                for rec in records:
                    if not isinstance(rec, dict):
                        trimmed.append(rec)
                        continue
                    rec_copy = dict(rec)
                    for io in ("stdout", "stderr"):
                        val = rec_copy.get(io, "")
                        if isinstance(val, str) and len(val) > self.SNAPSHOT_EXPLOIT_OUTPUT_MAX:
                            rec_copy[io] = (
                                val[: self.SNAPSHOT_EXPLOIT_OUTPUT_MAX] + "\n...(truncated)"
                            )
                            rec_copy["truncated"] = True
                    trimmed.append(rec_copy)
                payload[field_name] = trimmed
            exploit_results_snapshot.append(payload)

        base.update({
            "target_os": state.target_os,
            "scope_note": state.scope_note,
            "extra_hint": state.extra_hint,
            "user_prompt": state.user_prompt,
            "parsed_intent": state.parsed_intent,
            "pentest_plan": state.pentest_plan,
            "error_msg": state.error_msg,
            "open_ports": [p.model_dump() for p in state.open_ports],
            "os_info": state.os_info,
            "web_paths": state.web_paths,
            "path_contents": path_contents_snapshot,
            "subdomains": state.subdomains,
            "findings": [f.model_dump() for f in state.findings],
            "exploit_results": exploit_results_snapshot,
            "tool_records": [],
            "tool_records_count": len(state.tool_records or []),
            "decision_events": decision_tail_slice,
            "decision_events_tail": decision_tail_slice,
            "decision_events_total": decision_total,
            "post_findings": state.post_findings,
            "report_md": "",
            "report_available": bool(state.report_md or state.report_path),
            "phase_log": [],
            "phase_log_tail": phase_log_tail,
            "phase_log_total": log_total,
            "fingerprints": state.fingerprints,
            "foothold_status": state.foothold_status,
            "credential_store": state.credential_store,
            "loot_store": state.loot_store,
            "privesc_hypotheses": state.privesc_hypotheses,
            "objective_status": state.objective_status,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
            "max_privesc_rounds": state.max_privesc_rounds,
            "chain_summary": state.chain_summary,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "success_gate_level": state.success_gate_level,
            "autonomy_level": state.autonomy_level,
            "risk_budget": state.risk_budget,
            "max_react_rounds": state.max_react_rounds,
            "max_explore_rounds": state.max_explore_rounds,
            "skill_min_score": state.skill_min_score,
            "skill_weak_boost": state.skill_weak_boost,
            "pending_checkpoint": state.pending_checkpoint,
            "checkpoint_history": list(state.checkpoint_history or [])[-10:],
            "pending_user_prompt": state.pending_user_prompt,
            "attack_graph": state.attack_graph.to_payload() if state.attack_graph else {"nodes": [], "edges": []},
            "phase_visit_count": dict(state.phase_visit_count or {}),
            "replan_signals": dict(state.replan_signals or {}),
            "replan_count": state.replan_count,
            "max_replan": state.max_replan,
            "supervisor_round": state.supervisor_round,
            "supervisor_history": list(state.supervisor_history or [])[-20:],
            "secondary_attack_count": state.secondary_attack_count,
            "max_secondary_attacks": state.max_secondary_attacks,
            "prior_intel": state.runtime_facts.get("prior_intel"),
        })
        return base

    def ws_phase_payload(self, state: PentestState, log_tail: int = 5) -> dict:
        tail = max(1, min(log_tail, 50))
        log_total = len(state.phase_log or [])
        seqs = list(getattr(state, "phase_log_seqs", []) or [])
        last_seq = (
            int(seqs[-1])
            if (seqs and len(seqs) == log_total and log_total)
            else (log_total - 1 if log_total else -1)
        )
        return {
            "phase": state.current_phase,
            "status": state.status.value,
            "logs": state.phase_log[-tail:],
            "log_seq_last": last_seq,
            "branch_id": getattr(state, "active_branch_id", "") or "",
            "findings_count": len(state.findings),
            "got_shell": state.got_shell,
            "privilege_level": state.privilege_level,
            "foothold_status": state.foothold_status,
            "chain_visited": state.chain_visited,
            "secondary_elided": state.secondary_elided,
            "attack_next_steps": state.attack_next_steps,
            "privesc_attempt_count": state.privesc_attempt_count,
            "chain_template": {
                "id": getattr(state, "chain_template_id", "web"),
                "pipeline_steps": pipeline_steps_for(getattr(state, "chain_template_id", "web")),
            },
        }

    @staticmethod
    def _normalize_phase_log_ts(
        state_created_at: str, ts_short: str, prev_iso: str
    ) -> str:
        """把 phase_log 里的 ``[HH:MM:SS]`` 短时间戳标准化成 ISO-8601 串,
        与 ``push_decision`` 写入的 ``timestamp`` 对齐, 这样前端字典序 sort
        可以严格还原时间序, 不会再出现"HH:MM:SS 永远排在 YYYY-MM-DDTHH:MM
        前面"的错位。

        规则:
            - 输入已是 ISO (含 ``T``) → 直接透传
            - 否则用 ``prev_iso`` 的日期作为 anchor;
              若当前 HH:MM:SS 比 ``prev`` 的 HH:MM:SS 小, 视为跨午夜, 日期 +1
            - 没有 prev 时退到 ``state.created_at`` 的日期; 都没有就用 utcnow
            - ``ts_short`` 无法解析时返回空串 (调用方兜底)
        """
        import re as _re
        if not ts_short:
            return ""
        if "T" in ts_short and len(ts_short) >= 10:
            return ts_short
        m = _re.match(r"^(\d{2}):(\d{2}):(\d{2})", ts_short)
        if not m:
            return ""
        cur_hms = f"{m.group(1)}:{m.group(2)}:{m.group(3)}"

        base_date = ""
        base_hms = ""
        if prev_iso and len(prev_iso) >= 10 and prev_iso[4] == "-":
            base_date = prev_iso[:10]
            tm = _re.search(r"T(\d{2}:\d{2}:\d{2})", prev_iso)
            if tm:
                base_hms = tm.group(1)
        if not base_date:
            if state_created_at and len(state_created_at) >= 10:
                base_date = state_created_at[:10]
            else:
                base_date = datetime.utcnow().strftime("%Y-%m-%d")

        if base_hms and cur_hms < base_hms:
            try:
                from datetime import date as _date, timedelta as _td
                base_date = (_date.fromisoformat(base_date) + _td(days=1)).isoformat()
            except Exception:
                pass

        return f"{base_date}T{cur_hms}"



_state_manager = TaskStateManager()


def get_state_manager() -> TaskStateManager:
    return _state_manager
