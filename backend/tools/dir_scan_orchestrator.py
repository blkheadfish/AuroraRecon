"""
tools/dir_scan_orchestrator.py
LLM-in-the-Loop adaptive directory scanning engine.

Replaces the flat tool-execution loop in ReconAgent._dir_scan() with an
orchestrator that consults the LLM between tool runs to adapt strategy:
  - Probes LLM-recommended priority paths first
  - After each tool, optionally asks LLM to evaluate and adjust
  - Queues deep-scan and backup-variant tasks from LLM recommendations
  - Executes queued deep scans after the main loop
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.tools.executor import ToolExecutor, ExecuteResult, LogCallback, RecordCallback
from backend.tools.parsers.path_aggregator import PathAggregator
from backend.tools.tool_coverage_planner import ToolCoveragePlanner, CoverageReport

logger = logging.getLogger(__name__)

_BACKUP_SUFFIXES = [".bak", ".old", ".backup", ".swp", ".save", ".orig", "~", ".1"]

_SOURCE_FILE_EXTS = frozenset({
    ".php", ".jsp", ".jspx", ".asp", ".aspx", ".py", ".rb", ".cgi",
    ".conf", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".json",
    ".properties", ".env", ".htaccess", ".sql", ".sh",
})

_HIGH_VALUE_HINTS = frozenset({
    "admin", "login", "backup", "config", "upload", "api", "leak", "info_disclosure",
})

_LOG_PATH_PREVIEW = 28


def _preview_paths(paths: list[str], limit: int = _LOG_PATH_PREVIEW) -> str:
    if not paths:
        return "(无)"
    head = paths[:limit]
    s = ", ".join(head)
    if len(paths) > limit:
        s += f" …(共 {len(paths)} 条)"
    return s


@dataclass
class DeepScanTarget:
    path: str
    reason: str
    wordlist: str = "small"


@dataclass
class OrchestratorResult:
    paths: list[str] = field(default_factory=list)
    raw_output: str = ""
    coverage_report: CoverageReport = field(default_factory=CoverageReport)
    aggregator: PathAggregator = field(default_factory=PathAggregator)
    mid_scan_adaptations: list[dict] = field(default_factory=list)


class DirScanOrchestrator:
    """LLM-in-the-loop adaptive directory scanning engine."""

    def __init__(
        self,
        executor: ToolExecutor,
        aggregator: PathAggregator,
        planner: ToolCoveragePlanner,
        *,
        log_callback: LogCallback = None,
        record_callback: RecordCallback = None,
        task_id: Optional[str] = None,
    ):
        self.executor = executor
        self.aggregator = aggregator
        self.planner = planner
        self._log_cb = log_callback
        self._rec_cb = record_callback
        self._task_id = task_id
        self._round = 0
        self._deep_scan_queue: list[DeepScanTarget] = []
        self._custom_entries: list[str] = []
        self._raw_outputs: list[str] = []
        self._recent_new_hints: set[str] = set()
        self._active_plan: list[dict] = []

    async def run(
        self,
        plan: list[dict],
        base_url: str,
        scan_strategy: dict | None = None,
    ) -> OrchestratorResult:
        scan_strategy = scan_strategy or {}
        self._active_plan = plan

        # Step 0: probe LLM priority paths
        priority_paths = []
        for pp in scan_strategy.get("priority_paths", []):
            if isinstance(pp, dict):
                priority_paths.append(pp.get("path", ""))
            elif isinstance(pp, str):
                priority_paths.append(pp)
        priority_paths = [p for p in priority_paths if p]
        if priority_paths:
            await self._probe_priority_paths(base_url, priority_paths)

        # Step 1: main tool loop with LLM mid-scan eval
        for tool_spec in plan:
            should, skip_reason = self.planner.should_run(tool_spec)
            if not should:
                self.planner.record_result(
                    tool_spec["name"], "skipped", skip_reason=skip_reason,
                )
                if self._log_cb:
                    await self._log_cb(
                        f"[DirOrch] 跳过 {tool_spec['name']}: {skip_reason}"
                    )
                continue

            tool_name = tool_spec["name"]
            if self._log_cb:
                cmd_preview = str(tool_spec.get("runtime_command") or tool_spec.get("script") or "")
                cmd_preview = " ".join(cmd_preview.split())[:260]
                await self._log_cb(
                    f"[DirOrch] 执行 {tool_name} | timeout={tool_spec['timeout']}s"
                )

            t0 = time.monotonic()
            try:
                paths_before = set(self.aggregator._entries.keys())
                result: ExecuteResult = await self.executor.run_script(
                    script_content=tool_spec["script"],
                    timeout=tool_spec["timeout"],
                    task_id=self._task_id,
                    log_callback=self._log_cb,
                    record_purpose=f"{tool_name}_dir_scan",
                    record_runtime_command=str(tool_spec.get("runtime_command", "")),
                )
                elapsed = time.monotonic() - t0
                stdout = result.stdout or ""
                self._raw_outputs.append(f"=== {tool_name} ===\n{stdout}")
                new_count = self.aggregator.ingest(tool_name, stdout, base_url)
                new_paths_only = [
                    p for p in self.aggregator._entries
                    if p not in paths_before
                ]
                actionable_count = len(self.aggregator.get_actionable_paths())
                self.planner.record_result(
                    tool_name, "executed",
                    paths_found=new_count,
                    actionable_found=actionable_count,
                    raw_len=len(stdout),
                    elapsed=elapsed,
                )
                detail = _preview_paths(new_paths_only)
                logger.info(
                    "[DirOrch] %s 完成 +%d 条新路径 (累计 %d 条) %.1fs | 新增: %s",
                    tool_name, new_count, self.aggregator.count, elapsed, detail,
                )
                if self._log_cb:
                    await self._log_cb(
                        f"[DirOrch] {tool_name} 完成: +{new_count} 路径 "
                        f"(累计 {self.aggregator.count}), {elapsed:.1f}s"
                    )
                    if new_paths_only:
                        await self._log_cb(
                            f"[DirOrch] {tool_name} 本轮新增路径: {detail}"
                        )

                self._round += 1
                self._track_recent_hints(new_count)

                if self._should_consult_llm(new_count, tool_name, elapsed):
                    adaptation = await self._llm_mid_scan_eval(
                        base_url, tool_name, new_count, elapsed,
                    )
                    if adaptation:
                        await self._apply_adaptation(adaptation, base_url)

            except asyncio.TimeoutError:
                elapsed = time.monotonic() - t0
                self.planner.record_result(
                    tool_name, "timeout", elapsed=elapsed,
                    skip_reason=f"timeout after {elapsed:.0f}s",
                )
                if self._log_cb:
                    await self._log_cb(f"[DirOrch] {tool_name} 超时 ({elapsed:.0f}s)")
                self._round += 1
            except Exception as e:
                elapsed = time.monotonic() - t0
                self.planner.record_result(
                    tool_name, "failed",
                    skip_reason=str(e)[:200], elapsed=elapsed,
                )
                logger.warning(f"[DirOrch] {tool_name} 异常: {e}")
                self._round += 1

        # Step 1.5: deterministic backup variant probe for all source/config files
        source_files = self._collect_source_file_paths()
        if source_files:
            logger.info(
                "[DirOrch] Step1.5 确定性备份变体: 源文件 %d 个 — %s",
                len(source_files), _preview_paths(source_files, 20),
            )
            if self._log_cb:
                await self._log_cb(
                    f"[DirOrch] 确定性备份变体: 基于 {len(source_files)} 个源文件 "
                    f"({_preview_paths(source_files, 12)})"
                )
            await self._probe_backup_variants(base_url, source_files)

        # Step 2: execute queued deep scans
        await self._execute_deep_scans(base_url)

        report = self.planner.coverage_report()
        paths = self.aggregator.get_actionable_paths()
        combined_raw = "\n".join(self._raw_outputs)

        if self._log_cb:
            await self._log_cb(
                f"[DirOrch] 扫描完成: {len(paths)} 路径, "
                f"覆盖率{'达标' if report.satisfied else '未达标'} "
                f"({report.total_elapsed:.0f}s), "
                f"深扫任务 {len(self._deep_scan_queue)} 个"
            )
            await self._log_cb(
                f"[DirOrch] 可行动路径摘要 ({len(paths)} 条): {_preview_paths(paths, 40)}"
            )
        logger.info(
            "[DirOrch] 扫描结束 base=%s | 可行动路径 %d 条 | %s",
            base_url, len(paths), _preview_paths(paths, 50),
        )

        return OrchestratorResult(
            paths=paths,
            raw_output=combined_raw,
            coverage_report=report,
            aggregator=self.aggregator,
            mid_scan_adaptations=[],
        )

    def _track_recent_hints(self, new_count: int) -> None:
        """Track path hints from the most recent ingestion for LLM trigger logic."""
        self._recent_new_hints.clear()
        if new_count > 0:
            for entry in self.aggregator._entries.values():
                for h in entry.hints:
                    self._recent_new_hints.add(h)

    def _should_consult_llm(self, new_paths: int, tool_name: str, elapsed: float) -> bool:
        if self._round < 3:
            return False
        if new_paths > 15:
            return True
        if self._recent_new_hints & _HIGH_VALUE_HINTS:
            return True
        if "dirlist" in self._recent_new_hints:
            return True
        return False

    async def _llm_mid_scan_eval(
        self,
        base_url: str,
        tool_name: str,
        new_count: int,
        elapsed: float,
    ) -> dict | None:
        try:
            from backend.llm.router import LLMRouter
            from backend.llm.prompts.templates import DIR_MID_SCAN_EVAL

            all_paths = self.aggregator.get_actionable_paths()
            new_sample = all_paths[-min(new_count, 30):]

            prompt = DIR_MID_SCAN_EVAL.format(
                base_url=base_url,
                tool_name=tool_name,
                elapsed=elapsed,
                new_count=new_count,
                new_paths_sample="\n".join(f"  {p}" for p in new_sample),
                total_count=self.aggregator.count,
                all_paths_summary="\n".join(
                    f"  {p}" for p in all_paths[:50]
                ),
                executed_tools=", ".join(self.planner.executed_tool_names),
                remaining_budget=f"{self.planner.remaining_budget:.0f}",
            )

            llm = LLMRouter()
            raw = await llm.chat(
                prompt, response_format="json", temperature=0.1, max_tokens=1024,
            )
            adaptation = json.loads(raw)
            if self._log_cb:
                assessment = adaptation.get("assessment", "")
                await self._log_cb(f"[DirOrch] LLM 评估: {assessment}")
            return adaptation
        except Exception as exc:
            logger.warning(f"[DirOrch] LLM mid-scan eval failed: {exc}")
            return None

    async def _apply_adaptation(self, adaptation: dict, base_url: str) -> None:
        for target in adaptation.get("deep_scan_targets", []):
            if isinstance(target, dict) and target.get("path"):
                self._deep_scan_queue.append(DeepScanTarget(
                    path=target["path"],
                    reason=target.get("reason", ""),
                    wordlist=target.get("wordlist", "small"),
                ))

        variants = adaptation.get("backup_variant_checks", [])
        if variants:
            await self._probe_backup_variants(base_url, variants)

        new_entries = adaptation.get("new_wordlist_entries", [])
        if new_entries:
            self._custom_entries.extend(str(e) for e in new_entries[:50])

        ext_adj = adaptation.get("extension_adjustment")
        if ext_adj and isinstance(ext_adj, str) and len(ext_adj) > 2:
            updated = self.planner.update_pending_extensions(
                self._active_plan, ext_adj,
            )
            if self._log_cb:
                await self._log_cb(
                    f"[DirOrch] LLM 扩展名调整: {ext_adj} "
                    f"(已注入 {updated} 个待执行工具)"
                )

        strategy = adaptation.get("strategy_change")
        if strategy == "early_stop_quality_sufficient":
            self.planner.force_early_stop()
        elif strategy == "switch_to_aggressive":
            self.planner.upgrade_remaining_timeouts(factor=1.5)

    async def _probe_priority_paths(self, base_url: str, paths: list[str]) -> None:
        """Quick curl probe of LLM-recommended priority paths."""
        if not paths:
            return
        if self._log_cb:
            await self._log_cb(
                f"[DirOrch] LLM 优先路径探测: {len(paths)} 条"
            )

        probe_cmds = []
        for p in paths[:25]:
            p = p if p.startswith("/") else f"/{p}"
            probe_cmds.append(
                f'CODE=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'--max-time 5 "{base_url}{p}"); '
                f'[ "$CODE" != "000" ] && echo "{p} $CODE"'
            )
        script = "set +e\n" + "\n".join(probe_cmds)
        try:
            result = await self.executor.run_script(
                script_content=script,
                timeout=45,
                task_id=self._task_id,
                log_callback=self._log_cb,
                record_callback=self._rec_cb,
                record_phase="recon",
                record_purpose="llm_priority_probe",
            )
            found = 0
            hits: list[str] = []
            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        path, code = parts[0], parts[1]
                        if code in ("200", "301", "302", "403", "500"):
                            self.aggregator.add_paths(
                                [path], source="llm_priority", status=int(code),
                            )
                            found += 1
                            hits.append(f"{path}→{code}")
            if found:
                logger.info(
                    "[DirOrch] 优先路径探测命中 %d 条: %s",
                    found, _preview_paths(hits, 25),
                )
            if self._log_cb and found:
                await self._log_cb(
                    f"[DirOrch] 优先路径探测: {found} 条有效 — {_preview_paths(hits, 20)}"
                )
        except Exception as e:
            logger.warning(f"[DirOrch] Priority path probe failed: {e}")

    def _collect_source_file_paths(self, max_items: int = 20) -> list[str]:
        """Extract paths with code/config extensions from the aggregator for backup probing."""
        candidates: list[str] = []
        for entry in self.aggregator._entries.values():
            lower = entry.path.lower().rstrip("/")
            if any(lower.endswith(ext) for ext in _SOURCE_FILE_EXTS):
                candidates.append(entry.path)
        candidates.sort(key=lambda p: -self.aggregator._entries[p].confidence)
        return candidates[:max_items]

    async def _probe_backup_variants(self, base_url: str, source_paths: list[str]) -> None:
        """Probe backup/swap file variants for discovered source files."""
        targets: list[str] = []
        for p in source_paths[:10]:
            p = p if p.startswith("/") else f"/{p}"
            for suffix in _BACKUP_SUFFIXES:
                targets.append(f"{p}{suffix}")
            basename = p.rsplit("/", 1)
            if len(basename) == 2 and basename[1]:
                targets.append(f"{basename[0]}/.{basename[1]}.swp")

        if not targets:
            return
        if self._log_cb:
            await self._log_cb(
                f"[DirOrch] 备份变体探测: {len(targets)} 个变体"
            )

        probe_cmds = []
        for t in targets[:80]:
            probe_cmds.append(
                f'CODE=$(curl -s -o /dev/null -w "%{{http_code}}" '
                f'--max-time 4 "{base_url}{t}"); '
                f'[ "$CODE" = "200" ] || [ "$CODE" = "403" ] && echo "{t} $CODE"'
            )
        script = "set +e\n" + "\n".join(probe_cmds)
        try:
            result = await self.executor.run_script(
                script_content=script,
                timeout=60,
                task_id=self._task_id,
                log_callback=self._log_cb,
                record_callback=self._rec_cb,
                record_phase="recon",
                record_purpose="backup_variant_probe",
            )
            found = 0
            hit_lines: list[str] = []
            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        self.aggregator.add_paths(
                            [parts[0]], source="backup_variant", status=int(parts[1]),
                        )
                        found += 1
                        hit_lines.append(f"{parts[0]} HTTP {parts[1]}")
            if found:
                logger.info(
                    "[DirOrch] 备份变体命中 %d 个: %s",
                    found, _preview_paths(hit_lines, 30),
                )
            if self._log_cb and found:
                await self._log_cb(
                    f"[DirOrch] 备份变体发现 {found} 个: {_preview_paths(hit_lines, 24)}"
                )
        except Exception as e:
            logger.warning(f"[DirOrch] Backup variant probe failed: {e}")

    async def _execute_deep_scans(self, base_url: str) -> None:
        """Run queued recursive directory scans on high-value subdirectories."""
        if not self._deep_scan_queue:
            return

        unique_targets: dict[str, DeepScanTarget] = {}
        for t in self._deep_scan_queue:
            if t.path not in unique_targets:
                unique_targets[t.path] = t
        targets = list(unique_targets.values())[:5]

        if self._log_cb:
            await self._log_cb(
                f"[DirOrch] 深扫队列: {len(targets)} 个子目录"
            )

        for target in targets:
            sub_url = f"{base_url.rstrip('/')}{target.path}"
            wl = (
                '/usr/share/wordlists/dirb/common.txt'
                if target.wordlist == "small"
                else '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'
            )
            script = (
                f'WL="{wl}"; [ -f "$WL" ] || WL="/usr/share/wordlists/dirb/common.txt"; '
                f'feroxbuster -u "{sub_url}" -w "$WL" -t 30 --depth 2 '
                f'--no-state -q -C 404 2>/dev/null'
            )
            if self._log_cb:
                await self._log_cb(
                    f"[DirOrch] 深扫: {target.path} ({target.reason})"
                )
            try:
                result = await self.executor.run_script(
                    script_content=script,
                    timeout=120,
                    task_id=self._task_id,
                    log_callback=self._log_cb,
                    record_callback=self._rec_cb,
                    record_phase="recon",
                    record_purpose=f"deep_scan_{target.path.strip('/')}",
                )
                stdout = result.stdout or ""
                paths_before_ds = set(self.aggregator._entries.keys())
                new_count = self.aggregator.ingest("feroxbuster", stdout, base_url)
                new_only_ds = [
                    p for p in self.aggregator._entries if p not in paths_before_ds
                ]
                self._raw_outputs.append(f"=== deep_scan {target.path} ===\n{stdout}")
                logger.info(
                    "[DirOrch] 深扫 %s +%d 条 | %s",
                    target.path, new_count, _preview_paths(new_only_ds, 25),
                )
                if self._log_cb:
                    await self._log_cb(
                        f"[DirOrch] 深扫 {target.path}: +{new_count} 路径"
                    )
                    if new_only_ds:
                        await self._log_cb(
                            f"[DirOrch] 深扫 {target.path} 新增: {_preview_paths(new_only_ds, 20)}"
                        )
            except Exception as e:
                logger.warning(f"[DirOrch] Deep scan {target.path} failed: {e}")
