"""
skills/execution_learner.py
跨 session 执行学习与自适应优化模块

功能：
  1. 读取 JSONL 执行日志，统计每个 skill 的 success_rate
  2. 统计每个 path 的 success_rate，识别低价值路径
  3. 统计 probe 的实际价值（哪些探测变量被 exploit 使用）
  4. 生成动态优先级调整，自动提升高成功率路径
  5. 缓存分析结果供 SkillRegistry.reload() 加载

集成方式：
  - SkillRegistry.reload() 调用 learner.load() 加载分析结果
  - SkillEngine._execute_inner() 优先使用 adjusted priority
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CACHE_DIR = Path(os.getenv(
    "SKILL_LEARNER_CACHE_DIR",
    os.path.join(os.getcwd(), ".tmp_reports", "skill_learner"),
))

_LEARNER_CACHE_FILE = _CACHE_DIR / "learner_cache.json"

# 至少需要多少条记录才启用自适应（避免小样本噪声）
_MIN_SAMPLE_SIZE = 5

# 成功率偏差超过此值才调整优先级
_MIN_PRIORITY_DELTA = 0.2


@dataclass
class SkillProfile:
    """单个 skill 的学习画像"""
    skill_id: str
    total_runs: int = 0
    successful_runs: int = 0
    success_rate: float = 0.0
    avg_elapsed: float = 0.0
    avg_commands: float = 0.0
    avg_probes: float = 0.0

    # path_id → {total, success, rate}
    path_stats: dict[str, dict[str, int | float]] = field(default_factory=dict)

    # 哪些探测变量在被成功的 exploit 路径的 conditions 中引用
    used_probe_variables: set[str] = field(default_factory=set)

    # 动态优先级调整: path_id → priority delta (负数=提前, 正数=延后)
    priority_adjustments: dict[str, int] = field(default_factory=dict)

    last_updated: float = 0.0


class ExecutionLearner:
    """
    跨 session 执行学习器。

    用法:
        learner = ExecutionLearner()
        learner.analyze()          # 分析所有日志
        adjustments = learner.get_adaptive_priorities("lfi_rfi_exploit")
        # → {"lfi_wrapper_rce": -2, "lfi_cred_reuse": 0, "php_filter_chain": 2}
        learner.persist()          # 缓存结果
    """

    def __init__(self):
        self._profiles: dict[str, SkillProfile] = {}
        self._loaded = False

    # ── 分析与统计 ──────────────────────────────────────────

    def analyze(self) -> dict[str, SkillProfile]:
        """扫描所有执行日志，构建学习画像。返回 {skill_id: SkillProfile}。"""
        from backend.skills.execution_log import read_all_records

        records = read_all_records()
        if not records:
            logger.info("[ExecutionLearner] 无执行记录，跳过分析")
            return {}

        raw: dict[str, list[dict]] = defaultdict(list)
        for r in records:
            sid = r.get("skill_id", "unknown")
            if sid and sid != "unknown":
                raw[sid].append(r)

        for sid, runs in raw.items():
            profile = self._build_profile(sid, runs)
            self._profiles[sid] = profile

        self._loaded = True
        logger.info(
            "[ExecutionLearner] 分析完成: %d skills, %d total records",
            len(self._profiles), len(records),
        )
        return self._profiles

    def _build_profile(self, skill_id: str, runs: list[dict]) -> SkillProfile:
        profile = SkillProfile(skill_id=skill_id, last_updated=time.time())
        profile.total_runs = len(runs)

        if not runs:
            return profile

        profile.successful_runs = sum(1 for r in runs if r.get("success"))
        profile.success_rate = round(profile.successful_runs / len(runs), 3) if runs else 0

        elapsed_vals = [r.get("total_elapsed", 0) for r in runs if r.get("total_elapsed")]
        profile.avg_elapsed = round(sum(elapsed_vals) / len(elapsed_vals), 1) if elapsed_vals else 0

        cmd_counts = [r.get("commands_count", 0) for r in runs if r.get("commands_count")]
        profile.avg_commands = round(sum(cmd_counts) / len(cmd_counts), 1) if cmd_counts else 0

        probe_counts = [r.get("probe_count", 0) for r in runs if r.get("probe_count")]
        profile.avg_probes = round(sum(probe_counts) / len(probe_counts), 1) if probe_counts else 0

        # Per-path stats
        path_runs: dict[str, list[dict]] = defaultdict(list)
        for r in runs:
            pid = r.get("path_id", "") or "unknown"
            path_runs[pid].append(r)

        for pid, pruns in path_runs.items():
            total = len(pruns)
            success = sum(1 for r in pruns if r.get("success"))
            rate = round(success / total, 3) if total else 0
            profile.path_stats[pid] = {"total": total, "success": success, "rate": rate}

        # Compute dynamic priority adjustments
        self._compute_adjustments(profile)

        return profile

    def _compute_adjustments(self, profile: SkillProfile) -> None:
        """基于 path success rate 计算优先级调整。

        原则：
          - 成功率高的 path 优先级提前（负数 delta = 变小 = 更优先）
          - 成功率低的 path 优先级延后（正数 delta）
          - 样本数不足则不做调整
        """
        if profile.total_runs < _MIN_SAMPLE_SIZE:
            return

        # 计算所有 path 的平均成功率作为基准
        valid_paths = {
            pid: stats for pid, stats in profile.path_stats.items()
            if stats["total"] >= _MIN_SAMPLE_SIZE and pid not in ("unknown", "llm_freeform")
        }
        if not valid_paths:
            return

        rates = [s["rate"] for s in valid_paths.values()]
        avg_rate = sum(rates) / len(rates) if rates else 0

        for pid, stats in valid_paths.items():
            delta = stats["rate"] - avg_rate
            if abs(delta) < _MIN_PRIORITY_DELTA:
                continue

            # 高成功率 → 优先级提前（负数 delta）
            # 低成功率 → 优先级延后（正数 delta）
            magnitude = min(5, max(1, int(abs(delta) * 10)))
            adjustment = -magnitude if delta > 0 else magnitude
            profile.priority_adjustments[pid] = adjustment

            logger.debug(
                "[ExecutionLearner] %s path=%s rate=%.2f avg=%.2f delta=%.3f → adj=%+d",
                profile.skill_id, pid, stats["rate"], avg_rate, delta, adjustment,
            )

    # ── 查询接口 ────────────────────────────────────────────

    def get_profile(self, skill_id: str) -> Optional[SkillProfile]:
        return self._profiles.get(skill_id)

    def get_skill_success_rate(self, skill_id: str) -> float:
        profile = self._profiles.get(skill_id)
        return profile.success_rate if profile else -1.0

    def get_adaptive_priorities(self, skill_id: str) -> dict[str, int]:
        """返回动态优先级调整: {path_id: priority_delta}。

        engine 在排序 exploit_paths 时加上这些 delta。
        """
        profile = self._profiles.get(skill_id)
        if not profile or not profile.priority_adjustments:
            return {}
        return dict(profile.priority_adjustments)

    def get_path_success_rate(self, skill_id: str, path_id: str) -> float:
        profile = self._profiles.get(skill_id)
        if not profile:
            return -1.0
        stats = profile.path_stats.get(path_id, {})
        return stats.get("rate", -1.0)

    # ── 持久化 ──────────────────────────────────────────────

    def persist(self) -> None:
        """将分析结果缓存到磁盘。"""
        if not self._loaded:
            logger.warning("[ExecutionLearner] 未分析，跳过持久化")
            return

        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

        cache: dict[str, Any] = {}
        for sid, profile in self._profiles.items():
            cache[sid] = {
                "skill_id": profile.skill_id,
                "total_runs": profile.total_runs,
                "successful_runs": profile.successful_runs,
                "success_rate": profile.success_rate,
                "avg_elapsed": profile.avg_elapsed,
                "avg_commands": profile.avg_commands,
                "avg_probes": profile.avg_probes,
                "path_stats": {
                    pid: {k: v for k, v in stats.items()}
                    for pid, stats in profile.path_stats.items()
                },
                "priority_adjustments": dict(profile.priority_adjustments),
                "last_updated": profile.last_updated,
            }

        try:
            with open(_LEARNER_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            logger.info(
                "[ExecutionLearner] 缓存 %d skill profiles → %s",
                len(cache), _LEARNER_CACHE_FILE,
            )
        except Exception as e:
            logger.warning("[ExecutionLearner] 缓存写入失败: %s", e)

    def load(self) -> bool:
        """从磁盘加载缓存的分析结果。返回是否加载成功。"""
        if not _LEARNER_CACHE_FILE.exists():
            logger.debug("[ExecutionLearner] 缓存文件不存在: %s", _LEARNER_CACHE_FILE)
            return False

        try:
            with open(_LEARNER_CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception as e:
            logger.warning("[ExecutionLearner] 缓存读取失败: %s", e)
            return False

        for sid, data in cache.items():
            profile = SkillProfile(
                skill_id=sid,
                total_runs=data.get("total_runs", 0),
                successful_runs=data.get("successful_runs", 0),
                success_rate=data.get("success_rate", 0.0),
                avg_elapsed=data.get("avg_elapsed", 0.0),
                avg_commands=data.get("avg_commands", 0.0),
                avg_probes=data.get("avg_probes", 0.0),
                path_stats=data.get("path_stats", {}),
                priority_adjustments=data.get("priority_adjustments", {}),
                last_updated=data.get("last_updated", 0.0),
            )
            self._profiles[sid] = profile

        self._loaded = True
        logger.info(
            "[ExecutionLearner] 加载 %d skill profiles from cache", len(self._profiles),
        )
        return True

    # ── 低价值探测识别 ──────────────────────────────────────

    def identify_low_value_probes(self, skill_id: str) -> list[str]:
        """识别利用率低的探测步骤。

        启发式：如果 probe 输出的变量名从未在成功的 exploit path 中被引用，
        该 probe 可能价值不高。

        注意：此方法需要 skill.yaml 的 probes/exploit_paths 结构信息，
        当前版本仅基于执行统计做简单判断。
        """
        profile = self._profiles.get(skill_id)
        if not profile or profile.total_runs < _MIN_SAMPLE_SIZE:
            return []

        low_value: list[str] = []

        # 如果 avg_probes > 0 但 avg_commands 接近 avg_probes
        # （意味着大量 probe 命令 + 很少 exploit 命令）→ 可能过度探测
        if profile.avg_probes > 3 and profile.avg_commands < profile.avg_probes * 1.5:
            low_value.append("_excessive_probing")

        # 如果所有 path 成功率都很低但仍在探测 → 探测结果可能误导
        valid_paths = [s for pid, s in profile.path_stats.items()
                       if pid not in ("unknown", "llm_freeform")]
        if valid_paths and all(s["rate"] < 0.2 for s in valid_paths):
            low_value.append("_low_signal_probes")

        return low_value

    # ── 报告生成 ────────────────────────────────────────────

    def generate_report(self) -> str:
        """生成人类可读的分析报告。"""
        if not self._profiles:
            return "No data available. Run analyze() first."

        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("Execution Learner Report")
        lines.append("=" * 60)
        lines.append("")

        sorted_profiles = sorted(
            self._profiles.values(),
            key=lambda p: (-p.total_runs, p.skill_id),
        )

        for profile in sorted_profiles:
            lines.append(f"## {profile.skill_id}")
            lines.append(f"  Runs: {profile.total_runs} | "
                         f"Success: {profile.successful_runs} | "
                         f"Rate: {profile.success_rate:.1%}")
            lines.append(f"  Avg elapsed: {profile.avg_elapsed:.1f}s | "
                         f"Avg commands: {profile.avg_commands:.0f} | "
                         f"Avg probes: {profile.avg_probes:.0f}")

            if profile.path_stats:
                lines.append("  Path breakdown:")
                for pid, stats in sorted(
                    profile.path_stats.items(),
                    key=lambda x: -(x[1].get("rate", 0)),
                ):
                    adj = profile.priority_adjustments.get(pid, 0)
                    adj_str = f" [adj:{adj:+d}]" if adj else ""
                    lines.append(
                        f"    {pid}: {stats['total']} runs, "
                        f"{stats['success']} success, "
                        f"rate={stats['rate']:.1%}{adj_str}"
                    )

            low = self.identify_low_value_probes(profile.skill_id)
            if low:
                lines.append(f"  ⚠ Low signal: {', '.join(low)}")

            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


# ── 全局单例 ───────────────────────────────────────────────────

_learner: Optional[ExecutionLearner] = None
_learner_lock: Any = None  # lazy init


def _get_lock():
    global _learner_lock
    if _learner_lock is None:
        import threading
        _learner_lock = threading.Lock()
    return _learner_lock


def get_learner() -> ExecutionLearner:
    """获取全局 ExecutionLearner 单例。"""
    global _learner
    if _learner is not None:
        return _learner
    with _get_lock():
        if _learner is not None:
            return _learner
        _learner = ExecutionLearner()
        _learner.load()  # 尝试加载缓存
        return _learner


def refresh_learner() -> ExecutionLearner:
    """强制重新分析并持久化。"""
    learner = ExecutionLearner()
    learner.analyze()
    learner.persist()
    global _learner
    _learner = learner
    return learner
