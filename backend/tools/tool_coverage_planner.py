"""
tools/tool_coverage_planner.py
Stage-level tool coverage planner with adaptive selection and coverage guards.

For each pentest phase (recon dir-scan, surface enum, vuln scan), this module:
  1. Builds an ordered tool plan based on detected services and context.
  2. Enforces minimum coverage per category.
  3. Tracks execution results and emits a coverage report with skip reasons.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

MAX_TOOLS_PER_STAGE = int(os.getenv("MAX_TOOLS_PER_STAGE", "10"))
MAX_TOOL_TIMEOUT = int(os.getenv("MAX_TOOL_TIMEOUT", "360"))
MAX_STAGE_RUNTIME = int(os.getenv("MAX_STAGE_RUNTIME", "600"))

# ── Tool catalog by category ─────────────────────────────

_DIR_DISCOVERY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "feroxbuster", "priority": 1, "must_run": True,
        "script": (
            'WL="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"; '
            '[ -f "$WL" ] || WL="/usr/share/wordlists/dirb/common.txt"; '
            'feroxbuster -u "{url}" -w "$WL" -t 40 --depth 2 --no-state -q '
            '-C 404,301,302 --silent 2>/dev/null'
        ),
        "timeout": 180,
    },
    {
        "name": "dirsearch", "priority": 2, "must_run": True,
        "script": 'dirsearch -u "{url}" -e php,jsp,asp,html,txt,bak,old,swp -t 30 -q --format plain 2>/dev/null',
        "timeout": 150,
    },
    {
        "name": "gobuster", "priority": 3, "must_run": True,
        "script": 'gobuster dir -u "{url}" -w /usr/share/wordlists/dirb/common.txt -t 30 -q --no-error -b 404 2>/dev/null',
        "timeout": 120,
    },
    {
        "name": "dirb", "priority": 4, "must_run": False,
        "script": 'dirb "{url}" /usr/share/wordlists/dirb/common.txt -S -r -z 50 2>/dev/null',
        "timeout": 360,
    },
    {
        "name": "ffuf", "priority": 5, "must_run": False,
        "script": (
            'WL="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"; '
            '[ -f "$WL" ] || WL="/usr/share/wordlists/dirb/common.txt"; '
            'ffuf -u "{url}/FUZZ" -w "$WL" -mc 200,301,302,403,500 -t 40 -s 2>/dev/null'
        ),
        "timeout": 120,
    },
    {
        "name": "dirmap", "priority": 6, "must_run": False,
        "script": 'python3 /usr/share/dirmap/dirmap.py -i "{url}" -lcf 2>/dev/null || echo "__DIRMAP_NA__"',
        "timeout": 120,
    },
]

_WEB_PROBE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "nikto", "priority": 1, "must_run": True,
        "script": 'nikto -h "{url}" -C all -maxtime 120 -Format txt 2>/dev/null | head -200',
        "timeout": 150,
    },
    {
        "name": "katana", "priority": 2, "must_run": True,
        "script": 'katana -u "{url}" -d 3 -jc -silent -nc 2>/dev/null | head -300',
        "timeout": 120,
    },
    {
        "name": "wapiti", "priority": 3, "must_run": False,
        "script": 'wapiti -u "{url}" --scope url -m common --flush-session -f txt 2>/dev/null | head -200',
        "timeout": 180,
    },
]

_FUZZ_TOOLS: list[dict[str, Any]] = [
    {
        "name": "wfuzz", "priority": 1, "must_run": False,
        "script": (
            'WL="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"; '
            '[ -f "$WL" ] || WL="/usr/share/wordlists/dirb/common.txt"; '
            'wfuzz -c -z file,"$WL" --hc 404 -t 30 "{url}/FUZZ" 2>/dev/null | head -200'
        ),
        "timeout": 120,
    },
]

CATEGORY_TOOLS = {
    "dir_discovery": _DIR_DISCOVERY_TOOLS,
    "web_probe": _WEB_PROBE_TOOLS,
    "fuzz": _FUZZ_TOOLS,
}

CATEGORY_MIN_COVERAGE = {
    "dir_discovery": int(os.getenv("MIN_DIR_TOOLS", "3")),
    "web_probe": int(os.getenv("MIN_WEBPROBE_TOOLS", "2")),
    "fuzz": int(os.getenv("MIN_FUZZ_TOOLS", "1")),
}


@dataclass
class ToolExecRecord:
    name: str
    category: str
    status: str = "pending"   # pending | executed | skipped | failed | timeout
    skip_reason: str = ""
    paths_found: int = 0
    raw_output_len: int = 0
    elapsed: float = 0.0


@dataclass
class CoverageReport:
    category_counts: dict[str, int] = field(default_factory=dict)
    category_mins: dict[str, int] = field(default_factory=dict)
    satisfied: bool = True
    violations: list[str] = field(default_factory=list)
    tool_records: list[ToolExecRecord] = field(default_factory=list)
    total_paths: int = 0
    total_elapsed: float = 0.0

    def to_log_dict(self) -> dict:
        return {
            "satisfied": self.satisfied,
            "violations": self.violations,
            "category_counts": self.category_counts,
            "category_mins": self.category_mins,
            "total_paths": self.total_paths,
            "total_elapsed": round(self.total_elapsed, 1),
            "tools": [
                {"name": r.name, "category": r.category, "status": r.status,
                 "skip_reason": r.skip_reason, "paths": r.paths_found,
                 "elapsed": round(r.elapsed, 1)}
                for r in self.tool_records
            ],
        }


HIGH_CONFIDENCE_PATH_THRESHOLD = int(os.getenv("HIGH_CONFIDENCE_PATHS", "30"))
EARLY_STOP_MIN_TOOLS = int(os.getenv("EARLY_STOP_MIN_TOOLS", "3"))


class ToolCoveragePlanner:
    """Plans and tracks tool execution for a pentest stage.

    Budget controls (all env-configurable):
      MAX_TOOLS_PER_STAGE  — hard cap on tools per stage (default 10)
      MAX_TOOL_TIMEOUT     — per-tool cap in seconds (default 360)
      MAX_STAGE_RUNTIME    — cumulative wall-clock cap for a stage (default 600)
      HIGH_CONFIDENCE_PATHS — if reached AND min coverage met, skip optional tools (default 30)
      EARLY_STOP_MIN_TOOLS — minimum executed before early-stop can trigger (default 3)
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        max_tools: int = MAX_TOOLS_PER_STAGE,
        max_stage_runtime: float = MAX_STAGE_RUNTIME,
    ):
        self._categories = categories or ["dir_discovery", "web_probe", "fuzz"]
        self._max_tools = max_tools
        self._max_runtime = max_stage_runtime
        self._records: list[ToolExecRecord] = []
        self._start_time: float = 0.0
        self._executed_count = 0
        self._total_paths = 0

    def build_plan(self, url: str, existing_paths_count: int = 0) -> list[dict]:
        """Build an ordered list of tool specs to execute.

        Returns list of dicts with keys: name, category, script, timeout, must_run.
        """
        plan: list[dict] = []
        for cat in self._categories:
            tools = CATEGORY_TOOLS.get(cat, [])
            for t in sorted(tools, key=lambda x: x["priority"]):
                plan.append({
                    "name": t["name"],
                    "category": cat,
                    "script": t["script"].format(url=url),
                    # runtime_command 用于日志/前端展示真实执行命令
                    "runtime_command": t["script"].format(url=url),
                    "timeout": min(t["timeout"], MAX_TOOL_TIMEOUT),
                    "must_run": t["must_run"],
                })
        self._records = [
            ToolExecRecord(name=p["name"], category=p["category"])
            for p in plan
        ]
        self._start_time = time.monotonic()
        self._executed_count = 0
        self._total_paths = existing_paths_count
        return plan

    def should_run(self, tool_spec: dict) -> tuple[bool, str]:
        """Decide whether to run the next tool given current state.

        Checks (in order):
        1. Hard tool count limit
        2. Stage runtime budget
        3. Confidence-based early stop (only for optional tools after min coverage)
        """
        if self._executed_count >= self._max_tools:
            return False, f"max tools ({self._max_tools}) reached"

        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        if elapsed > self._max_runtime:
            return False, f"stage runtime budget ({self._max_runtime}s) exceeded"

        if not tool_spec.get("must_run", False) and self._can_early_stop():
            return False, (
                f"early stop: {self._total_paths} paths found "
                f"(>={HIGH_CONFIDENCE_PATH_THRESHOLD}) with "
                f"{self._executed_count} tools run, min coverage met"
            )

        return True, ""

    def _can_early_stop(self) -> bool:
        """Check if we can skip optional tools based on path confidence."""
        if self._executed_count < EARLY_STOP_MIN_TOOLS:
            return False
        if self._total_paths < HIGH_CONFIDENCE_PATH_THRESHOLD:
            return False
        cat_counts: dict[str, int] = {}
        for r in self._records:
            if r.status == "executed":
                cat_counts[r.category] = cat_counts.get(r.category, 0) + 1
        for cat in self._categories:
            required = CATEGORY_MIN_COVERAGE.get(cat, 1)
            if cat_counts.get(cat, 0) < required:
                return False
        return True

    def record_result(
        self, name: str, status: str, skip_reason: str = "",
        paths_found: int = 0, raw_len: int = 0, elapsed: float = 0.0,
    ) -> None:
        for r in self._records:
            if r.name == name and r.status == "pending":
                r.status = status
                r.skip_reason = skip_reason
                r.paths_found = paths_found
                r.raw_output_len = raw_len
                r.elapsed = elapsed
                if status == "executed":
                    self._executed_count += 1
                    self._total_paths += paths_found
                break

    def coverage_report(self) -> CoverageReport:
        report = CoverageReport(
            category_mins=dict(CATEGORY_MIN_COVERAGE),
        )
        cat_counts: dict[str, int] = {}
        for r in self._records:
            report.tool_records.append(r)
            report.total_paths += r.paths_found
            report.total_elapsed += r.elapsed
            if r.status == "executed":
                cat_counts[r.category] = cat_counts.get(r.category, 0) + 1
        report.category_counts = cat_counts

        for cat in self._categories:
            required = CATEGORY_MIN_COVERAGE.get(cat, 1)
            actual = cat_counts.get(cat, 0)
            if actual < required:
                report.satisfied = False
                report.violations.append(
                    f"{cat}: executed {actual}/{required} minimum tools"
                )
        return report
