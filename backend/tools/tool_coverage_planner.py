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
import re
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
            'feroxbuster -u "{url}" -w "$WL" -t {threads} --depth {depth} --no-state -q '
            '-C 404 --silent 2>/dev/null'
        ),
        "timeout": 180,
    },
    {
        "name": "dirsearch", "priority": 2, "must_run": True,
        "script": 'dirsearch -u "{url}" -e {extensions} -t {threads} -q --format plain 2>/dev/null',
        "timeout": 150,
    },
    {
        "name": "gobuster", "priority": 3, "must_run": True,
        "script": 'gobuster dir -u "{url}" -w /usr/share/wordlists/dirb/common.txt -t {threads} -q --no-error -b 404 2>/dev/null',
        "timeout": 120,
    },
    {
        "name": "dirb", "priority": 4, "must_run": False,
        "script": 'dirb "{url}" /usr/share/wordlists/dirb/common.txt -S -r -z {delay} 2>/dev/null',
        "timeout": 360,
    },
    {
        "name": "ffuf", "priority": 5, "must_run": False,
        "script": (
            'WL="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"; '
            '[ -f "$WL" ] || WL="/usr/share/wordlists/dirb/common.txt"; '
            'ffuf -u "{url}/FUZZ" -w "$WL" -mc 200,301,302,403,500 -t {threads} -s 2>/dev/null'
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


HIGH_CONFIDENCE_PATH_THRESHOLD = int(os.getenv("HIGH_CONFIDENCE_PATHS", "50"))
EARLY_STOP_MIN_TOOLS = int(os.getenv("EARLY_STOP_MIN_TOOLS", "3"))
ACTIONABLE_PATH_THRESHOLD = int(os.getenv("ACTIONABLE_PATH_THRESHOLD", "20"))


_TECH_EXTENSION_MAP: dict[str, str] = {
    "PHP": "php,phtml,php5,php7,inc",
    "JSP": "jsp,jspx,do,action",
    "Spring": "jsp,do,action,html,json",
    "Tomcat": "jsp,jspx,do,action,xml",
    "WebLogic": "jsp,jspx,do,action,xml",
    "JBoss": "jsp,jspx,do,action,war",
    "WordPress": "php,phtml,txt,xml,sql",
    "Django": "py,html,json,txt",
    "Flask": "py,html,json,txt",
    "IIS": "asp,aspx,ashx,asmx,config",
    "ASP": "asp,aspx,ashx,asmx,config",
    "Struts": "do,action,jsp,json",
}

_DEFAULT_EXTENSIONS = "php,jsp,asp,aspx,html,txt,bak,old,swp,json,xml,conf"


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
        self._actionable_paths = 0
        self._force_stop = False
        self._timeout_factor: float = 1.0
        self._custom_wordlist_path: str = ""

    def build_plan(
        self,
        url: str,
        existing_paths_count: int = 0,
        *,
        has_waf: bool = False,
        tech_hints: list[str] | None = None,
        scan_strategy: dict | None = None,
    ) -> list[dict]:
        """Build an ordered list of tool specs to execute.

        Args:
            url: target URL
            existing_paths_count: paths already discovered
            has_waf: if True, reduce concurrency and add delays
            tech_hints: detected technologies (e.g. ["PHP", "Tomcat"])
            scan_strategy: LLM-generated strategy dict with keys like
                ``extensions``, ``custom_wordlist_entries``, ``scan_profile``

        Returns list of dicts with keys: name, category, script, timeout, must_run.
        """
        scan_strategy = scan_strategy or {}

        threads = "10" if has_waf else "40"
        depth = "3" if not has_waf else "2"
        delay = "200" if has_waf else "50"

        if scan_strategy.get("scan_profile") == "aggressive" and not has_waf:
            threads = "50"
            depth = "4"
        elif scan_strategy.get("scan_profile") == "stealth":
            threads = "5"
            depth = "2"
            delay = "500"

        llm_extensions = scan_strategy.get("extensions", "")
        if llm_extensions and isinstance(llm_extensions, str) and len(llm_extensions) > 2:
            extensions = llm_extensions
        else:
            extensions = self._build_extensions(tech_hints)

        self._custom_wordlist_path = ""
        custom_entries = scan_strategy.get("custom_wordlist_entries") or []
        if custom_entries:
            self._custom_wordlist_path = self._write_custom_wordlist(custom_entries)

        fmt_vars = {
            "url": url,
            "threads": threads,
            "depth": depth,
            "delay": delay,
            "extensions": extensions,
        }

        plan: list[dict] = []
        for cat in self._categories:
            tools = CATEGORY_TOOLS.get(cat, [])
            for t in sorted(tools, key=lambda x: x["priority"]):
                script = t["script"].format(**fmt_vars)
                if self._custom_wordlist_path and cat == "dir_discovery":
                    script = self._inject_custom_wordlist(t["name"], script)
                plan.append({
                    "name": t["name"],
                    "category": cat,
                    "script": script,
                    "runtime_command": script,
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
        self._actionable_paths = 0
        return plan

    @staticmethod
    def _write_custom_wordlist(entries: list[str]) -> str:
        """Write LLM-generated custom wordlist entries to a temp file."""
        import tempfile
        clean = []
        for e in entries:
            e = str(e).strip().strip("/")
            if e and len(e) < 200:
                clean.append(e)
        if not clean:
            return ""
        try:
            fd, path = tempfile.mkstemp(prefix="llm_wl_", suffix=".txt")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(clean) + "\n")
            return path
        except Exception as exc:
            logger.warning(f"[Planner] Failed to write custom wordlist: {exc}")
            return ""

    @staticmethod
    def _inject_custom_wordlist(tool_name: str, script: str) -> str:
        """For tools that support multiple wordlists, append the custom one."""
        # feroxbuster supports -w <file> -w <file2>; append via second -w
        # gobuster/ffuf/dirb: append entries via cat pipe (complex), skip for now
        # dirsearch: supports -w; we can add it
        return script

    @staticmethod
    def _build_extensions(tech_hints: list[str] | None) -> str:
        if not tech_hints:
            return _DEFAULT_EXTENSIONS
        exts: list[str] = []
        for tech in tech_hints:
            mapped = _TECH_EXTENSION_MAP.get(tech, "")
            if mapped:
                for e in mapped.split(","):
                    e = e.strip()
                    if e and e not in exts:
                        exts.append(e)
        for fallback in ("html", "txt", "bak", "old", "swp", "json", "xml", "conf"):
            if fallback not in exts:
                exts.append(fallback)
        return ",".join(exts)

    def should_run(self, tool_spec: dict) -> tuple[bool, str]:
        """Decide whether to run the next tool given current state.

        Checks (in order):
        1. LLM force-stop signal
        2. Hard tool count limit
        3. Stage runtime budget
        4. Quality-based early stop (only for optional tools after min coverage)
        """
        if self._force_stop and not tool_spec.get("must_run", False):
            return False, "LLM force early stop (quality sufficient)"

        if self._executed_count >= self._max_tools:
            return False, f"max tools ({self._max_tools}) reached"

        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        if elapsed > self._max_runtime:
            return False, f"stage runtime budget ({self._max_runtime}s) exceeded"

        if not tool_spec.get("must_run", False) and self._can_early_stop():
            return False, (
                f"early stop: {self._actionable_paths} actionable / "
                f"{self._total_paths} total paths with "
                f"{self._executed_count} tools run, min coverage met"
            )

        if self._timeout_factor != 1.0:
            orig = tool_spec.get("timeout", 120)
            tool_spec["timeout"] = min(int(orig * self._timeout_factor), MAX_TOOL_TIMEOUT)

        return True, ""

    def _can_early_stop(self) -> bool:
        """Quality-based early stop: requires enough *actionable* (non-static) paths."""
        if self._executed_count < EARLY_STOP_MIN_TOOLS:
            return False
        if self._actionable_paths < ACTIONABLE_PATH_THRESHOLD:
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

    def force_early_stop(self) -> None:
        """LLM-driven signal: quality is sufficient, skip remaining optional tools."""
        self._force_stop = True
        logger.info("[Planner] LLM triggered force early stop")

    def upgrade_remaining_timeouts(self, factor: float = 1.5) -> None:
        """LLM-driven signal: increase remaining tool timeouts for aggressive scanning."""
        for r in self._records:
            if r.status == "pending":
                logger.debug(f"[Planner] Timeout upgrade applied (factor={factor})")
                break
        self._timeout_factor = factor

    def update_pending_extensions(self, plan: list[dict], new_extensions: str) -> int:
        """Inject new file extensions into pending tool scripts.

        Replaces the ``-e <extensions>`` argument for dirsearch and similar
        tools that haven't been executed yet, making LLM extension advice
        actually take effect.

        Returns the number of tool scripts updated.
        """
        if not new_extensions or not plan:
            return 0
        pending_names = {r.name for r in self._records if r.status == "pending"}
        if not pending_names:
            return 0
        _ext_flag_re = re.compile(r'-e\s+\S+')
        updated = 0
        for entry in plan:
            if entry.get("name") not in pending_names:
                continue
            script = entry.get("script", "")
            m = _ext_flag_re.search(script)
            if m:
                entry["script"] = script[:m.start()] + f"-e {new_extensions}" + script[m.end():]
                entry["runtime_command"] = entry["script"]
                updated += 1
        if updated:
            logger.info(f"[Planner] Updated extensions for {updated} pending tools -> {new_extensions}")
        return updated

    @property
    def executed_count(self) -> int:
        return self._executed_count

    @property
    def remaining_budget(self) -> float:
        if not self._start_time:
            return self._max_runtime
        return max(0, self._max_runtime - (time.monotonic() - self._start_time))

    @property
    def executed_tool_names(self) -> list[str]:
        return [r.name for r in self._records if r.status == "executed"]

    def record_result(
        self, name: str, status: str, skip_reason: str = "",
        paths_found: int = 0, actionable_found: int = 0,
        raw_len: int = 0, elapsed: float = 0.0,
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
                    self._actionable_paths += (actionable_found or paths_found)
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
