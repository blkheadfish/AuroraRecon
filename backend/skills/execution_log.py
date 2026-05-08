"""
skills/execution_log.py
Lightweight file-based persistence for Skill execution records.

Each completed Skill run writes a JSON line to
  .tmp_reports/skill_executions/<date>.jsonl
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_LOG_DIR = Path(os.getenv(
    "SKILL_EXEC_LOG_DIR",
    os.path.join(os.getcwd(), ".tmp_reports", "skill_executions"),
))


def persist_execution(record: dict[str, Any]) -> None:
    """Append a JSON record to today's execution log file."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        day = datetime.utcnow().strftime("%Y-%m-%d")
        path = _LOG_DIR / f"{day}.jsonl"
        record.setdefault("timestamp", datetime.utcnow().isoformat())
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception:
        logger.debug("Failed to persist skill execution record", exc_info=True)


def read_all_records() -> list[dict[str, Any]]:
    """Read all execution records across all day-files."""
    records: list[dict[str, Any]] = []
    if not _LOG_DIR.exists():
        return records
    for p in sorted(_LOG_DIR.glob("*.jsonl")):
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except Exception:
            continue
    return records


def get_stats() -> dict[str, Any]:
    """Aggregate success rates per skill_id, with role-dimension breakdown."""
    records = read_all_records()
    if not records:
        return {"total": 0, "skills": {}, "by_role": {}}

    per_skill: dict[str, dict] = {}
    per_role: dict[str, dict] = {}

    for r in records:
        sid = r.get("skill_id", "unknown")
        role = r.get("workflow_mode") or r.get("operator_role") or "unknown"

        entry = per_skill.setdefault(sid, {"total": 0, "success": 0, "avg_elapsed": 0.0})
        entry["total"] += 1
        if r.get("success"):
            entry["success"] += 1
        elapsed = r.get("total_elapsed", 0)
        entry["avg_elapsed"] = (
            (entry["avg_elapsed"] * (entry["total"] - 1) + elapsed) / entry["total"]
        )

        role_entry = per_role.setdefault(role, {
            "total": 0, "success": 0, "false_positives": 0,
            "avg_rounds": 0.0, "evidence_completeness": 0.0,
        })
        role_entry["total"] += 1
        if r.get("success"):
            role_entry["success"] += 1
        evidence_level = r.get("evidence_level", "")
        if r.get("success") and evidence_level in ("failed", ""):
            role_entry["false_positives"] += 1
        rounds = r.get("rounds", 0) or 0
        role_entry["avg_rounds"] = (
            (role_entry["avg_rounds"] * (role_entry["total"] - 1) + rounds) / role_entry["total"]
        )
        has_evidence = 1.0 if evidence_level and evidence_level != "failed" else 0.0
        role_entry["evidence_completeness"] = (
            (role_entry["evidence_completeness"] * (role_entry["total"] - 1) + has_evidence)
            / role_entry["total"]
        )

    for v in per_skill.values():
        v["success_rate"] = round(v["success"] / v["total"], 3) if v["total"] else 0

    for v in per_role.values():
        v["success_rate"] = round(v["success"] / v["total"], 3) if v["total"] else 0
        v["false_positive_rate"] = (
            round(v["false_positives"] / v["total"], 3) if v["total"] else 0
        )

    return {"total": len(records), "skills": per_skill, "by_role": per_role}
