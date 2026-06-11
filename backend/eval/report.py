"""Eval report models and aggregation."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TargetDef(BaseModel):
    id: str
    base_url: str
    expect_phase_reached: list[str] = Field(default_factory=list)
    expect_finding_name_contains: list[str] = Field(default_factory=list)
    expect_finding_cve: list[str] = Field(default_factory=list)
    expect_exploit_success: bool = False
    timeout_sec: int = 600


class EvalResult(BaseModel):
    target_id: str
    passed: bool
    phase_reached_check: bool
    finding_name_check: bool
    finding_cve_check: bool
    exploit_success_check: bool
    error: str = ""
    phases_visited: dict[str, int] = Field(default_factory=dict)
    finding_names: list[str] = Field(default_factory=list)
    finding_cves: list[list[str]] = Field(default_factory=list)
    exploit_success_count: int = 0
    status: str = ""
    duration_sec: float = 0.0
    trajectory: list[str] = Field(default_factory=list)
    expect_phase_reached: bool = False
    expect_finding_name: bool = False
    expect_finding_cve: bool = False
    expect_exploit_success: bool = False


def _build_table(results: list[EvalResult]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    detect_attempts = [r for r in results if r.expect_phase_reached or r.expect_finding_name or r.expect_finding_cve]
    detect_hits = [r for r in detect_attempts if r.phase_reached_check and r.finding_name_check and r.finding_cve_check]
    detect_rate = len(detect_hits) / len(detect_attempts) if detect_attempts else None

    exploit_attempts = [r for r in results if r.expect_exploit_success]
    exploit_hits = [r for r in exploit_attempts if r.exploit_success_check]
    exploit_rate = len(exploit_hits) / len(exploit_attempts) if exploit_attempts else None

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  AuroraRecon Eval Report")
    lines.append("=" * 70)
    lines.append(f"  targets: {total}   passed: {passed}   failed: {failed}")
    if detect_rate is not None:
        lines.append(f"  detect rate:  {detect_rate:.1%}")
    if exploit_rate is not None:
        lines.append(f"  exploit rate: {exploit_rate:.1%}")
    lines.append("-" * 70)

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        line = (
            f"  [{status}] {r.target_id:<20s}  "
            f"phase={r.phase_reached_check!s:<5s}  "
            f"name={r.finding_name_check!s:<5s}  "
            f"cve={r.finding_cve_check!s:<5s}  "
            f"exploit={r.exploit_success_check!s:<5s}  "
            f"{r.duration_sec:.1f}s"
        )
        lines.append(line)
        if r.error:
            lines.append(f"         ERR: {r.error.split(chr(10))[0][:120]}")
        if r.phases_visited:
            phases = ", ".join(f"{k}({v})" for k, v in r.phases_visited.items())
            lines.append(f"         phases: {phases}")
        if r.trajectory:
            lines.append(f"         trajectory: {' -> '.join(r.trajectory)}")
    lines.append("=" * 70)
    return "\n".join(lines)


def aggregate_json(results: list[EvalResult]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    detect_attempts = [r for r in results if r.expect_phase_reached or r.expect_finding_name or r.expect_finding_cve]
    detect_hits = [r for r in detect_attempts if r.phase_reached_check and r.finding_name_check and r.finding_cve_check]
    detect_rate = len(detect_hits) / len(detect_attempts) if detect_attempts else None
    exploit_attempts = [r for r in results if r.expect_exploit_success]
    exploit_hits = [r for r in exploit_attempts if r.exploit_success_check]
    exploit_rate = len(exploit_hits) / len(exploit_attempts) if exploit_attempts else None

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "detect_rate": detect_rate,
        "exploit_rate": exploit_rate,
        "results": [r.model_dump() for r in results],
    }
