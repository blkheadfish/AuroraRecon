"""Eval harness — runs targets through the orchestrator and inspects results."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import traceback
from pathlib import Path

import yaml

from backend.agents.models import PentestState
from backend.agents.orchestrator import Orchestrator
from backend.eval.report import EvalResult, TargetDef, _build_table, aggregate_json

_TARGETS_DEFAULT = Path(__file__).resolve().parent / "targets.yaml"


def _load_targets(path: str) -> list[TargetDef]:
    raw = yaml.safe_load(Path(path).read_text())
    targets = raw.get("targets", []) if isinstance(raw, dict) else []
    return [TargetDef(**t) for t in targets]


async def run_target(t: TargetDef) -> EvalResult:
    start = time.monotonic()
    state = PentestState(
        task_id=f"eval-{t.id}",
        target=t.base_url,
        auto_approve=True,
        success_gate_level="lenient",
    )

    phase_ok = True
    name_ok = True
    cve_ok = True
    exploit_ok = True
    error = ""
    phases_visited: dict[str, int] = {}
    finding_names: list[str] = []
    finding_cves: list[list[str]] = []
    exploit_success_count = 0
    status = ""
    trajectory: list[str] = []

    try:
        orch = Orchestrator()
        final = await asyncio.wait_for(
            orch.run(initial_state=state),
            timeout=t.timeout_sec,
        )
        status = final.status.value if hasattr(final.status, "value") else str(final.status)
        phases_visited = dict(final.phase_visit_count)
        finding_names = [f.name for f in final.findings]
        finding_cves = [list(f.cve) if f.cve else [] for f in final.findings]
        exploit_success_count = sum(1 for r in final.exploit_results if r.success)
        trajectory = list(final.chain_visited)

        if t.expect_phase_reached:
            phase_ok = any(
                p in final.phase_visit_count
                for p in t.expect_phase_reached
            )

        if t.expect_finding_name_contains:
            name_ok = any(
                any(expected.lower() in n.lower() for n in finding_names)
                for expected in t.expect_finding_name_contains
            )

        if t.expect_finding_cve:
            all_cves: set[str] = set()
            for cve_list in finding_cves:
                all_cves.update(cve_list)
            cve_ok = any(cve in all_cves for cve in t.expect_finding_cve)

        if t.expect_exploit_success:
            exploit_ok = exploit_success_count > 0

    except asyncio.TimeoutError:
        error = f"timeout after {t.timeout_sec}s"
    except Exception:
        error = traceback.format_exc()

    return EvalResult(
        target_id=t.id,
        passed=(phase_ok and name_ok and cve_ok and exploit_ok and error == ""),
        phase_reached_check=phase_ok,
        finding_name_check=name_ok,
        finding_cve_check=cve_ok,
        exploit_success_check=exploit_ok,
        error=error,
        phases_visited=phases_visited,
        finding_names=finding_names,
        finding_cves=finding_cves,
        exploit_success_count=exploit_success_count,
        status=status,
        duration_sec=time.monotonic() - start,
        trajectory=trajectory,
        expect_phase_reached=bool(t.expect_phase_reached),
        expect_finding_name=bool(t.expect_finding_name_contains),
        expect_finding_cve=bool(t.expect_finding_cve),
        expect_exploit_success=t.expect_exploit_success,
    )


async def _run_all(targets: list[TargetDef]) -> list[EvalResult]:
    results: list[EvalResult] = []
    for t in targets:
        result = await run_target(t)
        results.append(result)
    return results


async def _main() -> None:
    parser = argparse.ArgumentParser(description="AuroraRecon E2E eval harness")
    parser.add_argument(
        "--targets", default=str(_TARGETS_DEFAULT),
        help="Path to targets.yaml",
    )
    parser.add_argument("--only", default=None, help="Run a single target by id")
    parser.add_argument(
        "--out-dir", default=str(_TARGETS_DEFAULT.parent / "out"),
        help="Output directory for result JSON",
    )
    args = parser.parse_args()

    all_targets = _load_targets(args.targets)
    if args.only:
        all_targets = [t for t in all_targets if t.id == args.only]
        if not all_targets:
            print(f"Target '{args.only}' not found in {args.targets}")
            sys.exit(1)

    results = await _run_all(all_targets)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"eval_{ts}.json"
    out_path.write_text(json.dumps(aggregate_json(results), indent=2, ensure_ascii=False, default=str))

    print(_build_table(results))


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
