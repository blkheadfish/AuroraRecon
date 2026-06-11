"""Tests for eval harness: TargetDef parse, EvalResult construction, report aggregation."""
from __future__ import annotations

import pytest

from backend.eval.report import EvalResult, TargetDef, _build_table, aggregate_json


class TestTargetDef:
    def test_minimal_parse(self):
        t = TargetDef(id="test-1", base_url="http://10.0.0.1:8080")
        assert t.id == "test-1"
        assert t.base_url == "http://10.0.0.1:8080"
        assert t.expect_phase_reached == []
        assert t.expect_finding_name_contains == []
        assert t.expect_finding_cve == []
        assert t.expect_exploit_success is False
        assert t.timeout_sec == 600

    def test_full_parse(self):
        t = TargetDef(
            id="cve-test",
            base_url="http://10.0.0.2:8000",
            expect_phase_reached=["foothold_attempt", "report"],
            expect_finding_name_contains=["RCE"],
            expect_finding_cve=["CVE-2022-41678"],
            expect_exploit_success=True,
            timeout_sec=300,
        )
        assert t.expect_phase_reached == ["foothold_attempt", "report"]
        assert t.expect_finding_name_contains == ["RCE"]
        assert t.expect_finding_cve == ["CVE-2022-41678"]
        assert t.expect_exploit_success is True
        assert t.timeout_sec == 300


class TestEvalResult:
    def test_passed_when_all_checks_ok(self):
        r = EvalResult(
            target_id="t1",
            passed=True,
            phase_reached_check=True,
            finding_name_check=True,
            finding_cve_check=True,
            exploit_success_check=True,
        )
        assert r.passed is True

    def test_failed_when_exploit_fails(self):
        r = EvalResult(
            target_id="t1",
            passed=False,
            phase_reached_check=True,
            finding_name_check=True,
            finding_cve_check=True,
            exploit_success_check=False,
            error="no shell",
        )
        assert r.passed is False
        assert r.error == "no shell"

    def test_fields_serialize(self):
        r = EvalResult(
            target_id="t1",
            passed=True,
            phase_reached_check=True,
            finding_name_check=True,
            finding_cve_check=True,
            exploit_success_check=True,
            phases_visited={"recon": 1, "report": 1},
            finding_names=["Apache RCE"],
            finding_cves=[["CVE-2022-41678"]],
            exploit_success_count=1,
            status="completed",
            duration_sec=12.5,
            trajectory=["recon", "vuln_scan", "foothold_attempt", "report"],
            expect_phase_reached=True,
            expect_finding_cve=True,
            expect_exploit_success=True,
        )
        d = r.model_dump()
        assert d["target_id"] == "t1"
        assert d["phases_visited"] == {"recon": 1, "report": 1}
        assert d["finding_names"] == ["Apache RCE"]
        assert d["finding_cves"] == [["CVE-2022-41678"]]
        assert d["exploit_success_count"] == 1
        assert d["trajectory"] == ["recon", "vuln_scan", "foothold_attempt", "report"]
        assert d["expect_phase_reached"] is True


class TestReportAggregation:
    def _make_result(self, target_id: str, passed: bool, **kwargs):
        defaults = dict(
            target_id=target_id, passed=passed,
            phase_reached_check=kwargs.pop("phase", True),
            finding_name_check=kwargs.pop("name", True),
            finding_cve_check=kwargs.pop("cve", True),
            exploit_success_check=kwargs.pop("exploit", True),
            **kwargs,
        )
        return EvalResult(**defaults)

    def test_aggregate_all_pass(self):
        results = [
            self._make_result("t1", True),
            self._make_result("t2", True),
        ]
        report = aggregate_json(results)
        assert report["total"] == 2
        assert report["passed"] == 2
        assert report["failed"] == 0

    def test_aggregate_mixed(self):
        results = [
            self._make_result("t1", True),
            self._make_result("t2", False, exploit=False, error="boom"),
            self._make_result("t3", True),
        ]
        report = aggregate_json(results)
        assert report["total"] == 3
        assert report["passed"] == 2
        assert report["failed"] == 1

    def test_table_output(self):
        results = [
            self._make_result("t1", True, duration_sec=5.0),
            self._make_result("t2", False, exploit=False, error="timeout", duration_sec=30.0),
        ]
        table = _build_table(results)
        assert "PASS" in table
        assert "FAIL" in table
        assert "t1" in table
        assert "t2" in table
        assert "5.0s" in table

    def test_aggregate_empty(self):
        report = aggregate_json([])
        assert report["total"] == 0
        assert report["passed"] == 0
        assert "results" in report
