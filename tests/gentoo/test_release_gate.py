#!/usr/bin/env python3
"""Tests for release qualification gate (bd-2icq.17).

Validates:
- GateThresholds and GateConfig models
- ValidationResults rate calculations
- Gate check logic (pass/fail for each criterion)
- Dry-run report generation
- Release report schema
- CLI execution
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "release_gate.py"

import importlib.util

spec = importlib.util.spec_from_file_location("release_gate", str(GATE_SCRIPT))
rg_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["release_gate"] = rg_mod
spec.loader.exec_module(rg_mod)  # type: ignore[union-attr]

GateThresholds = rg_mod.GateThresholds
GateConfig = rg_mod.GateConfig
ValidationResults = rg_mod.ValidationResults
GateIssue = rg_mod.GateIssue
GateResult = rg_mod.GateResult
ReleaseReport = rg_mod.ReleaseReport
check_release_gate = rg_mod.check_release_gate
load_gate_configs = rg_mod.load_gate_configs
generate_dry_run_results = rg_mod.generate_dry_run_results
run_gate_check = rg_mod.run_gate_check


class TestGateThresholds(unittest.TestCase):
    def test_defaults(self) -> None:
        t = GateThresholds()
        self.assertEqual(t.build_success_rate_pct, 100.0)
        self.assertEqual(t.test_pass_rate_pct, 95.0)
        self.assertEqual(t.max_new_regressions, 0)
        self.assertEqual(t.max_overhead_pct, 15.0)

    def test_from_dict(self) -> None:
        t = GateThresholds.from_dict({
            "build_success_rate_pct": 90,
            "test_pass_rate_pct": 85,
            "max_new_regressions": 5,
            "max_overhead_pct": 10,
        })
        self.assertEqual(t.build_success_rate_pct, 90)
        self.assertEqual(t.max_new_regressions, 5)

    def test_from_empty_dict(self) -> None:
        t = GateThresholds.from_dict({})
        self.assertEqual(t.build_success_rate_pct, 100.0)


class TestGateConfig(unittest.TestCase):
    def test_from_dict(self) -> None:
        cfg = GateConfig.from_dict("tier1", {
            "name": "Tier 1",
            "required_for": "all releases",
            "package_count": 20,
            "thresholds": {"build_success_rate_pct": 100},
        })
        self.assertEqual(cfg.level, "tier1")
        self.assertEqual(cfg.name, "Tier 1")
        self.assertEqual(cfg.package_count, 20)
        self.assertEqual(cfg.thresholds.build_success_rate_pct, 100)


class TestValidationResults(unittest.TestCase):
    def test_rates(self) -> None:
        r = ValidationResults(
            build_total=20, build_success=18,
            test_total=20, test_pass=17,
        )
        self.assertAlmostEqual(r.build_success_rate, 90.0)
        self.assertAlmostEqual(r.test_pass_rate, 85.0)

    def test_zero_total(self) -> None:
        r = ValidationResults()
        self.assertEqual(r.build_success_rate, 0.0)
        self.assertEqual(r.test_pass_rate, 0.0)

    def test_perfect_rates(self) -> None:
        r = ValidationResults(
            build_total=10, build_success=10,
            test_total=10, test_pass=10,
        )
        self.assertAlmostEqual(r.build_success_rate, 100.0)
        self.assertAlmostEqual(r.test_pass_rate, 100.0)

    def test_to_dict(self) -> None:
        r = ValidationResults(
            build_total=20, build_success=18,
            test_total=20, test_pass=17,
            new_regressions=2, avg_overhead_pct=5.5,
        )
        d = r.to_dict()
        self.assertEqual(d["build_total"], 20)
        self.assertIn("build_success_rate_pct", d)
        self.assertIn("test_pass_rate_pct", d)


class TestCheckReleaseGate(unittest.TestCase):
    def _make_config(self, **kwargs: Any) -> GateConfig:
        thresholds = GateThresholds(
            build_success_rate_pct=kwargs.get("build_rate", 100),
            test_pass_rate_pct=kwargs.get("test_rate", 95),
            max_new_regressions=kwargs.get("max_reg", 0),
            max_overhead_pct=kwargs.get("max_overhead", 15),
        )
        return GateConfig(
            name="Test Gate", level="tier1",
            required_for="all", package_count=20,
            thresholds=thresholds,
        )

    def test_all_pass(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=20,
            test_total=20, test_pass=20,
            new_regressions=0, avg_overhead_pct=5.0,
        )
        gate = check_release_gate(results, self._make_config())
        self.assertTrue(gate.passed)
        self.assertEqual(len(gate.issues), 0)

    def test_build_failure(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=18,
            test_total=20, test_pass=20,
        )
        gate = check_release_gate(results, self._make_config(build_rate=100))
        self.assertFalse(gate.passed)
        self.assertEqual(len(gate.issues), 1)
        self.assertEqual(gate.issues[0].check, "build_success_rate")

    def test_test_failure(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=20,
            test_total=20, test_pass=18,
        )
        gate = check_release_gate(results, self._make_config(test_rate=95))
        self.assertFalse(gate.passed)
        self.assertEqual(gate.issues[0].check, "test_pass_rate")

    def test_regression_failure(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=20,
            test_total=20, test_pass=20,
            new_regressions=3,
        )
        gate = check_release_gate(results, self._make_config(max_reg=0))
        self.assertFalse(gate.passed)
        self.assertEqual(gate.issues[0].check, "new_regressions")

    def test_overhead_failure(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=20,
            test_total=20, test_pass=20,
            avg_overhead_pct=20.0,
        )
        gate = check_release_gate(results, self._make_config(max_overhead=15))
        self.assertFalse(gate.passed)
        self.assertEqual(gate.issues[0].check, "overhead")

    def test_multiple_failures(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=15,
            test_total=20, test_pass=15,
            new_regressions=5, avg_overhead_pct=25.0,
        )
        gate = check_release_gate(results, self._make_config())
        self.assertFalse(gate.passed)
        self.assertEqual(len(gate.issues), 4)

    def test_exactly_at_threshold(self) -> None:
        results = ValidationResults(
            build_total=20, build_success=20,
            test_total=20, test_pass=19,
            new_regressions=0, avg_overhead_pct=15.0,
        )
        gate = check_release_gate(results, self._make_config())
        self.assertTrue(gate.passed)

    def test_gate_result_to_dict(self) -> None:
        results = ValidationResults(build_total=10, build_success=10,
                                    test_total=10, test_pass=10)
        gate = check_release_gate(results, self._make_config())
        d = gate.to_dict()
        self.assertIn("gate_name", d)
        self.assertIn("passed", d)
        self.assertIn("issues", d)
        self.assertIn("results", d)


class TestDryRunResults(unittest.TestCase):
    def test_tier1(self) -> None:
        r = generate_dry_run_results("tier1")
        self.assertEqual(r.build_total, 20)
        self.assertGreater(r.build_success, 0)

    def test_top20(self) -> None:
        r = generate_dry_run_results("top20")
        self.assertEqual(r.build_total, 20)

    def test_top100(self) -> None:
        r = generate_dry_run_results("top100")
        self.assertEqual(r.build_total, 100)

    def test_deterministic(self) -> None:
        r1 = generate_dry_run_results("tier1")
        r2 = generate_dry_run_results("tier1")
        self.assertEqual(r1.build_success, r2.build_success)
        self.assertEqual(r1.test_pass, r2.test_pass)

    def test_has_packages(self) -> None:
        r = generate_dry_run_results("tier1")
        self.assertEqual(len(r.packages), 20)


class TestLoadGateConfigs(unittest.TestCase):
    def test_from_repo(self) -> None:
        configs = load_gate_configs()
        self.assertIn("tier1", configs)
        self.assertIn("top20", configs)
        self.assertIn("top100", configs)

    def test_tier1_thresholds(self) -> None:
        configs = load_gate_configs()
        t1 = configs["tier1"]
        self.assertEqual(t1.thresholds.build_success_rate_pct, 100)
        self.assertEqual(t1.thresholds.max_new_regressions, 0)

    def test_missing_file(self) -> None:
        configs = load_gate_configs(Path("/nonexistent/config.json"))
        self.assertIn("tier1", configs)


class TestReleaseReport(unittest.TestCase):
    def test_schema(self) -> None:
        report = ReleaseReport(timestamp="2025-01-01T00:00:00Z")
        d = report.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.17")
        self.assertIn("release_blocked", d)
        self.assertIn("gates", d)

    def test_blocked_report(self) -> None:
        report = ReleaseReport(
            release_blocked=True,
            blocking_gates=["Tier 1 (tier1)"],
        )
        d = report.to_dict()
        self.assertTrue(d["release_blocked"])
        self.assertEqual(len(d["blocking_gates"]), 1)

    def test_markdown(self) -> None:
        report = ReleaseReport(timestamp="2025-01-01T00:00:00Z")
        report.gates.append(GateResult(
            gate_name="Tier 1", gate_level="tier1", passed=True,
            results=ValidationResults(
                build_total=20, build_success=20,
                test_total=20, test_pass=20,
            ),
        ))
        md = report.to_markdown()
        self.assertIn("Release Qualification Report", md)
        self.assertIn("PASS", md)
        self.assertIn("Tier 1", md)

    def test_markdown_blocked(self) -> None:
        report = ReleaseReport(
            timestamp="2025-01-01T00:00:00Z",
            release_blocked=True,
            blocking_gates=["Tier 1 (tier1)"],
        )
        md = report.to_markdown()
        self.assertIn("BLOCKED", md)
        self.assertIn("Blocking Gates", md)


class TestRunGateCheck(unittest.TestCase):
    def test_dry_run_all(self) -> None:
        report = run_gate_check(["tier1", "top20", "top100"], DATA_DIR, dry_run=True)
        self.assertTrue(report.dry_run)
        self.assertEqual(len(report.gates), 3)

    def test_dry_run_single(self) -> None:
        report = run_gate_check(["tier1"], DATA_DIR, dry_run=True)
        self.assertEqual(len(report.gates), 1)
        self.assertEqual(report.gates[0].gate_level, "tier1")


class TestCLI(unittest.TestCase):
    def test_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(GATE_SCRIPT),
                 "--dry-run", "--format", "json", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.17")
            self.assertTrue(data["dry_run"])
            self.assertIn("gates", data)
            self.assertEqual(len(data["gates"]), 3)

    def test_single_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(GATE_SCRIPT),
                 "--dry-run", "--level", "tier1",
                 "--format", "json", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0)
            data = json.loads(output.read_text())
            self.assertEqual(len(data["gates"]), 1)

    def test_terminal_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(GATE_SCRIPT),
             "--dry-run", "--format", "terminal"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Release Qualification", result.stdout)
        self.assertIn("Release Gate Summary", result.stdout)


# Need Any import for type hints in _make_config
from typing import Any

DATA_DIR = REPO_ROOT / "data" / "gentoo"


if __name__ == "__main__":
    unittest.main()
