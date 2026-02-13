#!/usr/bin/env python3
"""Tests for regression detection and baseline management (bd-2icq.12).

Validates:
- Regression detection logic for all types
- Severity classification
- Baseline data model
- Dry-run mode
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
CHECK_REGRESSIONS = REPO_ROOT / "scripts" / "gentoo" / "check_regressions.py"
UPDATE_BASELINE = REPO_ROOT / "scripts" / "gentoo" / "update_baseline.py"

# Import modules under test
import importlib.util

spec_cr = importlib.util.spec_from_file_location("check_regressions", str(CHECK_REGRESSIONS))
check_regressions_mod = importlib.util.module_from_spec(spec_cr)  # type: ignore[arg-type]
sys.modules["check_regressions"] = check_regressions_mod
spec_cr.loader.exec_module(check_regressions_mod)  # type: ignore[union-attr]

spec_ub = importlib.util.spec_from_file_location("update_baseline", str(UPDATE_BASELINE))
update_baseline_mod = importlib.util.module_from_spec(spec_ub)  # type: ignore[arg-type]
sys.modules["update_baseline"] = update_baseline_mod
spec_ub.loader.exec_module(update_baseline_mod)  # type: ignore[union-attr]

Regression = check_regressions_mod.Regression
PackageResult = check_regressions_mod.PackageResult
BaselineData = check_regressions_mod.BaselineData
RegressionReport = check_regressions_mod.RegressionReport
check_regressions = check_regressions_mod.check_regressions
generate_dry_run_data = check_regressions_mod.generate_dry_run_data
create_baseline_from_results = update_baseline_mod.create_baseline_from_results
generate_dry_run_baseline = update_baseline_mod.generate_dry_run_baseline


class TestRegressionDetection(unittest.TestCase):
    def test_no_regressions(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success", overhead_percent=5.0,
        )
        current = [PackageResult(
            name="a/b", build_status="success", overhead_percent=5.0,
        )]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_build_failure(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success",
        )
        current = [PackageResult(name="a/b", build_status="failed")]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, "NEW_BUILD_FAILURE")
        self.assertEqual(regs[0].severity, "critical")

    def test_test_failure(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success",
            tests={"test_1": True, "test_2": True},
        )
        current = [PackageResult(
            name="a/b", build_status="success",
            tests={"test_1": True, "test_2": False},
        )]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, "NEW_TEST_FAILURE")
        self.assertEqual(regs[0].severity, "high")
        self.assertEqual(regs[0].test, "test_2")

    def test_performance_regression_warn(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success", overhead_percent=5.0,
        )
        current = [PackageResult(
            name="a/b", build_status="success", overhead_percent=30.0,
        )]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, "PERFORMANCE_REGRESSION")
        self.assertEqual(regs[0].severity, "medium")

    def test_performance_regression_block(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success", overhead_percent=5.0,
        )
        current = [PackageResult(
            name="a/b", build_status="success", overhead_percent=60.0,
        )]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, "high")

    def test_new_healing_pattern(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success",
            healing_types={"ClampSize": 5},
        )
        current = [PackageResult(
            name="a/b", build_status="success",
            healing_types={"ClampSize": 5, "NullifyReturn": 3},
        )]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, "NEW_HEALING_PATTERN")
        self.assertEqual(regs[0].severity, "low")

    def test_new_package_not_regression(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(name="a/b", build_status="success")
        current = [
            PackageResult(name="a/b", build_status="success"),
            PackageResult(name="c/d", build_status="failed"),  # new pkg, not regression
        ]
        regs = check_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_multiple_regressions(self) -> None:
        baseline = BaselineData()
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success",
            tests={"test_1": True}, overhead_percent=5.0,
        )
        current = [PackageResult(
            name="a/b", build_status="failed",
            tests={"test_1": False}, overhead_percent=60.0,
        )]
        regs = check_regressions(baseline, current)
        # Should find build failure + test failure + perf regression
        types = {r.type for r in regs}
        self.assertIn("NEW_BUILD_FAILURE", types)
        self.assertIn("NEW_TEST_FAILURE", types)


class TestRegressionReport(unittest.TestCase):
    def test_empty_report(self) -> None:
        r = RegressionReport()
        d = r.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.12")
        self.assertFalse(d["has_blockers"])
        self.assertEqual(d["total_regressions"], 0)

    def test_has_blockers(self) -> None:
        r = RegressionReport(regressions=[
            Regression(type="NEW_BUILD_FAILURE", package="a/b", severity="critical"),
        ])
        self.assertTrue(r.has_blockers)

    def test_no_blockers_with_low(self) -> None:
        r = RegressionReport(regressions=[
            Regression(type="NEW_HEALING_PATTERN", package="a/b", severity="low"),
        ])
        self.assertFalse(r.has_blockers)

    def test_by_severity(self) -> None:
        r = RegressionReport(regressions=[
            Regression(type="t1", package="a/b", severity="critical"),
            Regression(type="t2", package="a/b", severity="critical"),
            Regression(type="t3", package="a/b", severity="low"),
        ])
        self.assertEqual(r.by_severity["critical"], 2)
        self.assertEqual(r.by_severity["low"], 1)


class TestBaselineData(unittest.TestCase):
    def test_from_dict(self) -> None:
        d = {
            "timestamp": "2026-01-01T00:00:00Z",
            "packages": [
                {"package": "a/b", "build_status": "success", "overhead_percent": 5.0},
            ],
        }
        baseline = BaselineData.from_dict(d)
        self.assertEqual(len(baseline.packages), 1)
        pkg = baseline.get("a/b")
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg.build_status, "success")

    def test_roundtrip(self) -> None:
        baseline = BaselineData(timestamp="2026-01-01T00:00:00Z")
        baseline.packages["a/b"] = PackageResult(
            name="a/b", build_status="success", overhead_percent=5.0,
        )
        d = baseline.to_dict()
        loaded = BaselineData.from_dict(d)
        self.assertEqual(loaded.get("a/b").build_status, "success")


class TestDryRunData(unittest.TestCase):
    def test_generates_data(self) -> None:
        baseline, current = generate_dry_run_data()
        self.assertEqual(len(baseline.packages), 5)
        self.assertEqual(len(current), 5)

    def test_finds_regressions(self) -> None:
        baseline, current = generate_dry_run_data()
        regs = check_regressions(baseline, current)
        # Dry run introduces intentional regressions
        self.assertGreater(len(regs), 0)

    def test_deterministic(self) -> None:
        b1, c1 = generate_dry_run_data()
        b2, c2 = generate_dry_run_data()
        r1 = check_regressions(b1, c1)
        r2 = check_regressions(b2, c2)
        self.assertEqual(len(r1), len(r2))


class TestBaselineGeneration(unittest.TestCase):
    def test_dry_run_baseline(self) -> None:
        baseline = generate_dry_run_baseline()
        self.assertEqual(baseline["schema_version"], "v1")
        self.assertEqual(baseline["bead"], "bd-2icq.12")
        self.assertEqual(len(baseline["packages"]), 5)

    def test_from_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            results_path = Path(tmpdir) / "results.json"
            results_path.write_text(json.dumps({
                "packages": [
                    {"package": "a/b", "build_overhead_percent": 5.0},
                    {"package": "c/d", "build_overhead_percent": 3.0, "error": "fail"},
                ],
            }))
            baseline = create_baseline_from_results(results_path)
            self.assertEqual(len(baseline["packages"]), 2)
            self.assertEqual(baseline["packages"][0]["build_status"], "success")
            self.assertEqual(baseline["packages"][1]["build_status"], "failed")


class TestCLI(unittest.TestCase):
    def test_regression_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(CHECK_REGRESSIONS),
                 "--dry-run", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            # dry-run with intentional regressions returns 1
            self.assertIn(result.returncode, (0, 1))
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.12")
            self.assertTrue(data["dry_run"])
            self.assertGreater(data["total_regressions"], 0)

    def test_baseline_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "baseline.json"
            result = subprocess.run(
                [sys.executable, str(UPDATE_BASELINE),
                 "--dry-run", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(len(data["packages"]), 5)

    def test_baseline_show(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "baseline.json"
            # Create
            subprocess.run(
                [sys.executable, str(UPDATE_BASELINE),
                 "--dry-run", "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            # Show
            result = subprocess.run(
                [sys.executable, str(UPDATE_BASELINE),
                 "--show", "--output", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Packages: 5", result.stdout)


if __name__ == "__main__":
    unittest.main()
