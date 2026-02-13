#!/usr/bin/env python3
"""Tests for validation dashboard aggregator (bd-2icq.11).

Validates:
- DashboardSection model
- Dashboard aggregation and status computation
- Section builders with missing/present data
- JSON and markdown output
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
DASHBOARD_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "validation_dashboard.py"

import importlib.util

spec = importlib.util.spec_from_file_location("validation_dashboard", str(DASHBOARD_SCRIPT))
vd_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["validation_dashboard"] = vd_mod
spec.loader.exec_module(vd_mod)  # type: ignore[union-attr]

DashboardSection = vd_mod.DashboardSection
Dashboard = vd_mod.Dashboard
load_json_safe = vd_mod.load_json_safe
build_perf_section = vd_mod.build_perf_section
build_regression_section = vd_mod.build_regression_section
build_quarantine_section = vd_mod.build_quarantine_section
build_constraints_section = vd_mod.build_constraints_section
build_baseline_section = vd_mod.build_baseline_section
build_dashboard = vd_mod.build_dashboard


class TestDashboardSection(unittest.TestCase):
    def test_basic(self) -> None:
        s = DashboardSection(title="Test", status="ok", metrics={"a": 1})
        d = s.to_dict()
        self.assertEqual(d["title"], "Test")
        self.assertEqual(d["status"], "ok")
        self.assertEqual(d["metrics"]["a"], 1)

    def test_defaults(self) -> None:
        s = DashboardSection(title="Empty")
        d = s.to_dict()
        self.assertEqual(d["status"], "ok")
        self.assertEqual(d["metrics"], {})
        self.assertEqual(d["details"], [])

    def test_with_details(self) -> None:
        s = DashboardSection(title="Det", details=["line1", "line2"])
        d = s.to_dict()
        self.assertEqual(len(d["details"]), 2)


class TestDashboard(unittest.TestCase):
    def test_empty(self) -> None:
        db = Dashboard()
        self.assertEqual(db.compute_overall(), "unknown")

    def test_all_ok(self) -> None:
        db = Dashboard()
        db.add(DashboardSection(title="A", status="ok"))
        db.add(DashboardSection(title="B", status="ok"))
        self.assertEqual(db.compute_overall(), "ok")

    def test_warn_overrides_ok(self) -> None:
        db = Dashboard()
        db.add(DashboardSection(title="A", status="ok"))
        db.add(DashboardSection(title="B", status="warn"))
        self.assertEqual(db.compute_overall(), "warn")

    def test_error_overrides_warn(self) -> None:
        db = Dashboard()
        db.add(DashboardSection(title="A", status="warn"))
        db.add(DashboardSection(title="B", status="error"))
        self.assertEqual(db.compute_overall(), "error")

    def test_unknown_with_ok(self) -> None:
        db = Dashboard()
        db.add(DashboardSection(title="A", status="ok"))
        db.add(DashboardSection(title="B", status="unknown"))
        self.assertEqual(db.compute_overall(), "unknown")

    def test_to_dict_schema(self) -> None:
        db = Dashboard(timestamp="2025-01-01T00:00:00Z")
        db.add(DashboardSection(title="A", status="ok"))
        d = db.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.11")
        self.assertIn("sections", d)
        self.assertEqual(len(d["sections"]), 1)
        self.assertIn("overall_status", d)
        self.assertIn("timestamp", d)

    def test_to_dict_dry_run(self) -> None:
        db = Dashboard(dry_run=True)
        d = db.to_dict()
        self.assertTrue(d["dry_run"])

    def test_to_markdown(self) -> None:
        db = Dashboard(timestamp="2025-01-01T00:00:00Z")
        db.add(DashboardSection(
            title="Perf", status="ok",
            metrics={"passed": 10}, details=["detail1"],
        ))
        md = db.to_markdown()
        self.assertIn("FrankenLibC Gentoo Validation Dashboard", md)
        self.assertIn("PASS", md)
        self.assertIn("Perf", md)
        self.assertIn("**passed:**", md)
        self.assertIn("detail1", md)

    def test_markdown_error_status(self) -> None:
        db = Dashboard(timestamp="2025-01-01T00:00:00Z")
        db.add(DashboardSection(title="Bad", status="error"))
        md = db.to_markdown()
        self.assertIn("FAIL", md)


class TestLoadJsonSafe(unittest.TestCase):
    def test_missing_file(self) -> None:
        result = load_json_safe(Path("/nonexistent/path.json"))
        self.assertIsNone(result)

    def test_valid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"key": "value"}, f)
            f.flush()
            result = load_json_safe(Path(f.name))
        self.assertIsNotNone(result)
        self.assertEqual(result["key"], "value")

    def test_invalid_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json {{{")
            f.flush()
            result = load_json_safe(Path(f.name))
        self.assertIsNone(result)


class TestSectionBuilders(unittest.TestCase):
    """Test section builders with missing data (no data dir)."""

    def test_perf_missing(self) -> None:
        s = build_perf_section(Path("/nonexistent"))
        self.assertEqual(s.status, "unknown")

    def test_regression_missing(self) -> None:
        s = build_regression_section(Path("/nonexistent"))
        self.assertEqual(s.status, "unknown")

    def test_quarantine_missing(self) -> None:
        s = build_quarantine_section(Path("/nonexistent"))
        self.assertEqual(s.status, "unknown")

    def test_constraints_missing(self) -> None:
        s = build_constraints_section(Path("/nonexistent"))
        self.assertEqual(s.status, "unknown")

    def test_baseline_missing(self) -> None:
        s = build_baseline_section(Path("/nonexistent"))
        self.assertEqual(s.status, "unknown")


class TestSectionBuildersWithData(unittest.TestCase):
    """Test section builders with synthetic data."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.data_dir = Path(self.tmpdir)

    def test_perf_ok(self) -> None:
        perf_dir = self.data_dir / "perf-results"
        perf_dir.mkdir(parents=True)
        (perf_dir / "perf_benchmark_results.v1.json").write_text(json.dumps({
            "total_packages": 10, "successful": 10, "failed": 0,
            "avg_build_overhead_percent": 4.5,
            "median_build_overhead_percent": 3.8,
        }))
        s = build_perf_section(self.data_dir)
        self.assertEqual(s.status, "ok")
        self.assertEqual(s.metrics["total_packages"], 10)

    def test_perf_warn(self) -> None:
        perf_dir = self.data_dir / "perf-results"
        perf_dir.mkdir(parents=True)
        (perf_dir / "perf_benchmark_results.v1.json").write_text(json.dumps({
            "total_packages": 10, "successful": 8, "failed": 2,
        }))
        s = build_perf_section(self.data_dir)
        self.assertEqual(s.status, "warn")

    def test_regression_ok(self) -> None:
        (self.data_dir / "regression_report.v1.json").write_text(json.dumps({
            "has_blockers": False, "total_regressions": 0,
            "by_severity": {}, "by_type": {}, "regressions": [],
        }))
        s = build_regression_section(self.data_dir)
        self.assertEqual(s.status, "ok")

    def test_regression_error(self) -> None:
        (self.data_dir / "regression_report.v1.json").write_text(json.dumps({
            "has_blockers": True, "total_regressions": 3,
            "by_severity": {"critical": 1}, "by_type": {"build": 1},
            "regressions": [
                {"type": "build", "package": "a/b", "severity": "critical"},
            ],
        }))
        s = build_regression_section(self.data_dir)
        self.assertEqual(s.status, "error")
        self.assertEqual(len(s.details), 1)

    def test_regression_warn(self) -> None:
        (self.data_dir / "regression_report.v1.json").write_text(json.dumps({
            "has_blockers": False, "total_regressions": 2,
            "by_severity": {}, "by_type": {}, "regressions": [],
        }))
        s = build_regression_section(self.data_dir)
        self.assertEqual(s.status, "warn")

    def test_quarantine_ok(self) -> None:
        (self.data_dir / "quarantine.json").write_text(json.dumps({
            "statistics": {"total_quarantined": 5, "by_reason": {"flaky": 3, "oom": 2}},
        }))
        s = build_quarantine_section(self.data_dir)
        self.assertEqual(s.status, "ok")
        self.assertEqual(s.metrics["total_quarantined"], 5)

    def test_constraints_ok(self) -> None:
        (self.data_dir / "resource_constraints_report.v1.json").write_text(json.dumps({
            "total_tests": 20, "passed": 20, "failed": 0, "by_type": {},
        }))
        s = build_constraints_section(self.data_dir)
        self.assertEqual(s.status, "ok")

    def test_constraints_warn(self) -> None:
        (self.data_dir / "resource_constraints_report.v1.json").write_text(json.dumps({
            "total_tests": 20, "passed": 17, "failed": 3, "by_type": {},
        }))
        s = build_constraints_section(self.data_dir)
        self.assertEqual(s.status, "warn")

    def test_baseline_ok(self) -> None:
        (self.data_dir / "baseline.json").write_text(json.dumps({
            "packages": [{"name": "a/b"}, {"name": "c/d"}],
            "timestamp": "2025-01-01", "source": "dry-run",
        }))
        s = build_baseline_section(self.data_dir)
        self.assertEqual(s.status, "ok")
        self.assertEqual(s.metrics["packages"], 2)


class TestBuildDashboard(unittest.TestCase):
    def test_dry_run_flag(self) -> None:
        db = build_dashboard(Path("/nonexistent"), dry_run=True)
        self.assertTrue(db.dry_run)
        self.assertEqual(len(db.sections), 6)

    def test_all_data_sections_unknown_when_no_data(self) -> None:
        db = build_dashboard(Path("/nonexistent"), dry_run=True)
        # Skip fast_validate section (index 0) as it checks a real path
        for s in db.sections[1:]:
            self.assertEqual(s.status, "unknown", f"{s.title} should be unknown")

    def test_json_roundtrip(self) -> None:
        db = build_dashboard(Path("/nonexistent"), dry_run=True)
        d = db.to_dict()
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["schema_version"], "v1")
        self.assertEqual(parsed["bead"], "bd-2icq.11")
        self.assertEqual(len(parsed["sections"]), 6)


class TestCLI(unittest.TestCase):
    def test_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "dashboard.json"
            result = subprocess.run(
                [sys.executable, str(DASHBOARD_SCRIPT),
                 "--dry-run", "--format", "json", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.11")
            self.assertTrue(data["dry_run"])

    def test_markdown_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "dashboard.json"
            result = subprocess.run(
                [sys.executable, str(DASHBOARD_SCRIPT),
                 "--dry-run", "--format", "both", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0)
            md_path = Path(tmpdir) / "dashboard.md"
            self.assertTrue(md_path.exists())
            md_content = md_path.read_text()
            self.assertIn("FrankenLibC Gentoo Validation Dashboard", md_content)


if __name__ == "__main__":
    unittest.main()
