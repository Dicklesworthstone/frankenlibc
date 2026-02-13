#!/usr/bin/env python3
"""Tests for progress reporting infrastructure (bd-2icq.21).

Validates:
- BuildProgress model and calculations
- ETA estimation
- Resource snapshot
- Terminal rendering
- JSON output
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
REPORTER_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "progress_reporter.py"

import importlib.util

spec = importlib.util.spec_from_file_location("progress_reporter", str(REPORTER_SCRIPT))
pr_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["progress_reporter"] = pr_mod
spec.loader.exec_module(pr_mod)  # type: ignore[union-attr]

PackageStatus = pr_mod.PackageStatus
ResourceSnapshot = pr_mod.ResourceSnapshot
BuildProgress = pr_mod.BuildProgress
ProgressReport = pr_mod.ProgressReport
format_time = pr_mod.format_time
format_progress_bar = pr_mod.format_progress_bar
render_terminal = pr_mod.render_terminal
generate_dry_run_report = pr_mod.generate_dry_run_report


class TestFormatTime(unittest.TestCase):
    def test_seconds(self) -> None:
        self.assertEqual(format_time(30), "30s")

    def test_minutes(self) -> None:
        self.assertEqual(format_time(150), "2m 30s")

    def test_hours(self) -> None:
        result = format_time(3720)
        self.assertIn("1h", result)
        self.assertIn("2m", result)


class TestFormatProgressBar(unittest.TestCase):
    def test_zero(self) -> None:
        bar = format_progress_bar(0)
        self.assertIn("0%", bar)

    def test_fifty(self) -> None:
        bar = format_progress_bar(50)
        self.assertIn("50%", bar)

    def test_hundred(self) -> None:
        bar = format_progress_bar(100)
        self.assertIn("100%", bar)


class TestPackageStatus(unittest.TestCase):
    def test_basic(self) -> None:
        ps = PackageStatus(name="a/b", status="success", elapsed_s=120.5)
        d = ps.to_dict()
        self.assertEqual(d["name"], "a/b")
        self.assertEqual(d["status"], "success")
        self.assertEqual(d["elapsed_s"], 120.5)

    def test_failure(self) -> None:
        ps = PackageStatus(name="a/b", status="failed", failure_reason="oom")
        d = ps.to_dict()
        self.assertIn("failure_reason", d)
        self.assertEqual(d["failure_reason"], "oom")


class TestResourceSnapshot(unittest.TestCase):
    def test_percentages(self) -> None:
        rs = ResourceSnapshot(
            memory_used_mb=2048, memory_total_mb=8192,
            disk_used_gb=45.0, disk_total_gb=100.0,
        )
        self.assertAlmostEqual(rs.memory_percent, 25.0)
        self.assertAlmostEqual(rs.disk_percent, 45.0)

    def test_zero_total(self) -> None:
        rs = ResourceSnapshot()
        self.assertEqual(rs.memory_percent, 0.0)
        self.assertEqual(rs.disk_percent, 0.0)

    def test_to_dict(self) -> None:
        rs = ResourceSnapshot(cpu_percent=75.3, memory_used_mb=4096, memory_total_mb=8192)
        d = rs.to_dict()
        self.assertEqual(d["cpu_percent"], 75.3)
        self.assertIn("memory_percent", d)


class TestBuildProgress(unittest.TestCase):
    def test_empty(self) -> None:
        bp = BuildProgress()
        self.assertEqual(bp.percentage, 0.0)
        self.assertEqual(bp.avg_package_s, 0.0)
        self.assertEqual(bp.estimate_remaining_s(), 0.0)

    def test_percentage(self) -> None:
        bp = BuildProgress(total=100, completed=60)
        self.assertAlmostEqual(bp.percentage, 60.0)

    def test_eta(self) -> None:
        bp = BuildProgress(
            total=10, completed=5,
            package_times=[100, 100, 100, 100, 100],
        )
        self.assertAlmostEqual(bp.avg_package_s, 100.0)
        self.assertAlmostEqual(bp.estimate_remaining_s(), 500.0)

    def test_recent_failures(self) -> None:
        bp = BuildProgress(packages=[
            PackageStatus(name="a/b", status="success"),
            PackageStatus(name="c/d", status="failed", failure_reason="oom"),
            PackageStatus(name="e/f", status="failed", failure_reason="timeout"),
        ])
        failures = bp.recent_failures()
        self.assertEqual(len(failures), 2)

    def test_to_dict_schema(self) -> None:
        bp = BuildProgress(total=10, completed=5)
        d = bp.to_dict()
        self.assertIn("status", d)
        self.assertIn("progress", d)
        self.assertIn("summary", d)
        self.assertIn("timing", d)
        self.assertEqual(d["status"], "running")

    def test_complete_status(self) -> None:
        bp = BuildProgress(total=5, completed=5)
        d = bp.to_dict()
        self.assertEqual(d["status"], "complete")


class TestProgressReport(unittest.TestCase):
    def test_schema(self) -> None:
        report = ProgressReport()
        d = report.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.21")
        self.assertIn("resources", d)

    def test_speed_comparison_slower(self) -> None:
        report = ProgressReport(
            progress=BuildProgress(package_times=[500, 500]),
            historical_avg_s=200.0,
        )
        self.assertIn("slower", report.speed_comparison or "")

    def test_speed_comparison_faster(self) -> None:
        report = ProgressReport(
            progress=BuildProgress(package_times=[100, 100]),
            historical_avg_s=500.0,
        )
        self.assertIn("faster", report.speed_comparison or "")

    def test_speed_comparison_normal(self) -> None:
        report = ProgressReport(
            progress=BuildProgress(package_times=[200, 200]),
            historical_avg_s=200.0,
        )
        self.assertIn("normal", report.speed_comparison or "")


class TestTerminalRendering(unittest.TestCase):
    def test_renders(self) -> None:
        report = generate_dry_run_report(["sys-apps/coreutils", "dev-libs/json-c"])
        output = render_terminal(report)
        self.assertIn("FrankenLibC Gentoo Validation", output)
        self.assertIn("Progress:", output)
        self.assertIn("Stats:", output)

    def test_includes_failures(self) -> None:
        report = generate_dry_run_report(
            ["sys-apps/coreutils"] * 10,  # enough to generate some failures
        )
        output = render_terminal(report)
        # Should include timing info
        self.assertIn("Timing:", output)


class TestDryRunReport(unittest.TestCase):
    def test_generates_report(self) -> None:
        report = generate_dry_run_report(["a/b", "c/d", "e/f", "g/h", "i/j"])
        self.assertTrue(report.dry_run)
        self.assertEqual(report.progress.total, 5)
        self.assertGreater(report.progress.completed, 0)

    def test_deterministic(self) -> None:
        r1 = generate_dry_run_report(["a/b", "c/d"])
        r2 = generate_dry_run_report(["a/b", "c/d"])
        self.assertEqual(r1.progress.completed, r2.progress.completed)
        self.assertEqual(r1.progress.passed, r2.progress.passed)

    def test_has_resources(self) -> None:
        report = generate_dry_run_report(["a/b"])
        self.assertGreater(report.resources.cpu_percent, 0)
        self.assertGreater(report.resources.memory_total_mb, 0)


class TestCLI(unittest.TestCase):
    def test_terminal_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPORTER_SCRIPT), "--mode", "dry-run"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
        self.assertIn("FrankenLibC Gentoo Validation", result.stdout)

    def test_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "progress.json"
            result = subprocess.run(
                [sys.executable, str(REPORTER_SCRIPT),
                 "--mode", "dry-run", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.21")
            self.assertTrue(data["dry_run"])
            self.assertIn("progress", data)
            self.assertIn("resources", data)


if __name__ == "__main__":
    unittest.main()
