#!/usr/bin/env python3
"""Tests for flaky test detection and quarantine infrastructure (bd-2icq.24).

Validates:
- Flaky test detection logic
- Flake rate calculation
- Quarantine database operations
- Category classification
- CLI dry-run mode
- Import from detection report
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FLAKY_DETECTOR = REPO_ROOT / "scripts" / "gentoo" / "flaky_detector.py"
QUARANTINE_MANAGER = REPO_ROOT / "scripts" / "gentoo" / "quarantine_manager.py"

# Import modules under test
import importlib.util

spec_fd = importlib.util.spec_from_file_location("flaky_detector", str(FLAKY_DETECTOR))
flaky_detector = importlib.util.module_from_spec(spec_fd)  # type: ignore[arg-type]
sys.modules["flaky_detector"] = flaky_detector
spec_fd.loader.exec_module(flaky_detector)  # type: ignore[union-attr]

spec_qm = importlib.util.spec_from_file_location("quarantine_manager", str(QUARANTINE_MANAGER))
quarantine_manager = importlib.util.module_from_spec(spec_qm)  # type: ignore[arg-type]
sys.modules["quarantine_manager"] = quarantine_manager
spec_qm.loader.exec_module(quarantine_manager)  # type: ignore[union-attr]

TestOutcome = flaky_detector.TestOutcome
RunResult = flaky_detector.RunResult
FlakyTest = flaky_detector.FlakyTest
DetectionReport = flaky_detector.DetectionReport
calculate_flake_rate = flaky_detector.calculate_flake_rate
categorize_flake = flaky_detector.categorize_flake
detect_flaky_tests = flaky_detector.detect_flaky_tests
generate_dry_run_results = flaky_detector.generate_dry_run_results

QuarantinedTest = quarantine_manager.QuarantinedTest
QuarantineDB = quarantine_manager.QuarantineDB
import_detection_report = quarantine_manager.import_detection_report
filter_quarantined = quarantine_manager.filter_quarantined


class TestFlakeRateCalculation(unittest.TestCase):
    def test_all_pass(self) -> None:
        self.assertEqual(calculate_flake_rate([True, True, True]), 0.0)

    def test_all_fail(self) -> None:
        self.assertEqual(calculate_flake_rate([False, False, False]), 0.0)

    def test_one_flip(self) -> None:
        rate = calculate_flake_rate([True, True, False])
        self.assertAlmostEqual(rate, 1 / 3, places=4)

    def test_equal_split(self) -> None:
        rate = calculate_flake_rate([True, False, True, False])
        self.assertAlmostEqual(rate, 0.5)

    def test_empty(self) -> None:
        self.assertEqual(calculate_flake_rate([]), 0.0)

    def test_single(self) -> None:
        self.assertEqual(calculate_flake_rate([True]), 0.0)


class TestCategorization(unittest.TestCase):
    def test_timing(self) -> None:
        self.assertEqual(categorize_flake("test_timeout_handling", []), "timing_sensitive")
        self.assertEqual(categorize_flake("test_sleep_recovery", []), "timing_sensitive")

    def test_resource(self) -> None:
        self.assertEqual(categorize_flake("test_memory_limit", []), "resource_dependent")
        self.assertEqual(categorize_flake("test_oom_recovery", []), "resource_dependent")

    def test_network(self) -> None:
        self.assertEqual(categorize_flake("test_http_connect", []), "network_dependent")
        self.assertEqual(categorize_flake("test_socket_bind", []), "network_dependent")

    def test_random(self) -> None:
        self.assertEqual(categorize_flake("test_random_data", []), "random_seed")

    def test_order(self) -> None:
        self.assertEqual(categorize_flake("test_order_dependent", []), "order_dependent")

    def test_unknown(self) -> None:
        self.assertEqual(categorize_flake("test_basic_ops", []), "unknown")


class TestFlakeDetection(unittest.TestCase):
    def test_no_runs(self) -> None:
        self.assertEqual(detect_flaky_tests([]), [])

    def test_all_stable(self) -> None:
        runs = [
            RunResult(package="a/b", run_index=0, outcomes=[
                TestOutcome("t1", True), TestOutcome("t2", True),
            ]),
            RunResult(package="a/b", run_index=1, outcomes=[
                TestOutcome("t1", True), TestOutcome("t2", True),
            ]),
        ]
        self.assertEqual(detect_flaky_tests(runs), [])

    def test_one_flaky(self) -> None:
        runs = [
            RunResult(package="a/b", run_index=0, outcomes=[
                TestOutcome("t1", True), TestOutcome("t2", True),
            ]),
            RunResult(package="a/b", run_index=1, outcomes=[
                TestOutcome("t1", True), TestOutcome("t2", False),
            ]),
        ]
        flaky = detect_flaky_tests(runs)
        self.assertEqual(len(flaky), 1)
        self.assertEqual(flaky[0].test_name, "t2")

    def test_multiple_flaky(self) -> None:
        runs = [
            RunResult(package="a/b", run_index=0, outcomes=[
                TestOutcome("t1", True), TestOutcome("t2", True),
                TestOutcome("t3", False),
            ]),
            RunResult(package="a/b", run_index=1, outcomes=[
                TestOutcome("t1", False), TestOutcome("t2", False),
                TestOutcome("t3", False),
            ]),
        ]
        flaky = detect_flaky_tests(runs)
        self.assertEqual(len(flaky), 2)
        names = {f.test_name for f in flaky}
        self.assertEqual(names, {"t1", "t2"})

    def test_three_runs(self) -> None:
        runs = [
            RunResult(package="a/b", run_index=0, outcomes=[
                TestOutcome("t1", True),
            ]),
            RunResult(package="a/b", run_index=1, outcomes=[
                TestOutcome("t1", True),
            ]),
            RunResult(package="a/b", run_index=2, outcomes=[
                TestOutcome("t1", False),
            ]),
        ]
        flaky = detect_flaky_tests(runs)
        self.assertEqual(len(flaky), 1)
        self.assertAlmostEqual(flaky[0].flake_rate, 1 / 3, places=4)


class TestDryRunGeneration(unittest.TestCase):
    def test_generates_runs(self) -> None:
        runs = generate_dry_run_results("sys-apps/coreutils", 3)
        self.assertEqual(len(runs), 3)
        for r in runs:
            self.assertEqual(r.package, "sys-apps/coreutils")
            self.assertGreater(len(r.outcomes), 0)

    def test_deterministic(self) -> None:
        r1 = generate_dry_run_results("sys-apps/coreutils", 3)
        r2 = generate_dry_run_results("sys-apps/coreutils", 3)
        for a, b in zip(r1, r2):
            for oa, ob in zip(a.outcomes, b.outcomes):
                self.assertEqual(oa.test_name, ob.test_name)
                self.assertEqual(oa.passed, ob.passed)

    def test_has_flaky_tests(self) -> None:
        runs = generate_dry_run_results("sys-apps/coreutils", 3)
        flaky = detect_flaky_tests(runs)
        # Dry run should produce some flaky tests
        self.assertGreater(len(flaky), 0)


class TestDetectionReport(unittest.TestCase):
    def test_empty_report(self) -> None:
        r = DetectionReport()
        d = r.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.24")
        self.assertEqual(d["flaky_tests_found"], 0)

    def test_add_flaky(self) -> None:
        r = DetectionReport()
        tests = [FlakyTest(package="a/b", test_name="t1", category="timing_sensitive")]
        r.add(tests)
        self.assertEqual(r.packages_scanned, 1)
        self.assertEqual(r.flaky_tests_found, 1)
        self.assertEqual(r.by_category["timing_sensitive"], 1)


class TestQuarantineDB(unittest.TestCase):
    def test_empty_db(self) -> None:
        db = QuarantineDB()
        self.assertEqual(len(db.quarantined_tests), 0)
        self.assertFalse(db.is_quarantined("a/b", "t1"))

    def test_add_test(self) -> None:
        db = QuarantineDB()
        t = QuarantinedTest(package="a/b", test="t1", reason="timing_sensitive")
        self.assertTrue(db.add_test(t))
        self.assertTrue(db.is_quarantined("a/b", "t1"))

    def test_add_duplicate_updates(self) -> None:
        db = QuarantineDB()
        t1 = QuarantinedTest(package="a/b", test="t1", reason="unknown")
        db.add_test(t1)
        t2 = QuarantinedTest(package="a/b", test="t1", reason="timing_sensitive")
        self.assertFalse(db.add_test(t2))
        stored = db.get_test("a/b", "t1")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.occurrences, 2)
        self.assertEqual(stored.reason, "timing_sensitive")

    def test_remove_test(self) -> None:
        db = QuarantineDB()
        db.add_test(QuarantinedTest(package="a/b", test="t1"))
        self.assertTrue(db.remove_test("a/b", "t1"))
        self.assertFalse(db.is_quarantined("a/b", "t1"))

    def test_remove_nonexistent(self) -> None:
        db = QuarantineDB()
        self.assertFalse(db.remove_test("a/b", "t1"))

    def test_get_package_tests(self) -> None:
        db = QuarantineDB()
        db.add_test(QuarantinedTest(package="a/b", test="t1"))
        db.add_test(QuarantinedTest(package="a/b", test="t2"))
        db.add_test(QuarantinedTest(package="c/d", test="t3"))
        self.assertEqual(len(db.get_package_tests("a/b")), 2)
        self.assertEqual(len(db.get_package_tests("c/d")), 1)

    def test_save_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "quarantine.json"
            db = QuarantineDB()
            db.add_test(QuarantinedTest(
                package="a/b", test="t1", reason="timing_sensitive",
                flake_rate=0.33,
            ))
            db.save(path)

            loaded = QuarantineDB.load(path)
            self.assertEqual(len(loaded.quarantined_tests), 1)
            t = loaded.quarantined_tests[0]
            self.assertEqual(t.package, "a/b")
            self.assertEqual(t.test, "t1")
            self.assertEqual(t.reason, "timing_sensitive")
            self.assertAlmostEqual(t.flake_rate, 0.33, places=3)

    def test_statistics(self) -> None:
        db = QuarantineDB()
        db.add_test(QuarantinedTest(package="a/b", test="t1", reason="timing_sensitive"))
        db.add_test(QuarantinedTest(package="a/b", test="t2", reason="timing_sensitive"))
        db.add_test(QuarantinedTest(package="c/d", test="t3", reason="network_dependent"))
        stats = db.statistics()
        self.assertEqual(stats["total_quarantined"], 3)
        self.assertEqual(stats["by_reason"]["timing_sensitive"], 2)
        self.assertEqual(stats["by_reason"]["network_dependent"], 1)
        self.assertEqual(stats["by_package"]["a/b"], 2)

    def test_to_dict_schema(self) -> None:
        db = QuarantineDB()
        db.add_test(QuarantinedTest(package="a/b", test="t1"))
        d = db.to_dict()
        self.assertIn("version", d)
        self.assertIn("last_updated", d)
        self.assertIn("quarantined_tests", d)
        self.assertIn("statistics", d)


class TestFilterQuarantined(unittest.TestCase):
    def test_no_quarantined(self) -> None:
        db = QuarantineDB()
        results = [{"name": "t1", "passed": True}, {"name": "t2", "passed": False}]
        stable, quarantined = filter_quarantined(results, db, "a/b")
        self.assertEqual(len(stable), 2)
        self.assertEqual(len(quarantined), 0)

    def test_one_quarantined(self) -> None:
        db = QuarantineDB()
        db.add_test(QuarantinedTest(package="a/b", test="t2"))
        results = [{"name": "t1", "passed": True}, {"name": "t2", "passed": False}]
        stable, quarantined = filter_quarantined(results, db, "a/b")
        self.assertEqual(len(stable), 1)
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(stable[0]["name"], "t1")
        self.assertEqual(quarantined[0]["name"], "t2")


class TestImportReport(unittest.TestCase):
    def test_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_path.write_text(json.dumps({
                "flaky_tests": [
                    {"package": "a/b", "test": "t1", "reason": "timing_sensitive",
                     "flake_rate": 0.33},
                    {"package": "c/d", "test": "t2", "reason": "unknown",
                     "flake_rate": 0.5},
                ],
            }))
            db = QuarantineDB()
            added = import_detection_report(db, report_path)
            self.assertEqual(added, 2)
            self.assertTrue(db.is_quarantined("a/b", "t1"))
            self.assertTrue(db.is_quarantined("c/d", "t2"))


class TestCLIDryRun(unittest.TestCase):
    def test_detector_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(FLAKY_DETECTOR),
                 "--dry-run", "--package", "sys-apps/coreutils",
                 "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.24")
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["packages_scanned"], 1)

    def test_detector_tier1_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(FLAKY_DETECTOR),
                 "--dry-run", "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            data = json.loads(output.read_text())
            self.assertEqual(data["packages_scanned"], 5)

    def test_quarantine_init(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "quarantine.json"
            result = subprocess.run(
                [sys.executable, str(QUARANTINE_MANAGER),
                 "--action", "init", "--db", str(db_path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(db_path.exists())
            data = json.loads(db_path.read_text())
            self.assertEqual(data["version"], 1)

    def test_quarantine_add_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "quarantine.json"
            # Init
            subprocess.run(
                [sys.executable, str(QUARANTINE_MANAGER),
                 "--action", "init", "--db", str(db_path)],
                capture_output=True, text=True, timeout=10,
            )
            # Add
            result = subprocess.run(
                [sys.executable, str(QUARANTINE_MANAGER),
                 "--action", "add", "--package", "a/b", "--test", "t1",
                 "--reason", "timing_sensitive", "--db", str(db_path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("Added", result.stdout)
            # List
            result = subprocess.run(
                [sys.executable, str(QUARANTINE_MANAGER),
                 "--action", "list", "--db", str(db_path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("a/b::t1", result.stdout)


if __name__ == "__main__":
    unittest.main()
