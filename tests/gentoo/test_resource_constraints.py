#!/usr/bin/env python3
"""Tests for resource constraint testing infrastructure (bd-2icq.20).

Validates:
- Exit code categorization
- Constraint test result model
- Suite aggregation
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
CONSTRAINT_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "resource_constraints.py"

import importlib.util

spec = importlib.util.spec_from_file_location("resource_constraints", str(CONSTRAINT_SCRIPT))
rc_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["resource_constraints"] = rc_mod
spec.loader.exec_module(rc_mod)  # type: ignore[union-attr]

FailureType = rc_mod.FailureType
ResourceLimit = rc_mod.ResourceLimit
ConstraintTestResult = rc_mod.ConstraintTestResult
ConstraintSuite = rc_mod.ConstraintSuite
categorize_exit_code = rc_mod.categorize_exit_code
generate_oom_test = rc_mod.generate_oom_test
generate_timeout_test = rc_mod.generate_timeout_test
generate_disk_full_test = rc_mod.generate_disk_full_test
generate_baseline_test = rc_mod.generate_baseline_test
generate_contention_test = rc_mod.generate_contention_test
run_dry_suite = rc_mod.run_dry_suite


class TestExitCodeCategorization(unittest.TestCase):
    def test_success(self) -> None:
        self.assertEqual(categorize_exit_code(0), FailureType.SUCCESS)

    def test_oom_signal(self) -> None:
        self.assertEqual(categorize_exit_code(137), FailureType.FAILED_OOM)

    def test_timeout(self) -> None:
        self.assertEqual(categorize_exit_code(124), FailureType.FAILED_TIMEOUT)

    def test_enospc(self) -> None:
        self.assertEqual(categorize_exit_code(28), FailureType.FAILED_DISK_FULL)

    def test_oom_from_stderr(self) -> None:
        self.assertEqual(
            categorize_exit_code(1, "Cannot allocate memory"),
            FailureType.FAILED_OOM,
        )

    def test_disk_from_stderr(self) -> None:
        self.assertEqual(
            categorize_exit_code(1, "No space left on device"),
            FailureType.FAILED_DISK_FULL,
        )

    def test_timeout_from_stderr(self) -> None:
        self.assertEqual(
            categorize_exit_code(1, "Operation timed out"),
            FailureType.FAILED_TIMEOUT,
        )

    def test_network_from_stderr(self) -> None:
        self.assertEqual(
            categorize_exit_code(1, "Connection refused"),
            FailureType.FAILED_NETWORK,
        )

    def test_unknown(self) -> None:
        self.assertEqual(categorize_exit_code(42), FailureType.FAILED_UNKNOWN)


class TestResourceLimit(unittest.TestCase):
    def test_empty_limit(self) -> None:
        rl = ResourceLimit()
        self.assertEqual(rl.to_dict(), {})

    def test_memory_limit(self) -> None:
        rl = ResourceLimit(memory_mb=256)
        self.assertEqual(rl.to_dict(), {"memory_mb": 256})

    def test_full_limit(self) -> None:
        rl = ResourceLimit(memory_mb=256, disk_mb=100, timeout_s=30, cpus=0.5)
        d = rl.to_dict()
        self.assertEqual(d["memory_mb"], 256)
        self.assertEqual(d["disk_mb"], 100)
        self.assertEqual(d["timeout_s"], 30)
        self.assertEqual(d["cpus"], 0.5)


class TestConstraintTestResult(unittest.TestCase):
    def test_oom_passes_when_detected(self) -> None:
        r = ConstraintTestResult(
            test_name="oom", package="a/b", constraint_type="oom",
            limits=ResourceLimit(memory_mb=256),
            failure_type=FailureType.FAILED_OOM,
        )
        self.assertTrue(r.passed())

    def test_oom_fails_when_not_detected(self) -> None:
        r = ConstraintTestResult(
            test_name="oom", package="a/b", constraint_type="oom",
            limits=ResourceLimit(memory_mb=256),
            failure_type=FailureType.FAILED_UNKNOWN,
        )
        self.assertFalse(r.passed())

    def test_timeout_passes(self) -> None:
        r = ConstraintTestResult(
            test_name="timeout", package="a/b", constraint_type="timeout",
            limits=ResourceLimit(timeout_s=30),
            failure_type=FailureType.FAILED_TIMEOUT,
        )
        self.assertTrue(r.passed())

    def test_baseline_passes(self) -> None:
        r = ConstraintTestResult(
            test_name="baseline", package="a/b", constraint_type="baseline",
            limits=ResourceLimit(),
            failure_type=FailureType.SUCCESS,
        )
        self.assertTrue(r.passed())

    def test_to_dict_schema(self) -> None:
        r = ConstraintTestResult(
            test_name="test", package="a/b", constraint_type="oom",
            limits=ResourceLimit(memory_mb=256),
        )
        d = r.to_dict()
        required = {"test_name", "package", "constraint_type", "limits",
                     "failure_type", "exit_code", "duration_s",
                     "logs_preserved", "container_cleaned", "passed", "dry_run"}
        self.assertTrue(required.issubset(set(d.keys())))


class TestConstraintSuite(unittest.TestCase):
    def test_empty_suite(self) -> None:
        s = ConstraintSuite()
        d = s.to_dict()
        self.assertEqual(d["schema_version"], "v1")
        self.assertEqual(d["bead"], "bd-2icq.20")
        self.assertEqual(d["total_tests"], 0)

    def test_counts(self) -> None:
        s = ConstraintSuite()
        s.add(ConstraintTestResult(
            test_name="t1", package="a/b", constraint_type="oom",
            limits=ResourceLimit(), failure_type=FailureType.FAILED_OOM,
        ))
        s.add(ConstraintTestResult(
            test_name="t2", package="a/b", constraint_type="oom",
            limits=ResourceLimit(), failure_type=FailureType.FAILED_UNKNOWN,
        ))
        self.assertEqual(s.passed_count, 1)
        self.assertEqual(s.failed_count, 1)

    def test_by_type(self) -> None:
        s = ConstraintSuite()
        s.add(ConstraintTestResult(
            test_name="t1", package="a/b", constraint_type="oom",
            limits=ResourceLimit(),
        ))
        s.add(ConstraintTestResult(
            test_name="t2", package="a/b", constraint_type="timeout",
            limits=ResourceLimit(),
        ))
        self.assertEqual(s.by_type(), {"oom": 1, "timeout": 1})


class TestDryRunGenerators(unittest.TestCase):
    def test_oom_generator(self) -> None:
        r = generate_oom_test("sys-apps/coreutils")
        self.assertEqual(r.constraint_type, "oom")
        self.assertEqual(r.failure_type, FailureType.FAILED_OOM)
        self.assertEqual(r.exit_code, 137)
        self.assertTrue(r.passed())

    def test_timeout_generator(self) -> None:
        r = generate_timeout_test("sys-apps/coreutils")
        self.assertEqual(r.constraint_type, "timeout")
        self.assertEqual(r.failure_type, FailureType.FAILED_TIMEOUT)
        self.assertTrue(r.passed())

    def test_disk_full_generator(self) -> None:
        r = generate_disk_full_test("sys-apps/coreutils")
        self.assertEqual(r.constraint_type, "disk_full")
        self.assertEqual(r.failure_type, FailureType.FAILED_DISK_FULL)
        self.assertTrue(r.passed())

    def test_baseline_generator(self) -> None:
        r = generate_baseline_test("sys-apps/coreutils")
        self.assertEqual(r.constraint_type, "baseline")
        self.assertEqual(r.failure_type, FailureType.SUCCESS)
        self.assertTrue(r.passed())

    def test_contention_generator(self) -> None:
        r = generate_contention_test("sys-apps/coreutils")
        self.assertEqual(r.constraint_type, "contention")
        self.assertTrue(r.dry_run)

    def test_deterministic(self) -> None:
        r1 = generate_oom_test("sys-apps/coreutils")
        r2 = generate_oom_test("sys-apps/coreutils")
        self.assertEqual(r1.duration_s, r2.duration_s)


class TestDrySuite(unittest.TestCase):
    def test_run_dry_suite(self) -> None:
        suite = run_dry_suite(["sys-apps/coreutils", "dev-libs/json-c"])
        self.assertEqual(len(suite.results), 10)  # 5 tests per package
        self.assertTrue(suite.dry_run)

    def test_all_tests_pass(self) -> None:
        suite = run_dry_suite(["sys-apps/coreutils"])
        self.assertEqual(suite.passed_count, 5)
        self.assertEqual(suite.failed_count, 0)


class TestCLI(unittest.TestCase):
    def test_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(CONSTRAINT_SCRIPT),
                 "--mode", "dry-run",
                 "--package", "sys-apps/coreutils",
                 "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr[-300:]}")
            self.assertTrue(output.exists())
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], "v1")
            self.assertEqual(data["bead"], "bd-2icq.20")
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["total_tests"], 5)
            self.assertEqual(data["passed"], 5)

    def test_tier1_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, str(CONSTRAINT_SCRIPT),
                 "--mode", "dry-run",
                 "--output", str(output)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0)
            data = json.loads(output.read_text())
            self.assertEqual(data["total_tests"], 25)  # 5 tests x 5 packages


if __name__ == "__main__":
    unittest.main()
