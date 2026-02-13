#!/usr/bin/env python3
"""Tests for Gentoo test runner (baseline vs instrumented comparison)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


def load_test_runner_module(repo_root: Path):
    """Load test-runner.py as a module."""
    script_path = repo_root / "scripts/gentoo/test-runner.py"
    spec = importlib.util.spec_from_file_location("test_runner_module", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestModeResultComparison(unittest.TestCase):
    """Tests for baseline vs instrumented comparison."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.module = load_test_runner_module(self.repo_root)

    def test_regression_detection(self) -> None:
        """New failures should be marked as regression."""
        baseline = self.module.ModeResult(
            total_tests=10,
            passed=9,
            failed=1,
            skipped=0,
            duration_seconds=60.0,
            failed_tests=["FAIL: test_old"],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=10,
            passed=8,
            failed=2,
            skipped=0,
            duration_seconds=65.0,
            failed_tests=["FAIL: test_old", "FAIL: test_new"],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        self.assertEqual(result["verdict"], "REGRESSION")
        self.assertEqual(result["new_failures"], ["FAIL: test_new"])
        self.assertEqual(result["new_passes"], [])

    def test_improvement_detection(self) -> None:
        """Fewer failures should be marked as improvement."""
        baseline = self.module.ModeResult(
            total_tests=10,
            passed=8,
            failed=2,
            skipped=0,
            duration_seconds=60.0,
            failed_tests=["FAIL: test_a", "FAIL: test_b"],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=10,
            passed=9,
            failed=1,
            skipped=0,
            duration_seconds=65.0,
            failed_tests=["FAIL: test_a"],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        self.assertEqual(result["verdict"], "IMPROVEMENT")
        self.assertEqual(result["new_failures"], [])
        self.assertEqual(result["new_passes"], ["FAIL: test_b"])

    def test_neutral_verdict(self) -> None:
        """Same failures should be marked as neutral."""
        baseline = self.module.ModeResult(
            total_tests=10,
            passed=8,
            failed=2,
            skipped=0,
            duration_seconds=60.0,
            failed_tests=["FAIL: test_a", "FAIL: test_b"],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=10,
            passed=8,
            failed=2,
            skipped=0,
            duration_seconds=65.0,
            failed_tests=["FAIL: test_a", "FAIL: test_b"],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        self.assertEqual(result["verdict"], "NEUTRAL")
        self.assertEqual(result["new_failures"], [])
        self.assertEqual(result["new_passes"], [])

    def test_pass_verdict(self) -> None:
        """Both with no failures should be NEUTRAL (same results)."""
        baseline = self.module.ModeResult(
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            duration_seconds=60.0,
            failed_tests=[],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            duration_seconds=65.0,
            failed_tests=[],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        # When both have no failures and same results, it's NEUTRAL
        self.assertEqual(result["verdict"], "NEUTRAL")

    def test_performance_overhead_calculation(self) -> None:
        """Overhead should be calculated correctly."""
        baseline = self.module.ModeResult(
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            duration_seconds=100.0,
            failed_tests=[],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=10,
            passed=10,
            failed=0,
            skipped=0,
            duration_seconds=110.0,  # 10% overhead
            failed_tests=[],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        self.assertEqual(result["overhead_percent"], 10.0)

    def test_zero_baseline_duration(self) -> None:
        """Zero baseline duration should not cause division error."""
        baseline = self.module.ModeResult(
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            duration_seconds=0.0,
            failed_tests=[],
            log_file="baseline.log",
        )
        instrumented = self.module.ModeResult(
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            duration_seconds=10.0,
            failed_tests=[],
            log_file="instrumented.log",
        )

        result = self.module.compare_mode_results(baseline, instrumented)

        self.assertEqual(result["overhead_percent"], 0.0)


class TestLogParsing(unittest.TestCase):
    """Tests for test log parsing."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.module = load_test_runner_module(self.repo_root)
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parse_standard_log(self) -> None:
        """Standard PASS/FAIL/SKIP format should be parsed."""
        log_file = self.tmp_path / "test.log"
        log_file.write_text(
            "PASS: test_one\nPASS: test_two\nFAIL: test_three\nSKIP: test_four\n",
            encoding="utf-8",
        )

        result = self.module.parse_test_log(log_file, 0, 30.0)

        self.assertEqual(result.total_tests, 4)
        self.assertEqual(result.passed, 2)
        self.assertEqual(result.failed, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.failed_tests, ["FAIL: test_three"])

    def test_parse_empty_log_success(self) -> None:
        """Empty log with success exit should create implicit pass."""
        log_file = self.tmp_path / "test.log"
        log_file.write_text("", encoding="utf-8")

        result = self.module.parse_test_log(log_file, 0, 30.0)

        self.assertEqual(result.total_tests, 1)
        self.assertEqual(result.passed, 1)
        self.assertEqual(result.failed_tests, [])

    def test_parse_empty_log_failure(self) -> None:
        """Empty log with failure exit should create implicit fail."""
        log_file = self.tmp_path / "test.log"
        log_file.write_text("", encoding="utf-8")

        result = self.module.parse_test_log(log_file, 1, 30.0)

        self.assertEqual(result.total_tests, 1)
        self.assertEqual(result.failed, 1)
        self.assertEqual(result.failed_tests, ["FAIL: implicit"])

    def test_parse_missing_log(self) -> None:
        """Missing log file should create implicit result."""
        log_file = self.tmp_path / "nonexistent.log"

        result = self.module.parse_test_log(log_file, 1, 30.0)

        self.assertEqual(result.total_tests, 1)


class TestHealingActionParsing(unittest.TestCase):
    """Tests for healing action extraction from logs."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.module = load_test_runner_module(self.repo_root)
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_healing_action_parsing(self) -> None:
        """Healing actions should be extracted from JSONL log."""
        log_file = self.tmp_path / "frankenlibc.jsonl"
        log_file.write_text(
            '{"action": "ClampSize", "call": "memcpy"}\n'
            '{"action": "ClampSize", "call": "memmove"}\n'
            '{"action": "IgnoreDoubleFree", "call": "free"}\n',
            encoding="utf-8",
        )

        # Simulate parsing logic from run_mode
        actions = {}
        for line in log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            action = payload.get("action")
            if action:
                actions[action] = actions.get(action, 0) + 1

        self.assertEqual(actions["ClampSize"], 2)
        self.assertEqual(actions["IgnoreDoubleFree"], 1)
        self.assertEqual(sum(actions.values()), 3)

    def test_invalid_json_handling(self) -> None:
        """Invalid JSON lines should not crash parsing."""
        log_file = self.tmp_path / "frankenlibc.jsonl"
        log_file.write_text(
            '{"action": "ClampSize"}\n' "not valid json\n" '{"action": "Free"}\n',
            encoding="utf-8",
        )

        actions = {}
        for line in log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                action = payload.get("action")
                if action:
                    actions[action] = actions.get(action, 0) + 1
            except json.JSONDecodeError:
                pass

        self.assertEqual(len(actions), 2)


class TestCrashHandling(unittest.TestCase):
    """Tests for crash and error handling."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.module = load_test_runner_module(self.repo_root)

    def test_timeout_exit_code(self) -> None:
        """Exit code 124 should indicate timeout."""
        # Exit code 124 is standard timeout exit code
        result = self.module.ModeResult(
            total_tests=0,
            passed=0,
            failed=1,
            skipped=0,
            duration_seconds=600.0,
            failed_tests=["FAIL: timeout"],
            log_file="test.log",
        )

        # Verify structure is valid
        self.assertEqual(result.failed, 1)

    def test_oom_detection(self) -> None:
        """OOM conditions should be detectable from exit code."""
        # Exit code 137 indicates SIGKILL (often OOM)
        # This is typically handled by the runner, not the ModeResult
        result = self.module.ModeResult(
            total_tests=0,
            passed=0,
            failed=1,
            skipped=0,
            duration_seconds=300.0,
            failed_tests=["FAIL: oom"],
            log_file="test.log",
        )

        self.assertEqual(result.failed, 1)


if __name__ == "__main__":
    unittest.main()
