#!/usr/bin/env python3
"""Unit tests for E2E retry/flake policy helper (bd-b5a.3)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "scripts" / "e2e_flake_policy.py"

spec = importlib.util.spec_from_file_location("e2e_flake_policy", str(POLICY_PATH))
policy = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["e2e_flake_policy"] = policy
assert spec.loader is not None
spec.loader.exec_module(policy)  # type: ignore[union-attr]


class TestFlakeClassifier(unittest.TestCase):
    def test_all_pass_not_flaky(self) -> None:
        result = policy.classify_attempts([0, 0, 0], quarantine_threshold=0.34)
        self.assertEqual(result["retry_count"], 2)
        self.assertEqual(result["flake_score"], 0.0)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["is_flaky"], 0)

    def test_fail_then_pass_is_flaky(self) -> None:
        result = policy.classify_attempts([124, 0], quarantine_threshold=0.75)
        self.assertEqual(result["retry_count"], 1)
        self.assertAlmostEqual(result["flake_score"], 0.5, places=6)
        self.assertEqual(result["verdict"], "pass_with_retry")
        self.assertEqual(result["is_flaky"], 1)
        self.assertEqual(result["should_quarantine"], 0)

    def test_quarantined_flake_when_threshold_breached(self) -> None:
        result = policy.classify_attempts([1, 0], quarantine_threshold=0.4)
        self.assertEqual(result["verdict"], "quarantined_flake")
        self.assertEqual(result["should_quarantine"], 1)

    def test_consistent_failure_is_not_flaky(self) -> None:
        result = policy.classify_attempts([1, 1], quarantine_threshold=0.2)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["flake_score"], 0.0)
        self.assertEqual(result["is_flaky"], 0)


class TestRetryPolicy(unittest.TestCase):
    def test_retry_on_nonzero_enabled(self) -> None:
        should = policy.should_retry(
            exit_code=2,
            attempt_index=0,
            max_retries=2,
            retry_on_any_nonzero=True,
            retryable_codes={124, 125},
        )
        self.assertTrue(should)

    def test_retry_on_nonzero_disabled_respects_allowlist(self) -> None:
        should = policy.should_retry(
            exit_code=2,
            attempt_index=0,
            max_retries=2,
            retry_on_any_nonzero=False,
            retryable_codes={124, 125},
        )
        self.assertFalse(should)

    def test_retry_stops_at_max(self) -> None:
        should = policy.should_retry(
            exit_code=124,
            attempt_index=2,
            max_retries=2,
            retry_on_any_nonzero=True,
            retryable_codes={124, 125},
        )
        self.assertFalse(should)


class TestCliContract(unittest.TestCase):
    def test_classify_json_output(self) -> None:
        out = subprocess.check_output(
            [
                "python3",
                str(POLICY_PATH),
                "classify",
                "--exit-codes",
                "124,0",
                "--quarantine-threshold",
                "0.6",
                "--format",
                "json",
            ],
            text=True,
        )
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "pass_with_retry")
        self.assertEqual(payload["retry_count"], 1)

    def test_should_retry_cli(self) -> None:
        out = subprocess.check_output(
            [
                "python3",
                str(POLICY_PATH),
                "should-retry",
                "--exit-code",
                "124",
                "--attempt-index",
                "0",
                "--max-retries",
                "1",
                "--retry-on-any-nonzero",
                "0",
                "--retryable-codes",
                "124,125",
            ],
            text=True,
        ).strip()
        self.assertEqual(out, "1")


if __name__ == "__main__":
    unittest.main()
