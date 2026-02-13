#!/usr/bin/env python3
"""Tests for Tier 1 fast validation infrastructure (bd-2icq.18).

Validates:
- tier1-mini.txt package list integrity
- fast-validate.sh script correctness
- Exclusion policy compliance
- Dry-run mode produces valid summary artifacts
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TIER1_FILE = REPO_ROOT / "configs" / "gentoo" / "tier1-mini.txt"
EXCLUSIONS_FILE = REPO_ROOT / "configs" / "gentoo" / "exclusions.json"
TOP100_FILE = REPO_ROOT / "configs" / "gentoo" / "top100-packages.txt"
FAST_VALIDATE_SCRIPT = REPO_ROOT / "scripts" / "gentoo" / "fast-validate.sh"


def load_tier1_packages() -> list[str]:
    """Load non-comment, non-blank lines from tier1-mini.txt."""
    lines = TIER1_FILE.read_text().splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


def load_exclusions() -> set[str]:
    """Load excluded package set from exclusions.json."""
    if not EXCLUSIONS_FILE.exists():
        return set()
    data = json.loads(EXCLUSIONS_FILE.read_text())
    return {e["package"] for e in data.get("exclusions", [])}


def load_top100_packages() -> set[str]:
    """Load all packages from top100-packages.txt."""
    if not TOP100_FILE.exists():
        return set()
    lines = TOP100_FILE.read_text().splitlines()
    return {
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    }


class TestTier1MiniPackageList(unittest.TestCase):
    """Validate the tier1-mini.txt package selection."""

    def test_tier1_file_exists(self) -> None:
        self.assertTrue(
            TIER1_FILE.exists(),
            f"tier1-mini.txt not found at {TIER1_FILE}",
        )

    def test_exactly_five_packages(self) -> None:
        packages = load_tier1_packages()
        self.assertEqual(
            len(packages),
            5,
            f"Expected 5 packages, got {len(packages)}: {packages}",
        )

    def test_packages_are_valid_atoms(self) -> None:
        """Each package should be in category/name format."""
        packages = load_tier1_packages()
        for pkg in packages:
            parts = pkg.split("/")
            self.assertEqual(
                len(parts),
                2,
                f"Package '{pkg}' is not a valid Gentoo atom (category/name)",
            )
            self.assertTrue(
                len(parts[0]) > 0 and len(parts[1]) > 0,
                f"Package '{pkg}' has empty category or name",
            )

    def test_no_excluded_packages(self) -> None:
        """No tier1-mini package should be in the exclusion list."""
        packages = load_tier1_packages()
        excluded = load_exclusions()
        overlap = set(packages) & excluded
        self.assertEqual(
            len(overlap),
            0,
            f"Tier 1 packages overlap with exclusion list: {overlap}",
        )

    def test_all_packages_in_top100(self) -> None:
        """Every tier1-mini package should be in the top100 list."""
        packages = load_tier1_packages()
        top100 = load_top100_packages()
        if not top100:
            self.skipTest("top100-packages.txt not found")
        missing = set(packages) - top100
        self.assertEqual(
            len(missing),
            0,
            f"Tier 1 packages not in top100: {missing}",
        )

    def test_no_duplicates(self) -> None:
        packages = load_tier1_packages()
        self.assertEqual(
            len(packages),
            len(set(packages)),
            f"Duplicate packages found: {packages}",
        )

    def test_expected_packages_present(self) -> None:
        """Verify the specific 5 packages from the bead spec."""
        packages = set(load_tier1_packages())
        expected = {
            "sys-apps/coreutils",
            "dev-libs/json-c",
            "app-arch/gzip",
            "sys-apps/grep",
            "net-misc/curl",
        }
        self.assertEqual(
            packages,
            expected,
            f"Package mismatch. Expected: {expected}, Got: {packages}",
        )


class TestFastValidateScript(unittest.TestCase):
    """Validate the fast-validate.sh script structure and behavior."""

    def test_script_exists(self) -> None:
        self.assertTrue(
            FAST_VALIDATE_SCRIPT.exists(),
            f"fast-validate.sh not found at {FAST_VALIDATE_SCRIPT}",
        )

    def test_script_is_executable(self) -> None:
        self.assertTrue(
            os.access(FAST_VALIDATE_SCRIPT, os.X_OK),
            "fast-validate.sh is not executable",
        )

    def test_script_has_bash_shebang(self) -> None:
        first_line = FAST_VALIDATE_SCRIPT.read_text().splitlines()[0]
        self.assertIn(
            "bash",
            first_line,
            f"Expected bash shebang, got: {first_line}",
        )

    def test_script_references_tier1_mini(self) -> None:
        content = FAST_VALIDATE_SCRIPT.read_text()
        self.assertIn(
            "tier1-mini.txt",
            content,
            "Script should reference tier1-mini.txt",
        )

    def test_script_supports_dry_run(self) -> None:
        content = FAST_VALIDATE_SCRIPT.read_text()
        self.assertIn(
            "--dry-run",
            content,
            "Script should support --dry-run flag",
        )

    def test_script_supports_local_mode(self) -> None:
        content = FAST_VALIDATE_SCRIPT.read_text()
        self.assertIn(
            "--local",
            content,
            "Script should support --local flag",
        )

    def test_script_supports_fail_fast(self) -> None:
        content = FAST_VALIDATE_SCRIPT.read_text()
        self.assertIn(
            "fail-fast",
            content.lower().replace("_", "-"),
            "Script should support fail-fast behavior",
        )

    def test_bash_syntax_valid(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(FAST_VALIDATE_SCRIPT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"Bash syntax error: {result.stderr}",
        )

    def test_help_flag_exits_zero(self) -> None:
        result = subprocess.run(
            ["bash", str(FAST_VALIDATE_SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"--help should exit 0, got {result.returncode}: {result.stderr}",
        )


class TestDryRunExecution(unittest.TestCase):
    """Run fast-validate.sh --dry-run and validate its output."""

    def test_dry_run_produces_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            # Override artifact output to temp dir
            env["FRANKENLIBC_MODE"] = "hardened"
            result = subprocess.run(
                ["bash", str(FAST_VALIDATE_SCRIPT), "--dry-run"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(REPO_ROOT),
                env=env,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"Dry-run failed (rc={result.returncode}):\nstdout: {result.stdout[-500:]}\nstderr: {result.stderr[-500:]}",
            )
            # Verify "PASSED" appears in output
            combined = result.stdout + result.stderr
            self.assertIn(
                "PASS",
                combined,
                f"Expected PASS in dry-run output, got:\n{combined[-500:]}",
            )

    def test_dry_run_creates_per_package_results(self) -> None:
        result = subprocess.run(
            ["bash", str(FAST_VALIDATE_SCRIPT), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(result.returncode, 0, f"Dry-run failed: {result.stderr[-300:]}")

        # Find the most recent fast-validate results dir
        fast_dir = REPO_ROOT / "artifacts" / "gentoo-builds" / "fast-validate"
        if not fast_dir.exists():
            self.skipTest("No fast-validate artifacts directory created")

        runs = sorted(fast_dir.iterdir(), reverse=True)
        self.assertTrue(len(runs) > 0, "No dry-run result directories found")

        latest = runs[0]
        summary = latest / "summary.json"
        self.assertTrue(summary.exists(), f"summary.json not found in {latest}")

        data = json.loads(summary.read_text())
        self.assertEqual(data["total_packages"], 5)
        self.assertEqual(data["passed"], 5)
        self.assertEqual(data["failed"], 0)
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["bead"], "bd-2icq.18")

        # Verify per-package result files
        pkg_dir = latest / "packages"
        self.assertTrue(pkg_dir.exists(), "packages/ subdirectory not found")
        pkg_results = list(pkg_dir.glob("*/fast_validate_result.json"))
        self.assertEqual(
            len(pkg_results),
            5,
            f"Expected 5 per-package results, found {len(pkg_results)}",
        )


if __name__ == "__main__":
    unittest.main()
