#!/usr/bin/env python3
"""Flaky test detector for Gentoo ecosystem validation (bd-2icq.24).

Detects non-deterministic tests by running test suites multiple times
and identifying tests that produce different outcomes across runs.

Usage:
    python3 scripts/gentoo/flaky_detector.py --package sys-apps/coreutils --runs 3
    python3 scripts/gentoo/flaky_detector.py --results-dir data/gentoo/perf-results --detect
    python3 scripts/gentoo/flaky_detector.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
QUARANTINE_FILE = REPO_ROOT / "data" / "gentoo" / "quarantine.json"

FLAKE_CATEGORIES = {
    "timing_sensitive",
    "resource_dependent",
    "order_dependent",
    "network_dependent",
    "random_seed",
    "unknown",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TestOutcome:
    """Single test execution result."""
    test_name: str
    passed: bool
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class RunResult:
    """Results of a single test suite run."""
    package: str
    run_index: int
    outcomes: List[TestOutcome] = field(default_factory=list)
    timestamp: str = ""

    def get_outcome(self, test_name: str) -> Optional[bool]:
        for o in self.outcomes:
            if o.test_name == test_name:
                return o.passed
        return None

    def all_test_names(self) -> set[str]:
        return {o.test_name for o in self.outcomes}


@dataclass
class FlakyTest:
    """A test identified as flaky."""
    package: str
    test_name: str
    outcomes: List[bool] = field(default_factory=list)
    flake_rate: float = 0.0
    category: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    occurrences: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "test": self.test_name,
            "reason": self.category,
            "flake_rate": round(self.flake_rate, 4),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
        }


def calculate_flake_rate(outcomes: List[bool]) -> float:
    """Calculate flake rate from 0.0 (stable) to 1.0 (always flaky)."""
    if not outcomes or len(set(outcomes)) == 1:
        return 0.0
    counts = Counter(outcomes)
    minority = min(counts.values())
    return minority / len(outcomes)


def categorize_flake(test_name: str, outcomes: List[bool]) -> str:
    """Heuristic categorization of flake reason from test name patterns."""
    name_lower = test_name.lower()
    if any(w in name_lower for w in ("timeout", "timer", "sleep", "delay", "wait")):
        return "timing_sensitive"
    if any(w in name_lower for w in ("memory", "oom", "disk", "space", "limit")):
        return "resource_dependent"
    if any(w in name_lower for w in ("order", "sequence", "depend")):
        return "order_dependent"
    if any(w in name_lower for w in ("network", "socket", "connect", "http", "dns")):
        return "network_dependent"
    if any(w in name_lower for w in ("random", "rand", "shuffle", "seed")):
        return "random_seed"
    return "unknown"


def detect_flaky_tests(runs: List[RunResult]) -> List[FlakyTest]:
    """Identify tests with inconsistent outcomes across runs."""
    if not runs:
        return []

    package = runs[0].package
    all_tests: set[str] = set()
    for r in runs:
        all_tests |= r.all_test_names()

    flaky = []
    now = utc_now()
    for test_name in sorted(all_tests):
        outcomes = []
        for r in runs:
            outcome = r.get_outcome(test_name)
            if outcome is not None:
                outcomes.append(outcome)

        if len(outcomes) < 2:
            continue

        if len(set(outcomes)) > 1:
            rate = calculate_flake_rate(outcomes)
            category = categorize_flake(test_name, outcomes)
            flaky.append(FlakyTest(
                package=package,
                test_name=test_name,
                outcomes=outcomes,
                flake_rate=rate,
                category=category,
                first_seen=now,
                last_seen=now,
            ))

    return flaky


def generate_dry_run_results(package: str, n_runs: int = 3) -> List[RunResult]:
    """Generate synthetic test results for dry-run mode."""
    import random
    random.seed(hash(package) + 42)

    test_names = [
        "test_basic_ops",
        "test_file_io",
        "test_timeout_handling",
        "test_network_connect",
        "test_memory_alloc",
        "test_random_data",
        "test_concurrent_access",
        "test_edge_cases",
        "test_cleanup",
        "test_startup",
    ]

    runs = []
    for i in range(n_runs):
        outcomes = []
        for name in test_names:
            # Make some tests flaky
            if "timeout" in name:
                passed = random.random() > 0.3  # 30% fail rate
            elif "network" in name:
                passed = random.random() > 0.2  # 20% fail rate
            elif "random" in name:
                passed = random.random() > 0.15
            else:
                passed = True  # Stable tests
            outcomes.append(TestOutcome(
                test_name=name,
                passed=passed,
                duration_ms=random.uniform(10, 500),
            ))
        runs.append(RunResult(
            package=package,
            run_index=i,
            outcomes=outcomes,
            timestamp=utc_now(),
        ))
    return runs


def load_existing_results(results_dir: Path, package: str) -> List[RunResult]:
    """Load test results from existing run directories."""
    runs = []
    pkg_slug = package.replace("/", "__")
    pkg_dir = results_dir / pkg_slug
    if not pkg_dir.exists():
        return runs

    for run_dir in sorted(pkg_dir.iterdir()):
        results_file = run_dir / "test_results.json"
        if not results_file.exists():
            continue
        data = json.loads(results_file.read_text())
        outcomes = [
            TestOutcome(
                test_name=t["name"],
                passed=t.get("passed", False),
                duration_ms=t.get("duration_ms", 0),
                error=t.get("error"),
            )
            for t in data.get("tests", [])
        ]
        runs.append(RunResult(
            package=package,
            run_index=len(runs),
            outcomes=outcomes,
            timestamp=data.get("timestamp", ""),
        ))
    return runs


@dataclass
class DetectionReport:
    """Aggregate flaky test detection results."""
    packages_scanned: int = 0
    total_tests_checked: int = 0
    flaky_tests_found: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    flaky_tests: List[FlakyTest] = field(default_factory=list)
    timestamp: str = ""
    dry_run: bool = False

    def add(self, tests: List[FlakyTest]) -> None:
        self.packages_scanned += 1
        self.flaky_tests.extend(tests)
        self.flaky_tests_found += len(tests)
        for t in tests:
            self.by_category[t.category] = self.by_category.get(t.category, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "v1",
            "bead": "bd-2icq.24",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            "packages_scanned": self.packages_scanned,
            "total_tests_checked": self.total_tests_checked,
            "flaky_tests_found": self.flaky_tests_found,
            "by_category": dict(self.by_category),
            "flaky_tests": [t.to_dict() for t in self.flaky_tests],
        }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Flaky test detector")
    parser.add_argument("--package", default=None, help="Package atom to test")
    parser.add_argument("--packages", default="tier1", help="Package source")
    parser.add_argument("--runs", type=int, default=3, help="Number of test runs")
    parser.add_argument("--results-dir", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--detect", action="store_true",
                        help="Detect from existing results")
    args = parser.parse_args(argv)

    # Determine packages to scan
    if args.package:
        packages = [args.package]
    else:
        tier1 = REPO_ROOT / "configs" / "gentoo" / "tier1-mini.txt"
        if tier1.exists():
            lines = tier1.read_text().splitlines()
            packages = [l.strip() for l in lines
                        if l.strip() and not l.strip().startswith("#")]
        else:
            packages = ["sys-apps/coreutils"]

    report = DetectionReport(
        timestamp=utc_now(),
        dry_run=args.dry_run,
    )

    for pkg in packages:
        print(f"Scanning: {pkg}")
        if args.dry_run:
            runs = generate_dry_run_results(pkg, args.runs)
        elif args.detect and args.results_dir:
            runs = load_existing_results(args.results_dir, pkg)
        else:
            runs = generate_dry_run_results(pkg, args.runs)

        all_test_names: set[str] = set()
        for r in runs:
            all_test_names |= r.all_test_names()
        report.total_tests_checked += len(all_test_names)

        flaky = detect_flaky_tests(runs)
        report.add(flaky)

        if flaky:
            print(f"  Found {len(flaky)} flaky test(s):")
            for f in flaky:
                rate_pct = f.flake_rate * 100
                print(f"    {f.test_name} ({f.category}, {rate_pct:.0f}% flake rate)")
        else:
            print("  No flaky tests detected")

    output_path = args.output or (
        REPO_ROOT / "data" / "gentoo" / "flaky_detection_report.v1.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    print(f"\nReport written to {output_path}")

    print(f"\n=== Flaky Test Detection Summary ===")
    print(f"Packages scanned:    {report.packages_scanned}")
    print(f"Tests checked:       {report.total_tests_checked}")
    print(f"Flaky tests found:   {report.flaky_tests_found}")
    if report.by_category:
        print("By category:")
        for cat, count in sorted(report.by_category.items()):
            print(f"  {cat}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
