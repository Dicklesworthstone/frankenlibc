#!/usr/bin/env python3
"""Gentoo validation regression detector (bd-2icq.12).

Compares current validation results against a known-good baseline to
identify regressions. Types: build failures, test failures, performance
regressions, and unexpected healing patterns.

Usage:
    python3 scripts/gentoo/check_regressions.py --baseline data/gentoo/baseline.json --current results/summary.json
    python3 scripts/gentoo/check_regressions.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_FILE = REPO_ROOT / "data" / "gentoo" / "baseline.json"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Regression:
    """A detected regression."""
    type: str
    package: str
    severity: str
    test: Optional[str] = None
    detail: str = ""
    baseline_value: Optional[str] = None
    current_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": self.type,
            "package": self.package,
            "severity": self.severity,
            "detail": self.detail,
        }
        if self.test:
            d["test"] = self.test
        if self.baseline_value is not None:
            d["baseline_value"] = self.baseline_value
        if self.current_value is not None:
            d["current_value"] = self.current_value
        return d


@dataclass
class PackageResult:
    """Simplified package result for comparison."""
    name: str
    build_status: str = "unknown"
    test_status: str = "unknown"
    overhead_percent: float = 0.0
    healing_actions: int = 0
    healing_types: Dict[str, int] = field(default_factory=dict)
    tests: Dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PackageResult:
        return cls(
            name=d.get("package", d.get("name", "")),
            build_status=d.get("build_status", "success" if not d.get("error") else "failed"),
            test_status=d.get("test_status", "unknown"),
            overhead_percent=d.get("build_overhead_percent", d.get("overhead_percent", 0.0)),
            healing_actions=d.get("healing_actions", 0),
            healing_types=d.get("healing_types", d.get("by_action", {})),
            tests={t["name"]: t.get("passed", False)
                   for t in d.get("tests", [])},
        )


@dataclass
class BaselineData:
    """Known-good baseline results."""
    timestamp: str = ""
    packages: Dict[str, PackageResult] = field(default_factory=dict)

    def get(self, name: str) -> Optional[PackageResult]:
        return self.packages.get(name)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> BaselineData:
        baseline = cls(timestamp=d.get("timestamp", ""))
        for pkg in d.get("packages", []):
            pr = PackageResult.from_dict(pkg)
            baseline.packages[pr.name] = pr
        return baseline

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "v1",
            "bead": "bd-2icq.12",
            "timestamp": self.timestamp or utc_now(),
            "packages": [
                {
                    "package": pr.name,
                    "build_status": pr.build_status,
                    "test_status": pr.test_status,
                    "overhead_percent": round(pr.overhead_percent, 2),
                    "healing_actions": pr.healing_actions,
                    "healing_types": dict(pr.healing_types),
                    "tests": [{"name": k, "passed": v} for k, v in pr.tests.items()],
                }
                for pr in self.packages.values()
            ],
        }


def check_regressions(
    baseline: BaselineData,
    current: List[PackageResult],
    overhead_warn_pct: float = 20.0,
    overhead_block_pct: float = 50.0,
) -> List[Regression]:
    """Identify regressions between baseline and current results."""
    regressions = []

    for pkg in current:
        baseline_pkg = baseline.get(pkg.name)
        if baseline_pkg is None:
            continue

        # Build regression
        if baseline_pkg.build_status == "success" and pkg.build_status == "failed":
            regressions.append(Regression(
                type="NEW_BUILD_FAILURE",
                package=pkg.name,
                severity="critical",
                detail=f"Package built successfully in baseline but fails now",
                baseline_value="success",
                current_value="failed",
            ))

        # Test regression
        for test_name, baseline_passed in baseline_pkg.tests.items():
            current_passed = pkg.tests.get(test_name)
            if baseline_passed and current_passed is not None and not current_passed:
                regressions.append(Regression(
                    type="NEW_TEST_FAILURE",
                    package=pkg.name,
                    severity="high",
                    test=test_name,
                    detail=f"Test passed in baseline but fails now",
                    baseline_value="passed",
                    current_value="failed",
                ))

        # Performance regression
        if baseline_pkg.overhead_percent > 0:
            delta = pkg.overhead_percent - baseline_pkg.overhead_percent
            if delta > overhead_block_pct:
                regressions.append(Regression(
                    type="PERFORMANCE_REGRESSION",
                    package=pkg.name,
                    severity="high",
                    detail=f"Overhead increased by {delta:.1f}% (>{overhead_block_pct}% threshold)",
                    baseline_value=f"{baseline_pkg.overhead_percent:.1f}%",
                    current_value=f"{pkg.overhead_percent:.1f}%",
                ))
            elif delta > overhead_warn_pct:
                regressions.append(Regression(
                    type="PERFORMANCE_REGRESSION",
                    package=pkg.name,
                    severity="medium",
                    detail=f"Overhead increased by {delta:.1f}% (>{overhead_warn_pct}% threshold)",
                    baseline_value=f"{baseline_pkg.overhead_percent:.1f}%",
                    current_value=f"{pkg.overhead_percent:.1f}%",
                ))

        # Unexpected healing patterns
        for action_type, count in pkg.healing_types.items():
            baseline_count = baseline_pkg.healing_types.get(action_type, 0)
            if baseline_count == 0 and count > 0:
                regressions.append(Regression(
                    type="NEW_HEALING_PATTERN",
                    package=pkg.name,
                    severity="low",
                    detail=f"New healing action type '{action_type}' ({count} occurrences)",
                    baseline_value="0",
                    current_value=str(count),
                ))

    return regressions


@dataclass
class RegressionReport:
    """Full regression analysis report."""
    timestamp: str = ""
    baseline_timestamp: str = ""
    total_packages: int = 0
    regressions: List[Regression] = field(default_factory=list)
    dry_run: bool = False

    @property
    def has_blockers(self) -> bool:
        return any(r.severity in ("critical", "high") for r in self.regressions)

    @property
    def by_severity(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for r in self.regressions:
            result[r.severity] = result.get(r.severity, 0) + 1
        return result

    @property
    def by_type(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for r in self.regressions:
            result[r.type] = result.get(r.type, 0) + 1
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "v1",
            "bead": "bd-2icq.12",
            "timestamp": self.timestamp or utc_now(),
            "baseline_timestamp": self.baseline_timestamp,
            "dry_run": self.dry_run,
            "total_packages": self.total_packages,
            "total_regressions": len(self.regressions),
            "has_blockers": self.has_blockers,
            "by_severity": self.by_severity,
            "by_type": self.by_type,
            "regressions": [r.to_dict() for r in self.regressions],
        }


def generate_dry_run_data() -> tuple[BaselineData, List[PackageResult]]:
    """Generate synthetic baseline and current data for testing."""
    import random
    random.seed(42)

    packages = ["sys-apps/coreutils", "dev-libs/json-c", "app-arch/gzip",
                "sys-apps/grep", "net-misc/curl"]

    baseline = BaselineData(timestamp="2026-02-12T00:00:00Z")
    current_results = []

    for pkg in packages:
        overhead = random.uniform(2, 8)
        healing = random.randint(0, 20)
        tests = {f"test_{i}": True for i in range(5)}

        baseline_pkg = PackageResult(
            name=pkg,
            build_status="success",
            test_status="passed",
            overhead_percent=overhead,
            healing_actions=healing,
            healing_types={"ClampSize": healing // 2, "TruncateWithNull": healing - healing // 2}
            if healing > 0 else {},
            tests=dict(tests),
        )
        baseline.packages[pkg] = baseline_pkg

        # Current: introduce some regressions in the last package
        current_overhead = overhead + random.uniform(-1, 2)
        current_tests = dict(tests)
        current_build = "success"
        current_healing = dict(baseline_pkg.healing_types)

        if pkg == "net-misc/curl":
            # Simulate a test regression
            current_tests["test_2"] = False
        if pkg == "app-arch/gzip":
            # Simulate a new healing pattern
            current_healing["NullifyReturn"] = 3

        current_results.append(PackageResult(
            name=pkg,
            build_status=current_build,
            test_status="passed" if all(current_tests.values()) else "partial",
            overhead_percent=current_overhead,
            healing_actions=sum(current_healing.values()),
            healing_types=current_healing,
            tests=current_tests,
        ))

    return baseline, current_results


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Regression detector")
    parser.add_argument("--baseline", type=Path, default=BASELINE_FILE)
    parser.add_argument("--current", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overhead-warn", type=float, default=20.0)
    parser.add_argument("--overhead-block", type=float, default=50.0)
    args = parser.parse_args(argv)

    if args.dry_run:
        baseline, current_results = generate_dry_run_data()
    else:
        if not args.baseline.exists():
            print(f"Baseline not found: {args.baseline}", file=sys.stderr)
            print("Run with --dry-run to test, or create baseline first.", file=sys.stderr)
            return 2
        baseline = BaselineData.from_dict(json.loads(args.baseline.read_text()))

        if args.current and args.current.exists():
            data = json.loads(args.current.read_text())
            current_results = [PackageResult.from_dict(p) for p in data.get("packages", [])]
        else:
            print(f"Current results not found: {args.current}", file=sys.stderr)
            return 2

    regressions = check_regressions(
        baseline, current_results,
        overhead_warn_pct=args.overhead_warn,
        overhead_block_pct=args.overhead_block,
    )

    report = RegressionReport(
        timestamp=utc_now(),
        baseline_timestamp=baseline.timestamp,
        total_packages=len(current_results),
        regressions=regressions,
        dry_run=args.dry_run,
    )

    output_path = args.output or (
        REPO_ROOT / "data" / "gentoo" / "regression_report.v1.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    print(f"Report written to {output_path}")

    print(f"\n=== Regression Detection Summary ===")
    print(f"Packages checked:    {report.total_packages}")
    print(f"Regressions found:   {len(report.regressions)}")
    if report.by_severity:
        print("By severity:")
        for sev, count in sorted(report.by_severity.items(),
                                  key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
            print(f"  {sev}: {count}")
    if report.by_type:
        print("By type:")
        for typ, count in sorted(report.by_type.items()):
            print(f"  {typ}: {count}")

    if report.has_blockers:
        print("\nBLOCKED: Critical/high regressions found. Fix before merging.")
        return 1
    elif report.regressions:
        print("\nWARN: Non-blocking regressions found. Review recommended.")
        return 0
    else:
        print("\nPASS: No regressions detected.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
