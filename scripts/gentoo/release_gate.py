#!/usr/bin/env python3
"""Release qualification gate for Gentoo ecosystem validation (bd-2icq.17).

Checks validation results against tiered release gate thresholds.
Three gate levels: tier1 (all releases), top20 (minor), top100 (major).

Usage:
    python3 scripts/gentoo/release_gate.py --dry-run
    python3 scripts/gentoo/release_gate.py --level tier1 --data-dir data/gentoo
    python3 scripts/gentoo/release_gate.py --level all --output release-report.json
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
CONFIGS_DIR = REPO_ROOT / "configs" / "gentoo"
DATA_DIR = REPO_ROOT / "data" / "gentoo"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class GateThresholds:
    """Thresholds for a single release gate level."""
    build_success_rate_pct: float = 100.0
    test_pass_rate_pct: float = 95.0
    max_new_regressions: int = 0
    max_overhead_pct: float = 15.0

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> GateThresholds:
        return cls(
            build_success_rate_pct=d.get("build_success_rate_pct", 100.0),
            test_pass_rate_pct=d.get("test_pass_rate_pct", 95.0),
            max_new_regressions=d.get("max_new_regressions", 0),
            max_overhead_pct=d.get("max_overhead_pct", 15.0),
        )


@dataclass
class GateConfig:
    """Configuration for a release gate level."""
    name: str
    level: str
    required_for: str
    package_count: int
    thresholds: GateThresholds

    @classmethod
    def from_dict(cls, level: str, d: Dict[str, Any]) -> GateConfig:
        return cls(
            name=d.get("name", level),
            level=level,
            required_for=d.get("required_for", "unknown"),
            package_count=d.get("package_count", 0),
            thresholds=GateThresholds.from_dict(d.get("thresholds", {})),
        )


@dataclass
class ValidationResults:
    """Validation results to check against a gate."""
    build_total: int = 0
    build_success: int = 0
    test_total: int = 0
    test_pass: int = 0
    new_regressions: int = 0
    avg_overhead_pct: float = 0.0
    packages: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def build_success_rate(self) -> float:
        if self.build_total == 0:
            return 0.0
        return round(self.build_success / self.build_total * 100, 1)

    @property
    def test_pass_rate(self) -> float:
        if self.test_total == 0:
            return 0.0
        return round(self.test_pass / self.test_total * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "build_total": self.build_total,
            "build_success": self.build_success,
            "build_success_rate_pct": self.build_success_rate,
            "test_total": self.test_total,
            "test_pass": self.test_pass,
            "test_pass_rate_pct": self.test_pass_rate,
            "new_regressions": self.new_regressions,
            "avg_overhead_pct": round(self.avg_overhead_pct, 1),
        }


@dataclass
class GateIssue:
    """A specific gate check failure."""
    check: str
    actual: float
    threshold: float
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "actual": self.actual,
            "threshold": self.threshold,
            "message": self.message,
        }


@dataclass
class GateResult:
    """Result of checking validation results against a gate."""
    gate_name: str
    gate_level: str
    passed: bool
    issues: List[GateIssue] = field(default_factory=list)
    results: Optional[ValidationResults] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "gate_name": self.gate_name,
            "gate_level": self.gate_level,
            "passed": self.passed,
            "issue_count": len(self.issues),
            "issues": [i.to_dict() for i in self.issues],
        }
        if self.results:
            d["results"] = self.results.to_dict()
        return d


def check_release_gate(results: ValidationResults, config: GateConfig) -> GateResult:
    """Check if validation results meet release gate criteria."""
    issues: List[GateIssue] = []
    thresh = config.thresholds

    # Build success rate
    build_rate = results.build_success_rate
    if build_rate < thresh.build_success_rate_pct:
        issues.append(GateIssue(
            check="build_success_rate",
            actual=build_rate,
            threshold=thresh.build_success_rate_pct,
            message=f"Build rate {build_rate:.1f}% < required {thresh.build_success_rate_pct}%",
        ))

    # Test pass rate
    test_rate = results.test_pass_rate
    if test_rate < thresh.test_pass_rate_pct:
        issues.append(GateIssue(
            check="test_pass_rate",
            actual=test_rate,
            threshold=thresh.test_pass_rate_pct,
            message=f"Test rate {test_rate:.1f}% < required {thresh.test_pass_rate_pct}%",
        ))

    # New regressions
    if results.new_regressions > thresh.max_new_regressions:
        issues.append(GateIssue(
            check="new_regressions",
            actual=float(results.new_regressions),
            threshold=float(thresh.max_new_regressions),
            message=f"New regressions {results.new_regressions} > max {thresh.max_new_regressions}",
        ))

    # Performance overhead
    if results.avg_overhead_pct > thresh.max_overhead_pct:
        issues.append(GateIssue(
            check="overhead",
            actual=results.avg_overhead_pct,
            threshold=thresh.max_overhead_pct,
            message=f"Overhead {results.avg_overhead_pct:.1f}% > max {thresh.max_overhead_pct}%",
        ))

    return GateResult(
        gate_name=config.name,
        gate_level=config.level,
        passed=len(issues) == 0,
        issues=issues,
        results=results,
    )


def load_gate_configs(config_path: Optional[Path] = None) -> Dict[str, GateConfig]:
    """Load gate configurations from JSON."""
    path = config_path or (CONFIGS_DIR / "release-gates.json")
    if not path.exists():
        return {
            "tier1": GateConfig.from_dict("tier1", {
                "name": "Tier 1 Core Infrastructure",
                "required_for": "all releases",
                "package_count": 20,
                "thresholds": {},
            }),
        }
    data = json.loads(path.read_text())
    gates = data.get("gates", {})
    return {level: GateConfig.from_dict(level, cfg) for level, cfg in gates.items()}


def load_validation_results(data_dir: Path, level: str) -> ValidationResults:
    """Load validation results from data directory for a given level."""
    # Try fast-validate summary first
    fast_dir = REPO_ROOT / "artifacts" / "gentoo-builds" / "fast-validate"
    if fast_dir.exists():
        runs = sorted(fast_dir.iterdir(), reverse=True)
        if runs:
            summary = runs[0] / "summary.json"
            if summary.exists():
                data = json.loads(summary.read_text())
                return ValidationResults(
                    build_total=data.get("total_packages", 0),
                    build_success=data.get("passed", 0),
                    test_total=data.get("total_packages", 0),
                    test_pass=data.get("passed", 0),
                    new_regressions=0,
                    avg_overhead_pct=data.get("avg_overhead_percent", 0),
                )

    # Try perf benchmark results
    perf_path = data_dir / "perf-results" / "perf_benchmark_results.v1.json"
    if perf_path.exists():
        data = json.loads(perf_path.read_text())
        return ValidationResults(
            build_total=data.get("total_packages", 0),
            build_success=data.get("successful", 0),
            test_total=data.get("total_packages", 0),
            test_pass=data.get("successful", 0),
            new_regressions=data.get("failed", 0),
            avg_overhead_pct=data.get("avg_build_overhead_percent", 0),
        )

    # Regression report for new regressions count
    reg_path = data_dir / "regression_report.v1.json"
    new_regressions = 0
    if reg_path.exists():
        reg = json.loads(reg_path.read_text())
        new_regressions = reg.get("total_regressions", 0)

    return ValidationResults(new_regressions=new_regressions)


def generate_dry_run_results(level: str) -> ValidationResults:
    """Generate synthetic results for dry-run testing."""
    import random
    random.seed(17)

    configs = {
        "tier1": (20, 100.0, 97.0, 0, 4.2),
        "top20": (20, 95.0, 92.0, 1, 5.1),
        "top100": (100, 92.0, 88.0, 3, 6.8),
    }
    pkg_count, build_rate, test_rate, regressions, overhead = configs.get(
        level, (20, 100.0, 97.0, 0, 4.2)
    )

    build_success = int(pkg_count * build_rate / 100)
    test_pass = int(pkg_count * test_rate / 100)

    packages = []
    for i in range(pkg_count):
        status = "success" if i < build_success else "failed"
        packages.append({
            "name": f"category-{i // 20}/pkg-{i}",
            "build_status": status,
            "test_status": "pass" if i < test_pass else "fail",
            "overhead_pct": round(random.uniform(1, 12), 1),
        })

    return ValidationResults(
        build_total=pkg_count,
        build_success=build_success,
        test_total=pkg_count,
        test_pass=test_pass,
        new_regressions=regressions,
        avg_overhead_pct=overhead,
        packages=packages,
    )


@dataclass
class ReleaseReport:
    """Complete release qualification report."""
    gates: List[GateResult] = field(default_factory=list)
    timestamp: str = ""
    dry_run: bool = False
    release_blocked: bool = False
    blocking_gates: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "v1",
            "bead": "bd-2icq.17",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            "release_blocked": self.release_blocked,
            "blocking_gates": self.blocking_gates,
            "gate_count": len(self.gates),
            "gates_passed": sum(1 for g in self.gates if g.passed),
            "gates_failed": sum(1 for g in self.gates if not g.passed),
            "gates": [g.to_dict() for g in self.gates],
        }

    def to_markdown(self) -> str:
        status = "BLOCKED" if self.release_blocked else "PASS"
        lines = [
            "# FrankenLibC Release Qualification Report",
            "",
            f"**Status:** {status}",
            f"**Updated:** {self.timestamp or utc_now()}",
            f"**Dry run:** {self.dry_run}",
            "",
        ]

        if self.release_blocked:
            lines.append("## Blocking Gates")
            lines.append("")
            for gate_name in self.blocking_gates:
                lines.append(f"- {gate_name}")
            lines.append("")

        for gate in self.gates:
            icon = "PASS" if gate.passed else "FAIL"
            lines.append(f"## {icon} {gate.gate_name} ({gate.gate_level})")
            lines.append("")
            if gate.results:
                r = gate.results
                lines.extend([
                    f"- Build: {r.build_success}/{r.build_total} ({r.build_success_rate:.1f}%)",
                    f"- Tests: {r.test_pass}/{r.test_total} ({r.test_pass_rate:.1f}%)",
                    f"- Regressions: {r.new_regressions}",
                    f"- Overhead: {r.avg_overhead_pct:.1f}%",
                    "",
                ])
            if gate.issues:
                lines.append("### Issues")
                for issue in gate.issues:
                    lines.append(f"- {issue.message}")
                lines.append("")

        return "\n".join(lines)


def run_gate_check(
    levels: List[str],
    data_dir: Path,
    dry_run: bool = False,
    config_path: Optional[Path] = None,
) -> ReleaseReport:
    """Run release gate checks for specified levels."""
    gate_configs = load_gate_configs(config_path)
    report = ReleaseReport(timestamp=utc_now(), dry_run=dry_run)

    for level in levels:
        config = gate_configs.get(level)
        if not config:
            continue

        if dry_run:
            results = generate_dry_run_results(level)
        else:
            results = load_validation_results(data_dir, level)

        gate_result = check_release_gate(results, config)
        report.gates.append(gate_result)

        if not gate_result.passed:
            report.release_blocked = True
            report.blocking_gates.append(f"{gate_result.gate_name} ({level})")

    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Release qualification gate")
    parser.add_argument("--level", default="all",
                        choices=["tier1", "top20", "top100", "all"])
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--format", choices=["json", "markdown", "both", "terminal"],
                        default="terminal")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.level == "all":
        levels = ["tier1", "top20", "top100"]
    else:
        levels = [args.level]

    report = run_gate_check(levels, args.data_dir, dry_run=args.dry_run,
                            config_path=args.config)

    # Terminal output
    if args.format in ("terminal", "both"):
        print(report.to_markdown())

    # JSON output
    if args.format in ("json", "both") or args.output:
        json_path = args.output or (args.data_dir / "release_gate_report.v1.json")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        print(f"\nJSON report written to {json_path}")

    # Markdown output
    if args.format == "both" and args.output:
        md_path = args.output.with_suffix(".md")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(report.to_markdown())

    # Summary
    print(f"\n=== Release Gate Summary ===")
    status = "BLOCKED" if report.release_blocked else "PASS"
    print(f"Overall: {status}")
    for g in report.gates:
        icon = "+" if g.passed else "!"
        print(f"  [{icon}] {g.gate_name}: {'PASS' if g.passed else 'FAIL'}")
        for issue in g.issues:
            print(f"      - {issue.message}")

    return 1 if report.release_blocked else 0


if __name__ == "__main__":
    sys.exit(main())
