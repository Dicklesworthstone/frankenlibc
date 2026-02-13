#!/usr/bin/env python3
"""Validation dashboard data aggregator (bd-2icq.11).

Aggregates data from all Gentoo validation artifacts into a unified
dashboard report in JSON and markdown formats.

Sources: perf benchmarks, regression reports, flaky quarantine,
resource constraints, progress reports, fast validation.

Usage:
    python3 scripts/gentoo/validation_dashboard.py --dry-run
    python3 scripts/gentoo/validation_dashboard.py --data-dir data/gentoo --output dashboard.json
    python3 scripts/gentoo/validation_dashboard.py --format markdown --output dashboard.md
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
DATA_DIR = REPO_ROOT / "data" / "gentoo"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class DashboardSection:
    """A section of the dashboard."""
    title: str
    status: str = "ok"  # ok, warn, error, unknown
    metrics: Dict[str, Any] = field(default_factory=dict)
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "status": self.status,
            "metrics": self.metrics,
            "details": self.details,
        }


@dataclass
class Dashboard:
    """Complete validation dashboard."""
    sections: List[DashboardSection] = field(default_factory=list)
    timestamp: str = ""
    dry_run: bool = False
    overall_status: str = "unknown"

    def add(self, section: DashboardSection) -> None:
        self.sections.append(section)

    def compute_overall(self) -> str:
        statuses = [s.status for s in self.sections]
        if not statuses:
            return "unknown"
        if "error" in statuses:
            return "error"
        if "warn" in statuses:
            return "warn"
        if all(s == "ok" for s in statuses):
            return "ok"
        return "unknown"

    def to_dict(self) -> Dict[str, Any]:
        self.overall_status = self.compute_overall()
        return {
            "schema_version": "v1",
            "bead": "bd-2icq.11",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            "overall_status": self.overall_status,
            "sections": [s.to_dict() for s in self.sections],
        }

    def to_markdown(self) -> str:
        self.overall_status = self.compute_overall()
        status_icon = {"ok": "PASS", "warn": "WARN", "error": "FAIL", "unknown": "?"}
        lines = [
            "# FrankenLibC Gentoo Validation Dashboard",
            "",
            f"**Status:** {status_icon.get(self.overall_status, '?')}",
            f"**Updated:** {self.timestamp or utc_now()}",
            f"**Dry run:** {self.dry_run}",
            "",
        ]

        for section in self.sections:
            icon = status_icon.get(section.status, "?")
            lines.append(f"## {icon} {section.title}")
            lines.append("")
            if section.metrics:
                for key, value in section.metrics.items():
                    lines.append(f"- **{key}:** {value}")
                lines.append("")
            if section.details:
                for detail in section.details:
                    lines.append(f"  - {detail}")
                lines.append("")

        return "\n".join(lines)


def load_json_safe(path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON file, returning None if not found."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def build_perf_section(data_dir: Path) -> DashboardSection:
    """Build performance benchmark section."""
    data = load_json_safe(data_dir / "perf-results" / "perf_benchmark_results.v1.json")
    if not data:
        return DashboardSection(
            title="Performance Benchmarks",
            status="unknown",
            details=["No performance benchmark data found"],
        )

    return DashboardSection(
        title="Performance Benchmarks",
        status="ok" if data.get("failed", 0) == 0 else "warn",
        metrics={
            "total_packages": data.get("total_packages", 0),
            "successful": data.get("successful", 0),
            "failed": data.get("failed", 0),
            "avg_overhead_pct": data.get("avg_build_overhead_percent", 0),
            "median_overhead_pct": data.get("median_build_overhead_percent", 0),
        },
    )


def build_regression_section(data_dir: Path) -> DashboardSection:
    """Build regression detection section."""
    data = load_json_safe(data_dir / "regression_report.v1.json")
    if not data:
        return DashboardSection(
            title="Regression Detection",
            status="unknown",
            details=["No regression report found"],
        )

    has_blockers = data.get("has_blockers", False)
    total = data.get("total_regressions", 0)

    return DashboardSection(
        title="Regression Detection",
        status="error" if has_blockers else ("warn" if total > 0 else "ok"),
        metrics={
            "total_regressions": total,
            "has_blockers": has_blockers,
            "by_severity": data.get("by_severity", {}),
            "by_type": data.get("by_type", {}),
        },
        details=[
            f"{r['type']}: {r['package']} ({r['severity']})"
            for r in data.get("regressions", [])[:10]
        ],
    )


def build_quarantine_section(data_dir: Path) -> DashboardSection:
    """Build flaky test quarantine section."""
    data = load_json_safe(data_dir / "quarantine.json")
    if not data:
        return DashboardSection(
            title="Flaky Test Quarantine",
            status="unknown",
            details=["No quarantine database found"],
        )

    stats = data.get("statistics", {})
    total = stats.get("total_quarantined", 0)

    return DashboardSection(
        title="Flaky Test Quarantine",
        status="ok",
        metrics={
            "total_quarantined": total,
            "by_reason": stats.get("by_reason", {}),
        },
    )


def build_constraints_section(data_dir: Path) -> DashboardSection:
    """Build resource constraints section."""
    data = load_json_safe(data_dir / "resource_constraints_report.v1.json")
    if not data:
        return DashboardSection(
            title="Resource Constraints",
            status="unknown",
            details=["No resource constraints report found"],
        )

    failed = data.get("failed", 0)
    return DashboardSection(
        title="Resource Constraints",
        status="ok" if failed == 0 else "warn",
        metrics={
            "total_tests": data.get("total_tests", 0),
            "passed": data.get("passed", 0),
            "failed": failed,
            "by_type": data.get("by_type", {}),
        },
    )


def build_baseline_section(data_dir: Path) -> DashboardSection:
    """Build baseline status section."""
    data = load_json_safe(data_dir / "baseline.json")
    if not data:
        return DashboardSection(
            title="Baseline",
            status="unknown",
            details=["No baseline found"],
        )

    return DashboardSection(
        title="Baseline",
        status="ok",
        metrics={
            "packages": len(data.get("packages", [])),
            "timestamp": data.get("timestamp", "unknown"),
            "source": data.get("source", "unknown"),
        },
    )


def build_fast_validate_section() -> DashboardSection:
    """Build fast validation section from latest artifacts."""
    fast_dir = REPO_ROOT / "artifacts" / "gentoo-builds" / "fast-validate"
    if not fast_dir.exists():
        return DashboardSection(
            title="Tier 1 Fast Validation",
            status="unknown",
            details=["No fast validation artifacts found"],
        )

    runs = sorted(fast_dir.iterdir(), reverse=True)
    if not runs:
        return DashboardSection(
            title="Tier 1 Fast Validation",
            status="unknown",
            details=["No fast validation runs found"],
        )

    latest = runs[0]
    data = load_json_safe(latest / "summary.json")
    if not data:
        return DashboardSection(
            title="Tier 1 Fast Validation",
            status="unknown",
            details=["No summary found in latest run"],
        )

    failed = data.get("failed", 0)
    return DashboardSection(
        title="Tier 1 Fast Validation",
        status="ok" if failed == 0 else "error",
        metrics={
            "total_packages": data.get("total_packages", 0),
            "passed": data.get("passed", 0),
            "failed": failed,
            "timestamp": data.get("timestamp", ""),
            "dry_run": data.get("dry_run", False),
        },
    )


def build_dashboard(data_dir: Path, dry_run: bool = False) -> Dashboard:
    """Build complete dashboard from all available data."""
    dashboard = Dashboard(timestamp=utc_now(), dry_run=dry_run)

    dashboard.add(build_fast_validate_section())
    dashboard.add(build_perf_section(data_dir))
    dashboard.add(build_regression_section(data_dir))
    dashboard.add(build_quarantine_section(data_dir))
    dashboard.add(build_constraints_section(data_dir))
    dashboard.add(build_baseline_section(data_dir))

    return dashboard


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validation dashboard")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    dashboard = build_dashboard(args.data_dir, dry_run=args.dry_run)

    if args.format in ("json", "both"):
        json_path = args.output or (args.data_dir / "validation_dashboard.v1.json")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(dashboard.to_dict(), indent=2) + "\n")
        print(f"JSON dashboard written to {json_path}")

    if args.format in ("markdown", "both"):
        md_path = (args.output.with_suffix(".md") if args.output
                   else args.data_dir / "validation_dashboard.v1.md")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(dashboard.to_markdown())
        print(f"Markdown dashboard written to {md_path}")

    if args.format == "markdown" and not args.output:
        print(dashboard.to_markdown())

    print(f"\n=== Dashboard Summary ===")
    print(f"Overall: {dashboard.compute_overall().upper()}")
    for s in dashboard.sections:
        icon = {"ok": "+", "warn": "~", "error": "!", "unknown": "?"}
        print(f"  [{icon.get(s.status, '?')}] {s.title}: {s.status}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
