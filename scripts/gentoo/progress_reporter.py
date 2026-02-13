#!/usr/bin/env python3
"""Progress reporting for Gentoo validation builds (bd-2icq.21).

Provides real-time status, ETA calculation, resource monitoring,
and structured JSON output for long-running build pipelines.

Usage:
    python3 scripts/gentoo/progress_reporter.py --dry-run
    python3 scripts/gentoo/progress_reporter.py --mode json --output status.json
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class PackageStatus:
    """Status of a single package in the pipeline."""
    name: str
    status: str = "pending"  # pending, building, success, failed, skipped
    phase: str = ""  # compile, test, install
    elapsed_s: float = 0.0
    failure_reason: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "elapsed_s": round(self.elapsed_s, 1),
        }
        if self.phase:
            d["phase"] = self.phase
        if self.failure_reason:
            d["failure_reason"] = self.failure_reason
        if self.start_time:
            d["start_time"] = self.start_time
        if self.end_time:
            d["end_time"] = self.end_time
        return d


@dataclass
class ResourceSnapshot:
    """Point-in-time resource usage."""
    cpu_percent: float = 0.0
    memory_used_mb: int = 0
    memory_total_mb: int = 0
    disk_used_gb: float = 0.0
    disk_total_gb: float = 0.0
    timestamp: str = ""

    @property
    def memory_percent(self) -> float:
        if self.memory_total_mb == 0:
            return 0.0
        return round(self.memory_used_mb / self.memory_total_mb * 100, 1)

    @property
    def disk_percent(self) -> float:
        if self.disk_total_gb == 0:
            return 0.0
        return round(self.disk_used_gb / self.disk_total_gb * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_used_mb": self.memory_used_mb,
            "memory_total_mb": self.memory_total_mb,
            "memory_percent": self.memory_percent,
            "disk_used_gb": round(self.disk_used_gb, 1),
            "disk_total_gb": round(self.disk_total_gb, 1),
            "disk_percent": self.disk_percent,
            "timestamp": self.timestamp or utc_now(),
        }


@dataclass
class BuildProgress:
    """Overall build pipeline progress."""
    total: int = 0
    completed: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    pending: int = 0
    current_package: Optional[PackageStatus] = None
    packages: List[PackageStatus] = field(default_factory=list)
    package_times: List[float] = field(default_factory=list)
    started_at: str = ""
    elapsed_s: float = 0.0

    @property
    def percentage(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.completed / self.total * 100, 1)

    @property
    def avg_package_s(self) -> float:
        if not self.package_times:
            return 0.0
        return sum(self.package_times) / len(self.package_times)

    def estimate_remaining_s(self) -> float:
        """ETA based on moving average of completed package times."""
        if not self.package_times:
            return 0.0
        remaining = self.total - self.completed
        return self.avg_package_s * remaining

    def recent_failures(self, n: int = 5) -> List[PackageStatus]:
        return [p for p in self.packages if p.status == "failed"][-n:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "running" if self.completed < self.total else "complete",
            "progress": {
                "completed": self.completed,
                "total": self.total,
                "percentage": self.percentage,
            },
            "current_package": (self.current_package.to_dict()
                                if self.current_package else None),
            "summary": {
                "passed": self.passed,
                "failed": self.failed,
                "skipped": self.skipped,
                "pending": self.pending,
            },
            "timing": {
                "started_at": self.started_at,
                "elapsed_s": round(self.elapsed_s, 1),
                "eta_s": round(self.estimate_remaining_s(), 1),
                "avg_package_s": round(self.avg_package_s, 1),
            },
            "recent_failures": [f.to_dict() for f in self.recent_failures()],
        }


@dataclass
class ProgressReport:
    """Complete progress report with resource info."""
    progress: BuildProgress = field(default_factory=BuildProgress)
    resources: ResourceSnapshot = field(default_factory=ResourceSnapshot)
    timestamp: str = ""
    dry_run: bool = False
    historical_avg_s: Optional[float] = None

    @property
    def speed_comparison(self) -> Optional[str]:
        """Compare current speed to historical average."""
        if self.historical_avg_s is None or self.progress.avg_package_s == 0:
            return None
        ratio = self.progress.avg_package_s / self.historical_avg_s
        if ratio > 1.2:
            return f"{(ratio - 1) * 100:.0f}% slower than usual"
        if ratio < 0.8:
            return f"{(1 - ratio) * 100:.0f}% faster than usual"
        return "within normal range"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "schema_version": "v1",
            "bead": "bd-2icq.21",
            "timestamp": self.timestamp or utc_now(),
            "dry_run": self.dry_run,
            **self.progress.to_dict(),
            "resources": self.resources.to_dict(),
        }
        if self.speed_comparison:
            d["speed_comparison"] = self.speed_comparison
        return d


def format_time(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f}m {seconds % 60:.0f}s"
    hours = minutes / 60
    return f"{hours:.0f}h {minutes % 60:.0f}m"


def format_progress_bar(pct: float, width: int = 40) -> str:
    """Render a text progress bar."""
    filled = int(width * pct / 100)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    return f"[{bar}] {pct:.0f}%"


def render_terminal(report: ProgressReport) -> str:
    """Render progress report as terminal output."""
    prog = report.progress
    res = report.resources
    lines = [
        "FrankenLibC Gentoo Validation",
        "=" * 60,
        "",
        f"Progress: {format_progress_bar(prog.percentage)}",
        f"  {prog.completed}/{prog.total} packages",
        "",
    ]

    if prog.current_package:
        cp = prog.current_package
        lines.append(f"Current:  {cp.name} ({cp.status}, {format_time(cp.elapsed_s)} elapsed)")

    lines.extend([
        "",
        f"Stats:  Passed: {prog.passed}  Failed: {prog.failed}  "
        f"Skipped: {prog.skipped}  Pending: {prog.pending}",
        "",
        f"Timing:",
        f"  Avg build time:   {format_time(prog.avg_package_s)}",
        f"  Est. remaining:   {format_time(prog.estimate_remaining_s())}",
        f"  Total elapsed:    {format_time(prog.elapsed_s)}",
    ])

    if res.memory_total_mb > 0:
        lines.extend([
            "",
            f"Resources:",
            f"  CPU: {res.cpu_percent:.0f}%  "
            f"Mem: {res.memory_used_mb}MB/{res.memory_total_mb}MB ({res.memory_percent:.0f}%)  "
            f"Disk: {res.disk_used_gb:.1f}GB/{res.disk_total_gb:.1f}GB ({res.disk_percent:.0f}%)",
        ])

    failures = prog.recent_failures()
    if failures:
        lines.extend(["", "Recent failures:"])
        for f in failures:
            reason = f.failure_reason or "unknown"
            lines.append(f"  x {f.name} ({reason})")

    if report.speed_comparison:
        lines.extend(["", f"Speed: {report.speed_comparison}"])

    lines.extend(["", f"Updated: {report.timestamp or utc_now()}"])
    return "\n".join(lines)


def generate_dry_run_report(packages: List[str]) -> ProgressReport:
    """Generate a synthetic progress report for testing."""
    import random
    random.seed(42)

    total = len(packages)
    completed = int(total * 0.6)

    pkg_statuses = []
    times = []
    passed = 0
    failed = 0
    skipped = 0

    for i, pkg in enumerate(packages):
        if i < completed:
            t = random.uniform(60, 600)
            times.append(t)
            if random.random() > 0.9:
                reasons = ["timeout", "oom", "test_failures"]
                status = PackageStatus(
                    name=pkg, status="failed", elapsed_s=t,
                    failure_reason=random.choice(reasons),
                    end_time=utc_now(),
                )
                failed += 1
            elif random.random() > 0.95:
                status = PackageStatus(name=pkg, status="skipped", elapsed_s=0)
                skipped += 1
            else:
                status = PackageStatus(
                    name=pkg, status="success", elapsed_s=t,
                    end_time=utc_now(),
                )
                passed += 1
            pkg_statuses.append(status)
        elif i == completed:
            current = PackageStatus(
                name=pkg, status="building", phase="compile",
                elapsed_s=random.uniform(30, 300),
                start_time=utc_now(),
            )
            pkg_statuses.append(current)
        else:
            pkg_statuses.append(PackageStatus(name=pkg, status="pending"))

    progress = BuildProgress(
        total=total,
        completed=completed,
        passed=passed,
        failed=failed,
        skipped=skipped,
        pending=total - completed - 1,
        current_package=pkg_statuses[completed] if completed < total else None,
        packages=pkg_statuses,
        package_times=times,
        started_at=utc_now(),
        elapsed_s=sum(times) + random.uniform(30, 300),
    )

    resources = ResourceSnapshot(
        cpu_percent=random.uniform(40, 95),
        memory_used_mb=random.randint(1024, 4096),
        memory_total_mb=8192,
        disk_used_gb=random.uniform(20, 60),
        disk_total_gb=100.0,
        timestamp=utc_now(),
    )

    return ProgressReport(
        progress=progress,
        resources=resources,
        timestamp=utc_now(),
        dry_run=True,
        historical_avg_s=random.uniform(200, 400),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Progress reporter")
    parser.add_argument("--mode", default="terminal",
                        choices=["terminal", "json", "dry-run"])
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--packages", default="tier1")
    args = parser.parse_args(argv)

    # Load packages
    tier1 = REPO_ROOT / "configs" / "gentoo" / "tier1-mini.txt"
    if args.packages == "tier1" and tier1.exists():
        lines = tier1.read_text().splitlines()
        packages = [l.strip() for l in lines
                    if l.strip() and not l.strip().startswith("#")]
    elif args.packages == "top100":
        top100 = REPO_ROOT / "configs" / "gentoo" / "top100-packages.txt"
        if top100.exists():
            lines = top100.read_text().splitlines()
            packages = [l.strip() for l in lines
                        if l.strip() and not l.strip().startswith("#")]
        else:
            packages = ["sys-apps/coreutils"]
    else:
        packages = [args.packages]

    report = generate_dry_run_report(packages)

    if args.mode in ("terminal", "dry-run"):
        print(render_terminal(report))

    if args.mode == "json" or args.output:
        output_path = args.output or (
            REPO_ROOT / "data" / "gentoo" / "progress_report.v1.json"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")
        print(f"\nJSON report written to {output_path}")

    if args.mode == "dry-run" and args.output:
        output_path = args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
