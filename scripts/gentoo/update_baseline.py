#!/usr/bin/env python3
"""Baseline management for Gentoo validation (bd-2icq.12).

Creates and updates the known-good baseline from validation results.

Usage:
    python3 scripts/gentoo/update_baseline.py --from results/summary.json
    python3 scripts/gentoo/update_baseline.py --dry-run
    python3 scripts/gentoo/update_baseline.py --show
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_FILE = REPO_ROOT / "data" / "gentoo" / "baseline.json"
BASELINE_HISTORY = REPO_ROOT / "data" / "gentoo" / "baseline_history"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_baseline_from_results(results_path: Path) -> Dict[str, Any]:
    """Create a baseline from validation results."""
    data = json.loads(results_path.read_text())

    packages = []
    for pkg in data.get("packages", []):
        entry: Dict[str, Any] = {
            "package": pkg.get("package", pkg.get("name", "")),
            "build_status": "success" if not pkg.get("error") else "failed",
            "test_status": pkg.get("test_status", "unknown"),
            "overhead_percent": round(pkg.get("build_overhead_percent",
                                              pkg.get("overhead_percent", 0.0)), 2),
            "healing_actions": 0,
            "healing_types": {},
            "tests": [],
        }

        profile = pkg.get("latency_profile", {})
        if profile:
            entry["healing_actions"] = profile.get("healing_actions", 0)
            entry["healing_types"] = profile.get("by_action", {})

        packages.append(entry)

    return {
        "schema_version": "v1",
        "bead": "bd-2icq.12",
        "timestamp": utc_now(),
        "source": str(results_path),
        "packages": packages,
    }


def generate_dry_run_baseline() -> Dict[str, Any]:
    """Generate a synthetic baseline for testing."""
    import random
    random.seed(42)

    packages = ["sys-apps/coreutils", "dev-libs/json-c", "app-arch/gzip",
                "sys-apps/grep", "net-misc/curl"]

    entries = []
    for pkg in packages:
        overhead = round(random.uniform(2, 8), 2)
        healing = random.randint(0, 20)
        entries.append({
            "package": pkg,
            "build_status": "success",
            "test_status": "passed",
            "overhead_percent": overhead,
            "healing_actions": healing,
            "healing_types": {
                "ClampSize": healing // 2,
                "TruncateWithNull": healing - healing // 2,
            } if healing > 0 else {},
            "tests": [{"name": f"test_{i}", "passed": True} for i in range(5)],
        })

    return {
        "schema_version": "v1",
        "bead": "bd-2icq.12",
        "timestamp": utc_now(),
        "source": "dry-run",
        "packages": entries,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Baseline manager")
    parser.add_argument("--from-results", type=Path, default=None,
                        dest="from_results",
                        help="Create baseline from results file")
    parser.add_argument("--output", type=Path, default=BASELINE_FILE)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--show", action="store_true",
                        help="Show current baseline info")
    parser.add_argument("--keep-history", action="store_true", default=True)
    args = parser.parse_args(argv)

    if args.show:
        if not args.output.exists():
            print("No baseline exists yet.")
            return 0
        data = json.loads(args.output.read_text())
        print(f"Baseline timestamp: {data.get('timestamp', 'unknown')}")
        print(f"Source: {data.get('source', 'unknown')}")
        print(f"Packages: {len(data.get('packages', []))}")
        for pkg in data.get("packages", []):
            print(f"  {pkg['package']}: {pkg['build_status']} "
                  f"(overhead={pkg.get('overhead_percent', 0):.1f}%)")
        return 0

    if args.dry_run:
        baseline = generate_dry_run_baseline()
    elif args.from_results:
        if not args.from_results.exists():
            print(f"Results file not found: {args.from_results}", file=sys.stderr)
            return 1
        baseline = create_baseline_from_results(args.from_results)
    else:
        print("Specify --from-results <path> or --dry-run", file=sys.stderr)
        return 1

    # Archive existing baseline
    if args.keep_history and args.output.exists():
        BASELINE_HISTORY.mkdir(parents=True, exist_ok=True)
        archive = BASELINE_HISTORY / f"baseline_{utc_stamp()}.json"
        shutil.copy2(args.output, archive)
        print(f"Archived previous baseline to {archive}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"Baseline written to {args.output}")
    print(f"  Packages: {len(baseline['packages'])}")
    print(f"  Timestamp: {baseline['timestamp']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
