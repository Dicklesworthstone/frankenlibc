#!/usr/bin/env python3
"""Flaky test quarantine database manager (bd-2icq.24).

Manages the quarantine database for tests identified as flaky.
Supports adding, removing, querying, and re-evaluating quarantined tests.

Usage:
    python3 scripts/gentoo/quarantine_manager.py --action add --package sys-apps/coreutils --test test_timeout
    python3 scripts/gentoo/quarantine_manager.py --action list
    python3 scripts/gentoo/quarantine_manager.py --action check --package sys-apps/coreutils --test test_timeout
    python3 scripts/gentoo/quarantine_manager.py --action import --report data/gentoo/flaky_detection_report.v1.json
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
QUARANTINE_FILE = REPO_ROOT / "data" / "gentoo" / "quarantine.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass
class QuarantinedTest:
    """A test in quarantine."""
    package: str
    test: str
    reason: str = "unknown"
    flake_rate: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    occurrences: int = 1
    tracking_issue: Optional[str] = None
    notes: Optional[str] = None

    def key(self) -> str:
        return f"{self.package}::{self.test}"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "package": self.package,
            "test": self.test,
            "reason": self.reason,
            "flake_rate": round(self.flake_rate, 4),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
        }
        if self.tracking_issue:
            d["tracking_issue"] = self.tracking_issue
        if self.notes:
            d["notes"] = self.notes
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> QuarantinedTest:
        return cls(
            package=d["package"],
            test=d["test"],
            reason=d.get("reason", "unknown"),
            flake_rate=d.get("flake_rate", 0.0),
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            occurrences=d.get("occurrences", 1),
            tracking_issue=d.get("tracking_issue"),
            notes=d.get("notes"),
        )


@dataclass
class QuarantineDB:
    """Quarantine database."""
    version: int = 1
    last_updated: str = ""
    quarantined_tests: List[QuarantinedTest] = field(default_factory=list)

    def _index(self) -> Dict[str, int]:
        return {t.key(): i for i, t in enumerate(self.quarantined_tests)}

    def is_quarantined(self, package: str, test: str) -> bool:
        key = f"{package}::{test}"
        return key in self._index()

    def add_test(self, test: QuarantinedTest) -> bool:
        """Add or update a quarantined test. Returns True if new."""
        idx = self._index()
        key = test.key()
        if key in idx:
            existing = self.quarantined_tests[idx[key]]
            existing.last_seen = test.last_seen or utc_date()
            existing.occurrences += 1
            existing.flake_rate = max(existing.flake_rate, test.flake_rate)
            if test.reason != "unknown":
                existing.reason = test.reason
            return False
        else:
            if not test.first_seen:
                test.first_seen = utc_date()
            if not test.last_seen:
                test.last_seen = utc_date()
            self.quarantined_tests.append(test)
            return True

    def remove_test(self, package: str, test: str) -> bool:
        """Remove a test from quarantine. Returns True if found and removed."""
        key = f"{package}::{test}"
        idx = self._index()
        if key in idx:
            del self.quarantined_tests[idx[key]]
            return True
        return False

    def get_test(self, package: str, test: str) -> Optional[QuarantinedTest]:
        key = f"{package}::{test}"
        idx = self._index()
        if key in idx:
            return self.quarantined_tests[idx[key]]
        return None

    def get_package_tests(self, package: str) -> List[QuarantinedTest]:
        return [t for t in self.quarantined_tests if t.package == package]

    def statistics(self) -> Dict[str, Any]:
        by_reason: Dict[str, int] = {}
        by_package: Dict[str, int] = {}
        for t in self.quarantined_tests:
            by_reason[t.reason] = by_reason.get(t.reason, 0) + 1
            by_package[t.package] = by_package.get(t.package, 0) + 1
        return {
            "total_quarantined": len(self.quarantined_tests),
            "by_reason": by_reason,
            "by_package": by_package,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "last_updated": self.last_updated or utc_now(),
            "quarantined_tests": [t.to_dict() for t in self.quarantined_tests],
            "statistics": self.statistics(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> QuarantineDB:
        db = cls(
            version=d.get("version", 1),
            last_updated=d.get("last_updated", ""),
        )
        for td in d.get("quarantined_tests", []):
            db.quarantined_tests.append(QuarantinedTest.from_dict(td))
        return db

    def save(self, path: Path) -> None:
        self.last_updated = utc_now()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")

    @classmethod
    def load(cls, path: Path) -> QuarantineDB:
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text()))


def import_detection_report(db: QuarantineDB, report_path: Path) -> int:
    """Import flaky tests from a detection report into the quarantine DB."""
    data = json.loads(report_path.read_text())
    added = 0
    for ft in data.get("flaky_tests", []):
        test = QuarantinedTest(
            package=ft["package"],
            test=ft["test"],
            reason=ft.get("reason", "unknown"),
            flake_rate=ft.get("flake_rate", 0.0),
            first_seen=ft.get("first_seen", utc_date()),
            last_seen=ft.get("last_seen", utc_date()),
        )
        if db.add_test(test):
            added += 1
    return added


def filter_quarantined(
    results: List[Dict[str, Any]], db: QuarantineDB, package: str
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split test results into stable and quarantined sets."""
    stable = []
    quarantined = []
    for r in results:
        test_name = r.get("name", r.get("test", ""))
        if db.is_quarantined(package, test_name):
            quarantined.append(r)
        else:
            stable.append(r)
    return stable, quarantined


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Quarantine database manager")
    parser.add_argument("--action", required=True,
                        choices=["add", "remove", "check", "list", "import",
                                 "stats", "init"])
    parser.add_argument("--package", default=None)
    parser.add_argument("--test", default=None)
    parser.add_argument("--reason", default="unknown")
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--db", type=Path, default=QUARANTINE_FILE)
    args = parser.parse_args(argv)

    db = QuarantineDB.load(args.db)

    if args.action == "init":
        db.save(args.db)
        print(f"Initialized quarantine database at {args.db}")
        return 0

    if args.action == "add":
        if not args.package or not args.test:
            print("--package and --test required for add", file=sys.stderr)
            return 1
        test = QuarantinedTest(
            package=args.package,
            test=args.test,
            reason=args.reason,
        )
        is_new = db.add_test(test)
        db.save(args.db)
        action = "Added" if is_new else "Updated"
        print(f"{action}: {args.package}::{args.test} (reason={args.reason})")
        return 0

    if args.action == "remove":
        if not args.package or not args.test:
            print("--package and --test required for remove", file=sys.stderr)
            return 1
        if db.remove_test(args.package, args.test):
            db.save(args.db)
            print(f"Removed: {args.package}::{args.test}")
        else:
            print(f"Not found: {args.package}::{args.test}")
        return 0

    if args.action == "check":
        if not args.package or not args.test:
            print("--package and --test required for check", file=sys.stderr)
            return 1
        if db.is_quarantined(args.package, args.test):
            t = db.get_test(args.package, args.test)
            print(f"QUARANTINED: {args.package}::{args.test}")
            if t:
                print(f"  Reason: {t.reason}")
                print(f"  Flake rate: {t.flake_rate:.1%}")
                print(f"  Occurrences: {t.occurrences}")
            return 1  # non-zero = quarantined
        else:
            print(f"NOT quarantined: {args.package}::{args.test}")
            return 0

    if args.action == "list":
        if args.package:
            tests = db.get_package_tests(args.package)
        else:
            tests = db.quarantined_tests
        if not tests:
            print("No quarantined tests")
            return 0
        for t in tests:
            print(f"  {t.package}::{t.test} ({t.reason}, "
                  f"rate={t.flake_rate:.1%}, occ={t.occurrences})")
        print(f"\nTotal: {len(tests)} quarantined test(s)")
        return 0

    if args.action == "import":
        if not args.report:
            print("--report required for import", file=sys.stderr)
            return 1
        if not args.report.exists():
            print(f"Report not found: {args.report}", file=sys.stderr)
            return 1
        added = import_detection_report(db, args.report)
        db.save(args.db)
        print(f"Imported {added} new flaky test(s) into quarantine")
        print(f"Total quarantined: {len(db.quarantined_tests)}")
        return 0

    if args.action == "stats":
        stats = db.statistics()
        print(f"Total quarantined: {stats['total_quarantined']}")
        if stats["by_reason"]:
            print("By reason:")
            for reason, count in sorted(stats["by_reason"].items()):
                print(f"  {reason}: {count}")
        if stats["by_package"]:
            print("By package:")
            for pkg, count in sorted(stats["by_package"].items()):
                print(f"  {pkg}: {count}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
