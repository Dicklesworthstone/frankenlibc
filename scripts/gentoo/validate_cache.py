#!/usr/bin/env python3
"""Validate Gentoo binary cache metadata and produce deterministic reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Keep script runnable directly from repository root.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cache_manager import BinaryPackageCache  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Gentoo binary package cache metadata.")
    parser.add_argument("--cache-dir", default="/var/cache/binpkgs", help="Binary cache root")
    parser.add_argument("--metadata-file", default="", help="Optional metadata file override")
    parser.add_argument("--max-age-days", type=int, default=7, help="Maximum acceptable cache age")
    parser.add_argument("--max-entries", type=int, default=4096)
    parser.add_argument("--mode", default="", help="Require cached entries to match this mode")
    parser.add_argument("--franken-version", default="", help="Require cached entries to match this FrankenLibC version")
    parser.add_argument("--log-file", default="", help="Emit structured validation logs to JSONL path")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when invalid entries are detected")
    parser.add_argument("--report", default="", help="Optional report output path (JSON)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cache = BinaryPackageCache(
        cache_dir=Path(args.cache_dir),
        max_age_days=args.max_age_days,
        max_entries=args.max_entries,
        metadata_file=Path(args.metadata_file) if args.metadata_file else None,
        log_file=Path(args.log_file) if args.log_file else None,
    )
    report = cache.validate_all(
        expected_mode=args.mode or None,
        expected_frankenlibc_version=args.franken_version or None,
    )
    body = json.dumps(report, indent=2, sort_keys=True)
    print(body)

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(body + "\n", encoding="utf-8")

    if args.strict and int(report["invalid_count"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
