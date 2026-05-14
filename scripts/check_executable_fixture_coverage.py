#!/usr/bin/env python3
"""Emit executable fixture coverage inventory for conformance fixtures.

The report joins three surfaces:
  * tests/conformance/fixtures/*.json fixture files
  * crates/frankenlibc-harness/tests/*.rs isolated harness tests
  * crates/frankenlibc_conformance/src/lib.rs execute_fixture_case dispatch text

It is intentionally a gap detector. By default it exits 0 after reporting every
gap; pass --fail-on-gaps when a caller wants to make those gaps blocking.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


SCHEMA_VERSION = "v1"
BEAD_ID = "bd-j1u6u.1"


def find_repo_root() -> Path:
    candidate = Path(__file__).resolve().parent.parent
    if (candidate / "Cargo.toml").exists():
        return candidate
    cwd = Path.cwd()
    if (cwd / "Cargo.toml").exists():
        return cwd
    raise SystemExit("ERROR: could not find repo root")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"ERROR: failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid JSON in {path}: {exc}") from exc


def slug_for_fixture(path: Path) -> str:
    stem = re.sub(r"[^a-zA-Z0-9]+", "_", path.stem).strip("_").lower()
    return f"{stem}_conformance_test.rs"


def fixture_inventory(root: Path) -> list[dict]:
    fixtures_dir = root / "tests" / "conformance" / "fixtures"
    rows = []
    for path in sorted(fixtures_dir.glob("*.json")):
        data = load_json(path)
        cases = data.get("cases", [])
        if not isinstance(cases, list):
            cases = []
        symbols = sorted(
            {
                case.get("function", "")
                for case in cases
                if isinstance(case, dict) and case.get("function")
            }
        )
        rows.append(
            {
                "fixture_path": str(path.relative_to(root)),
                "fixture_basename": path.name,
                "family": data.get("family", ""),
                "wave_id": data.get("campaign", {}).get("wave_id", ""),
                "case_count": len(cases),
                "symbols": symbols,
            }
        )
    return rows


def harness_references(root: Path, fixture_basenames: set[str]) -> dict[str, list[dict]]:
    tests_dir = root / "crates" / "frankenlibc-harness" / "tests"
    refs: dict[str, list[dict]] = {name: [] for name in fixture_basenames}
    for test_path in sorted(tests_dir.glob("*.rs")):
        text = test_path.read_text(encoding="utf-8")
        executable = "CARGO_BIN_EXE_harness" in text and "conformance-matrix-case" in text
        for basename in fixture_basenames:
            if basename in text:
                refs[basename].append(
                    {
                        "test_path": str(test_path.relative_to(root)),
                        "executes_conformance_matrix_case": executable,
                    }
                )
    return refs


def conformance_unit_references(root: Path, fixture_basenames: set[str]) -> dict[str, bool]:
    lib_path = root / "crates" / "frankenlibc_conformance" / "src" / "lib.rs"
    text = lib_path.read_text(encoding="utf-8")
    return {basename: basename in text for basename in fixture_basenames}


def dispatch_missing_symbols(root: Path, symbols: list[str]) -> list[str]:
    lib_path = root / "crates" / "frankenlibc_conformance" / "src" / "lib.rs"
    text = lib_path.read_text(encoding="utf-8")
    return [symbol for symbol in symbols if f'"{symbol}"' not in text]


def build_report(root: Path) -> dict:
    fixtures = fixture_inventory(root)
    basenames = {row["fixture_basename"] for row in fixtures}
    harness_refs = harness_references(root, basenames)
    unit_refs = conformance_unit_references(root, basenames)

    inventory = []
    gaps = []
    case_count = 0
    executable_count = 0
    dispatch_missing_total = 0

    for row in fixtures:
        case_count += int(row["case_count"])
        refs = harness_refs.get(row["fixture_basename"], [])
        executable_tests = [
            ref["test_path"]
            for ref in refs
            if ref["executes_conformance_matrix_case"]
        ]
        missing_symbols = dispatch_missing_symbols(root, row["symbols"])
        dispatch_missing_total += len(missing_symbols)
        executable = bool(executable_tests) and not missing_symbols
        if executable:
            executable_count += 1

        inventory_row = {
            **row,
            "harness_tests": [ref["test_path"] for ref in refs],
            "executable_harness_tests": executable_tests,
            "conformance_unit_reference": bool(unit_refs.get(row["fixture_basename"])),
            "missing_executor_symbols": missing_symbols,
            "executable_via_harness": executable,
            "suggested_test_target": str(
                Path("crates/frankenlibc-harness/tests") / slug_for_fixture(Path(row["fixture_basename"]))
            ),
        }
        inventory.append(inventory_row)

        if not executable:
            gaps.append(
                {
                    "fixture_path": row["fixture_path"],
                    "family": row["family"],
                    "wave_id": row["wave_id"],
                    "missing_harness_matrix_case_test": not bool(executable_tests),
                    "missing_executor_symbols": missing_symbols,
                    "suggested_test_target": inventory_row["suggested_test_target"],
                    "failure_signature": "missing_harness_matrix_case_test"
                    if not executable_tests
                    else "missing_execute_fixture_case_dispatch",
                }
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "summary": {
            "fixture_file_count": len(fixtures),
            "fixture_case_count": case_count,
            "executable_fixture_file_count": executable_count,
            "gap_count": len(gaps),
            "dispatch_missing_symbol_count": dispatch_missing_total,
            "status": "pass" if not gaps else "pass_with_gaps",
        },
        "required_gap_fields": [
            "fixture_path",
            "family",
            "wave_id",
            "missing_harness_matrix_case_test",
            "missing_executor_symbols",
            "suggested_test_target",
            "failure_signature",
        ],
        "fixture_inventory": inventory,
        "gaps": gaps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--fail-on-gaps", action="store_true")
    args = parser.parse_args()

    root = args.repo_root.resolve() if args.repo_root else find_repo_root()
    report = build_report(root)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    if args.fail_on_gaps and report["summary"]["gap_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
