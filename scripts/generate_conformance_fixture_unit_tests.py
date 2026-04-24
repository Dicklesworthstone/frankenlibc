#!/usr/bin/env python3
"""generate_conformance_fixture_unit_tests.py — bd-2hh.5

Conformance fixture verification and regression detection:
  1. Fixture loading — every fixture file can be parsed into FixtureSet.
  2. Format validation — all cases have required fields with valid values.
  3. Per-symbol regression — tracks case counts per symbol for regression.
  4. Deterministic output — fixture parsing is deterministic (same input = same output).
  5. Coverage baseline — captures current state for regression detection.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


REQUIRED_TOP_LEVEL = ["family"]
REQUIRED_CASE_FIELDS = ["name", "function", "inputs", "mode"]
EXPECTED_CONTRACT_FIELDS = {
    "expected_output",
    "expected_output_bytes",
    "expected_output_pattern",
    "expected_return",
    "expected_values",
    "expected_n_value",
}
VALID_MODES = {"strict", "hardened", "both"}


def compute_fixture_hash(data):
    """Compute deterministic hash of fixture content."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def sanitize_trace_component(value):
    sanitized = "".join(
        ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value)
    )
    return sanitized or "unknown"


def make_log_row(timestamp, run_id, fixture_file, family, symbol, outcome, artifact_refs, details):
    return {
        "timestamp": timestamp,
        "trace_id": f"bd-2hh.5::{run_id}::{sanitize_trace_component(fixture_file)}",
        "bead_id": "bd-2hh.5",
        "scenario_id": run_id,
        "mode": "fixture_validation",
        "api_family": family or "conformance",
        "symbol": symbol or family or "fixture_validation",
        "decision_path": "conformance::fixture_validation::report",
        "healing_action": None,
        "errno": 0,
        "latency_ns": 0,
        "artifact_refs": artifact_refs,
        "outcome": outcome,
        **details,
    }


def synthesize_structured_cases(data):
    family = data.get("family", "")
    cases = []

    for scenario in data.get("program_scenarios", []):
        scenario_id = scenario.get("scenario_id", "unknown_program_scenario")
        expected = scenario.get("expected", {})
        for mode in ("strict", "hardened"):
            mode_expected = expected.get(mode)
            if not isinstance(mode_expected, dict):
                continue
            cases.append(
                {
                    "name": f"{scenario_id}_{mode}",
                    "function": family,
                    "inputs": {
                        "scenario_id": scenario_id,
                        "source": scenario.get("source"),
                        "jump_depth": scenario.get("jump_depth"),
                        "mask_state": scenario.get("mask_state"),
                    },
                    "expected_output": mode_expected,
                    "mode": mode,
                }
            )

    for scenario in data.get("unsupported_scenarios", []):
        scenario_id = scenario.get("scenario_id", "unknown_unsupported_scenario")
        for mode in scenario.get("modes", []):
            cases.append(
                {
                    "name": f"{scenario_id}_{mode}",
                    "function": family,
                    "inputs": {
                        "scenario_id": scenario_id,
                        "jump_depth": scenario.get("jump_depth"),
                        "mask_state": scenario.get("mask_state"),
                    },
                    "expected_output": {
                        "expected_outcome": scenario.get("expected_outcome"),
                        "expected_errno": scenario.get("expected_errno"),
                        "documented_semantics": scenario.get(
                            "documented_semantics"
                        ),
                    },
                    "mode": mode,
                }
            )

    return cases


def validate_fixture(fixture_path):
    """Validate a fixture file thoroughly."""
    issues = []
    warnings = []

    try:
        data = load_json_file(fixture_path)
    except json.JSONDecodeError as e:
        return None, [f"JSON parse error: {e}"], []
    except OSError as e:
        return None, [f"File read error: {e}"], []

    # Top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in data:
            issues.append(f"Missing top-level field: {field}")

    version = data.get("version", data.get("schema_version", ""))
    if version != "v1":
        warnings.append(f"Unexpected version: {version}")

    family = data.get("family", "")
    if not family:
        issues.append("Empty family field")

    has_legacy_cases = "cases" in data
    has_structured_cases = any(
        key in data for key in ("program_scenarios", "unsupported_scenarios")
    )
    if not has_legacy_cases and not has_structured_cases:
        issues.append("Missing top-level fixture cases or structured scenarios")
        return data, issues, warnings

    if has_legacy_cases:
        cases = data.get("cases", [])
        if not isinstance(cases, list):
            issues.append("'cases' is not an array")
            return data, issues, warnings
    else:
        cases = synthesize_structured_cases(data)

    if len(cases) == 0:
        warnings.append("Empty cases array")

    # Validate each case
    case_names = set()
    for i, case in enumerate(cases):
        prefix = f"Case {i}"
        if not isinstance(case, dict):
            issues.append(f"{prefix}: not an object")
            continue

        name = case.get("name", "")
        if name:
            prefix = f"Case '{name}'"
            if name in case_names:
                issues.append(f"{prefix}: duplicate case name")
            case_names.add(name)
        else:
            issues.append(f"{prefix}: missing name")

        for field in REQUIRED_CASE_FIELDS:
            if field not in case:
                issues.append(f"{prefix}: missing field '{field}'")

        if not any(field in case for field in EXPECTED_CONTRACT_FIELDS):
            issues.append(f"{prefix}: missing output/return expectation field")

        mode = case.get("mode", "")
        if mode and mode not in VALID_MODES:
            issues.append(f"{prefix}: invalid mode '{mode}'")

        fn = case.get("function", "")
        if not fn:
            issues.append(f"{prefix}: empty function name")

        # Validate expected_output is present and non-null
        if "expected_output" in case and case["expected_output"] is None:
            warnings.append(f"{prefix}: expected_output is null")

    if not has_legacy_cases:
        data = dict(data)
        data["cases"] = cases
        data["version"] = version

    return data, issues, warnings


def build_regression_baseline(all_fixtures):
    """Build a regression baseline: per-symbol case counts and fixture hashes."""
    symbol_cases = defaultdict(lambda: {"count": 0, "fixtures": []})

    for finfo in all_fixtures:
        data = finfo.get("data")
        if not data:
            continue
        fixture_file = finfo["file"]
        for case in data.get("cases", []):
            fn = case.get("function", "")
            if fn:
                symbol_cases[fn]["count"] += 1
                if fixture_file not in symbol_cases[fn]["fixtures"]:
                    symbol_cases[fn]["fixtures"].append(fixture_file)

    return dict(symbol_cases)


def main():
    parser = argparse.ArgumentParser(
        description="Conformance fixture unit test validation")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--log", help="Optional JSONL log output path")
    parser.add_argument(
        "--timestamp",
        default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        help="Deterministic timestamp to embed in generated artifacts",
    )
    args = parser.parse_args()

    root = find_repo_root()
    fixtures_dir = root / "tests" / "conformance" / "fixtures"

    if not fixtures_dir.exists():
        print("ERROR: tests/conformance/fixtures/ not found", file=sys.stderr)
        sys.exit(1)

    fixture_files = sorted(fixtures_dir.glob("*.json"))

    all_fixtures = []
    total_issues = 0
    total_warnings = 0
    total_cases = 0
    all_hashes = {}
    log_rows = []

    for fp in fixture_files:
        data, issues, warnings = validate_fixture(fp)
        total_issues += len(issues)
        total_warnings += len(warnings)

        case_count = len(data.get("cases", [])) if data else 0
        total_cases += case_count

        fixture_hash = compute_fixture_hash(data) if data else None
        if fixture_hash:
            all_hashes[fp.name] = fixture_hash

        all_fixtures.append({
            "file": fp.name,
            "version": data.get("version", "") if data else "",
            "family": data.get("family", "") if data else "",
            "case_count": case_count,
            "fixture_hash": fixture_hash,
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "data": data,
        })

        primary_symbol = ""
        if data and data.get("cases"):
            primary_symbol = data["cases"][0].get("function", "")
        log_rows.append(
            make_log_row(
                args.timestamp,
                sanitize_trace_component(Path(args.output).stem if args.output else "fixture-unit-tests"),
                fp.name,
                data.get("family", "") if data else "",
                primary_symbol,
                "pass" if len(issues) == 0 else "fail",
                [
                    "scripts/generate_conformance_fixture_unit_tests.py",
                    f"tests/conformance/fixtures/{fp.name}",
                ],
                {
                    "event": "fixture_validation_result",
                    "valid": len(issues) == 0,
                    "issue_count": len(issues),
                    "warning_count": len(warnings),
                    "fixture_hash": fixture_hash,
                },
            )
        )

    # Build regression baseline
    regression_baseline = build_regression_baseline(all_fixtures)

    # Check determinism: same file should hash the same
    determinism_ok = True
    for fp in fixture_files[:5]:
        data1 = load_json_file(fp)
        data2 = load_json_file(fp)
        if compute_fixture_hash(data1) != compute_fixture_hash(data2):
            determinism_ok = False
            break

    # Summary
    valid_files = sum(1 for f in all_fixtures if f["valid"])
    invalid_files = [f for f in all_fixtures if not f["valid"]]
    unique_families = len(set(f["family"] for f in all_fixtures if f["family"]))
    unique_symbols = len(regression_baseline)

    # Strip internal data field from output
    fixture_results = []
    for f in all_fixtures:
        fixture_results.append({
            "file": f["file"],
            "version": f["version"],
            "family": f["family"],
            "case_count": f["case_count"],
            "fixture_hash": f["fixture_hash"],
            "valid": f["valid"],
            "issues": f["issues"],
            "warnings": f["warnings"],
        })

    report = {
        "schema_version": "v1",
        "bead": "bd-2hh.5",
        "generated_at": args.timestamp,
        "summary": {
            "total_fixture_files": len(fixture_files),
            "valid_fixture_files": valid_files,
            "invalid_fixture_files": len(invalid_files),
            "total_cases": total_cases,
            "total_issues": total_issues,
            "total_warnings": total_warnings,
            "unique_families": unique_families,
            "unique_symbols": unique_symbols,
            "determinism_verified": determinism_ok,
        },
        "regression_detection": {
            "status": "attention_required" if invalid_files else "clean",
            "invalid_fixture_files": [f["file"] for f in invalid_files],
            "invalid_fixture_issue_counts": {
                f["file"]: len(f["issues"]) for f in invalid_files
            },
            "baseline_fixture_digest": hashlib.sha256(
                json.dumps(
                    {
                        "fixture_hashes": all_hashes,
                        "symbols": regression_baseline,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        },
        "fixture_results": fixture_results,
        "regression_baseline": {
            "symbol_count": unique_symbols,
            "total_cases": total_cases,
            "symbols": {k: v for k, v in sorted(regression_baseline.items())},
        },
        "fixture_hashes": all_hashes,
    }

    log_rows.append(
        make_log_row(
            args.timestamp,
            sanitize_trace_component(Path(args.output).stem if args.output else "fixture-unit-tests"),
            "summary",
            "conformance",
            "fixture_validation",
            report["regression_detection"]["status"],
            [
                "scripts/generate_conformance_fixture_unit_tests.py",
                args.output or "stdout",
            ],
            {
                "event": "fixture_validation_summary",
                "valid_fixture_files": valid_files,
                "invalid_fixture_files": len(invalid_files),
                "total_fixture_files": len(fixture_files),
                "determinism_verified": determinism_ok,
                "baseline_fixture_digest": report["regression_detection"][
                    "baseline_fixture_digest"
                ],
            },
        )
    )

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.log:
        Path(args.log).parent.mkdir(parents=True, exist_ok=True)
        Path(args.log).write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
