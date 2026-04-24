#!/usr/bin/env python3
"""generate_conformance_fixture_pipeline.py — bd-2hh.1

Conformance fixture capture pipeline validation:
  1. Scans all fixture JSON files and counts cases per symbol.
  2. Cross-references against support matrix (Implemented symbols).
  3. Validates >=10 fixture cases per Implemented symbol threshold.
  4. Identifies symbols needing more fixtures.
  5. Validates fixture format: version, family, cases array, required case fields.
  6. Generates deterministic pipeline report.

Generates a JSON report to stdout (or --output).
"""
import argparse
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
MIN_CASES_THRESHOLD = 10
MIN_COVERAGE_PCT = 5.0


def validate_fixture_file(fixture_path):
    """Validate a single fixture file and return (cases_by_symbol, issues)."""
    issues = []
    cases_by_symbol = defaultdict(int)

    try:
        data = load_json_file(fixture_path)
    except (json.JSONDecodeError, OSError) as e:
        return {}, [f"Failed to load: {e}"]

    if "version" not in data and "schema_version" not in data:
        issues.append("Missing 'version' field")
    if "cases" in data:
        cases = data.get("cases", [])
        if not isinstance(cases, list):
            issues.append("'cases' is not an array")
            return {}, issues

        for i, case in enumerate(cases):
            for field in REQUIRED_CASE_FIELDS:
                if field not in case:
                    issues.append(f"Case {i}: missing required field '{field}'")

            if not any(field in case for field in EXPECTED_CONTRACT_FIELDS):
                issues.append(f"Case {i}: missing output/return expectation field")

            mode = case.get("mode", "")
            if mode and mode not in VALID_MODES:
                issues.append(f"Case {i}: invalid mode '{mode}'")

            fn = case.get("function", "")
            if fn:
                cases_by_symbol[fn] += 1
    elif "program_scenarios" in data or "unsupported_scenarios" in data:
        program_scenarios = data.get("program_scenarios", [])
        unsupported_scenarios = data.get("unsupported_scenarios", [])
        if not isinstance(program_scenarios, list):
            issues.append("'program_scenarios' is not an array")
            return {}, issues
        if not isinstance(unsupported_scenarios, list):
            issues.append("'unsupported_scenarios' is not an array")
            return {}, issues
        family = data.get("family", "")
        for scenario in program_scenarios:
            if family:
                cases_by_symbol[family] += 1
        for scenario in unsupported_scenarios:
            if family:
                cases_by_symbol[family] += 1
    else:
        issues.append("Missing 'cases' array")
        return {}, issues

    return dict(cases_by_symbol), issues


def load_support_matrix(root):
    """Load support matrix and return set of Implemented symbols."""
    matrix_path = root / "support_matrix.json"
    if not matrix_path.exists():
        return {}, {}

    matrix = load_json_file(matrix_path)
    symbols = matrix.get("symbols", [])

    implemented = {}
    all_symbols = {}
    for info in symbols:
        name = info.get("symbol", "")
        status = info.get("status", "")
        module = info.get("module", "unknown")
        all_symbols[name] = {"status": status, "module": module}
        if status in ("Implemented", "RawSyscall"):
            implemented[name] = {"status": status, "module": module}

    return implemented, all_symbols


def main():
    parser = argparse.ArgumentParser(
        description="Conformance fixture capture pipeline validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fixtures_dir = root / "tests" / "conformance" / "fixtures"

    if not fixtures_dir.exists():
        print("ERROR: tests/conformance/fixtures/ not found", file=sys.stderr)
        sys.exit(1)

    # Scan all fixture files
    fixture_files = sorted(fixtures_dir.glob("*.json"))

    global_cases_by_symbol = defaultdict(int)
    fixture_summaries = []
    total_issues = 0

    for fp in fixture_files:
        cases_by_sym, issues = validate_fixture_file(fp)
        total_cases = sum(cases_by_sym.values())
        total_issues += len(issues)

        for sym, count in cases_by_sym.items():
            global_cases_by_symbol[sym] += count

        fixture_summaries.append({
            "file": fp.name,
            "total_cases": total_cases,
            "symbols_covered": len(cases_by_sym),
            "symbols": dict(cases_by_sym),
            "valid": len(issues) == 0,
            "issues": issues,
        })

    # Load support matrix
    implemented, all_symbols = load_support_matrix(root)

    # Per-symbol coverage analysis
    symbol_coverage = []
    symbols_at_threshold = 0
    symbols_below_threshold = 0
    symbols_with_zero = 0

    for sym, info in sorted(implemented.items()):
        case_count = global_cases_by_symbol.get(sym, 0)
        meets_threshold = case_count >= MIN_CASES_THRESHOLD
        if meets_threshold:
            symbols_at_threshold += 1
        elif case_count == 0:
            symbols_with_zero += 1
            symbols_below_threshold += 1
        else:
            symbols_below_threshold += 1

        symbol_coverage.append({
            "symbol": sym,
            "module": info["module"],
            "status": info["status"],
            "fixture_cases": case_count,
            "meets_threshold": meets_threshold,
            "gap": max(0, MIN_CASES_THRESHOLD - case_count),
        })

    # Module-level aggregation
    module_stats = defaultdict(lambda: {
        "total_symbols": 0, "covered_symbols": 0,
        "at_threshold": 0, "total_cases": 0
    })
    for sc in symbol_coverage:
        mod = sc["module"]
        module_stats[mod]["total_symbols"] += 1
        if sc["fixture_cases"] > 0:
            module_stats[mod]["covered_symbols"] += 1
        if sc["meets_threshold"]:
            module_stats[mod]["at_threshold"] += 1
        module_stats[mod]["total_cases"] += sc["fixture_cases"]

    module_summary = []
    for mod, stats in sorted(module_stats.items()):
        total = stats["total_symbols"]
        module_summary.append({
            "module": mod,
            "total_symbols": total,
            "covered_symbols": stats["covered_symbols"],
            "at_threshold": stats["at_threshold"],
            "total_cases": stats["total_cases"],
            "coverage_pct": round(stats["covered_symbols"] / total * 100, 1) if total else 0,
            "threshold_pct": round(stats["at_threshold"] / total * 100, 1) if total else 0,
        })

    # Symbols not in support matrix but with fixtures
    extra_symbols = []
    for sym, count in sorted(global_cases_by_symbol.items()):
        if sym not in all_symbols:
            extra_symbols.append({"symbol": sym, "fixture_cases": count})

    total_implemented = len(implemented)
    total_fixture_cases = sum(global_cases_by_symbol.values())
    total_unique_symbols = len(global_cases_by_symbol)
    coverage_pct = round(
        sum(1 for s in symbol_coverage if s["fixture_cases"] > 0) / total_implemented * 100, 1
    ) if total_implemented else 0
    threshold_pct = round(
        symbols_at_threshold / total_implemented * 100, 1
    ) if total_implemented else 0

    report = {
        "schema_version": "v1",
        "bead": "bd-2hh.1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_fixture_files": len(fixture_files),
            "total_fixture_cases": total_fixture_cases,
            "unique_symbols_in_fixtures": total_unique_symbols,
            "implemented_symbols": total_implemented,
            "symbols_with_fixtures": sum(1 for s in symbol_coverage if s["fixture_cases"] > 0),
            "symbols_at_threshold": symbols_at_threshold,
            "symbols_below_threshold": symbols_below_threshold,
            "symbols_with_zero_fixtures": symbols_with_zero,
            "coverage_pct": coverage_pct,
            "min_coverage_pct": MIN_COVERAGE_PCT,
            "threshold_pct": threshold_pct,
            "min_cases_threshold": MIN_CASES_THRESHOLD,
            "fixture_format_issues": total_issues,
        },
        "module_summary": module_summary,
        "symbol_coverage": symbol_coverage,
        "fixture_files": fixture_summaries,
        "extra_symbols": extra_symbols,
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
