#!/usr/bin/env python3
"""generate_per_symbol_fixture_tests.py — bd-ldj.5

Per-symbol conformance fixture unit tests:
  1. Fixture inventory — enumerate all fixture files and parse cases.
  2. Per-symbol mapping — map each symbol to its fixture cases.
  3. Coverage validation — flag symbols with no fixture coverage.
  4. Case quality — verify cases have required fields and valid values.
  5. Edge case audit — check for NULL, zero-length, INT_MAX boundary cases.

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


REQUIRED_CASE_FIELDS = ["name", "function", "inputs", "expected_output", "mode"]
VALID_MODES = {"strict", "hardened", "both"}

# Edge case patterns to look for in inputs
EDGE_CASE_PATTERNS = {
    "null_input": ["null", "NULL", "nullptr", "0x0"],
    "zero_length": ["0", "\"\"", "[]", "empty"],
    "max_int": ["INT_MAX", "2147483647", "UINT_MAX", "4294967295",
                "SIZE_MAX", "LONG_MAX"],
    "negative": ["-1", "-2147483648", "INT_MIN", "LONG_MIN"],
    "boundary": ["255", "256", "65535", "65536", "127", "128"],
}


def detect_edge_cases(case):
    """Detect which edge case patterns a test case covers."""
    found = set()
    inputs_str = json.dumps(case.get("inputs", {})).lower()
    name_str = case.get("name", "").lower()

    for pattern_name, patterns in EDGE_CASE_PATTERNS.items():
        for p in patterns:
            if p.lower() in inputs_str or p.lower() in name_str:
                found.add(pattern_name)
                break

    return sorted(found)


def analyze_fixture_file(fixture_path):
    """Analyze a single fixture file."""
    try:
        data = load_json_file(fixture_path)
    except (json.JSONDecodeError, OSError) as e:
        return {"error": str(e), "valid": False}

    family = data.get("family", "")
    version = data.get("version", "")
    cases = data.get("cases", [])

    per_symbol = defaultdict(list)
    issues = []
    edge_case_coverage = defaultdict(set)

    for i, case in enumerate(cases):
        if not isinstance(case, dict):
            issues.append(f"Case {i}: not a dict")
            continue

        fn = case.get("function", "")
        name = case.get("name", "")

        # Field validation
        for field in REQUIRED_CASE_FIELDS:
            if field not in case:
                issues.append(f"Case '{name}': missing field '{field}'")

        mode = case.get("mode", "")
        if mode and mode not in VALID_MODES:
            issues.append(f"Case '{name}': invalid mode '{mode}'")

        if fn:
            edge_cases = detect_edge_cases(case)
            per_symbol[fn].append({
                "name": name,
                "mode": mode,
                "has_expected_errno": "expected_errno" in case,
                "edge_cases": edge_cases,
            })
            for ec in edge_cases:
                edge_case_coverage[fn].add(ec)

    return {
        "file": fixture_path.name,
        "family": family,
        "version": version,
        "valid": len(issues) == 0,
        "total_cases": len(cases),
        "unique_symbols": len(per_symbol),
        "symbols": dict(per_symbol),
        "issues": issues,
        "edge_case_coverage": {k: sorted(v) for k, v in edge_case_coverage.items()},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Per-symbol conformance fixture unit tests")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fixtures_dir = root / "tests" / "conformance" / "fixtures"
    matrix_path = root / "support_matrix.json"

    if not fixtures_dir.exists():
        print("ERROR: tests/conformance/fixtures/ not found", file=sys.stderr)
        sys.exit(1)

    # Load support matrix for symbol universe
    implemented_symbols = set()
    all_symbols = {}
    if matrix_path.exists():
        matrix = load_json_file(matrix_path)
        for sym in matrix.get("symbols", []):
            name = sym.get("symbol", "")
            status = sym.get("status", "")
            module = sym.get("module", "")
            all_symbols[name] = {
                "status": status,
                "module": module,
                "perf_class": sym.get("perf_class", ""),
            }
            if status in ("Implemented", "RawSyscall"):
                implemented_symbols.add(name)

    # Analyze all fixture files
    fixture_files = sorted(fixtures_dir.glob("*.json"))
    fixture_analyses = []

    # Build per-symbol aggregation
    symbol_cases = defaultdict(lambda: {
        "total_cases": 0,
        "fixture_files": [],
        "modes": set(),
        "edge_cases": set(),
        "has_errno_check": False,
    })

    total_cases = 0
    total_issues = 0

    for fp in fixture_files:
        analysis = analyze_fixture_file(fp)
        fixture_analyses.append({
            "file": analysis.get("file", ""),
            "family": analysis.get("family", ""),
            "valid": analysis.get("valid", False),
            "total_cases": analysis.get("total_cases", 0),
            "unique_symbols": analysis.get("unique_symbols", 0),
            "issues": analysis.get("issues", []),
        })
        total_cases += analysis.get("total_cases", 0)
        total_issues += len(analysis.get("issues", []))

        for sym, case_list in analysis.get("symbols", {}).items():
            info = symbol_cases[sym]
            info["total_cases"] += len(case_list)
            if analysis["file"] not in info["fixture_files"]:
                info["fixture_files"].append(analysis["file"])
            for c in case_list:
                info["modes"].add(c["mode"])
                info["edge_cases"].update(c["edge_cases"])
                if c["has_expected_errno"]:
                    info["has_errno_check"] = True

    # Build per-symbol test report
    per_symbol_report = []
    for sym_name in sorted(all_symbols.keys()):
        sym_info = all_symbols[sym_name]
        case_info = symbol_cases.get(sym_name)

        has_fixtures = case_info is not None and case_info["total_cases"] > 0
        case_count = case_info["total_cases"] if case_info else 0
        modes = sorted(case_info["modes"]) if case_info else []
        edge_cases = sorted(case_info["edge_cases"]) if case_info else []

        # Quality assessment
        quality_issues = []
        if sym_info["status"] == "Implemented" and not has_fixtures:
            quality_issues.append("implemented symbol has no fixtures")
        if has_fixtures and case_count < 2:
            quality_issues.append("fewer than 2 test cases")
        if has_fixtures and not edge_cases:
            quality_issues.append("no edge cases detected")
        if has_fixtures and "both" not in modes and len(modes) < 2:
            quality_issues.append("missing dual-mode coverage")

        per_symbol_report.append({
            "symbol": sym_name,
            "status": sym_info["status"],
            "module": sym_info["module"],
            "perf_class": sym_info["perf_class"],
            "has_fixtures": has_fixtures,
            "case_count": case_count,
            "fixture_files": case_info["fixture_files"] if case_info else [],
            "modes_tested": modes,
            "edge_cases_covered": edge_cases,
            "has_errno_check": case_info["has_errno_check"] if case_info else False,
            "quality_issues": quality_issues,
        })

    # Summary stats
    symbols_with_fixtures = sum(1 for s in per_symbol_report if s["has_fixtures"])
    impl_with_fixtures = sum(
        1 for s in per_symbol_report
        if s["has_fixtures"] and s["status"] == "Implemented"
    )
    impl_total = sum(1 for s in per_symbol_report if s["status"] == "Implemented")
    symbols_with_edge = sum(
        1 for s in per_symbol_report
        if s["edge_cases_covered"]
    )
    symbols_with_errno = sum(
        1 for s in per_symbol_report if s["has_errno_check"]
    )
    total_quality_issues = sum(
        len(s["quality_issues"]) for s in per_symbol_report
    )

    # Action list for uncovered symbols
    uncovered_actions = []
    for s in per_symbol_report:
        if not s["has_fixtures"] and s["status"] in ("Implemented", "RawSyscall"):
            uncovered_actions.append({
                "symbol": s["symbol"],
                "status": s["status"],
                "module": s["module"],
                "action": "create fixture cases",
                "priority": "high" if s["perf_class"] == "strict_hotpath" else "normal",
            })

    report_hash = hashlib.sha256(
        json.dumps(
            [(s["symbol"], s["case_count"]) for s in per_symbol_report],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:16]

    report = {
        "schema_version": "v1",
        "bead": "bd-ldj.5",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_hash": report_hash,
        "summary": {
            "total_symbols": len(per_symbol_report),
            "symbols_with_fixtures": symbols_with_fixtures,
            "symbols_without_fixtures": len(per_symbol_report) - symbols_with_fixtures,
            "fixture_coverage_pct": round(
                symbols_with_fixtures / len(per_symbol_report) * 100, 1
            ) if per_symbol_report else 0,
            "implemented_coverage_pct": round(
                impl_with_fixtures / impl_total * 100, 1
            ) if impl_total else 0,
            "total_fixture_files": len(fixture_analyses),
            "total_cases": total_cases,
            "total_format_issues": total_issues,
            "symbols_with_edge_cases": symbols_with_edge,
            "symbols_with_errno_checks": symbols_with_errno,
            "total_quality_issues": total_quality_issues,
            "uncovered_action_count": len(uncovered_actions),
        },
        "fixture_file_analyses": fixture_analyses,
        "per_symbol_report": per_symbol_report,
        "uncovered_action_list": uncovered_actions,
        "edge_case_categories": list(EDGE_CASE_PATTERNS.keys()),
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
