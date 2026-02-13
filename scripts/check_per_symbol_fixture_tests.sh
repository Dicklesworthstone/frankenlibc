#!/usr/bin/env bash
# check_per_symbol_fixture_tests.sh — CI gate for bd-ldj.5
# Validates per-symbol conformance fixture unit test coverage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/per_symbol_fixture_tests.v1.json"

echo "=== Per-Symbol Fixture Tests Gate (bd-ldj.5) ==="

echo "--- Generating per-symbol fixture test report ---"
python3 "$SCRIPT_DIR/generate_per_symbol_fixture_tests.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: per-symbol fixture test report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
symbols = report.get("per_symbol_report", [])
files = report.get("fixture_file_analyses", [])

total = summary.get("total_symbols", 0)
with_fix = summary.get("symbols_with_fixtures", 0)
coverage = summary.get("fixture_coverage_pct", 0)
impl_cov = summary.get("implemented_coverage_pct", 0)
total_cases = summary.get("total_cases", 0)
edge_count = summary.get("symbols_with_edge_cases", 0)
format_issues = summary.get("total_format_issues", 0)

print(f"Symbols:                 {total}")
print(f"  With fixtures:         {with_fix}")
print(f"  Coverage:              {coverage}%")
print(f"  Implemented coverage:  {impl_cov}%")
print(f"  Total cases:           {total_cases}")
print(f"  Edge case coverage:    {edge_count}")
print(f"  Format issues:         {format_issues}")
print()

# Must have symbols
if total < 100:
    print(f"FAIL: Only {total} symbols (need >= 100)")
    errors += 1
else:
    print(f"PASS: {total} symbols in universe")

# Must have fixture coverage >= 50%
if coverage < 50:
    print(f"FAIL: Fixture coverage {coverage}% < 50%")
    errors += 1
else:
    print(f"PASS: Fixture coverage {coverage}%")

# Must have >= 200 total cases
if total_cases < 200:
    print(f"FAIL: Only {total_cases} total cases (need >= 200)")
    errors += 1
else:
    print(f"PASS: {total_cases} fixture cases")

# No format issues
if format_issues > 0:
    print(f"FAIL: {format_issues} fixture format issues")
    errors += 1
else:
    print("PASS: No fixture format issues")

# Edge case coverage should exist
if edge_count < 20:
    print(f"FAIL: Only {edge_count} symbols with edge cases (need >= 20)")
    errors += 1
else:
    print(f"PASS: {edge_count} symbols have edge case coverage")

# Implemented symbols should have >= 50% coverage
if impl_cov < 50:
    print(f"FAIL: Implemented symbol coverage {impl_cov}% < 50%")
    errors += 1
else:
    print(f"PASS: Implemented symbol coverage {impl_cov}%")

# Uncovered action list must be present
actions = report.get("uncovered_action_list", [])
if with_fix < total and not actions:
    print("FAIL: Missing uncovered action list")
    errors += 1
else:
    print(f"PASS: {len(actions)} uncovered symbols documented with actions")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_per_symbol_fixture_tests: PASS")
PY
