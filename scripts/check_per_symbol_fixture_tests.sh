#!/usr/bin/env bash
# check_per_symbol_fixture_tests.sh — CI gate for bd-ldj.5
# Validates per-symbol conformance fixture unit test coverage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL_REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_REPORT:-$REPO_ROOT/tests/conformance/per_symbol_fixture_tests.v1.json}"
GENERATED_REPORT="${FRANKENLIBC_PER_SYMBOL_FIXTURE_GENERATED_REPORT:-$REPO_ROOT/target/conformance/per_symbol_fixture_tests.generated.v1.json}"
BASELINE="${FRANKENLIBC_PER_SYMBOL_FIXTURE_BASELINE:-$REPO_ROOT/tests/conformance/conformance_coverage_baseline.v1.json}"
MODE="regenerate"

usage() {
    cat <<'USAGE'
Usage: scripts/check_per_symbol_fixture_tests.sh [--validate-only]

Modes:
  default          Regenerate tests/conformance/per_symbol_fixture_tests.v1.json in place.
  --validate-only  Regenerate to target/conformance, compare against the canonical
                   report ignoring volatile generated_at metadata, and leave the
                   canonical report unchanged.

Environment overrides:
  FRANKENLIBC_PER_SYMBOL_FIXTURE_REPORT
  FRANKENLIBC_PER_SYMBOL_FIXTURE_GENERATED_REPORT
  FRANKENLIBC_PER_SYMBOL_FIXTURE_BASELINE
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --validate-only)
            MODE="validate-only"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FAIL: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

echo "=== Per-Symbol Fixture Tests Gate (bd-ldj.5) ==="

if [ "$MODE" = "validate-only" ]; then
    REPORT="$GENERATED_REPORT"
    echo "--- Generating per-symbol fixture test report for validation ---"
    mkdir -p "$(dirname "$GENERATED_REPORT")"
else
    REPORT="$CANONICAL_REPORT"
    echo "--- Generating per-symbol fixture test report ---"
fi

python3 "$SCRIPT_DIR/generate_per_symbol_fixture_tests.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: per-symbol fixture test report not generated"
    exit 1
fi

if [ "$MODE" = "validate-only" ]; then
    if [ ! -f "$CANONICAL_REPORT" ]; then
        echo "FAIL: canonical per-symbol fixture test report missing: $CANONICAL_REPORT"
        exit 1
    fi

    python3 - "$CANONICAL_REPORT" "$GENERATED_REPORT" <<'PY'
import json
import sys

canonical_path = sys.argv[1]
generated_path = sys.argv[2]

with open(canonical_path, encoding="utf-8") as f:
    canonical = json.load(f)
with open(generated_path, encoding="utf-8") as f:
    generated = json.load(f)

canonical.pop("generated_at", None)
generated.pop("generated_at", None)

if canonical != generated:
    print("FAIL: generated per-symbol fixture report differs from canonical report")
    print(f"  canonical: {canonical_path}")
    print(f"  generated: {generated_path}")
    print("  volatile field ignored: generated_at")
    sys.exit(1)

print("PASS: generated report matches canonical report ignoring generated_at")
PY
fi

python3 - "$REPORT" "$BASELINE" <<'PY'
import json, sys

report_path = sys.argv[1]
baseline_path = sys.argv[2]
errors = 0

with open(report_path) as f:
    report = json.load(f)
with open(baseline_path) as f:
    baseline = json.load(f)

summary = report.get("summary", {})
baseline_summary = baseline.get("summary", {})
symbols = report.get("per_symbol_report", [])
files = report.get("fixture_file_analyses", [])

total = summary.get("total_symbols", 0)
with_fix = summary.get("symbols_with_fixtures", 0)
coverage = summary.get("fixture_coverage_pct", 0)
impl_cov = summary.get("implemented_coverage_pct", 0)
total_cases = summary.get("total_cases", 0)
edge_count = summary.get("symbols_with_edge_cases", 0)
format_issues = summary.get("total_format_issues", 0)
baseline_with_fix = baseline_summary.get("symbols_with_fixtures", 0)
baseline_coverage = baseline_summary.get("coverage_pct", 0)

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

# Must not regress below canonical fixture coverage baseline.
if coverage + 0.25 < baseline_coverage:
    print(f"FAIL: Fixture coverage {coverage}% < baseline {baseline_coverage}%")
    errors += 1
else:
    print(f"PASS: Fixture coverage {coverage}% (baseline {baseline_coverage}%)")

if with_fix < baseline_with_fix:
    print(f"FAIL: Fixture-linked symbols {with_fix} < baseline {baseline_with_fix}")
    errors += 1
else:
    print(f"PASS: Fixture-linked symbols {with_fix} (baseline {baseline_with_fix})")

# Must still have a meaningful case inventory.
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

# Implemented coverage should remain non-zero while the broader fixture program expands.
if impl_cov <= 0:
    print(f"FAIL: Implemented symbol coverage {impl_cov}% <= 0%")
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
