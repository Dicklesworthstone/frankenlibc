#!/usr/bin/env bash
# check_fuzz_phase2_targets.sh — CI gate for bd-1oz.7
# Validates phase-2 fuzz target readiness and nightly policy thresholds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fuzz_phase2_targets.v1.json"

echo "=== Fuzz Phase-2 Targets Gate (bd-1oz.7) ==="

echo "--- Generating phase-2 fuzz target report ---"
python3 "$SCRIPT_DIR/generate_fuzz_phase2_targets.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: phase-2 fuzz target report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json
import sys

report_path = sys.argv[1]
errors = 0

with open(report_path, encoding="utf-8") as f:
    report = json.load(f)

summary = report.get("summary", {})
targets = report.get("target_assessments", [])
policy = report.get("nightly_policy", {})
coverage = report.get("coverage_summary", {})

total = summary.get("total_targets", 0)
functional = summary.get("functional_targets", 0)
smoke_viable = summary.get("smoke_viable_targets", 0)
avg_score = summary.get("average_readiness_score", 0)
symbols = summary.get("total_symbols_covered", 0)
families = summary.get("transition_families_covered", 0)

print(f"Phase-2 targets:         {total}")
print(f"  Functional:            {functional}")
print(f"  Smoke-viable:          {smoke_viable}")
print(f"  Avg readiness score:   {avg_score}")
print(f"  Symbols covered:       {symbols}")
print(f"  Transition families:   {families}")
print()

if total < 4:
    print(f"FAIL: Only {total} phase-2 targets (need >= 4)")
    errors += 1
else:
    print(f"PASS: {total} phase-2 targets found")

if functional < 4:
    print(f"FAIL: Only {functional} functional targets (need >= 4)")
    errors += 1
else:
    print(f"PASS: {functional} functional targets")

if smoke_viable < total:
    print(f"FAIL: Only {smoke_viable}/{total} targets are smoke-viable")
    errors += 1
else:
    print(f"PASS: All {total} targets are smoke-viable")

if avg_score < 70:
    print(f"FAIL: Average readiness {avg_score} < 70")
    errors += 1
else:
    print(f"PASS: Average readiness score {avg_score}")

if symbols < 10:
    print(f"FAIL: Only {symbols} symbols covered (need >= 10)")
    errors += 1
else:
    print(f"PASS: {symbols} symbols covered")

required_families = {"resolver", "locale", "runtime-math"}
observed_families = set(coverage.get("transition_families", []))
missing = sorted(required_families - observed_families)
if missing:
    print(f"FAIL: Missing transition families: {', '.join(missing)}")
    errors += 1
else:
    print("PASS: Resolver, locale, and runtime-math families covered")

if policy.get("target_group") != "phase2":
    print("FAIL: Nightly policy target group must be phase2")
    errors += 1
else:
    print("PASS: Nightly policy targets phase2")

if policy.get("max_crashes") != 0:
    print("FAIL: Nightly policy must fail on any crash")
    errors += 1
else:
    print("PASS: Nightly policy fails on any crash")

if policy.get("runs_per_target", 0) < 1_000_000:
    print("FAIL: Nightly policy runs_per_target below 1,000,000")
    errors += 1
else:
    print("PASS: Nightly run budget meets threshold")

required_targets = set(policy.get("required_targets", []))
actual_targets = {target.get("target") for target in targets}
if required_targets != actual_targets:
    print("FAIL: Nightly policy target set does not match report targets")
    errors += 1
else:
    print("PASS: Nightly policy target set matches report targets")

if errors:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print("\ncheck_fuzz_phase2_targets: PASS")
PY
