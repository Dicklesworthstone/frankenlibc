#!/usr/bin/env bash
# check_cve_heap_overflow_validation.sh — CI gate for bd-1m5.1
# Validates the CVE Arena heap overflow test suite completeness.
#
# Checks:
#   1. Validation report generates successfully.
#   2. All heap overflow manifests are valid.
#   3. All C triggers compile.
#   4. ClampSize healing action is exercised.
#   5. Coverage matrix includes all heap CVEs.
#
# --strict: requires >= 5 heap overflow tests and CWE-122 coverage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/heap_overflow_validation.v1.json"

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

echo "=== CVE Heap Overflow Validation Gate (bd-1m5.1) ==="

# 1. Generate the validation report
echo "--- Generating heap overflow validation report ---"
python3 "$SCRIPT_DIR/generate_cve_heap_overflow_validation.py" -o "$REPORT" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: validation report not generated"
    exit 1
fi

# 2. Validate report and check thresholds
python3 - "$REPORT" "$STRICT" <<'PY'
import json, sys

report_path = sys.argv[1]
strict = sys.argv[2].lower() == "true"
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
tests = report.get("tests", [])

total = summary.get("total_heap_overflow_tests", 0)
valid = summary.get("manifests_valid", 0)
with_triggers = summary.get("with_trigger_files", 0)
c_compiles = summary.get("c_triggers_compile", 0)
c_healed = summary.get("c_triggers_hardened_healed", 0)
c_total = summary.get("c_triggers_total", 0)
healing = summary.get("unique_healing_actions", [])
cwes_covered = set(summary.get("heap_cwes_covered", []))
issues = summary.get("total_issues", 0)

print(f"Heap overflow tests: {total}")
print(f"  Manifests valid:   {valid}/{total}")
print(f"  With triggers:     {with_triggers}/{total}")
print(f"  C compiles:        {c_compiles}/{c_total}")
print(f"  C healed (LD_PRELOAD): {c_healed}/{c_total}")
print(f"  Issues:            {issues}")
print(f"  Healing actions:   {', '.join(healing)}")
print(f"  CWEs covered:      {', '.join(sorted(cwes_covered))}")

# Per-test details
print(f"\nTest details:")
for t in tests:
    status = "VALID" if t["manifest_valid"] else "INVALID"
    comp = ""
    if t["c_compiles"] is not None:
        comp = " [compiles]" if t["c_compiles"] else " [COMPILE FAIL]"
    triggers = ", ".join(t["trigger_files"])
    print(f"  {t['cve_id']:35s} CVSS={t.get('cvss_score', '?'):>4}  {status}{comp}  [{triggers}]")
    if t["issues"]:
        for iss in t["issues"]:
            print(f"    ISSUE: {iss}")

# Coverage matrix
matrix = report.get("coverage_matrix_check", {})
if matrix.get("exists"):
    missing = matrix.get("heap_cves_missing", [])
    if missing:
        print(f"\nCoverage matrix missing heap CVEs: {', '.join(missing)}")
    else:
        print(f"\nCoverage matrix: all heap CVEs present ({matrix.get('total_cves_in_matrix', 0)} total)")

print("")

# Check 1: All manifests valid
if valid < total:
    print(f"FAIL: {total - valid} invalid manifest(s)")
    errors += 1
else:
    print(f"PASS: All {total} manifests valid")

# Check 2: All tests have triggers
if with_triggers < total:
    print(f"FAIL: {total - with_triggers} test(s) missing triggers")
    errors += 1
else:
    print(f"PASS: All {total} tests have trigger files")

# Check 3: C triggers compile
if c_total > 0 and c_compiles < c_total:
    print(f"FAIL: {c_total - c_compiles} C trigger(s) fail to compile")
    errors += 1
elif c_total > 0:
    print(f"PASS: All {c_total} C triggers compile")

if c_total > 0 and c_healed < c_total:
    print(f"FAIL: {c_total - c_healed} C trigger(s) failed hardened LD_PRELOAD healing check")
    errors += 1
elif c_total > 0:
    print(f"PASS: All {c_total} C triggers healed under hardened LD_PRELOAD")

# Check 4: ClampSize exercised (key healing for heap overflows)
if "ClampSize" not in healing:
    print("FAIL: ClampSize healing not exercised by any test")
    errors += 1
else:
    print("PASS: ClampSize healing action exercised")

# Check 5: Coverage matrix includes all heap CVEs
if matrix.get("exists"):
    missing = matrix.get("heap_cves_missing", [])
    if missing:
        print(f"FAIL: Coverage matrix missing: {', '.join(missing)}")
        errors += 1
    else:
        print("PASS: Coverage matrix includes all heap CVEs")

# Check 6: No validation issues
if issues > 0:
    print(f"FAIL: {issues} validation issue(s)")
    errors += 1
else:
    print("PASS: Zero validation issues")

# Strict checks
if strict:
    if total < 5:
        print(f"FAIL: Only {total} heap overflow tests (strict requires >= 5)")
        errors += 1
    else:
        print(f"PASS: {total} heap overflow tests >= 5 (strict)")

    if "CWE-122" not in cwes_covered:
        print("FAIL: CWE-122 (Heap Buffer Overflow) not covered (strict)")
        errors += 1
    else:
        print("PASS: CWE-122 covered (strict)")

if errors > 0:
    mode = "strict" if strict else "default"
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

mode = "strict" if strict else "default"
print(f"\ncheck_cve_heap_overflow_validation ({mode}): PASS")
PY
