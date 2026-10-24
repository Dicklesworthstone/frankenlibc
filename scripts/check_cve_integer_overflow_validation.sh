#!/usr/bin/env bash
# check_cve_integer_overflow_validation.sh — CI gate for bd-1m5.4
# Validates the CVE Arena integer overflow test suite completeness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/integer_overflow_validation.v1.json"

echo "=== CVE Integer Overflow Validation Gate (bd-1m5.4) ==="

echo "--- Generating integer overflow validation report ---"
python3 "$SCRIPT_DIR/generate_cve_integer_overflow_validation.py" -o "$REPORT" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: validation report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
tests = report.get("tests", [])

total = summary.get("total_intovf_tests", 0)
valid = summary.get("manifests_valid", 0)
with_triggers = summary.get("with_trigger_files", 0)
c_compiles = summary.get("c_triggers_compile", 0)
c_healed = summary.get("c_triggers_hardened_healed", 0)
c_total = summary.get("c_triggers_total", 0)
healing = summary.get("unique_healing_actions", [])
patterns = set(summary.get("overflow_patterns_covered", []))
issues = summary.get("total_issues", 0)

print(f"Integer overflow tests: {total}")
print(f"  Manifests valid:     {valid}/{total}")
print(f"  With triggers:       {with_triggers}/{total}")
print(f"  C compiles:          {c_compiles}/{c_total}")
print(f"  C healed (LD_PRELOAD): {c_healed}/{c_total}")
print(f"  Issues:              {issues}")
print(f"  Healing actions:     {', '.join(healing)}")
print(f"  Overflow patterns:   {', '.join(sorted(patterns))}")

for t in tests:
    status = "VALID" if t["manifest_valid"] else "INVALID"
    comp = ""
    if t["c_compiles"] is not None:
        comp = " [compiles]" if t["c_compiles"] else " [COMPILE FAIL]"
    triggers = ", ".join(t["trigger_files"])
    pats = ", ".join(t["overflow_patterns"])
    print(f"  {t['cve_id']:35s} CVSS={t.get('cvss_score', '?'):>4}  {status}{comp}  patterns=[{pats}]")

matrix = report.get("coverage_matrix_check", {})
if matrix.get("exists"):
    missing = matrix.get("intovf_cves_missing", [])
    if missing:
        print(f"\nCoverage matrix missing: {', '.join(missing)}")
    else:
        print(f"\nCoverage matrix: all integer overflow CVEs present")

print("")

if valid < total:
    print(f"FAIL: {total - valid} invalid manifest(s)")
    errors += 1
else:
    print(f"PASS: All {total} manifests valid")

if with_triggers < total:
    print(f"FAIL: {total - with_triggers} test(s) missing triggers")
    errors += 1
else:
    print(f"PASS: All {total} tests have trigger files")

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

# Integer overflow specific: must exercise ClampSize healing
if "ClampSize" not in healing:
    print("FAIL: ClampSize healing action not exercised")
    errors += 1
else:
    print(f"PASS: ClampSize healing action exercised")

# Must cover integer_overflow pattern
if "integer_overflow" not in patterns:
    print("FAIL: integer_overflow pattern not covered")
    errors += 1
else:
    print(f"PASS: integer_overflow pattern covered")

if matrix.get("exists"):
    missing = matrix.get("intovf_cves_missing", [])
    if missing:
        print(f"FAIL: Coverage matrix missing: {', '.join(missing)}")
        errors += 1
    else:
        print("PASS: Coverage matrix includes all integer overflow CVEs")

if total == 0:
    print("FAIL: No integer overflow tests found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_integer_overflow_validation: PASS")
PY
