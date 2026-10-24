#!/usr/bin/env bash
# check_cve_format_string_validation.sh — CI gate for bd-1m5.2
# Validates the CVE Arena format string test suite completeness.
#
# Checks:
#   1. Validation report generates successfully.
#   2. All format string manifests are valid.
#   3. C triggers compile.
#   4. UpgradeToSafeVariant healing action exercised.
#   5. All three attack vector types covered (info_leak, crash, write).
#   6. Coverage matrix includes all format string CVEs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/format_string_validation.v1.json"

echo "=== CVE Format String Validation Gate (bd-1m5.2) ==="

# 1. Generate the validation report
echo "--- Generating format string validation report ---"
python3 "$SCRIPT_DIR/generate_cve_format_string_validation.py" -o "$REPORT" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: validation report not generated"
    exit 1
fi

# 2. Validate report and check thresholds
python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
tests = report.get("tests", [])

total = summary.get("total_format_string_tests", 0)
valid = summary.get("manifests_valid", 0)
with_triggers = summary.get("with_trigger_files", 0)
c_compiles = summary.get("c_triggers_compile", 0)
c_healed = summary.get("c_triggers_hardened_healed", 0)
c_total = summary.get("c_triggers_total", 0)
healing = summary.get("unique_healing_actions", [])
vectors_covered = set(summary.get("attack_vectors_covered", []))
vectors_target = set(summary.get("attack_vectors_target", []))
issues = summary.get("total_issues", 0)

print(f"Format string tests: {total}")
print(f"  Manifests valid:   {valid}/{total}")
print(f"  With triggers:     {with_triggers}/{total}")
print(f"  C compiles:        {c_compiles}/{c_total}")
print(f"  C healed (LD_PRELOAD): {c_healed}/{c_total}")
print(f"  Issues:            {issues}")
print(f"  Healing actions:   {', '.join(healing)}")
print(f"  Attack vectors:    {', '.join(sorted(vectors_covered))}")

for t in tests:
    status = "VALID" if t["manifest_valid"] else "INVALID"
    comp = ""
    if t["c_compiles"] is not None:
        comp = " [compiles]" if t["c_compiles"] else " [COMPILE FAIL]"
    triggers = ", ".join(t["trigger_files"])
    print(f"\n  {t['cve_id']:35s} CVSS={t.get('cvss_score', '?'):>4}  {status}{comp}  [{triggers}]")
    av = t.get("attack_vectors", {})
    if av.get("vector_details"):
        for v in av["vector_details"]:
            print(f"    vector: {v['name']:12s} payload={v['payload'][:30]}")

matrix = report.get("coverage_matrix_check", {})
if matrix.get("exists"):
    missing = matrix.get("format_cves_missing", [])
    if missing:
        print(f"\nCoverage matrix missing format CVEs: {', '.join(missing)}")
    else:
        print(f"\nCoverage matrix: all format string CVEs present")

print("")

# Check 1: Manifests valid
if valid < total:
    print(f"FAIL: {total - valid} invalid manifest(s)")
    errors += 1
else:
    print(f"PASS: All {total} manifests valid")

# Check 2: Triggers exist
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

# Check 4: UpgradeToSafeVariant exercised
if "UpgradeToSafeVariant" not in healing:
    print("FAIL: UpgradeToSafeVariant healing not exercised")
    errors += 1
else:
    print("PASS: UpgradeToSafeVariant healing exercised")

# Check 5: All attack vector types covered
missing_vectors = vectors_target - vectors_covered
if missing_vectors:
    print(f"FAIL: Missing attack vectors: {', '.join(sorted(missing_vectors))}")
    errors += 1
else:
    print(f"PASS: All {len(vectors_target)} attack vector types covered")

# Check 6: Coverage matrix
if matrix.get("exists"):
    missing = matrix.get("format_cves_missing", [])
    if missing:
        print(f"FAIL: Coverage matrix missing: {', '.join(missing)}")
        errors += 1
    else:
        print("PASS: Coverage matrix includes all format string CVEs")

# Check 7: At least one test exists
if total == 0:
    print("FAIL: No format string tests found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_format_string_validation: PASS")
PY
