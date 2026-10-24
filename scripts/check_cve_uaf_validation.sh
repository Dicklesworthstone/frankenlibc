#!/usr/bin/env bash
# check_cve_uaf_validation.sh — CI gate for bd-1m5.3
# Validates the CVE Arena use-after-free test suite completeness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/uaf_validation.v1.json"

echo "=== CVE Use-After-Free Validation Gate (bd-1m5.3) ==="

echo "--- Generating UAF validation report ---"
python3 "$SCRIPT_DIR/generate_cve_uaf_validation.py" -o "$REPORT" 2>&1

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

total = summary.get("total_uaf_tests", 0)
valid = summary.get("manifests_valid", 0)
with_triggers = summary.get("with_trigger_files", 0)
c_compiles = summary.get("c_triggers_compile", 0)
c_healed = summary.get("c_triggers_hardened_healed", 0)
c_total = summary.get("c_triggers_total", 0)
healing = summary.get("unique_healing_actions", [])
patterns = set(summary.get("uaf_patterns_covered", []))
issues = summary.get("total_issues", 0)

print(f"UAF tests:          {total}")
print(f"  Manifests valid:  {valid}/{total}")
print(f"  With triggers:    {with_triggers}/{total}")
print(f"  C compiles:       {c_compiles}/{c_total}")
print(f"  C healed (LD_PRELOAD): {c_healed}/{c_total}")
print(f"  Issues:           {issues}")
print(f"  Healing actions:  {', '.join(healing)}")
print(f"  UAF patterns:     {', '.join(sorted(patterns))}")

for t in tests:
    status = "VALID" if t["manifest_valid"] else "INVALID"
    comp = ""
    if t["c_compiles"] is not None:
        comp = " [compiles]" if t["c_compiles"] else " [COMPILE FAIL]"
    triggers = ", ".join(t["trigger_files"])
    pats = ", ".join(t["uaf_patterns"])
    print(f"  {t['cve_id']:35s} CVSS={t.get('cvss_score', '?'):>4}  {status}{comp}  patterns=[{pats}]")

matrix = report.get("coverage_matrix_check", {})
if matrix.get("exists"):
    missing = matrix.get("uaf_cves_missing", [])
    if missing:
        print(f"\nCoverage matrix missing: {', '.join(missing)}")
    else:
        print(f"\nCoverage matrix: all UAF CVEs present")

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

# UAF-specific: must exercise IgnoreDoubleFree or IgnoreForeignFree
uaf_healing = {"IgnoreDoubleFree", "IgnoreForeignFree"} & set(healing)
if not uaf_healing:
    print("FAIL: No UAF-specific healing actions exercised")
    errors += 1
else:
    print(f"PASS: UAF healing actions exercised ({', '.join(sorted(uaf_healing))})")

# Must cover both use_after_free and double_free patterns
required_patterns = {"use_after_free", "double_free"}
missing_patterns = required_patterns - patterns
if missing_patterns:
    print(f"FAIL: Missing UAF patterns: {', '.join(sorted(missing_patterns))}")
    errors += 1
else:
    print(f"PASS: Both use_after_free and double_free patterns covered")

if matrix.get("exists"):
    missing = matrix.get("uaf_cves_missing", [])
    if missing:
        print(f"FAIL: Coverage matrix missing: {', '.join(missing)}")
        errors += 1
    else:
        print("PASS: Coverage matrix includes all UAF CVEs")

if total == 0:
    print("FAIL: No UAF tests found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_uaf_validation: PASS")
PY
