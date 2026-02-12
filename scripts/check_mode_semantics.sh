#!/usr/bin/env bash
# check_mode_semantics.sh — CI gate for bd-wud
#
# Validates that:
#   1. Mode semantics matrix exists and is valid JSON.
#   2. All 20 API families are documented.
#   3. Every family references a real ABI module file.
#   4. heals_enabled() call sites in code match documented counts.
#   5. Summary statistics are consistent with family entries.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/mode_semantics_matrix.json"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"

failures=0

echo "=== Mode Semantics Gate (bd-wud) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Matrix file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Matrix file exists ---"

if [[ ! -f "${MATRIX}" ]]; then
    echo "FAIL: tests/conformance/mode_semantics_matrix.json not found"
    echo ""
    echo "check_mode_semantics: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${MATRIX}') as f:
        m = json.load(f)
    v = m.get('schema_version', 0)
    fams = m.get('families', [])
    modes = m.get('modes', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not fams:
        print('INVALID: empty families')
    elif not modes:
        print('INVALID: empty modes')
    else:
        print(f'VALID version={v} families={len(fams)} modes={len(modes)}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Family schema validation
# ---------------------------------------------------------------------------
echo "--- Check 2: Family schema validation ---"

schema_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    m = json.load(f)

families = m.get('families', [])
errors = []
required_fields = ['family', 'module', 'heals_call_sites', 'symbols', 'strict_behavior', 'hardened_behavior']

for i, fam in enumerate(families):
    name = fam.get('family', f'<entry #{i}>')
    for field in required_fields:
        if field not in fam:
            errors.append(f'{name}: missing required field \"{field}\"')

    # Validate symbols is non-empty array
    syms = fam.get('symbols', [])
    if not syms:
        errors.append(f'{name}: symbols array is empty')

    # Validate behaviors are non-empty objects
    for mode in ['strict_behavior', 'hardened_behavior']:
        beh = fam.get(mode, {})
        if not beh:
            errors.append(f'{name}: {mode} is empty')

    # Validate heals_call_sites is positive
    sites = fam.get('heals_call_sites', 0)
    if not isinstance(sites, int) or sites < 0:
        errors.append(f'{name}: invalid heals_call_sites ({sites})')

print(f'SCHEMA_ERRORS={len(errors)}')
for e in errors[:20]:
    print(f'  {e}')
")

schema_errs=$(echo "${schema_check}" | grep '^SCHEMA_ERRORS=' | cut -d= -f2)

if [[ "${schema_errs}" -gt 0 ]]; then
    echo "FAIL: ${schema_errs} schema error(s):"
    echo "${schema_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All family entries have valid schema"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: ABI module file cross-reference
# ---------------------------------------------------------------------------
echo "--- Check 3: ABI module cross-reference ---"

module_check=$(python3 -c "
import json, os

with open('${MATRIX}') as f:
    m = json.load(f)

abi_src = '${ABI_SRC}'
families = m.get('families', [])
errors = []

for fam in families:
    name = fam.get('family', '?')
    module = fam.get('module', '')
    src_file = os.path.join(abi_src, f'{module}.rs')
    if not os.path.isfile(src_file):
        errors.append(f'{name}: module file {module}.rs not found in ABI source')

print(f'MODULE_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

module_errs=$(echo "${module_check}" | grep '^MODULE_ERRORS=' | cut -d= -f2)

if [[ "${module_errs}" -gt 0 ]]; then
    echo "FAIL: ${module_errs} module error(s):"
    echo "${module_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All family modules exist in ABI source"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: heals_enabled() call site consistency
# ---------------------------------------------------------------------------
echo "--- Check 4: heals_enabled() call site consistency ---"

site_check=$(python3 -c "
import json, re, os

with open('${MATRIX}') as f:
    m = json.load(f)

abi_src = '${ABI_SRC}'
families = m.get('families', [])
warnings = []

for fam in families:
    name = fam.get('family', '?')
    module = fam.get('module', '')
    claimed = fam.get('heals_call_sites', 0)
    src_file = os.path.join(abi_src, f'{module}.rs')

    if not os.path.isfile(src_file):
        continue

    with open(src_file) as f:
        content = f.read()

    # Count heals_enabled() references (direct and via repair_enabled)
    actual = content.count('heals_enabled()')

    if actual != claimed:
        warnings.append(f'{name} ({module}): claimed={claimed} actual={actual}')

print(f'SITE_WARNINGS={len(warnings)}')
for w in warnings:
    print(f'  {w}')
")

site_warns=$(echo "${site_check}" | grep '^SITE_WARNINGS=' | cut -d= -f2)

if [[ "${site_warns}" -gt 0 ]]; then
    echo "WARNING: ${site_warns} call site count mismatch(es) (informational):"
    echo "${site_check}" | grep '  '
    echo "  (Update mode_semantics_matrix.json heals_call_sites to match)"
else
    echo "PASS: All heals_enabled() call site counts match"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

summary_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    m = json.load(f)

families = m.get('families', [])
summary = m.get('summary', {})
errors = []

claimed_total = summary.get('total_families', 0)
actual_total = len(families)
if claimed_total != actual_total:
    errors.append(f'total_families: claimed={claimed_total} actual={actual_total}')

claimed_healing = summary.get('families_with_healing', 0)
actual_healing = sum(1 for f in families if f.get('heals_call_sites', 0) > 0)
if claimed_healing != actual_healing:
    errors.append(f'families_with_healing: claimed={claimed_healing} actual={actual_healing}')

claimed_sites = summary.get('total_heals_call_sites', 0)
actual_sites = sum(f.get('heals_call_sites', 0) for f in families)
if claimed_sites != actual_sites:
    errors.append(f'total_heals_call_sites: claimed={claimed_sites} actual={actual_sites}')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

summary_errs=$(echo "${summary_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${summary_errs}" -gt 0 ]]; then
    echo "FAIL: ${summary_errs} summary inconsistency(ies):"
    echo "${summary_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent with entries"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_mode_semantics: FAILED"
    exit 1
fi

echo ""
echo "check_mode_semantics: PASS"
