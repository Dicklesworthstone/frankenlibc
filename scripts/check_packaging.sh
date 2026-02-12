#!/usr/bin/env bash
# check_packaging.sh — CI gate for bd-30h
#
# Validates that:
#   1. Packaging spec JSON exists and is valid.
#   2. Both artifacts (interpose/replace) are defined with required fields.
#   3. Assessment counts match support_matrix.json.
#   4. Replace blockers match actual GlibcCallThrough+Stub symbols.
#   5. Interpose artifact build command succeeds (cdylib exists).
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/packaging_spec.json"
MATRIX="${ROOT}/support_matrix.json"
README="${ROOT}/README.md"

failures=0

echo "=== Packaging Gate (bd-30h) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Spec file exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/packaging_spec.json not found"
    echo ""
    echo "check_packaging: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
import re
try:
    with open('${SPEC}') as f:
        spec = json.load(f)
    v = spec.get('schema_version', 0)
    artifacts = spec.get('artifacts', {})
    assessment = spec.get('current_assessment', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not artifacts:
        print('INVALID: empty artifacts')
    elif not assessment:
        print('INVALID: empty current_assessment')
    else:
        print(f'VALID version={v} artifacts={len(artifacts)} symbols={assessment.get(\"total_symbols\", 0)}')
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
# Check 2: Both artifacts defined with required fields
# ---------------------------------------------------------------------------
echo "--- Check 2: Artifact definitions ---"

artifact_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

artifacts = spec.get('artifacts', {})
errors = []
required_fields = ['name', 'artifact_name', 'description', 'build_command', 'output_path',
                   'host_glibc_required', 'allowed_statuses', 'replacement_levels',
                   'cargo_profile', 'crate_type', 'guarantee']

for artifact_id in ['interpose', 'replace']:
    if artifact_id not in artifacts:
        errors.append(f'Missing artifact: {artifact_id}')
        continue
    art = artifacts[artifact_id]
    for field in required_fields:
        if field not in art:
            errors.append(f'{artifact_id}: missing field \"{field}\"')

    # Interpose must allow all statuses
    if artifact_id == 'interpose':
        allowed = set(art.get('allowed_statuses', []))
        required = {'Implemented', 'RawSyscall', 'GlibcCallThrough', 'Stub'}
        missing = required - allowed
        if missing:
            errors.append(f'interpose: allowed_statuses missing {missing}')
        if not art.get('host_glibc_required', False):
            errors.append('interpose: host_glibc_required should be true')

    # Replace must only allow standalone statuses
    if artifact_id == 'replace':
        allowed = set(art.get('allowed_statuses', []))
        forbidden = allowed & {'GlibcCallThrough', 'Stub'}
        if forbidden:
            errors.append(f'replace: allowed_statuses should not include {forbidden}')
        if art.get('host_glibc_required', True):
            errors.append('replace: host_glibc_required should be false')

print(f'ARTIFACT_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

artifact_errs=$(echo "${artifact_check}" | grep '^ARTIFACT_ERRORS=' | cut -d= -f2)

if [[ "${artifact_errs}" -gt 0 ]]; then
    echo "FAIL: ${artifact_errs} artifact definition error(s):"
    echo "${artifact_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Both artifacts defined with required fields and correct contracts"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: support_matrix artifact applicability matches packaging contracts
# ---------------------------------------------------------------------------
echo "--- Check 3: support_matrix artifact applicability ---"

applicability_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
tax = matrix.get('taxonomy', {})
app = tax.get('artifact_applicability')

if not isinstance(app, dict):
    errors.append('support_matrix.taxonomy.artifact_applicability missing or invalid')
else:
    interpose_expected = set(spec.get('artifacts', {}).get('interpose', {}).get('allowed_statuses', []))
    replace_expected = set(spec.get('artifacts', {}).get('replace', {}).get('allowed_statuses', []))
    interpose_decl = set(app.get('Interpose', []))
    replace_decl = set(app.get('Replace', []))

    if interpose_decl != interpose_expected:
        errors.append(
            f'Interpose applicability mismatch: matrix={sorted(interpose_decl)} spec={sorted(interpose_expected)}'
        )
    if replace_decl != replace_expected:
        errors.append(
            f'Replace applicability mismatch: matrix={sorted(replace_decl)} spec={sorted(replace_expected)}'
        )
    if not app.get('rule'):
        errors.append('artifact_applicability.rule is missing')

print(f'APPLICABILITY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

app_errs=$(echo "${applicability_check}" | grep '^APPLICABILITY_ERRORS=' | cut -d= -f2)
if [[ "${app_errs}" -gt 0 ]]; then
    echo "FAIL: ${app_errs} artifact applicability error(s):"
    echo "${applicability_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: support_matrix artifact applicability aligns with packaging spec"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Assessment counts match support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 4: Assessment counts ---"

assess_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
assessment = spec.get('current_assessment', {})
symbols = matrix.get('symbols', [])

# Total
matrix_total = len(symbols)
claimed_total = assessment.get('total_symbols', 0)
if claimed_total != matrix_total:
    errors.append(f'total_symbols: spec={claimed_total} matrix={matrix_total}')

# Count by status
counts = {}
for sym in symbols:
    st = sym.get('status', 'Unknown')
    counts[st] = counts.get(st, 0) + 1

dist = assessment.get('symbol_distribution', {})
for st, claimed in dist.items():
    actual = counts.get(st, 0)
    if claimed != actual:
        errors.append(f'symbol_distribution.{st}: spec={claimed} matrix={actual}')

# interpose_ready should be total (all symbols)
interpose_ready = assessment.get('interpose_ready', 0)
if interpose_ready != matrix_total:
    errors.append(f'interpose_ready: spec={interpose_ready} should be {matrix_total}')

# replace_ready = Implemented + RawSyscall
impl_count = counts.get('Implemented', 0) + counts.get('RawSyscall', 0)
replace_ready = assessment.get('replace_ready', 0)
if replace_ready != impl_count:
    errors.append(f'replace_ready: spec={replace_ready} should be {impl_count}')

# replace_blocked = GlibcCallThrough + Stub
blocked_count = counts.get('GlibcCallThrough', 0) + counts.get('Stub', 0)
replace_blocked = assessment.get('replace_blocked', 0)
if replace_blocked != blocked_count:
    errors.append(f'replace_blocked: spec={replace_blocked} should be {blocked_count}')

print(f'ASSESS_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution
print()
print(f'Interpose: {interpose_ready}/{matrix_total} symbols ready (100%)')
pct = round(replace_ready * 100 / matrix_total) if matrix_total > 0 else 0
print(f'Replace: {replace_ready}/{matrix_total} symbols ready ({pct}%)')
print(f'Replace blockers: {replace_blocked} symbols')
")

assess_errs=$(echo "${assess_check}" | grep '^ASSESS_ERRORS=' | cut -d= -f2)

if [[ "${assess_errs}" -gt 0 ]]; then
    echo "FAIL: ${assess_errs} assessment mismatch(es):"
    echo "${assess_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Assessment counts match support_matrix.json"
fi
echo "${assess_check}" | grep -E '^(Interpose|Replace)' || true
echo ""

# ---------------------------------------------------------------------------
# Check 5: Replace blockers match actual CallThrough+Stub
# ---------------------------------------------------------------------------
echo "--- Check 5: Replace blockers ---"

blocker_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
replace = spec.get('artifacts', {}).get('replace', {})
blockers = replace.get('blockers', {})

# Count actual GlibcCallThrough by module
ct_by_mod = {}
for sym in matrix.get('symbols', []):
    if sym.get('status') == 'GlibcCallThrough':
        m = sym.get('module', 'unknown')
        ct_by_mod[m] = ct_by_mod.get(m, 0) + 1

# Count actual Stub by module
stub_by_mod = {}
for sym in matrix.get('symbols', []):
    if sym.get('status') == 'Stub':
        m = sym.get('module', 'unknown')
        stub_by_mod[m] = stub_by_mod.get(m, 0) + 1

# Check callthrough breakdown
ct_claimed = blockers.get('GlibcCallThrough_remaining', {})
for m, claimed in ct_claimed.items():
    actual = ct_by_mod.get(m, 0)
    if claimed != actual:
        errors.append(f'GlibcCallThrough_remaining.{m}: spec={claimed} matrix={actual}')

for m, actual in ct_by_mod.items():
    if m not in ct_claimed:
        errors.append(f'GlibcCallThrough_remaining missing {m} ({actual} symbols)')

# Check stub breakdown
stub_claimed = blockers.get('Stub_remaining', {})
for m, claimed in stub_claimed.items():
    actual = stub_by_mod.get(m, 0)
    if claimed != actual:
        errors.append(f'Stub_remaining.{m}: spec={claimed} matrix={actual}')

for m, actual in stub_by_mod.items():
    if m not in stub_claimed:
        errors.append(f'Stub_remaining missing {m} ({actual} symbols)')

# Check total
total_claimed = blockers.get('total_symbols_to_migrate', 0)
total_actual = sum(ct_by_mod.values()) + sum(stub_by_mod.values())
if total_claimed != total_actual:
    errors.append(f'total_symbols_to_migrate: spec={total_claimed} actual={total_actual}')

print(f'BLOCKER_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

blocker_errs=$(echo "${blocker_check}" | grep '^BLOCKER_ERRORS=' | cut -d= -f2)

if [[ "${blocker_errs}" -gt 0 ]]; then
    echo "FAIL: ${blocker_errs} blocker mismatch(es):"
    echo "${blocker_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Replace blockers match actual GlibcCallThrough+Stub symbols"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: Interpose artifact build command verification
# ---------------------------------------------------------------------------
echo "--- Check 6: Build artifact existence ---"

target_dir="${CARGO_TARGET_DIR:-${ROOT}/target}"
interpose_output="$(python3 -c "
import json
with open('${SPEC}') as f:
    spec = json.load(f)
print(spec['artifacts']['interpose']['output_path'])
")"
interpose_rel="${interpose_output#target/}"
ARTIFACT="${target_dir%/}/${interpose_rel}"
if [[ -f "${ARTIFACT}" ]]; then
    size=$(stat -c%s "${ARTIFACT}" 2>/dev/null || stat -f%z "${ARTIFACT}" 2>/dev/null || echo "?")
    echo "PASS: ${ARTIFACT} exists (${size} bytes)"
else
    echo "WARN: ${ARTIFACT} not found (run 'cargo build -p frankenlibc-abi --release' to produce it)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 7: README command alignment with packaging spec
# ---------------------------------------------------------------------------
echo "--- Check 7: README alignment ---"

if [[ ! -f "${README}" ]]; then
    echo "FAIL: README.md not found"
    failures=$((failures + 1))
else
    readme_check=$(python3 -c "
import json
import re

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${README}', encoding='utf-8') as f:
    readme = f.read()

errors = []
interpose = spec.get('artifacts', {}).get('interpose', {})
replace = spec.get('artifacts', {}).get('replace', {})

required_literals = [
    interpose.get('build_command', ''),
    interpose.get('output_path', ''),
    interpose.get('artifact_name', ''),
    replace.get('artifact_name', ''),
]

for lit in required_literals:
    if lit and lit not in readme:
        errors.append(f'Missing README literal: {lit}')

interpose_deploy = interpose.get('deployment', '')
if interpose_deploy.startswith('LD_PRELOAD='):
    preload_prefix = interpose_deploy.split(' ', 1)[0]
    if preload_prefix not in readme:
        errors.append(f'Missing README deployment prefix: {preload_prefix}')

hardened_deploy = interpose.get('deployment_modes', {}).get('hardened', '')
if hardened_deploy.startswith('FRANKENLIBC_MODE=hardened'):
    hardened_prefix = hardened_deploy.split(' ', 1)[0]
    if hardened_prefix not in readme:
        errors.append(f'Missing README hardened prefix: {hardened_prefix}')

for status_token in ['Implemented', 'RawSyscall', 'GlibcCallThrough', 'Stub']:
    if status_token not in readme:
        errors.append(f'Missing README status token for applicability guidance: {status_token}')

if 'symbols apply to both artifacts.' not in readme:
    errors.append('Missing README applicability phrase for dual-artifact symbols')

if not re.search(r'symbols apply to (\x60)?Interpose(\x60)? only\.', readme, flags=re.IGNORECASE):
    errors.append('Missing README applicability phrase for interpose-only symbols')

print(f'README_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

    readme_errs=$(echo "${readme_check}" | grep '^README_ERRORS=' | cut -d= -f2)
    if [[ "${readme_errs}" -gt 0 ]]; then
        echo "FAIL: ${readme_errs} README alignment error(s):"
        echo "${readme_check}" | grep '  '
        failures=$((failures + 1))
    else
        echo "PASS: README commands and artifact references align with packaging spec"
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_packaging: FAILED"
    exit 1
fi

echo ""
echo "check_packaging: PASS"
