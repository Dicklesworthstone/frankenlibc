#!/usr/bin/env bash
# check_replacement_levels.sh — CI gate for bd-2bu
#
# Validates that:
#   1. Replacement levels JSON exists and is valid.
#   2. All four levels are defined with required fields.
#   3. Current assessment matches support_matrix.json counts.
#   4. Level status progression is consistent (achieved < in_progress < planned < roadmap).
#   5. Gate criteria thresholds are monotonically tightening.
#   6. README claim and release-tag policy do not drift above current_level.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
MATRIX="${ROOT}/support_matrix.json"
README="${ROOT}/README.md"

failures=0

echo "=== Replacement Levels Gate (bd-2bu) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Levels file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Levels file exists and is valid ---"

if [[ ! -f "${LEVELS}" ]]; then
    echo "FAIL: tests/conformance/replacement_levels.json not found"
    echo ""
    echo "check_replacement_levels: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${LEVELS}') as f:
        lvl = json.load(f)
    v = lvl.get('schema_version', 0)
    levels = lvl.get('levels', [])
    assessment = lvl.get('current_assessment', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not levels:
        print('INVALID: empty levels')
    elif not assessment:
        print('INVALID: empty current_assessment')
    else:
        print(f'VALID version={v} levels={len(levels)} symbols={assessment.get(\"total_symbols\", 0)}')
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
# Check 2: All four levels defined with required fields
# ---------------------------------------------------------------------------
echo "--- Check 2: Level definitions ---"

level_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []
required_fields = ['level', 'name', 'description', 'deployment', 'host_glibc_required', 'gate_criteria', 'status']
expected_ids = ['L0', 'L1', 'L2', 'L3']
found_ids = []

for entry in levels:
    lid = entry.get('level', '?')
    found_ids.append(lid)
    for field in required_fields:
        if field not in entry:
            errors.append(f'{lid}: missing field \"{field}\"')

    # Gate criteria required fields
    gc = entry.get('gate_criteria', {})
    for gf in ['max_callthrough_pct', 'max_stub_pct', 'min_implemented_pct', 'e2e_smoke_required']:
        if gf not in gc:
            errors.append(f'{lid}: gate_criteria missing \"{gf}\"')

missing = [x for x in expected_ids if x not in found_ids]
extra = [x for x in found_ids if x not in expected_ids]

if missing:
    errors.append(f'Missing levels: {missing}')
if extra:
    errors.append(f'Unexpected levels: {extra}')

print(f'LEVEL_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
print(f'FOUND_LEVELS={len(found_ids)}')
")

level_errs=$(echo "${level_check}" | grep '^LEVEL_ERRORS=' | cut -d= -f2)

if [[ "${level_errs}" -gt 0 ]]; then
    echo "FAIL: ${level_errs} level definition error(s):"
    echo "${level_check}" | grep '  '
    failures=$((failures + 1))
else
    found=$(echo "${level_check}" | grep '^FOUND_LEVELS=' | cut -d= -f2)
    echo "PASS: All ${found} levels defined with required fields"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Current assessment matches support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 3: Assessment vs support matrix ---"

assessment_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

assessment = lvl.get('current_assessment', {})
symbols = matrix.get('symbols', [])
errors = []

# Count statuses from matrix
counts = {}
module_counts = {}
for sym in symbols:
    status = sym.get('status', 'Unknown')
    module = sym.get('module', 'unknown')
    counts[status] = counts.get(status, 0) + 1
    key = (status, module)
    module_counts[key] = module_counts.get(key, 0) + 1

matrix_total = len(symbols)
claimed_total = assessment.get('total_symbols', 0)
if claimed_total != matrix_total:
    errors.append(f'total_symbols: claimed={claimed_total} matrix={matrix_total}')

for status_key, json_key in [('Implemented', 'implemented'), ('RawSyscall', 'raw_syscall'),
                               ('GlibcCallThrough', 'callthrough'), ('Stub', 'stub')]:
    actual = counts.get(status_key, 0)
    claimed = assessment.get(json_key, 0)
    if claimed != actual:
        errors.append(f'{json_key}: claimed={claimed} matrix={actual}')

# Check callthrough breakdown
ct_breakdown = assessment.get('callthrough_breakdown', {})
for module, claimed_count in ct_breakdown.items():
    actual_count = module_counts.get(('GlibcCallThrough', module), 0)
    if claimed_count != actual_count:
        errors.append(f'callthrough_breakdown.{module}: claimed={claimed_count} matrix={actual_count}')

# Check stub breakdown
stub_breakdown = assessment.get('stub_breakdown', {})
for module, claimed_count in stub_breakdown.items():
    actual_count = module_counts.get(('Stub', module), 0)
    if claimed_count != actual_count:
        errors.append(f'stub_breakdown.{module}: claimed={claimed_count} matrix={actual_count}')

print(f'ASSESSMENT_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution report
print()
for status in ['Implemented', 'RawSyscall', 'GlibcCallThrough', 'Stub']:
    c = counts.get(status, 0)
    pct = round(c * 100 / matrix_total) if matrix_total > 0 else 0
    print(f'{status}: {c} ({pct}%)')
")

assessment_errs=$(echo "${assessment_check}" | grep '^ASSESSMENT_ERRORS=' | cut -d= -f2)

if [[ "${assessment_errs}" -gt 0 ]]; then
    echo "FAIL: ${assessment_errs} assessment mismatch(es):"
    echo "${assessment_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Current assessment matches support_matrix.json"
fi
echo "${assessment_check}" | grep -E '^(Implemented|RawSyscall|GlibcCallThrough|Stub):' || true
echo ""

# ---------------------------------------------------------------------------
# Check 4: Status progression consistency
# ---------------------------------------------------------------------------
echo "--- Check 4: Status progression ---"

status_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []

valid_statuses = ['achieved', 'in_progress', 'planned', 'roadmap']
status_order = {s: i for i, s in enumerate(valid_statuses)}

prev_order = -1
prev_level = None
for entry in levels:
    lid = entry.get('level', '?')
    status = entry.get('status', 'unknown')
    if status not in valid_statuses:
        errors.append(f'{lid}: invalid status \"{status}\" (expected one of {valid_statuses})')
        continue
    order = status_order[status]
    if order < prev_order:
        errors.append(f'{lid} ({status}) is less mature than {prev_level} — status should be monotonically non-decreasing')
    prev_order = order
    prev_level = lid

# Check current_level is consistent
current = lvl.get('current_level', '')
achieved = [e.get('level') for e in levels if e.get('status') == 'achieved']
if current and current not in achieved:
    errors.append(f'current_level={current} but its status is not \"achieved\"')

print(f'STATUS_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

status_errs=$(echo "${status_check}" | grep '^STATUS_ERRORS=' | cut -d= -f2)

if [[ "${status_errs}" -gt 0 ]]; then
    echo "FAIL: ${status_errs} status progression error(s):"
    echo "${status_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Status progression is consistent"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Gate criteria monotonically tightening
# ---------------------------------------------------------------------------
echo "--- Check 5: Gate criteria monotonicity ---"

mono_check=$(python3 -c "
import json

with open('${LEVELS}') as f:
    lvl = json.load(f)

levels = lvl.get('levels', [])
errors = []

# max_callthrough_pct should decrease (or stay same) as levels increase
# max_stub_pct should decrease (or stay same)
# min_implemented_pct should increase (or stay same)
prev = {}
for entry in levels:
    lid = entry.get('level', '?')
    gc = entry.get('gate_criteria', {})

    for field, direction in [('max_callthrough_pct', 'decreasing'),
                              ('max_stub_pct', 'decreasing'),
                              ('min_implemented_pct', 'increasing')]:
        val = gc.get(field)
        if val is None:
            continue
        if field in prev:
            if direction == 'decreasing' and val > prev[field][1]:
                errors.append(f'{field}: {lid}={val} > {prev[field][0]}={prev[field][1]} (should be non-increasing)')
            elif direction == 'increasing' and val < prev[field][1]:
                errors.append(f'{field}: {lid}={val} < {prev[field][0]}={prev[field][1]} (should be non-decreasing)')
        prev[field] = (lid, val)

print(f'MONO_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

mono_errs=$(echo "${mono_check}" | grep '^MONO_ERRORS=' | cut -d= -f2)

if [[ "${mono_errs}" -gt 0 ]]; then
    echo "FAIL: ${mono_errs} monotonicity violation(s):"
    echo "${mono_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Gate criteria monotonically tighten across levels"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: README + release tag claim drift
# ---------------------------------------------------------------------------
echo "--- Check 6: Claim drift (README + release tags) ---"

claim_check=$(python3 -c "
import json
import re

with open('${LEVELS}') as f:
    lvl = json.load(f)
with open('${README}', encoding='utf-8') as f:
    readme = f.read()

errors = []
levels = lvl.get('levels', [])
level_map = {entry.get('level'): entry for entry in levels}
current = lvl.get('current_level', '')
if not current:
    errors.append('current_level is missing')
entry = level_map.get(current, {})
name = entry.get('name', '')
if not name:
    errors.append(f'current_level={current} not found in levels[]')

expected_claim = f'Declared replacement level claim: **{current} — {name}**.'
if expected_claim not in readme:
    errors.append('README replacement-level claim line is missing or stale')
claim_matches = re.findall(r'Declared replacement level claim: \\*\\*(L[0-3]) — ([^*]+)\\*\\*\\.', readme)
if len(claim_matches) != 1:
    errors.append(f'Expected exactly one replacement-level claim line in README, found {len(claim_matches)}')

policy = lvl.get('release_tag_policy')
if not isinstance(policy, dict):
    errors.append('release_tag_policy missing or invalid')
else:
    tag_format = policy.get('tag_format', '')
    if not tag_format:
        errors.append('release_tag_policy.tag_format missing')
    suffixes = policy.get('level_tag_suffix')
    if not isinstance(suffixes, dict):
        errors.append('release_tag_policy.level_tag_suffix missing or invalid')
    else:
        for lid in ['L0', 'L1', 'L2', 'L3']:
            expected_suffix = f'-{lid}'
            actual_suffix = suffixes.get(lid)
            if actual_suffix != expected_suffix:
                errors.append(
                    f'release_tag_policy.level_tag_suffix.{lid}={actual_suffix!r} expected {expected_suffix!r}'
                )

    claimed_release_level = policy.get('current_release_level', '')
    if claimed_release_level != current:
        errors.append(
            f'release_tag_policy.current_release_level={claimed_release_level!r} must match current_level={current!r}'
        )

    example = policy.get('current_release_tag_example', '')
    required_suffix = f'-{current}'
    if not example:
        errors.append('release_tag_policy.current_release_tag_example missing')
    elif not example.endswith(required_suffix):
        errors.append(
            f'current_release_tag_example={example!r} must end with {required_suffix!r}'
        )

print(f'CLAIM_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

claim_errs=$(echo "${claim_check}" | grep '^CLAIM_ERRORS=' | cut -d= -f2)

if [[ "${claim_errs}" -gt 0 ]]; then
    echo "FAIL: ${claim_errs} claim drift error(s):"
    echo "${claim_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: README and release-tag policy are aligned to current_level"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_replacement_levels: FAILED"
    exit 1
fi

echo ""
echo "check_replacement_levels: PASS"
