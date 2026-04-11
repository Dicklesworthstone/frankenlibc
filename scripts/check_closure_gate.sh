#!/usr/bin/env bash
# check_closure_gate.sh — CI gate for bd-4rl
#
# Validates that every closed critique bead has proper evidence:
#   1. Closure evidence schema exists and is valid.
#   2. Every non-exempt closed critique bead has a verification matrix entry.
#   3. Matrix entries have test commands (unit_cmds or e2e_cmds).
#   4. Matrix entries have artifact references.
#   5. Coverage is not "missing" and close_blockers are empty.
#
# Legacy-exempt beads (closed before gate establishment) produce warnings.
#
# Source selection:
# - FRANKENLIBC_CLOSURE_GATE_SOURCE=beads uses .beads/issues.jsonl
# - default (matrix) uses verification_matrix.json to avoid stale beads in rch
#
# Exit codes:
#   0 — all non-exempt beads pass evidence checks
#   1 — one or more non-exempt beads fail evidence checks
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${ROOT}/tests/conformance/closure_evidence_schema.json"
MATRIX="${ROOT}/tests/conformance/verification_matrix.json"
BEADS="${ROOT}/.beads/issues.jsonl"
SOURCE="${FRANKENLIBC_CLOSURE_GATE_SOURCE:-matrix}"

failures=0

echo "=== Closure Evidence Gate (bd-4rl) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Schema file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Schema file exists ---"

if [[ ! -f "${SCHEMA}" ]]; then
    echo "FAIL: tests/conformance/closure_evidence_schema.json not found"
    failures=$((failures + 1))
    echo ""
    echo "check_closure_gate: FAILED"
    exit 1
fi

schema_valid=$(python3 -c "
import json
try:
    with open('${SCHEMA}') as f:
        schema = json.load(f)
    v = schema.get('schema_version', 0)
    reqs = schema.get('evidence_requirements', {})
    exempt = schema.get('legacy_exempt', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not reqs:
        print('INVALID: empty evidence_requirements')
    else:
        print(f'VALID version={v} requirements={len(reqs)} exempt={len(exempt)}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${schema_valid}" == INVALID* ]]; then
    echo "FAIL: ${schema_valid}"
    failures=$((failures + 1))
else
    echo "PASS: ${schema_valid}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Evidence audit for closed critique beads
# ---------------------------------------------------------------------------
echo "--- Check 2: Closed critique bead evidence audit ---"
echo "Source: ${SOURCE}"

audit_result=$(python3 -c "
import json
import os

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

source = os.environ.get('FRANKENLIBC_CLOSURE_GATE_SOURCE', 'matrix').lower()
if source not in ('matrix', 'beads'):
    print(f'INVALID: unknown source {source}')
    raise SystemExit(1)

bead_lines = []
if source == 'beads':
    with open('${BEADS}') as f:
        bead_lines = f.readlines()

legacy_exempt = set(schema.get('legacy_exempt', []))

# Parse beads (optional)
beads = {}
if bead_lines:
    for line in bead_lines:
        line = line.strip()
        if not line:
            continue
        b = json.loads(line)
        beads[b['id']] = b

# Find closed critique beads
closed_critique = {}
if source == 'beads':
    for bid, b in beads.items():
        if b.get('status') == 'closed' and 'critique' in b.get('labels', []):
            closed_critique[bid] = b
else:
    for entry in matrix.get('entries', []):
        if entry.get('status') == 'closed' and 'critique' in entry.get('labels', []):
            bid = entry.get('bead_id')
            if bid:
                closed_critique[bid] = entry

# Build matrix lookup
matrix_map = {}
for e in matrix.get('entries', []):
    matrix_map[e['bead_id']] = e

# Audit each closed critique bead
failures = []
warnings = []
stats = {'total': 0, 'exempt': 0, 'pass': 0, 'fail': 0, 'warn': 0}

for bid in sorted(closed_critique.keys()):
    stats['total'] += 1
    is_exempt = bid in legacy_exempt
    issues = []

    entry = matrix_map.get(bid)
    if not entry:
        issues.append('no_matrix_entry')
    else:
        row = entry.get('row', {})
        cs = entry.get('coverage_summary', {})

        # Check test commands
        unit_cmds = row.get('unit_cmds', [])
        e2e_cmds = row.get('e2e_cmds', [])
        if not unit_cmds and not e2e_cmds:
            issues.append('no_test_commands')

        # Check artifact references
        artifact_paths = row.get('artifact_paths', [])
        log_refs = row.get('log_schema_refs', [])
        if not artifact_paths and not log_refs:
            issues.append('no_artifact_refs')

        # Check coverage status
        overall = cs.get('overall', 'missing')
        if overall == 'missing':
            issues.append('coverage_missing')

        # Check close blockers
        blockers = row.get('close_blockers', [])
        if blockers:
            issues.append(f'close_blockers={len(blockers)}')

    if not issues:
        stats['pass'] += 1
    elif is_exempt:
        stats['exempt'] += 1
        stats['warn'] += 1
        for issue in issues:
            warnings.append(f'{bid}: {issue} (legacy-exempt)')
    else:
        stats['fail'] += 1
        for issue in issues:
            failures.append(f'{bid}: {issue}')

print(f'TOTAL={stats[\"total\"]}')
print(f'PASS={stats[\"pass\"]}')
print(f'FAIL={stats[\"fail\"]}')
print(f'EXEMPT_WARN={stats[\"warn\"]}')

if failures:
    print('')
    print('FAILURES:')
    for f in failures:
        print(f'  {f}')

if warnings:
    print('')
    print('LEGACY WARNINGS (informational):')
    for w in warnings:
        print(f'  {w}')
")

total=$(echo "${audit_result}" | grep '^TOTAL=' | cut -d= -f2)
pass_count=$(echo "${audit_result}" | grep '^PASS=' | cut -d= -f2)
fail_count=$(echo "${audit_result}" | grep '^FAIL=' | cut -d= -f2)
warn_count=$(echo "${audit_result}" | grep '^EXEMPT_WARN=' | cut -d= -f2)

echo "Closed critique beads: ${total}"
echo "Evidence complete: ${pass_count}"
echo "Evidence failures: ${fail_count}"
echo "Legacy-exempt warnings: ${warn_count}"
echo ""

if [[ "${fail_count}" -gt 0 ]]; then
    echo "FAIL: ${fail_count} non-exempt bead(s) lack required evidence:"
    echo "${audit_result}" | grep -A1000 'FAILURES:' | grep '  bd-' || true
    echo ""
    failures=$((failures + 1))
else
    echo "PASS: All non-exempt closed beads have evidence (or are legacy-exempt)"
fi

if [[ "${warn_count}" -gt 0 ]]; then
    echo ""
    echo "WARNING: ${warn_count} legacy-exempt bead(s) lack evidence (not blocking):"
    echo "${audit_result}" | grep -A1000 'LEGACY WARNINGS' | grep '  bd-' || true
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Evidence requirement coverage
# ---------------------------------------------------------------------------
echo "--- Check 3: Evidence requirement field coverage ---"

field_check=$(python3 -c "
import json

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

reqs = schema.get('evidence_requirements', {})
entries = matrix.get('entries', [])
errors = []

# Verify the schema's required fields are present in matrix entries
for e in entries:
    bid = e.get('bead_id', '<unknown>')
    row = e.get('row', {})

    # Check row exists
    if not row:
        errors.append(f'{bid}: missing row object')
        continue

    # Check required row fields exist
    for field in ['unit_cmds', 'e2e_cmds', 'artifact_paths', 'close_blockers']:
        if field not in row:
            errors.append(f'{bid}: row missing field \"{field}\"')

    # Check coverage_summary exists
    if 'coverage_summary' not in e:
        errors.append(f'{bid}: missing coverage_summary')

print(f'FIELD_ERRORS={len(errors)}')
for err in errors[:20]:
    print(f'  {err}')
")

field_errs=$(echo "${field_check}" | grep '^FIELD_ERRORS=' | cut -d= -f2)

if [[ "${field_errs}" -gt 0 ]]; then
    echo "FAIL: ${field_errs} field error(s) in matrix entries:"
    echo "${field_check}" | grep '  ' | head -20
    failures=$((failures + 1))
else
    echo "PASS: All matrix entries have required evidence fields"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Coverage debt summary
# ---------------------------------------------------------------------------
echo "--- Check 4: Coverage debt summary ---"

python3 -c "
import json
import os

with open('${SCHEMA}') as f:
    schema = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

source = os.environ.get('FRANKENLIBC_CLOSURE_GATE_SOURCE', 'matrix').lower()
bead_lines = []
if source == 'beads':
    with open('${BEADS}') as f:
        bead_lines = f.readlines()

legacy_exempt = set(schema.get('legacy_exempt', []))

beads = {}
if bead_lines:
    for line in bead_lines:
        line = line.strip()
        if not line:
            continue
        b = json.loads(line)
        beads[b['id']] = b

# Count beads in each state
closed_critique = set()
if source == 'beads':
    for bid, b in beads.items():
        if b.get('status') == 'closed' and 'critique' in b.get('labels', []):
            closed_critique.add(bid)
else:
    for entry in matrix.get('entries', []):
        if entry.get('status') == 'closed' and 'critique' in entry.get('labels', []):
            bid = entry.get('bead_id')
            if bid:
                closed_critique.add(bid)

matrix_map = {}
for e in matrix.get('entries', []):
    matrix_map[e['bead_id']] = e

# Debt = closed critique beads without complete evidence
no_entry = sum(1 for bid in closed_critique if bid not in matrix_map)
has_entry = sum(1 for bid in closed_critique if bid in matrix_map)
exempt_no_entry = sum(1 for bid in closed_critique if bid in legacy_exempt and bid not in matrix_map)

complete = 0
partial = 0
missing = 0
for bid in closed_critique:
    if bid in matrix_map:
        overall = matrix_map[bid].get('coverage_summary', {}).get('overall', 'missing')
        if overall == 'complete':
            complete += 1
        elif overall == 'partial':
            partial += 1
        else:
            missing += 1

print(f'Closed critique beads: {len(closed_critique)}')
print(f'  With matrix entry: {has_entry} (complete={complete}, partial={partial}, missing={missing})')
print(f'  Without matrix entry: {no_entry} ({exempt_no_entry} legacy-exempt)')
print(f'  Coverage debt: {no_entry + missing + partial} beads need evidence improvement')
"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_closure_gate: FAILED"
    exit 1
fi

echo ""
echo "check_closure_gate: PASS"
