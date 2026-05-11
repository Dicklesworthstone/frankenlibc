#!/usr/bin/env bash
# check_matrix_drift.sh — CI gate for bd-34w
#
# Validates that every open/in_progress critique bead has a row in the
# verification matrix. Detects drift when new beads are created without
# corresponding matrix entries.
#
# Exit codes:
#   0 — no drift detected
#   1 — missing matrix rows or validation errors
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/verification_matrix.json"
BEADS="${FRANKENLIBC_VERIFICATION_MATRIX_BEADS:-${ROOT}/.beads/issues.jsonl}"

failures=0

echo "=== Verification Matrix Drift Guard (bd-34w) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Matrix file exists
# ---------------------------------------------------------------------------
echo "--- Check 1: Matrix file exists ---"

if [[ ! -f "${MATRIX}" ]]; then
    echo "FAIL: tests/conformance/verification_matrix.json not found"
    failures=$((failures + 1))
    echo ""
    echo "check_matrix_drift: FAILED"
    exit 1
fi
echo "PASS: Matrix file exists"
echo ""

# ---------------------------------------------------------------------------
# Check 2: Compare critique beads vs matrix rows
# ---------------------------------------------------------------------------
echo "--- Check 2: Drift detection ---"

drift_result=$(python3 -c "
import json

with open('${MATRIX}') as f:
    matrix = json.load(f)
with open('${BEADS}') as f:
    bead_lines = f.readlines()

# Parse beads
beads = {}
for line in bead_lines:
    line = line.strip()
    if not line:
        continue
    b = json.loads(line)
    beads[b['id']] = b

# Find open/in_progress critique beads
critique_beads = {}
for bid, b in beads.items():
    if b.get('status') in ('open', 'in_progress'):
        labels = b.get('labels', [])
        if 'critique' in labels:
            critique_beads[bid] = b

# Find matrix-covered bead IDs
matrix_entries = matrix.get('entries', [])
covered = set(e['bead_id'] for e in matrix_entries)

# Detect missing rows
missing = []
for bid in sorted(critique_beads.keys()):
    if bid not in covered:
        b = critique_beads[bid]
        missing.append({
            'bead_id': bid,
            'priority': b.get('priority', 99),
            'title': b['title'][:80],
            'labels': b.get('labels', [])
        })

# Detect stale rows (matrix rows for closed beads)
stale = []
for e in matrix_entries:
    bid = e['bead_id']
    b = beads.get(bid)
    if b and b.get('status') == 'closed':
        stale.append({
            'bead_id': bid,
            'title': b['title'][:60],
            'closed_reason': b.get('close_reason', 'unknown')
        })

# Report
print(f'CRITIQUE_BEADS={len(critique_beads)}')
print(f'MATRIX_ROWS={len(matrix_entries)}')
print(f'COVERED={len(covered)}')
print(f'MISSING={len(missing)}')
print(f'STALE={len(stale)}')

if missing:
    print('')
    print('MISSING ROWS:')
    for m in missing:
        print(f\"  {m['bead_id']} P{m['priority']} [{','.join(m['labels'][:3])}] {m['title']}\")

if stale:
    print('')
    print('STALE ROWS (closed beads still in matrix):')
    for s in stale:
        print(f\"  {s['bead_id']} closed={s['closed_reason']} {s['title']}\")
")

critique_count=$(echo "${drift_result}" | grep '^CRITIQUE_BEADS=' | cut -d= -f2)
matrix_rows=$(echo "${drift_result}" | grep '^MATRIX_ROWS=' | cut -d= -f2)
missing_count=$(echo "${drift_result}" | grep '^MISSING=' | cut -d= -f2)
stale_count=$(echo "${drift_result}" | grep '^STALE=' | cut -d= -f2)

echo "Critique beads (open/in_progress): ${critique_count}"
echo "Matrix rows: ${matrix_rows}"
echo "Missing rows: ${missing_count}"
echo "Stale rows: ${stale_count}"
echo ""

if [[ "${missing_count}" -gt 0 ]]; then
    echo "FAIL: ${missing_count} critique bead(s) without matrix rows:"
    echo "${drift_result}" | grep -A1000 'MISSING ROWS:' | grep '  bd-'
    echo ""
    failures=$((failures + 1))
else
    echo "PASS: All critique beads have matrix rows"
fi

if [[ "${stale_count}" -gt 0 ]]; then
    echo "WARNING: ${stale_count} stale row(s) for closed beads (informational):"
    echo "${drift_result}" | grep -A1000 'STALE ROWS' | grep '  bd-'
    echo ""
fi

# ---------------------------------------------------------------------------
# Check 3: Verify matrix entries have required fields
# ---------------------------------------------------------------------------
echo "--- Check 3: Entry schema validation ---"

entry_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    matrix = json.load(f)

required = ['bead_id', 'title', 'obligations', 'coverage', 'coverage_summary']
valid_overall = ['missing', 'partial', 'complete']
errors = []

for i, entry in enumerate(matrix.get('entries', [])):
    bid = entry.get('bead_id', f'<entry #{i}>')
    for field in required:
        if field not in entry:
            errors.append(f'{bid}: missing required field \"{field}\"')
    # Validate coverage_summary.overall
    cs = entry.get('coverage_summary', {})
    overall = cs.get('overall', '') if isinstance(cs, dict) else ''
    if overall and overall not in valid_overall:
        errors.append(f'{bid}: invalid coverage_summary.overall \"{overall}\"')
    if not bid.startswith('bd-'):
        errors.append(f'{bid}: bead_id should start with \"bd-\"')

print(f'SCHEMA_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

schema_errs=$(echo "${entry_check}" | grep '^SCHEMA_ERRORS=' | cut -d= -f2)

if [[ "${schema_errs}" -gt 0 ]]; then
    echo "FAIL: ${schema_errs} schema error(s):"
    echo "${entry_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All matrix entries have valid schema"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Dashboard consistency
# ---------------------------------------------------------------------------
echo "--- Check 4: Dashboard consistency ---"

dash_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    matrix = json.load(f)

entries = matrix.get('entries', [])
dashboard = matrix.get('dashboard', {})
errors = []

if not dashboard:
    errors.append('Missing dashboard section')
else:
    claimed_total = dashboard.get('total_critique_beads', 0)
    actual_total = len(entries)
    if claimed_total != actual_total:
        errors.append(f'Dashboard total={claimed_total} but entries has {actual_total} rows')

    by_status = dashboard.get('by_coverage_status', {})
    actual_by_status = {}
    for e in entries:
        cs = e.get('coverage_summary', {})
        s = cs.get('overall', 'missing') if isinstance(cs, dict) else 'missing'
        actual_by_status[s] = actual_by_status.get(s, 0) + 1

    for status, count in by_status.items():
        actual = actual_by_status.get(status, 0)
        if count != actual:
            errors.append(f'Dashboard {status}={count} but actual={actual}')

print(f'DASH_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

dash_errs=$(echo "${dash_check}" | grep '^DASH_ERRORS=' | cut -d= -f2)

if [[ "${dash_errs}" -gt 0 ]]; then
    echo "FAIL: ${dash_errs} dashboard inconsistency(ies):"
    echo "${dash_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Dashboard is consistent with entries"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"
echo "Note: Stale rows are informational warnings, not failures."

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_matrix_drift: FAILED"
    exit 1
fi

echo ""
echo "check_matrix_drift: PASS"
