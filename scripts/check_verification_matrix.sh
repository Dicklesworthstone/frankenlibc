#!/usr/bin/env bash
# check_verification_matrix.sh — CI gate for bd-id3
#
# Validates:
# 1. verification_matrix.json exists and is valid JSON
# 2. Every open/in_progress critique bead has a populated verification row
# 3. Coverage dashboard is present and internally consistent
# 4. Missing evidence blocks bead closure (report gaps)
#
# Exit codes:
#   0 — all checks pass (informational gaps reported)
#   1 — structural validation failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/verification_matrix.json"
BEADS="${FRANKENLIBC_VERIFICATION_MATRIX_BEADS:-${ROOT}/.beads/issues.jsonl}"

failures=0
warnings=0

echo "=== Verification Matrix Gate (bd-id3) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Matrix file exists and is valid JSON
# ---------------------------------------------------------------------------
echo "--- Check 1: Matrix exists and is valid JSON ---"

if [[ ! -f "${MATRIX}" ]]; then
    echo "FAIL: verification_matrix.json not found at ${MATRIX}"
    exit 1
fi

if ! python3 -c "import json; json.load(open('${MATRIX}'))" 2>/dev/null; then
    echo "FAIL: verification_matrix.json is not valid JSON"
    exit 1
fi
echo "PASS: Matrix file exists and parses as valid JSON"
echo ""

# ---------------------------------------------------------------------------
# Check 2: Schema validation
# ---------------------------------------------------------------------------
echo "--- Check 2: Schema structure validation ---"

schema_ok=$(python3 -c "
import json, sys

with open('${MATRIX}') as f:
    m = json.load(f)

errors = []

# Required top-level keys
for key in ['matrix_version', 'generated_utc', 'schema', 'dashboard', 'entries']:
    if key not in m:
        errors.append(f'Missing top-level key: {key}')

# Schema must define coverage_statuses, obligation_types, and row contract
if 'schema' in m:
    for key in [
        'coverage_statuses',
        'obligation_types',
        'row_schema_version',
        'row_status_states',
        'row_status_transitions',
        'row_template',
        'stream_examples',
    ]:
        if key not in m['schema']:
            errors.append(f'Missing schema key: {key}')

    row_template = m['schema'].get('row_template', {})
    for key in [
        'bead_id',
        'stream',
        'status',
        'unit_cmds',
        'e2e_cmds',
        'expected_assertions',
        'log_schema_refs',
        'artifact_paths',
        'perf_proof_refs',
        'close_blockers',
        'notes',
    ]:
        if key not in row_template:
            errors.append(f'Missing row_template key: {key}')

    valid_row_states = {'missing', 'partial', 'complete'}
    transitions = m['schema'].get('row_status_transitions', [])
    transition_targets = {
        t.get('to')
        for t in transitions
        if isinstance(t, dict) and t.get('to') is not None
    }
    if transition_targets != valid_row_states:
        errors.append(
            f'row_status_transitions must define exactly {sorted(valid_row_states)}, got {sorted(transition_targets)}'
        )
    for idx, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            errors.append(f'row_status_transitions[{idx}] must be an object')
            continue
        if not transition.get('when'):
            errors.append(f'row_status_transitions[{idx}] missing non-empty when clause')

    stream_examples = m['schema'].get('stream_examples', [])
    if not isinstance(stream_examples, list) or not stream_examples:
        errors.append('stream_examples must be a non-empty array')
    else:
        required_streams = {'docs', 'e2e', 'syscall', 'stubs', 'math', 'perf'}
        seen_streams = set()
        for idx, row in enumerate(stream_examples):
            if not isinstance(row, dict):
                errors.append(f'stream_examples[{idx}] must be an object')
                continue

            for key in [
                'bead_id',
                'stream',
                'status',
                'unit_cmds',
                'e2e_cmds',
                'expected_assertions',
                'log_schema_refs',
                'artifact_paths',
                'perf_proof_refs',
                'close_blockers',
                'notes',
            ]:
                if key not in row:
                    errors.append(f'stream_examples[{idx}] missing key: {key}')

            stream = row.get('stream')
            if stream:
                seen_streams.add(stream)
            if stream not in required_streams:
                errors.append(f'stream_examples[{idx}] has invalid stream: {stream}')

            status = row.get('status')
            if status not in valid_row_states:
                errors.append(f'stream_examples[{idx}] has invalid status: {status}')

            for arr_key in [
                'unit_cmds',
                'e2e_cmds',
                'expected_assertions',
                'log_schema_refs',
                'artifact_paths',
                'perf_proof_refs',
                'close_blockers',
            ]:
                if arr_key in row and not isinstance(row[arr_key], list):
                    errors.append(f'stream_examples[{idx}].{arr_key} must be an array')

        missing_streams = sorted(required_streams - seen_streams)
        if missing_streams:
            sep = ', '
            errors.append(
                f'stream_examples missing required stream(s): {sep.join(missing_streams)}'
            )

# Dashboard must have summary stats
if 'dashboard' in m:
    for key in ['total_critique_beads', 'by_coverage_status', 'by_priority', 'by_obligation_type', 'by_stream']:
        if key not in m['dashboard']:
            errors.append(f'Missing dashboard key: {key}')

# Each entry must have required fields
for i, e in enumerate(m.get('entries', [])):
    for key in ['bead_id', 'title', 'priority', 'status', 'obligations', 'coverage', 'coverage_summary', 'row']:
        if key not in e:
            errors.append(f'Entry {i} ({e.get(\"bead_id\",\"?\")}) missing key: {key}')
    # Coverage summary must have overall + counts
    cs = e.get('coverage_summary', {})
    for key in ['overall', 'required', 'complete', 'partial', 'missing']:
        if key not in cs:
            errors.append(f'Entry {e.get(\"bead_id\",\"?\")} coverage_summary missing: {key}')
    # Coverage counts must be consistent
    r = cs.get('required', 0)
    c = cs.get('complete', 0)
    p = cs.get('partial', 0)
    mi = cs.get('missing', 0)
    if c + p + mi != r:
        errors.append(f'Entry {e.get(\"bead_id\",\"?\")} count mismatch: {c}+{p}+{mi} != {r}')

    row = e.get('row', {})
    for key in [
        'bead_id',
        'stream',
        'status',
        'unit_cmds',
        'e2e_cmds',
        'expected_assertions',
        'log_schema_refs',
        'artifact_paths',
        'perf_proof_refs',
        'close_blockers',
        'notes',
    ]:
        if key not in row:
            errors.append(f'Entry {e.get(\"bead_id\",\"?\")} row missing key: {key}')

    for list_key in ['unit_cmds', 'expected_assertions', 'log_schema_refs', 'artifact_paths']:
        if not isinstance(row.get(list_key), list) or not row.get(list_key):
            errors.append(f'Entry {e.get(\"bead_id\",\"?\")} row.{list_key} must be a non-empty array')

if errors:
    for e in errors:
        print(f'SCHEMA_ERROR: {e}')
    print(f'SCHEMA_ERRORS={len(errors)}')
else:
    print('SCHEMA_ERRORS=0')
")

schema_errors=$(echo "${schema_ok}" | grep 'SCHEMA_ERRORS=' | cut -d= -f2)
if [[ "${schema_errors}" -gt 0 ]]; then
    echo "FAIL: Schema validation errors:"
    echo "${schema_ok}" | grep 'SCHEMA_ERROR:'
    failures=$((failures + 1))
else
    echo "PASS: Schema structure is valid"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Bead coverage completeness
# ---------------------------------------------------------------------------
echo "--- Check 3: All critique beads have verification rows ---"

coverage_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    m = json.load(f)
with open('${BEADS}') as f:
    beads = [json.loads(line) for line in f]

matrix_ids = {e['bead_id'] for e in m['entries']}

missing = []
for b in beads:
    labels = b.get('labels', [])
    status = b.get('status', '')
    if 'critique' in labels and status in ('open', 'in_progress'):
        if b['id'] not in matrix_ids:
            missing.append(b['id'])

if missing:
    for mid in sorted(missing):
        print(f'MISSING_BEAD: {mid}')
print(f'MISSING_BEADS={len(missing)}')
")

missing_beads=$(echo "${coverage_check}" | grep 'MISSING_BEADS=' | cut -d= -f2)
if [[ "${missing_beads}" -gt 0 ]]; then
    echo "FAIL: ${missing_beads} critique bead(s) missing from verification matrix:"
    echo "${coverage_check}" | grep 'MISSING_BEAD:'
    failures=$((failures + 1))
else
    echo "PASS: All open/in_progress critique beads have verification rows"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Coverage gap report (informational)
# ---------------------------------------------------------------------------
echo "--- Check 4: Coverage gap report ---"

python3 -c "
import json

with open('${MATRIX}') as f:
    m = json.load(f)

d = m['dashboard']
print(f\"Total critique beads: {d['total_critique_beads']}\")
print(f\"Coverage: {json.dumps(d['by_coverage_status'])}\")
print()
print('By priority:')
for p, stats in sorted(d['by_priority'].items()):
    print(f'  {p}: {stats[\"total\"]} total, {stats.get(\"complete\",0)} complete, {stats.get(\"partial\",0)} partial, {stats.get(\"missing\",0)} missing')
print()
print('By obligation type:')
for ot, stats in sorted(d['by_obligation_type'].items()):
    print(f'  {ot:25s} {stats[\"required\"]:3d} required  {stats.get(\"complete\",0):3d} complete  {stats.get(\"partial\",0):3d} partial  {stats.get(\"missing\",0):3d} missing')
print()

print('By stream:')
for stream, stats in sorted(d['by_stream'].items()):
    print(f'  {stream:10s} {stats.get(\"total\",0):3d} total  {stats.get(\"complete\",0):3d} complete  {stats.get(\"partial\",0):3d} partial  {stats.get(\"missing\",0):3d} missing')
print()

# List P0 beads with missing coverage
print('P0 beads needing evidence:')
for e in m['entries']:
    if e['priority'] == 0 and e['coverage_summary']['overall'] in ('missing', 'partial'):
        missing_types = [k for k, v in e['coverage'].items() if v['status'] == 'missing']
        print(f\"  {e['bead_id']:8s} [{e['coverage_summary']['overall']:7s}] missing: {', '.join(missing_types)}\")
"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"
echo "Warnings: ${warnings}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_verification_matrix: FAILED"
    exit 1
fi

echo ""
echo "check_verification_matrix: PASS"
