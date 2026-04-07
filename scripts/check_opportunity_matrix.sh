#!/usr/bin/env bash
# check_opportunity_matrix.sh — CI gate for bd-1ik
#
# Validates that:
#   1. Opportunity matrix JSON exists and is valid.
#   2. Scoring dimensions and formula are defined.
#   3. All entries have required fields, replay metadata, and valid scores.
#   4. Computed scores match the formula.
#   5. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/opportunity_matrix.json"

failures=0

echo "=== Opportunity Matrix Gate (bd-1ik) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Matrix file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Matrix file exists and is valid ---"

if [[ ! -f "${MATRIX}" ]]; then
    echo "FAIL: tests/conformance/opportunity_matrix.json not found"
    echo ""
    echo "check_opportunity_matrix: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${MATRIX}') as f:
        mat = json.load(f)
    v = mat.get('schema_version', 0)
    entries = mat.get('entries', [])
    scoring = mat.get('scoring', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not entries:
        print('INVALID: empty entries')
    elif not scoring:
        print('INVALID: empty scoring')
    else:
        print(f'VALID version={v} entries={len(entries)} threshold={scoring.get(\"threshold\", \"?\")}')
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
# Check 2: Scoring dimensions defined
# ---------------------------------------------------------------------------
echo "--- Check 2: Scoring dimensions ---"

dim_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    mat = json.load(f)

scoring = mat.get('scoring', {})
dims = scoring.get('dimensions', {})
errors = []

for dim_name in ['impact', 'confidence', 'effort']:
    if dim_name not in dims:
        errors.append(f'Missing dimension: {dim_name}')
        continue
    dim = dims[dim_name]
    if not dim.get('description'):
        errors.append(f'{dim_name}: missing description')
    if not dim.get('scale'):
        errors.append(f'{dim_name}: missing scale')
    if not dim.get('anchors'):
        errors.append(f'{dim_name}: missing anchors')

if not scoring.get('formula'):
    errors.append('Missing scoring formula')
if 'threshold' not in scoring:
    errors.append('Missing threshold')

print(f'DIM_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

dim_errs=$(echo "${dim_check}" | grep '^DIM_ERRORS=' | cut -d= -f2)

if [[ "${dim_errs}" -gt 0 ]]; then
    echo "FAIL: ${dim_errs} scoring dimension error(s):"
    echo "${dim_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All scoring dimensions defined with descriptions, scales, and anchors"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Entries have required fields and valid ranges
# ---------------------------------------------------------------------------
echo "--- Check 3: Entry validation ---"

entry_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    mat = json.load(f)

entries = mat.get('entries', [])
errors = []
required = [
    'id',
    'title',
    'impact',
    'confidence',
    'effort',
    'score',
    'rationale',
    'status',
    'lever_category',
    'golden_output_verification',
    'rollback_instructions',
    'attribution_metadata',
]

ids_seen = set()
for entry in entries:
    eid = entry.get('id', '?')

    for field in required:
        if field not in entry:
            errors.append(f'{eid}: missing field \"{field}\"')

    # Check ranges (0.0 to 5.0)
    for dim in ['impact', 'confidence', 'effort']:
        val = entry.get(dim)
        if val is not None and not (0.0 <= val <= 5.0):
            errors.append(f'{eid}.{dim}={val}: out of range [0.0, 5.0]')

    # Check score >= 0
    score = entry.get('score', 0)
    if score < 0:
        errors.append(f'{eid}: negative score {score}')

    # Check valid status
    valid_statuses = ['eligible', 'deferred', 'in_progress', 'completed']
    status = entry.get('status', '')
    if status not in valid_statuses:
        errors.append(f'{eid}: invalid status \"{status}\"')

    golden = entry.get('golden_output_verification', {})
    if not golden.get('artifact_refs'):
        errors.append(f'{eid}: golden_output_verification.artifact_refs must not be empty')
    if not golden.get('verification_command'):
        errors.append(f'{eid}: golden_output_verification.verification_command missing')
    if not golden.get('invariants'):
        errors.append(f'{eid}: golden_output_verification.invariants must not be empty')

    rollback = entry.get('rollback_instructions', {})
    if 'git revert' not in rollback.get('command', ''):
        errors.append(f'{eid}: rollback command must contain git revert')
    if not rollback.get('artifact_regeneration_commands'):
        errors.append(f'{eid}: rollback_instructions.artifact_regeneration_commands must not be empty')
    if not rollback.get('expected_revert_scope'):
        errors.append(f'{eid}: rollback_instructions.expected_revert_scope missing')

    attribution = entry.get('attribution_metadata', {})
    if not attribution.get('opportunity_owner'):
        errors.append(f'{eid}: attribution_metadata.opportunity_owner missing')
    if not attribution.get('selection_basis'):
        errors.append(f'{eid}: attribution_metadata.selection_basis missing')
    if not attribution.get('baseline_artifacts'):
        errors.append(f'{eid}: attribution_metadata.baseline_artifacts must not be empty')
    if not attribution.get('profile_artifacts'):
        errors.append(f'{eid}: attribution_metadata.profile_artifacts must not be empty')

    # Check unique ID
    if eid in ids_seen:
        errors.append(f'{eid}: duplicate ID')
    ids_seen.add(eid)

print(f'ENTRY_ERRORS={len(errors)}')
print(f'TOTAL_ENTRIES={len(entries)}')
for e in errors:
    print(f'  {e}')
")

entry_errs=$(echo "${entry_check}" | grep '^ENTRY_ERRORS=' | cut -d= -f2)

if [[ "${entry_errs}" -gt 0 ]]; then
    echo "FAIL: ${entry_errs} entry validation error(s):"
    echo "${entry_check}" | grep '  '
    failures=$((failures + 1))
else
    entry_ct=$(echo "${entry_check}" | grep '^TOTAL_ENTRIES=' | cut -d= -f2)
    echo "PASS: All ${entry_ct} entries have required fields and valid ranges"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Computed scores match formula
# ---------------------------------------------------------------------------
echo "--- Check 4: Score formula verification ---"

score_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    mat = json.load(f)

entries = mat.get('entries', [])
errors = []

# Formula: score = (impact * 0.5) + (confidence * 0.3) + (effort * 0.2)
for entry in entries:
    eid = entry.get('id', '?')
    impact = entry.get('impact', 0)
    confidence = entry.get('confidence', 0)
    effort = entry.get('effort', 0)
    claimed = entry.get('score', 0)

    computed = round((impact * 0.5) + (confidence * 0.3) + (effort * 0.2), 1)
    if abs(computed - claimed) > 0.05:
        errors.append(f'{eid}: claimed={claimed} computed={computed} (impact={impact} conf={confidence} effort={effort})')

print(f'SCORE_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

score_errs=$(echo "${score_check}" | grep '^SCORE_ERRORS=' | cut -d= -f2)

if [[ "${score_errs}" -gt 0 ]]; then
    echo "FAIL: ${score_errs} score formula mismatch(es):"
    echo "${score_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All scores match formula (impact*0.5 + confidence*0.3 + effort*0.2)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    mat = json.load(f)

entries = mat.get('entries', [])
deferred = mat.get('deferred', [])
summary = mat.get('summary', {})
errors = []

total = len(entries)
eligible = sum(1 for e in entries if e.get('status') == 'eligible')
deferred_count = len(deferred)
avg_score = round(sum(e.get('score', 0) for e in entries) / total, 2) if total > 0 else 0

if summary.get('total_entries', 0) != total:
    errors.append(f'total_entries: claimed={summary.get(\"total_entries\")} actual={total}')
if summary.get('eligible', 0) != eligible:
    errors.append(f'eligible: claimed={summary.get(\"eligible\")} actual={eligible}')
if summary.get('deferred', 0) != deferred_count:
    errors.append(f'deferred: claimed={summary.get(\"deferred\")} actual={deferred_count}')
if summary.get('required_wave_metadata', 0) != 4:
    errors.append(
        f'required_wave_metadata: claimed={summary.get(\"required_wave_metadata\")} actual=4'
    )

claimed_avg = summary.get('average_score', 0)
if abs(claimed_avg - avg_score) > 0.05:
    errors.append(f'average_score: claimed={claimed_avg} computed={avg_score}')

# Check highest/lowest
if entries:
    scores = [(e.get('score', 0), e.get('id', '')) for e in entries]
    highest = max(scores)
    lowest = min(scores)
    claimed_highest = summary.get('highest_score', {})
    claimed_lowest = summary.get('lowest_score', {})
    if claimed_highest.get('score') != highest[0]:
        errors.append(f'highest_score: claimed={claimed_highest.get(\"score\")} actual={highest[0]}')
    if claimed_lowest.get('score') != lowest[0]:
        errors.append(f'lowest_score: claimed={claimed_lowest.get(\"score\")} actual={lowest[0]}')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution
print(f'Entries: {total} (eligible={eligible}, deferred={deferred_count})')
print(f'Average score: {avg_score}')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary inconsistency(ies):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${sum_check}" | grep -E '^(Entries|Average)' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_opportunity_matrix: FAILED"
    exit 1
fi

echo ""
echo "check_opportunity_matrix: PASS"
