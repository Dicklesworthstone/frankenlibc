#!/usr/bin/env bash
# check_workload_matrix.sh — CI gate for bd-3u0
#
# Validates that:
#   1. Workload matrix JSON exists and is valid.
#   2. All workloads have required fields and valid modules.
#   3. Replacement blockers match support_matrix non-replaceable status truth.
#   4. Subsystem impact counts match actual blocker references.
#   5. Milestone mappings reference valid beads.
#   6. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKLOADS="${ROOT}/tests/conformance/workload_matrix.json"
MATRIX="${ROOT}/support_matrix.json"
BEADS="${ROOT}/.beads/issues.jsonl"

failures=0

echo "=== Workload Matrix Gate (bd-3u0) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: File exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Workload matrix exists and is valid ---"

if [[ ! -f "${WORKLOADS}" ]]; then
    echo "FAIL: tests/conformance/workload_matrix.json not found"
    echo ""
    echo "check_workload_matrix: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${WORKLOADS}') as f:
        wl = json.load(f)
    v = wl.get('schema_version', 0)
    workloads = wl.get('workloads', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not workloads:
        print('INVALID: empty workloads')
    else:
        print(f'VALID version={v} workloads={len(workloads)}')
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
# Check 2: Workload entries have required fields and valid modules
# ---------------------------------------------------------------------------
echo "--- Check 2: Workload entry validation ---"

entry_check=$(python3 -c "
import json

with open('${WORKLOADS}') as f:
    wl = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

valid_modules = set(sym.get('module', '') for sym in matrix.get('symbols', []))
errors = []
workloads = wl.get('workloads', [])
required = ['id', 'binary', 'description', 'category', 'required_modules', 'blocked_by', 'interpose_ready', 'replace_ready', 'priority_impact']
ids_seen = set()

for entry in workloads:
    wid = entry.get('id', '?')
    for field in required:
        if field not in entry:
            errors.append(f'{wid}: missing field \"{field}\"')

    for mod in entry.get('required_modules', []):
        if mod not in valid_modules:
            errors.append(f'{wid}: invalid module \"{mod}\"')

    if wid in ids_seen:
        errors.append(f'{wid}: duplicate ID')
    ids_seen.add(wid)

print(f'ENTRY_ERRORS={len(errors)}')
print(f'TOTAL={len(workloads)}')
for e in errors:
    print(f'  {e}')
")

entry_errs=$(echo "${entry_check}" | grep '^ENTRY_ERRORS=' | cut -d= -f2)

if [[ "${entry_errs}" -gt 0 ]]; then
    echo "FAIL: ${entry_errs} entry error(s):"
    echo "${entry_check}" | grep '  '
    failures=$((failures + 1))
else
    total=$(echo "${entry_check}" | grep '^TOTAL=' | cut -d= -f2)
    echo "PASS: All ${total} workload entries valid"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Replacement blockers match support_matrix status truth
# ---------------------------------------------------------------------------
echo "--- Check 3: Replacement blocker status truth ---"

blocker_check=$(python3 -c "
import json
from collections import Counter, defaultdict

with open('${WORKLOADS}') as f:
    wl = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

blocker_statuses = ('WrapsHostLibc', 'GlibcCallThrough', 'Stub')
module_counts = defaultdict(Counter)
for sym in matrix.get('symbols', []):
    status = sym.get('status')
    if status in blocker_statuses:
        module_counts[sym.get('module', 'unknown')][status] += 1

errors = []
for w in wl.get('workloads', []):
    wid = w.get('id', '?')
    required_modules = list(dict.fromkeys(w.get('required_modules', [])))
    expected_modules = [
        mod for mod in required_modules
        if sum(module_counts.get(mod, {}).values()) > 0
    ]
    actual_modules = w.get('blocked_by', [])
    if actual_modules != expected_modules:
        errors.append(f'{wid}: blocked_by={actual_modules} expected={expected_modules}')

    expected_blockers = []
    for mod in expected_modules:
        counts = module_counts.get(mod, {})
        for status in blocker_statuses:
            count = counts.get(status, 0)
            if count:
                expected_blockers.append(f'{mod} ({count} {status})')
    actual_blockers = w.get('replace_blockers', [])
    if actual_blockers != expected_blockers:
        errors.append(f'{wid}: replace_blockers={actual_blockers} expected={expected_blockers}')

    expected_ready = not expected_modules
    if bool(w.get('replace_ready')) != expected_ready:
        errors.append(f'{wid}: replace_ready={w.get(\"replace_ready\")} expected={expected_ready}')

print(f'BLOCKER_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

blocker_errs=$(echo "${blocker_check}" | grep '^BLOCKER_ERRORS=' | cut -d= -f2)

if [[ "${blocker_errs}" -gt 0 ]]; then
    echo "FAIL: ${blocker_errs} replacement blocker error(s):"
    echo "${blocker_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Workload blockers match support_matrix replacement status truth"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Subsystem impact counts match blocker references
# ---------------------------------------------------------------------------
echo "--- Check 4: Subsystem impact consistency ---"

impact_check=$(python3 -c "
import json

with open('${WORKLOADS}') as f:
    wl = json.load(f)

errors = []
workloads = wl.get('workloads', [])
subsystem_impact = wl.get('subsystem_impact', {})
valid_ids = set(w.get('id') for w in workloads)

# Build actual blocker map from workload entries
actual_blockers = {}
for w in workloads:
    wid = w.get('id', '?')
    for mod in w.get('blocked_by', []):
        actual_blockers.setdefault(mod, []).append(wid)

# Check each claimed subsystem
for mod, info in subsystem_impact.items():
    if mod == 'description':
        continue
    claimed_count = info.get('blocked_workloads', 0)
    claimed_ids = set(info.get('workload_ids', []))
    actual_ids = set(actual_blockers.get(mod, []))

    if claimed_count != len(actual_ids):
        errors.append(f'{mod}: claimed {claimed_count} blocked, actual {len(actual_ids)}')
    if claimed_ids != actual_ids:
        missing = actual_ids - claimed_ids
        extra = claimed_ids - actual_ids
        if missing:
            errors.append(f'{mod}: missing workload refs {missing}')
        if extra:
            errors.append(f'{mod}: extra workload refs {extra}')

    # Verify all referenced IDs exist
    for wid in claimed_ids:
        if wid not in valid_ids:
            errors.append(f'{mod}: references nonexistent workload {wid}')

print(f'IMPACT_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

impact_errs=$(echo "${impact_check}" | grep '^IMPACT_ERRORS=' | cut -d= -f2)

if [[ "${impact_errs}" -gt 0 ]]; then
    echo "FAIL: ${impact_errs} subsystem impact error(s):"
    echo "${impact_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Subsystem impact counts match blocker references"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Milestone mappings reference valid beads
# ---------------------------------------------------------------------------
echo "--- Check 5: Milestone bead references ---"

milestone_check=$(python3 -c "
import json

with open('${WORKLOADS}') as f:
    wl = json.load(f)

errors = []
bead_ids = set()
try:
    with open('${BEADS}') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            bead_ids.add(obj.get('id', ''))
except FileNotFoundError:
    pass

milestones = wl.get('milestone_mapping', {}).get('milestones', [])
valid_wl_ids = set(w.get('id') for w in wl.get('workloads', []))

for ms in milestones:
    bid = ms.get('bead', '')
    if bid and bid not in bead_ids:
        errors.append(f'Milestone bead {bid} not in issues.jsonl')
    for wid in ms.get('unblocks_workloads', []):
        if wid not in valid_wl_ids:
            errors.append(f'Milestone {bid}: references nonexistent workload {wid}')

print(f'MILESTONE_ERRORS={len(errors)}')
print(f'MILESTONES={len(milestones)}')
for e in errors:
    print(f'  {e}')
")

ms_errs=$(echo "${milestone_check}" | grep '^MILESTONE_ERRORS=' | cut -d= -f2)

if [[ "${ms_errs}" -gt 0 ]]; then
    echo "FAIL: ${ms_errs} milestone error(s):"
    echo "${milestone_check}" | grep '  '
    failures=$((failures + 1))
else
    ms_count=$(echo "${milestone_check}" | grep '^MILESTONES=' | cut -d= -f2)
    echo "PASS: All ${ms_count} milestones reference valid beads and workloads"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 6: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${WORKLOADS}') as f:
    wl = json.load(f)

errors = []
workloads = wl.get('workloads', [])
summary = wl.get('summary', {})

total = len(workloads)
interpose_ready = sum(1 for w in workloads if w.get('interpose_ready'))
replace_ready = sum(1 for w in workloads if w.get('replace_ready'))
replace_blocked = total - replace_ready
blocker_counts = {}
workload_blocker_counts = {}
for w in workloads:
    wid = w.get('id', '?')
    mods = w.get('blocked_by', [])
    workload_blocker_counts[wid] = len(mods)
    for mod in mods:
        blocker_counts[mod] = blocker_counts.get(mod, 0) + 1

if summary.get('total_workloads', 0) != total:
    errors.append(f'total_workloads: claimed={summary.get(\"total_workloads\")} actual={total}')
if summary.get('interpose_ready', 0) != interpose_ready:
    errors.append(f'interpose_ready: claimed={summary.get(\"interpose_ready\")} actual={interpose_ready}')
if summary.get('replace_ready', 0) != replace_ready:
    errors.append(f'replace_ready: claimed={summary.get(\"replace_ready\")} actual={replace_ready}')
if summary.get('replace_blocked', 0) != replace_blocked:
    errors.append(f'replace_blocked: claimed={summary.get(\"replace_blocked\")} actual={replace_blocked}')

# Check category counts
cats = {}
for w in workloads:
    c = w.get('category', 'unknown')
    cats[c] = cats.get(c, 0) + 1
claimed_cats = summary.get('categories', {})
for c, count in cats.items():
    if claimed_cats.get(c, 0) != count:
        errors.append(f'categories.{c}: claimed={claimed_cats.get(c)} actual={count}')

top_blocker = summary.get('top_blocker')
if blocker_counts:
    actual_top = max(blocker_counts.items(), key=lambda item: (item[1], item[0]))
    expected_top = f'{actual_top[0]} (blocks {actual_top[1]} workloads)'
    if top_blocker != expected_top:
        errors.append(f'top_blocker: claimed={top_blocker!r} actual={expected_top!r}')
else:
    if top_blocker is not None:
        errors.append(f'top_blocker: claimed={top_blocker!r} actual=None')

most_blocked = summary.get('most_blocked_workload')
if any(count > 0 for count in workload_blocker_counts.values()):
    actual_wid, actual_count = max(workload_blocker_counts.items(), key=lambda item: (item[1], item[0]))
    binary = next((w.get('binary', actual_wid) for w in workloads if w.get('id') == actual_wid), actual_wid)
    expected = f'{actual_wid} {binary} ({actual_count} module blockers)'
    if most_blocked != expected:
        errors.append(f'most_blocked_workload: claimed={most_blocked!r} actual={expected!r}')
else:
    if most_blocked is not None:
        errors.append(f'most_blocked_workload: claimed={most_blocked!r} actual=None')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

print(f'Interpose: {interpose_ready}/{total} ready')
print(f'Replace: {replace_ready}/{total} ready, {replace_blocked} blocked')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary error(s):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${sum_check}" | grep -E '^(Interpose|Replace)' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_workload_matrix: FAILED"
    exit 1
fi

echo ""
echo "check_workload_matrix: PASS"
