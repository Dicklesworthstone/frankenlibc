#!/usr/bin/env bash
# check_stub_priority.sh — CI gate for bd-4ia
#
# Validates that:
#   1. Stub priority ranking JSON exists and is valid.
#   2. Ranked symbols match actual non-implemented symbols in support_matrix.json.
#   3. Scores are computed correctly (severity_weight * workloads_blocked).
#   4. Tier assignments are consistent with symbol status/perf_class.
#   5. Burn-down wave plan accounts for all symbols.
#   6. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_stub_priority_ranking.py"
RANKING="${ROOT}/tests/conformance/stub_priority_ranking.json"
MATRIX="${ROOT}/support_matrix.json"
WORKLOADS="${ROOT}/tests/conformance/workload_matrix.json"

failures=0

echo "=== Stub Priority Ranking Gate (bd-4ia) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 0: Artifact reproducibility
# ---------------------------------------------------------------------------
echo "--- Check 0: Artifact reproducibility ---"

if [[ ! -f "${GEN}" ]]; then
    echo "FAIL: scripts/generate_stub_priority_ranking.py not found"
    failures=$((failures + 1))
else
    if python3 "${GEN}" \
        --support-matrix "${MATRIX}" \
        --workload-matrix "${WORKLOADS}" \
        --output "${RANKING}" \
        --check; then
        echo "PASS: stub_priority_ranking.json is reproducible from support_matrix/workload_matrix"
    else
        echo "FAIL: stub_priority_ranking.json is stale or generator drifted"
        failures=$((failures + 1))
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Check 1: File exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Ranking exists and is valid ---"

if [[ ! -f "${RANKING}" ]]; then
    echo "FAIL: tests/conformance/stub_priority_ranking.json not found"
    echo ""
    echo "check_stub_priority: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${RANKING}') as f:
        r = json.load(f)
    v = r.get('schema_version', 0)
    tiers = r.get('symbol_ranking', {}).get('tiers', [])
    modules = r.get('module_ranking', {}).get('entries', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not tiers:
        print('INVALID: empty symbol_ranking.tiers')
    elif not modules:
        print('INVALID: empty module_ranking.entries')
    else:
        total = sum(len(t.get('symbols', [])) for t in tiers)
        print(f'VALID version={v} tiers={len(tiers)} symbols={total} modules={len(modules)}')
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
# Check 2: Ranked symbols match support_matrix non-implemented
# ---------------------------------------------------------------------------
echo "--- Check 2: Symbol cross-reference with support_matrix ---"

sym_check=$(python3 -c "
import json

with open('${RANKING}') as f:
    ranking = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []

# Actual non-implemented from support matrix
actual_stubs = set()
actual_ct = set()
for s in matrix.get('symbols', []):
    if s.get('status') == 'Stub':
        actual_stubs.add(s['symbol'])
    elif s.get('status') == 'GlibcCallThrough':
        actual_ct.add(s['symbol'])

actual_all = actual_stubs | actual_ct

# Ranked symbols from tiers
ranked_symbols = set()
for tier in ranking.get('symbol_ranking', {}).get('tiers', []):
    for sym in tier.get('symbols', []):
        name = sym.get('symbol', '')
        if name in ranked_symbols:
            errors.append(f'Duplicate symbol in ranking: {name}')
        ranked_symbols.add(name)

# Cross-check
missing = actual_all - ranked_symbols
extra = ranked_symbols - actual_all
if missing:
    errors.append(f'Symbols in matrix but not ranked: {sorted(missing)}')
if extra:
    errors.append(f'Symbols ranked but not in matrix: {sorted(extra)}')

# Check status correctness
for tier in ranking.get('symbol_ranking', {}).get('tiers', []):
    for sym in tier.get('symbols', []):
        name = sym.get('symbol', '')
        claimed_status = sym.get('status', '')
        if claimed_status == 'Stub' and name not in actual_stubs:
            errors.append(f'{name}: claimed Stub but not Stub in matrix')
        elif claimed_status == 'GlibcCallThrough' and name not in actual_ct:
            errors.append(f'{name}: claimed GlibcCallThrough but not CT in matrix')

print(f'SYM_ERRORS={len(errors)}')
print(f'RANKED={len(ranked_symbols)}')
print(f'ACTUAL_STUBS={len(actual_stubs)}')
print(f'ACTUAL_CT={len(actual_ct)}')
for e in errors:
    print(f'  {e}')
")

sym_errs=$(echo "${sym_check}" | grep '^SYM_ERRORS=' | cut -d= -f2)

if [[ "${sym_errs}" -gt 0 ]]; then
    echo "FAIL: ${sym_errs} symbol cross-reference error(s):"
    echo "${sym_check}" | grep '  '
    failures=$((failures + 1))
else
    ranked=$(echo "${sym_check}" | grep '^RANKED=' | cut -d= -f2)
    echo "PASS: ${ranked} ranked symbols match support_matrix"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Score computation
# ---------------------------------------------------------------------------
echo "--- Check 3: Score formula verification ---"

score_check=$(python3 -c "
import json

with open('${RANKING}') as f:
    ranking = json.load(f)
with open('${WORKLOADS}') as f:
    wl = json.load(f)

errors = []

weights = ranking.get('scoring', {}).get('severity_weights', {})
stub_weight = weights.get('Stub', {}).get('weight', 0)
ct_hot_weight = weights.get('GlibcCallThrough_hotpath', {}).get('weight', 0)
ct_cold_weight = weights.get('GlibcCallThrough_coldpath', {}).get('weight', 0)

# Get workloads blocked by module from workload_matrix
impact = wl.get('subsystem_impact', {})
workloads_by_module = {}
for mod, info in impact.items():
    if mod == 'description':
        continue
    workloads_by_module[mod] = info.get('blocked_workloads', 0)

# Verify scores
for tier in ranking.get('symbol_ranking', {}).get('tiers', []):
    for sym in tier.get('symbols', []):
        name = sym.get('symbol', '')
        module = sym.get('module', '')
        status = sym.get('status', '')
        perf_class = sym.get('perf_class', '')
        claimed_score = sym.get('score', 0)

        if status == 'Stub':
            w = stub_weight
        elif perf_class == 'strict_hotpath':
            w = ct_hot_weight
        else:
            w = ct_cold_weight

        wl_blocked = workloads_by_module.get(module, 0)
        expected = w * wl_blocked

        if abs(claimed_score - expected) > 0.01:
            errors.append(f'{name}: claimed={claimed_score} expected={expected} (w={w} * wl={wl_blocked})')

print(f'SCORE_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

score_errs=$(echo "${score_check}" | grep '^SCORE_ERRORS=' | cut -d= -f2)

if [[ "${score_errs}" -gt 0 ]]; then
    echo "FAIL: ${score_errs} score error(s):"
    echo "${score_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All symbol scores match formula"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Tier assignments consistent
# ---------------------------------------------------------------------------
echo "--- Check 4: Tier assignment consistency ---"

tier_check=$(python3 -c "
import json

with open('${RANKING}') as f:
    ranking = json.load(f)

errors = []

for tier in ranking.get('symbol_ranking', {}).get('tiers', []):
    tid = tier.get('tier', '?')
    for sym in tier.get('symbols', []):
        name = sym.get('symbol', '')
        status = sym.get('status', '')
        perf_class = sym.get('perf_class', '')

        if tid == 'T1_critical' and status != 'Stub':
            errors.append(f'{name}: in T1_critical but status={status} (expected Stub)')
        elif tid == 'T2_hotpath' and (status != 'GlibcCallThrough' or perf_class != 'strict_hotpath'):
            errors.append(f'{name}: in T2_hotpath but status={status} perf={perf_class}')
        elif tid == 'T3_coldpath' and (status != 'GlibcCallThrough' or perf_class != 'coldpath'):
            errors.append(f'{name}: in T3_coldpath but status={status} perf={perf_class}')

    # Verify count
    syms = tier.get('symbols', [])
    claimed = tier.get('count', 0)
    if len(syms) != claimed:
        errors.append(f'{tid}: count={claimed} but {len(syms)} symbols')

print(f'TIER_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

tier_errs=$(echo "${tier_check}" | grep '^TIER_ERRORS=' | cut -d= -f2)

if [[ "${tier_errs}" -gt 0 ]]; then
    echo "FAIL: ${tier_errs} tier error(s):"
    echo "${tier_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Tier assignments match symbol status/perf_class"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Burn-down wave plan
# ---------------------------------------------------------------------------
echo "--- Check 5: Burn-down wave plan ---"

wave_check=$(python3 -c "
import json

with open('${RANKING}') as f:
    ranking = json.load(f)

errors = []
burn = ranking.get('burn_down', {})
waves = burn.get('wave_plan', [])
total = burn.get('total_non_implemented', 0)
by_status = burn.get('by_status', {})
by_perf = burn.get('by_perf_class', {})

# Check by_status sum
status_sum = sum(by_status.values())
if status_sum != total:
    errors.append(f'by_status sum={status_sum} != total={total}')

# Check by_perf_class sum
perf_sum = sum(by_perf.values())
if perf_sum != total:
    errors.append(f'by_perf_class sum={perf_sum} != total={total}')

# Check wave symbols total
wave_total = sum(w.get('symbols', 0) for w in waves)
if wave_total != total:
    errors.append(f'wave symbols total={wave_total} != total={total}')

# Check in_progress/planned/unscheduled counts
in_progress = sum(w.get('symbols', 0) for w in waves if w.get('status') == 'in_progress')
planned = sum(w.get('symbols', 0) for w in waves if w.get('status') == 'planned')
unscheduled = sum(w.get('symbols', 0) for w in waves if w.get('status') == 'unscheduled')

if burn.get('symbols_in_progress', 0) != in_progress:
    errors.append(f'symbols_in_progress: claimed={burn.get(\"symbols_in_progress\")} actual={in_progress}')
if burn.get('symbols_planned', 0) != planned:
    errors.append(f'symbols_planned: claimed={burn.get(\"symbols_planned\")} actual={planned}')
if burn.get('symbols_unscheduled', 0) != unscheduled:
    errors.append(f'symbols_unscheduled: claimed={burn.get(\"symbols_unscheduled\")} actual={unscheduled}')

print(f'WAVE_ERRORS={len(errors)}')
print(f'In-progress: {in_progress} | Planned: {planned} | Unscheduled: {unscheduled} | Total: {wave_total}')
for e in errors:
    print(f'  {e}')
")

wave_errs=$(echo "${wave_check}" | grep '^WAVE_ERRORS=' | cut -d= -f2)

if [[ "${wave_errs}" -gt 0 ]]; then
    echo "FAIL: ${wave_errs} burn-down error(s):"
    echo "${wave_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Burn-down wave plan consistent"
fi
echo "${wave_check}" | grep -E '^In-progress' || true
echo ""

# ---------------------------------------------------------------------------
# Check 6: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 6: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${RANKING}') as f:
    ranking = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
summary = ranking.get('summary', {})

# Actual counts
actual_stubs = sum(1 for s in matrix.get('symbols', []) if s.get('status') == 'Stub')
actual_ct = sum(1 for s in matrix.get('symbols', []) if s.get('status') == 'GlibcCallThrough')
actual_total = actual_stubs + actual_ct

if summary.get('total_non_implemented', 0) != actual_total:
    errors.append(f'total_non_implemented: claimed={summary.get(\"total_non_implemented\")} actual={actual_total}')
if summary.get('stubs', 0) != actual_stubs:
    errors.append(f'stubs: claimed={summary.get(\"stubs\")} actual={actual_stubs}')
if summary.get('callthroughs', 0) != actual_ct:
    errors.append(f'callthroughs: claimed={summary.get(\"callthroughs\")} actual={actual_ct}')

# Tier counts
tiers = ranking.get('symbol_ranking', {}).get('tiers', [])
tier_counts = summary.get('tier_counts', {})
for t in tiers:
    tid = t.get('tier', '?')
    actual = len(t.get('symbols', []))
    claimed = tier_counts.get(tid, 0)
    if actual != claimed:
        errors.append(f'tier_counts.{tid}: claimed={claimed} actual={actual}')

# Modules affected
modules = set()
for t in tiers:
    for s in t.get('symbols', []):
        modules.add(s.get('module', ''))
if summary.get('modules_affected', 0) != len(modules):
    errors.append(f'modules_affected: claimed={summary.get(\"modules_affected\")} actual={len(modules)}')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Stubs: {actual_stubs} | Callthroughs: {actual_ct} | Total: {actual_total} | Modules: {len(modules)}')
for e in errors:
    print(f'  {e}')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary error(s):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${sum_check}" | grep -E '^Stubs' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_stub_priority: FAILED"
    exit 1
fi

echo ""
echo "check_stub_priority: PASS"
