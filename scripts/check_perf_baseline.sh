#!/usr/bin/env bash
# check_perf_baseline.sh — CI gate for bd-2wp
#
# Validates that:
#   1. Perf baseline spec JSON exists and is valid.
#   2. Benchmark suites reference existing crates/benches.
#   3. Baseline file exists and covers all enforced suites.
#   4. Percentile targets are well-defined.
#   5. Regeneration procedure is complete.
#   6. Summary statistics are consistent.
#   7. Profile artifact contract is defined and complete.
#
# This gate validates the perf baseline specification and baseline file structure.
# It does NOT run benchmarks (that's perf_gate.sh).
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/perf_baseline_spec.json"
BASELINE="${ROOT}/scripts/perf_baseline.json"

failures=0

echo "=== Perf Baseline Suite Gate (bd-2wp) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Perf baseline spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/perf_baseline_spec.json not found"
    echo ""
    echo "check_perf_baseline: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    suites = s.get('benchmark_suites', {}).get('suites', [])
    pct = s.get('percentile_targets', {})
    regen = s.get('regeneration', {})
    reg = s.get('regression_detection', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not suites:
        print('INVALID: empty benchmark suites')
    elif not pct:
        print('INVALID: missing percentile_targets')
    elif not regen:
        print('INVALID: missing regeneration')
    elif not reg:
        print('INVALID: missing regression_detection')
    else:
        print(f'VALID version={v} suites={len(suites)}')
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
# Check 2: Benchmark suites reference valid crates and benches
# ---------------------------------------------------------------------------
echo "--- Check 2: Benchmark suite crate/bench references ---"

suite_check=$(python3 -c "
import json, os

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
suites = spec.get('benchmark_suites', {}).get('suites', [])

for suite in suites:
    sid = suite.get('id', '?')
    crate = suite.get('crate', '')
    command = suite.get('command', '')

    # Crate must exist
    crate_dir = os.path.join('${ROOT}', 'crates', crate)
    if not os.path.isdir(crate_dir):
        errors.append(f'{sid}: crate directory not found: crates/{crate}')

    # Command must reference --bench
    if '--bench' not in command:
        errors.append(f'{sid}: command missing --bench flag')

    # Must have at least one benchmark
    benchmarks = suite.get('benchmarks', [])
    if not benchmarks:
        errors.append(f'{sid}: no benchmarks defined')

    # Must have modes
    modes = suite.get('modes', [])
    if not modes:
        errors.append(f'{sid}: no modes defined')

    # Each benchmark must have name and description
    for bench in benchmarks:
        if not bench.get('name'):
            errors.append(f'{sid}: benchmark missing name')
        if not bench.get('description'):
            errors.append(f'{sid}/{bench.get(\"name\",\"?\")}: missing description')

print(f'SUITE_ERRORS={len(errors)}')
print(f'SUITES={len(suites)}')
total_benchmarks = sum(len(s.get('benchmarks', [])) for s in suites)
print(f'BENCHMARKS={total_benchmarks}')
for e in errors:
    print(f'  {e}')
")

suite_errs=$(echo "${suite_check}" | grep '^SUITE_ERRORS=' | cut -d= -f2)

if [[ "${suite_errs}" -gt 0 ]]; then
    echo "FAIL: ${suite_errs} suite reference error(s):"
    echo "${suite_check}" | grep '  '
    failures=$((failures + 1))
else
    scount=$(echo "${suite_check}" | grep '^SUITES=' | cut -d= -f2)
    bcount=$(echo "${suite_check}" | grep '^BENCHMARKS=' | cut -d= -f2)
    echo "PASS: ${scount} suites with ${bcount} total benchmarks validated"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Baseline file exists and covers enforced suites
# ---------------------------------------------------------------------------
echo "--- Check 3: Baseline file coverage ---"

baseline_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []

# Check baseline file exists
try:
    with open('${BASELINE}') as f:
        baseline = json.load(f)
except FileNotFoundError:
    print('BASELINE_ERRORS=1')
    print('  Baseline file not found: scripts/perf_baseline.json')
    exit()
except json.JSONDecodeError as e:
    print('BASELINE_ERRORS=1')
    print(f'  Baseline file invalid JSON: {e}')
    exit()

# Check version
if 'version' not in baseline:
    errors.append('Baseline missing version field')

if 'generated_at_utc' not in baseline:
    errors.append('Baseline missing generated_at_utc field')

# Check enforced suites have baselines
suites = spec.get('benchmark_suites', {}).get('suites', [])
enforced = [s for s in suites if s.get('enforced_in_gate', False)]

p50 = baseline.get('baseline_p50_ns_op', {})
for suite in enforced:
    sid = suite.get('id', '?')
    if sid not in p50:
        errors.append(f'Enforced suite \"{sid}\" not found in baseline_p50_ns_op')
        continue

    suite_baselines = p50[sid]
    for mode in suite.get('modes', []):
        if mode not in suite_baselines:
            errors.append(f'{sid}: mode \"{mode}\" not in baseline')
            continue

        mode_baselines = suite_baselines[mode]
        for bench in suite.get('benchmarks', []):
            bname = bench.get('name', '?')
            if bname not in mode_baselines:
                errors.append(f'{sid}/{mode}/{bname}: missing from baseline')

print(f'BASELINE_ERRORS={len(errors)}')
print(f'ENFORCED_SUITES={len(enforced)}')
for e in errors:
    print(f'  {e}')
")

baseline_errs=$(echo "${baseline_check}" | grep '^BASELINE_ERRORS=' | cut -d= -f2)

if [[ "${baseline_errs}" -gt 0 ]]; then
    echo "FAIL: ${baseline_errs} baseline coverage error(s):"
    echo "${baseline_check}" | grep '  '
    failures=$((failures + 1))
else
    ecount=$(echo "${baseline_check}" | grep '^ENFORCED_SUITES=' | cut -d= -f2)
    echo "PASS: Baseline covers all ${ecount} enforced suites"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Percentile targets well-defined
# ---------------------------------------------------------------------------
echo "--- Check 4: Percentile targets ---"

pct_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
pct = spec.get('percentile_targets', {})

captured = pct.get('captured_percentiles', [])
if not captured:
    errors.append('No captured_percentiles defined')

required_pcts = ['p50', 'p95', 'p99']
for p in required_pcts:
    if p not in captured:
        errors.append(f'Missing percentile: {p}')

primary = pct.get('primary_gate_metric', '')
if primary != 'p50':
    errors.append(f'Primary gate metric should be p50, got: {primary}')

gate_behavior = pct.get('gate_behavior', {})
if not gate_behavior:
    errors.append('Missing gate_behavior')
else:
    for p in required_pcts:
        if p not in gate_behavior:
            errors.append(f'Missing gate_behavior for {p}')

print(f'PCT_ERRORS={len(errors)}')
print(f'PERCENTILES={len(captured)}')
for e in errors:
    print(f'  {e}')
")

pct_errs=$(echo "${pct_check}" | grep '^PCT_ERRORS=' | cut -d= -f2)

if [[ "${pct_errs}" -gt 0 ]]; then
    echo "FAIL: ${pct_errs} percentile target error(s):"
    echo "${pct_check}" | grep '  '
    failures=$((failures + 1))
else
    pcount=$(echo "${pct_check}" | grep '^PERCENTILES=' | cut -d= -f2)
    echo "PASS: ${pcount} percentiles defined with gate behavior"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Regeneration procedure complete
# ---------------------------------------------------------------------------
echo "--- Check 5: Regeneration procedure ---"

regen_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
regen = spec.get('regeneration', {})

prereqs = regen.get('prerequisites', [])
if len(prereqs) < 2:
    errors.append(f'Too few prerequisites: {len(prereqs)} (need >= 2)')

commands = regen.get('command_sequence', [])
if len(commands) < 2:
    errors.append(f'Too few commands: {len(commands)} (need >= 2)')

# Must mention cargo bench
cmd_text = ' '.join(commands).lower()
if 'cargo bench' not in cmd_text:
    errors.append('Command sequence must include cargo bench')

validation = regen.get('validation', {})
if not validation:
    errors.append('Missing validation section')
else:
    if 'min_repeat_runs' not in validation:
        errors.append('Missing min_repeat_runs in validation')
    if 'max_cv_pct' not in validation:
        errors.append('Missing max_cv_pct in validation')

update_policy = regen.get('update_policy', '')
if not update_policy:
    errors.append('Missing update_policy')

print(f'REGEN_ERRORS={len(errors)}')
print(f'PREREQS={len(prereqs)} COMMANDS={len(commands)}')
for e in errors:
    print(f'  {e}')
")

regen_errs=$(echo "${regen_check}" | grep '^REGEN_ERRORS=' | cut -d= -f2)

if [[ "${regen_errs}" -gt 0 ]]; then
    echo "FAIL: ${regen_errs} regeneration procedure error(s):"
    echo "${regen_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Regeneration procedure complete"
fi
echo "${regen_check}" | grep -E '^PREREQS' || true
echo ""

# ---------------------------------------------------------------------------
# Check 6: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 6: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
summary = spec.get('summary', {})
suites = spec.get('benchmark_suites', {}).get('suites', [])
pct = spec.get('percentile_targets', {}).get('captured_percentiles', [])
regen_steps = len(spec.get('regeneration', {}).get('command_sequence', []))
prereq_checks = len(spec.get('regeneration', {}).get('prerequisites', []))

total_benchmarks = sum(len(s.get('benchmarks', [])) for s in suites)
enforced_count = sum(1 for s in suites if s.get('enforced_in_gate', False))
planned_count = sum(1 for s in suites if not s.get('enforced_in_gate', False))
modes = set()
for s in suites:
    for m in s.get('modes', []):
        modes.add(m)

if summary.get('total_suites', 0) != len(suites):
    errors.append(f'total_suites: claimed={summary.get(\"total_suites\")} actual={len(suites)}')
if summary.get('total_benchmarks', 0) != total_benchmarks:
    errors.append(f'total_benchmarks: claimed={summary.get(\"total_benchmarks\")} actual={total_benchmarks}')
if summary.get('enforced_suites', 0) != enforced_count:
    errors.append(f'enforced_suites: claimed={summary.get(\"enforced_suites\")} actual={enforced_count}')
if summary.get('planned_suites', 0) != planned_count:
    errors.append(f'planned_suites: claimed={summary.get(\"planned_suites\")} actual={planned_count}')
if summary.get('modes', 0) != len(modes):
    errors.append(f'modes: claimed={summary.get(\"modes\")} actual={len(modes)}')
if summary.get('captured_percentiles', 0) != len(pct):
    errors.append(f'captured_percentiles: claimed={summary.get(\"captured_percentiles\")} actual={len(pct)}')
if summary.get('regeneration_steps', 0) != regen_steps:
    errors.append(f'regeneration_steps: claimed={summary.get(\"regeneration_steps\")} actual={regen_steps}')
if summary.get('prerequisite_checks', 0) != prereq_checks:
    errors.append(f'prerequisite_checks: claimed={summary.get(\"prerequisite_checks\")} actual={prereq_checks}')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Suites: {len(suites)} | Benchmarks: {total_benchmarks} | Enforced: {enforced_count} | Planned: {planned_count} | Modes: {len(modes)} | Percentiles: {len(pct)}')
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
echo "${sum_check}" | grep -E '^Suites' || true
echo ""

# ---------------------------------------------------------------------------
# Check 7: Profile artifact contract
# ---------------------------------------------------------------------------
echo "--- Check 7: Profile artifact contract ---"

artifact_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
profile_artifacts = spec.get('profile_artifacts', {})
if not profile_artifacts:
    errors.append('Missing profile_artifacts section')
else:
    required_files = profile_artifacts.get('required_files', [])
    required_set = set(required_files)
    must_have = {
        'manifest.txt',
        'commands.log',
        'summary.log',
        'targets.tsv',
        'profile_report.v1.json',
        'hotspot_opportunity_matrix.v1.json',
    }
    for req in sorted(must_have):
        if req not in required_set:
            errors.append(f'missing required profile artifact: {req}')

    if len(required_files) < len(must_have):
        errors.append(f'too few required_files entries: {len(required_files)} (need >= {len(must_have)})')

    per_target = profile_artifacts.get('per_target_required', [])
    per_target_set = set(per_target)
    for req in ['cpu/<slug>.top5.txt', 'alloc/<slug>.top5.txt', 'syscall/<slug>.top5.txt']:
        if req not in per_target_set:
            errors.append(f'missing per_target_required pattern: {req}')

    structured = profile_artifacts.get('structured_reports', {})
    profile_report = structured.get('profile_report_v1', {}).get('required_fields', [])
    hotspot = structured.get('hotspot_opportunity_matrix_v1', {}).get('required_fields', [])

    for req in ['schema_version', 'generated_at_utc', 'run', 'targets', 'summary']:
        if req not in profile_report:
            errors.append(f'profile_report_v1 missing required field declaration: {req}')

    for req in ['schema_version', 'generated_at_utc', 'source_run', 'scoring', 'entries', 'summary']:
        if req not in hotspot:
            errors.append(f'hotspot_opportunity_matrix_v1 missing required field declaration: {req}')

summary = spec.get('summary', {})
claimed_required_files = summary.get('profile_required_files')
actual_required_files = len(profile_artifacts.get('required_files', [])) if profile_artifacts else 0
if claimed_required_files is None:
    errors.append('summary.profile_required_files missing')
elif claimed_required_files != actual_required_files:
    errors.append(
        f'summary.profile_required_files mismatch: claimed={claimed_required_files} actual={actual_required_files}'
    )

print(f'ARTIFACT_ERRORS={len(errors)}')
print(f'PROFILE_REQUIRED_FILES={actual_required_files}')
for e in errors:
    print(f'  {e}')
")

artifact_errs=$(echo "${artifact_check}" | grep '^ARTIFACT_ERRORS=' | cut -d= -f2)

if [[ "${artifact_errs}" -gt 0 ]]; then
    echo "FAIL: ${artifact_errs} profile artifact contract error(s):"
    echo "${artifact_check}" | grep '  '
    failures=$((failures + 1))
else
    acount=$(echo "${artifact_check}" | grep '^PROFILE_REQUIRED_FILES=' | cut -d= -f2)
    echo "PASS: Profile artifact contract defines ${acount} required run files"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_perf_baseline: FAILED"
    exit 1
fi

echo ""
echo "check_perf_baseline: PASS"
