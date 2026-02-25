#!/usr/bin/env bash
# check_anytime_valid_monitor.sh — CI gate for bd-182
#
# Validates that:
#   1. Anytime-valid monitor spec JSON exists and is valid.
#   2. E-process parameters are consistent with implementation constants.
#   3. Alpha-investing FDR bound is correctly computed.
#   4. Alert budget contracts are complete and well-formed.
#   5. Companion monitors match math_governance.json production_monitor list.
#   6. Summary statistics are consistent.
#   7. Statistical kernel implementation/wiring coverage remains complete.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/anytime_valid_monitor_spec.json"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"

failures=0

echo "=== Anytime-Valid Monitor Gate (bd-182) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/anytime_valid_monitor_spec.json not found"
    echo ""
    echo "check_anytime_valid_monitor: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    ep = s.get('eprocess_policy', {})
    ai = s.get('alpha_investing_policy', {})
    abc = s.get('alert_budget_contracts', {})
    cm = s.get('companion_monitors', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not ep:
        print('INVALID: missing eprocess_policy')
    elif not ai:
        print('INVALID: missing alpha_investing_policy')
    elif not abc:
        print('INVALID: missing alert_budget_contracts')
    elif not cm:
        print('INVALID: missing companion_monitors')
    else:
        print(f'VALID version={v}')
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
# Check 2: E-process parameters internally consistent
# ---------------------------------------------------------------------------
echo "--- Check 2: E-process parameters ---"

ep_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
ep = spec.get('eprocess_policy', {})
params = ep.get('parameters', {})

# Required parameters
required_params = ['null_budget_p0', 'alternative_q1', 'warmup_calls', 'warning_threshold_e', 'alarm_threshold_e']
for p in required_params:
    if p not in params:
        errors.append(f'Missing parameter: {p}')

if not errors:
    p0 = params['null_budget_p0']['value']
    q1 = params['alternative_q1']['value']
    warn_e = params['warning_threshold_e']['value']
    alarm_e = params['alarm_threshold_e']['value']
    warmup = params['warmup_calls']['value']

    if not (0 < p0 < 1):
        errors.append(f'p0 must be in (0,1), got {p0}')
    if not (p0 < q1 < 1):
        errors.append(f'q1 must be in (p0,1), got {q1}')
    if not (1.0 < warn_e < alarm_e):
        errors.append(f'warning_e ({warn_e}) must be < alarm_e ({alarm_e}) and > 1')
    if warmup < 1:
        errors.append(f'warmup_calls must be >= 1, got {warmup}')

# Check states
states = ep.get('states', [])
state_names = [s['state'] for s in states]
expected_states = ['Calibrating', 'Normal', 'Warning', 'Alarm']
for es in expected_states:
    if es not in state_names:
        errors.append(f'Missing e-process state: {es}')

# Check API families
families = ep.get('api_family_list', [])
count = ep.get('api_families_monitored', 0)
if len(families) != count:
    errors.append(f'api_family_list length ({len(families)}) != api_families_monitored ({count})')

print(f'EP_ERRORS={len(errors)}')
print(f'PARAMS={len(required_params)} STATES={len(states)} FAMILIES={len(families)}')
for e in errors:
    print(f'  {e}')
")

ep_errs=$(echo "${ep_check}" | grep '^EP_ERRORS=' | cut -d= -f2)

if [[ "${ep_errs}" -gt 0 ]]; then
    echo "FAIL: ${ep_errs} e-process parameter error(s):"
    echo "${ep_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: E-process parameters validated"
fi
echo "${ep_check}" | grep -E '^PARAMS' || true
echo ""

# ---------------------------------------------------------------------------
# Check 3: Alpha-investing FDR bound
# ---------------------------------------------------------------------------
echo "--- Check 3: Alpha-investing FDR bound ---"

ai_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
ai = spec.get('alpha_investing_policy', {})
params = ai.get('parameters', {})

required_params = ['initial_wealth_milli', 'spend_fraction_milli', 'reward_milli', 'depleted_threshold_milli', 'generous_threshold_milli']
for p in required_params:
    if p not in params:
        errors.append(f'Missing parameter: {p}')

if not errors:
    w0 = params['initial_wealth_milli']['value']
    reward = params['reward_milli']['value']
    depleted = params['depleted_threshold_milli']['value']
    generous = params['generous_threshold_milli']['value']

    # FDR bound: E[false discoveries] <= W(0)/reward
    fdr_bound = w0 / reward
    claimed_bound = ai.get('fdr_guarantee', {}).get('bound', 0)
    if claimed_bound != fdr_bound:
        errors.append(f'FDR bound mismatch: claimed={claimed_bound} computed=W(0)/reward={fdr_bound}')

    if not (depleted < generous < w0):
        errors.append(f'Threshold ordering violated: depleted({depleted}) < generous({generous}) < initial({w0})')

# Check states
states = ai.get('states', [])
state_names = [s['state'] for s in states]
expected = ['Calibrating', 'Normal', 'Generous', 'Depleted']
for es in expected:
    if es not in state_names:
        errors.append(f'Missing alpha-investing state: {es}')

print(f'AI_ERRORS={len(errors)}')
print(f'W0={params.get(\"initial_wealth_milli\", {}).get(\"value\", \"?\")} reward={params.get(\"reward_milli\", {}).get(\"value\", \"?\")} FDR_bound={ai.get(\"fdr_guarantee\", {}).get(\"bound\", \"?\")}')
for e in errors:
    print(f'  {e}')
")

ai_errs=$(echo "${ai_check}" | grep '^AI_ERRORS=' | cut -d= -f2)

if [[ "${ai_errs}" -gt 0 ]]; then
    echo "FAIL: ${ai_errs} alpha-investing error(s):"
    echo "${ai_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Alpha-investing FDR bound verified"
fi
echo "${ai_check}" | grep -E '^W0=' || true
echo ""

# ---------------------------------------------------------------------------
# Check 4: Alert budget contracts complete
# ---------------------------------------------------------------------------
echo "--- Check 4: Alert budget contracts ---"

abc_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
contracts = spec.get('alert_budget_contracts', {}).get('contracts', [])

if len(contracts) < 4:
    errors.append(f'Too few contracts: {len(contracts)} (need >= 4)')

seen_ids = set()
for c in contracts:
    cid = c.get('id', '?')
    if cid in seen_ids:
        errors.append(f'Duplicate contract ID: {cid}')
    seen_ids.add(cid)
    if not c.get('name'):
        errors.append(f'{cid}: missing name')
    if not c.get('invariant'):
        errors.append(f'{cid}: missing invariant')
    if not c.get('enforcement'):
        errors.append(f'{cid}: missing enforcement')

# Must include anytime validity contract
contract_names = [c.get('name', '').lower() for c in contracts]
has_anytime = any('anytime' in n for n in contract_names)
if not has_anytime:
    errors.append('No contract for anytime validity')

has_wealth = any('wealth' in n for n in contract_names)
if not has_wealth:
    errors.append('No contract for wealth non-negativity')

print(f'ABC_ERRORS={len(errors)}')
print(f'CONTRACTS={len(contracts)}')
for e in errors:
    print(f'  {e}')
")

abc_errs=$(echo "${abc_check}" | grep '^ABC_ERRORS=' | cut -d= -f2)

if [[ "${abc_errs}" -gt 0 ]]; then
    echo "FAIL: ${abc_errs} contract error(s):"
    echo "${abc_check}" | grep '  '
    failures=$((failures + 1))
else
    ccount=$(echo "${abc_check}" | grep '^CONTRACTS=' | cut -d= -f2)
    echo "PASS: ${ccount} alert budget contracts validated (anytime + wealth present)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Companion monitors match governance
# ---------------------------------------------------------------------------
echo "--- Check 5: Companion monitors vs governance ---"

cm_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${GOVERNANCE}') as f:
    gov = json.load(f)

errors = []

spec_monitors = set(m['module'] for m in spec.get('companion_monitors', {}).get('modules', []))
gov_monitors = set(m['module'] for m in gov.get('classifications', {}).get('production_monitor', []))

missing_from_spec = gov_monitors - spec_monitors
extra_in_spec = spec_monitors - gov_monitors

for m in missing_from_spec:
    errors.append(f'Monitor in governance but not in spec: {m}')
for m in extra_in_spec:
    errors.append(f'Monitor in spec but not in governance: {m}')

claimed_count = spec.get('companion_monitors', {}).get('total_production_monitors', 0)
if claimed_count != len(spec_monitors):
    errors.append(f'total_production_monitors: claimed={claimed_count} actual={len(spec_monitors)}')

print(f'CM_ERRORS={len(errors)}')
print(f'SPEC_MONITORS={len(spec_monitors)} GOV_MONITORS={len(gov_monitors)}')
for e in errors:
    print(f'  {e}')
")

cm_errs=$(echo "${cm_check}" | grep '^CM_ERRORS=' | cut -d= -f2)

if [[ "${cm_errs}" -gt 0 ]]; then
    echo "FAIL: ${cm_errs} companion monitor error(s):"
    echo "${cm_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Companion monitors match governance production_monitor list"
fi
echo "${cm_check}" | grep -E '^SPEC' || true
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

ep = spec.get('eprocess_policy', {})
ai = spec.get('alpha_investing_policy', {})
abc = spec.get('alert_budget_contracts', {}).get('contracts', [])
cm = spec.get('companion_monitors', {}).get('modules', [])
cal = spec.get('false_alarm_calibration', {}).get('targets', {})

ep_params = len(ep.get('parameters', {}))
ep_states = len(ep.get('states', []))
ai_params = len(ai.get('parameters', {}))
ai_states = len(ai.get('states', []))
families = ep.get('api_families_monitored', 0)
fdr_bound = ai.get('fdr_guarantee', {}).get('bound', 0)

if summary.get('eprocess_parameters', 0) != ep_params:
    errors.append(f'eprocess_parameters: claimed={summary.get(\"eprocess_parameters\")} actual={ep_params}')
if summary.get('eprocess_states', 0) != ep_states:
    errors.append(f'eprocess_states: claimed={summary.get(\"eprocess_states\")} actual={ep_states}')
if summary.get('alpha_investing_parameters', 0) != ai_params:
    errors.append(f'alpha_investing_parameters: claimed={summary.get(\"alpha_investing_parameters\")} actual={ai_params}')
if summary.get('alpha_investing_states', 0) != ai_states:
    errors.append(f'alpha_investing_states: claimed={summary.get(\"alpha_investing_states\")} actual={ai_states}')
if summary.get('alert_budget_contracts', 0) != len(abc):
    errors.append(f'alert_budget_contracts: claimed={summary.get(\"alert_budget_contracts\")} actual={len(abc)}')
if summary.get('companion_monitors', 0) != len(cm):
    errors.append(f'companion_monitors: claimed={summary.get(\"companion_monitors\")} actual={len(cm)}')
if summary.get('api_families_monitored', 0) != families:
    errors.append(f'api_families_monitored: claimed={summary.get(\"api_families_monitored\")} actual={families}')
if summary.get('fdr_bound', 0) != fdr_bound:
    errors.append(f'fdr_bound: claimed={summary.get(\"fdr_bound\")} actual={fdr_bound}')
if summary.get('calibration_targets', 0) != len(cal):
    errors.append(f'calibration_targets: claimed={summary.get(\"calibration_targets\")} actual={len(cal)}')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'EP: {ep_params} params, {ep_states} states | AI: {ai_params} params, {ai_states} states | ABC: {len(abc)} | Monitors: {len(cm)} | Families: {families}')
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
echo "${sum_check}" | grep -E '^EP' || true
echo ""

# ---------------------------------------------------------------------------
# Check 7: Statistical kernel coverage (bd-5vr.3)
# ---------------------------------------------------------------------------
echo "--- Check 7: Statistical kernel coverage ---"

stat_check=$(python3 -c "
import pathlib

root = pathlib.Path('${ROOT}')
errors = []

required_files = {
    'risk': 'crates/frankenlibc-membrane/src/runtime_math/risk.rs',
    'eprocess': 'crates/frankenlibc-membrane/src/runtime_math/eprocess.rs',
    'cvar': 'crates/frankenlibc-membrane/src/runtime_math/cvar.rs',
    'alpha_investing': 'crates/frankenlibc-membrane/src/runtime_math/alpha_investing.rs',
    'changepoint': 'crates/frankenlibc-membrane/src/runtime_math/changepoint.rs',
    'large_deviations': 'crates/frankenlibc-membrane/src/large_deviations.rs',
    'spectral_monitor': 'crates/frankenlibc-membrane/src/spectral_monitor.rs',
}

for module, rel in required_files.items():
    path = root / rel
    if not path.is_file():
        errors.append(f'{module}: missing source file {rel}')
        continue
    text = path.read_text(encoding='utf-8', errors='replace')
    if '#[cfg(test)]' not in text:
        errors.append(f'{module}: missing #[cfg(test)] coverage block')
    if 'pub struct' not in text and 'pub enum' not in text:
        errors.append(f'{module}: missing public struct/enum API surface')

mod_path = root / 'crates/frankenlibc-membrane/src/runtime_math/mod.rs'
if not mod_path.is_file():
    errors.append('runtime_math/mod.rs missing')
else:
    mod_text = mod_path.read_text(encoding='utf-8', errors='replace')
    wiring_patterns = {
        'risk': 'use self::risk::ConformalRiskEngine;',
        'eprocess': 'use self::eprocess::{AnytimeEProcessMonitor, SequentialState};',
        'cvar': 'use self::cvar::{DroCvarController, TailState};',
        'alpha_investing': 'use self::alpha_investing::{AlphaInvestingController, AlphaInvestingState};',
        'changepoint': 'use self::changepoint::{ChangepointController, ChangepointState};',
        'large_deviations': 'use crate::large_deviations::{LargeDeviationsMonitor, RateState};',
        'spectral_monitor': 'use crate::spectral_monitor::{PhaseState, SpectralMonitor};',
    }
    for module, pattern in wiring_patterns.items():
        if pattern not in mod_text:
            errors.append(f'{module}: runtime_math/mod.rs missing wiring pattern: {pattern}')

print(f'STAT_ERRORS={len(errors)}')
print(f'KERNELS={len(required_files)}')
for e in errors:
    print(f'  {e}')
")

stat_errs=$(echo "${stat_check}" | grep '^STAT_ERRORS=' | cut -d= -f2)

if [[ "${stat_errs}" -gt 0 ]]; then
    echo "FAIL: ${stat_errs} statistical-kernel coverage error(s):"
    echo "${stat_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Statistical-kernel implementation/wiring coverage validated"
fi
echo "${stat_check}" | grep -E '^KERNELS=' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_anytime_valid_monitor: FAILED"
    exit 1
fi

echo ""
echo "check_anytime_valid_monitor: PASS"
