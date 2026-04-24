#!/usr/bin/env bash
# check_workload_api_wave_plan.sh — CI gate for bd-3mam (uplifted by bd-1x3.2)
#
# Validates:
# 1) workload-ranked top-N wave-plan artifact is reproducible from source inputs.
# 2) ranking, wave dependencies, summary fields, and Top50/Top200 wave selection are internally consistent.
# 3) integration hooks (setjmp/tls/threading/hard_parts) and downgrade policy are present.
# 4) deterministic report + structured log artifacts are emitted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_workload_api_wave_plan.py"
ARTIFACT="${ROOT}/tests/conformance/workload_api_wave_plan.v1.json"
SUPPORT="${ROOT}/support_matrix.json"
WORKLOAD="${ROOT}/tests/conformance/workload_matrix.json"
CENSUS="${ROOT}/tests/conformance/callthrough_census.v1.json"
STUB_DEBT="${ROOT}/tests/conformance/stub_todo_debt_census.v1.json"
WAIVER="${ROOT}/tests/conformance/stub_regression_waiver_policy.v1.json"
FIXTURES="${ROOT}/tests/conformance/fixtures"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/workload_api_wave_plan.report.json"
LOG="${OUT_DIR}/workload_api_wave_plan.log.jsonl"
TRACE_ID="bd-1x3.2-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"

for path in "${GEN}" "${SUPPORT}" "${WORKLOAD}" "${CENSUS}" "${STUB_DEBT}" "${WAIVER}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: missing required input ${path}" >&2
    exit 1
  fi
done
if [[ ! -d "${FIXTURES}" ]]; then
  echo "FAIL: missing required fixtures directory ${FIXTURES}" >&2
  exit 1
fi

if [[ ! -f "${ARTIFACT}" ]]; then
  (
    cd "${ROOT}"
    python3 "scripts/generate_workload_api_wave_plan.py" \
      --output "tests/conformance/workload_api_wave_plan.v1.json" \
      --top-n 200 \
      --stub-debt-census "tests/conformance/stub_todo_debt_census.v1.json" \
      --waiver-policy "tests/conformance/stub_regression_waiver_policy.v1.json" \
      --fixtures-dir "tests/conformance/fixtures"
  )
fi

(
  cd "${ROOT}"
  python3 "scripts/generate_workload_api_wave_plan.py" \
    --output "tests/conformance/workload_api_wave_plan.v1.json" \
    --top-n 200 \
    --stub-debt-census "tests/conformance/stub_todo_debt_census.v1.json" \
    --waiver-policy "tests/conformance/stub_regression_waiver_policy.v1.json" \
    --fixtures-dir "tests/conformance/fixtures" \
    --check
)

python3 - "${ARTIFACT}" "${SUPPORT}" "${WORKLOAD}" "${WAIVER}" "${REPORT}" <<'PY'
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
support_path = pathlib.Path(sys.argv[2])
workload_path = pathlib.Path(sys.argv[3])
waiver_path = pathlib.Path(sys.argv[4])
report_path = pathlib.Path(sys.argv[5])

artifact = json.loads(artifact_path.read_text(encoding='utf-8'))
support = json.loads(support_path.read_text(encoding='utf-8'))
workload = json.loads(workload_path.read_text(encoding='utf-8'))
waiver = json.loads(waiver_path.read_text(encoding='utf-8'))

def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def require_nonnegative_int(mapping, key):
    if key not in mapping:
        raise SystemExit(f'FAIL: summary.{key} is required')
    value = to_int(mapping.get(key), -1)
    if value < 0:
        raise SystemExit(f'FAIL: summary.{key} must be a non-negative integer')
    return value

if artifact.get('schema_version') != 'v1':
    raise SystemExit('FAIL: schema_version must be v1')
if artifact.get('bead') != 'bd-3mam':
    raise SystemExit('FAIL: bead must be bd-3mam')
if artifact.get('uplift_bead') != 'bd-1x3.2':
    raise SystemExit('FAIL: uplift_bead must be bd-1x3.2')

summary = artifact.get('summary', {})
module_rows = artifact.get('module_ranking', [])
symbol_rows = artifact.get('symbol_ranking_top_n', [])
wave_rows = artifact.get('wave_plan', [])
implementation_waves = artifact.get('implementation_waves', {})
downgrade_policy = artifact.get('downgrade_policy', {})
candidate_count = require_nonnegative_int(summary, 'candidate_symbols')

if candidate_count > 0:
    if not module_rows:
        raise SystemExit('FAIL: module_ranking must be non-empty when candidates remain')
    if not symbol_rows:
        raise SystemExit('FAIL: symbol_ranking_top_n must be non-empty when candidates remain')
    if not wave_rows:
        raise SystemExit('FAIL: wave_plan must be non-empty when candidates remain')
else:
    if module_rows:
        raise SystemExit('FAIL: module_ranking must be empty when no candidates remain')
    if symbol_rows:
        raise SystemExit('FAIL: symbol_ranking_top_n must be empty when no candidates remain')
    if wave_rows:
        raise SystemExit('FAIL: wave_plan must be empty when no candidates remain')
if not isinstance(implementation_waves, dict):
    raise SystemExit('FAIL: implementation_waves must be object')
if not isinstance(downgrade_policy, dict):
    raise SystemExit('FAIL: downgrade_policy must be object')

candidate_statuses = {'GlibcCallThrough', 'Stub'}
support_symbols = {
    str(row.get('symbol')): row
    for row in support.get('symbols', [])
    if isinstance(row, dict) and row.get('status') in candidate_statuses
}

# Check symbol ranking order and schema.
prev_score = None
seen_symbols = set()
ranked_symbol_to_wave = {}
for idx, row in enumerate(symbol_rows, start=1):
    rank = row.get('rank')
    if rank != idx:
        raise SystemExit(f'FAIL: symbol rank mismatch at index {idx}: got {rank}')
    symbol = str(row.get('symbol'))
    module = str(row.get('module'))
    status = str(row.get('status'))
    score = float(row.get('score'))
    selected_wave = str(row.get('selected_wave', ''))
    call_frequency = to_int(row.get('call_frequency', -1), -1)
    fixture_call_frequency = to_int(row.get('fixture_call_frequency', -1), -1)
    trace_weight = float(row.get('trace_weight', -1))
    debt_risk_score = to_int(row.get('stub_debt_risk_score', -1), -1)
    debt_risk_weight = float(row.get('debt_risk_weight', -1))
    if symbol in seen_symbols:
        raise SystemExit(f'FAIL: duplicate symbol in symbol_ranking_top_n: {symbol}')
    seen_symbols.add(symbol)
    if symbol not in support_symbols:
        raise SystemExit(f'FAIL: symbol_ranking_top_n includes unsupported symbol {symbol}')
    support_module = str(support_symbols[symbol].get('module'))
    if support_module != module:
        raise SystemExit(
            f'FAIL: symbol/module mismatch for {symbol}: artifact={module} support_matrix={support_module}'
        )
    if status not in candidate_statuses:
        raise SystemExit(f'FAIL: invalid status for {symbol}: {status!r}')
    if selected_wave not in {'Top50', 'Top200', 'Backlog', 'downgrade-policy'}:
        raise SystemExit(f'FAIL: invalid selected_wave for {symbol}: {selected_wave!r}')
    if call_frequency < 0 or fixture_call_frequency < 0:
        raise SystemExit(f'FAIL: invalid call_frequency fields for {symbol}')
    if trace_weight < 0:
        raise SystemExit(f'FAIL: trace_weight must be non-negative for {symbol}')
    if debt_risk_score < 0 or debt_risk_weight < 0:
        raise SystemExit(f'FAIL: invalid debt risk fields for {symbol}')
    if prev_score is not None and score > prev_score + 1e-9:
        raise SystemExit('FAIL: symbol ranking is not sorted by descending score')
    prev_score = score
    ranked_symbol_to_wave[symbol] = selected_wave

# Check module ranking order and uniqueness.
prev_module_score = None
seen_modules = set()
for idx, row in enumerate(module_rows, start=1):
    rank = row.get('rank')
    if rank != idx:
        raise SystemExit(f'FAIL: module rank mismatch at index {idx}: got {rank}')
    module = str(row.get('module'))
    total = float(row.get('total_symbol_score'))
    if module in seen_modules:
        raise SystemExit(f'FAIL: duplicate module in module_ranking: {module}')
    seen_modules.add(module)
    if prev_module_score is not None and total > prev_module_score + 1e-9:
        raise SystemExit('FAIL: module ranking is not sorted by descending total_symbol_score')
    prev_module_score = total

# Validate wave dependencies and coverage.
wave_ids = [str(w.get('wave_id')) for w in wave_rows]
if len(wave_ids) != len(set(wave_ids)):
    raise SystemExit('FAIL: duplicate wave_id in wave_plan')
wave_map = {str(w.get('wave_id')): w for w in wave_rows}
for wave in wave_rows:
    wave_id = str(wave.get('wave_id'))
    for dep in wave.get('depends_on', []):
        dep_id = str(dep)
        if dep_id not in wave_map:
            raise SystemExit(f'FAIL: wave {wave_id} depends on unknown wave_id {dep_id}')

visiting = set()
visited = set()

def dfs(node: str):
    if node in visiting:
        raise SystemExit(f'FAIL: cycle detected in wave dependencies at {node}')
    if node in visited:
        return
    visiting.add(node)
    for dep in wave_map[node].get('depends_on', []):
        dfs(str(dep))
    visiting.remove(node)
    visited.add(node)

for wave_id in wave_ids:
    dfs(wave_id)

# Integration hooks must be present and non-empty.
hooks = artifact.get('integration_hooks', {})
for key in ('setjmp', 'tls', 'threading', 'hard_parts'):
    vals = hooks.get(key)
    if not isinstance(vals, list) or not vals:
        raise SystemExit(f'FAIL: integration_hooks.{key} must be a non-empty array')

# Implementation wave and downgrade policy validation.
top50 = implementation_waves.get('top50', {})
top200 = implementation_waves.get('top200', {})
if not isinstance(top50, dict) or not isinstance(top200, dict):
    raise SystemExit('FAIL: implementation_waves.top50/top200 must be objects')

top50_symbols = top50.get('symbols', [])
top200_symbols = top200.get('symbols', [])
if not isinstance(top50_symbols, list) or not isinstance(top200_symbols, list):
    raise SystemExit('FAIL: implementation_waves top50/top200 symbols must be arrays')
if to_int(top50.get('target_size', -1), -1) != 50:
    raise SystemExit('FAIL: implementation_waves.top50.target_size must be 50')
if to_int(top200.get('target_size', -1), -1) != 200:
    raise SystemExit('FAIL: implementation_waves.top200.target_size must be 200')
if to_int(top50.get('actual_size', -1), -1) != len(top50_symbols):
    raise SystemExit('FAIL: implementation_waves.top50.actual_size mismatch')
if to_int(top200.get('actual_size', -1), -1) != len(top200_symbols):
    raise SystemExit('FAIL: implementation_waves.top200.actual_size mismatch')
if not set(top50_symbols).issubset(set(top200_symbols)):
    raise SystemExit('FAIL: top50 symbols must be subset of top200 symbols')
if len(top50_symbols) != len(set(top50_symbols)):
    raise SystemExit('FAIL: implementation_waves.top50.symbols contains duplicates')
if len(top200_symbols) != len(set(top200_symbols)):
    raise SystemExit('FAIL: implementation_waves.top200.symbols contains duplicates')

waiver_symbols = {
    str(row.get('symbol'))
    for row in waiver.get('waivers', [])
    if str(row.get('symbol', ''))
}
downgraded_rows = downgrade_policy.get('waived_symbols', [])
if not isinstance(downgraded_rows, list):
    raise SystemExit('FAIL: downgrade_policy.waived_symbols must be array')
if to_int(downgrade_policy.get('waived_symbol_count', -1), -1) != len(downgraded_rows):
    raise SystemExit('FAIL: downgrade_policy.waived_symbol_count mismatch')
downgraded_symbols = {str(row.get('symbol', '')) for row in downgraded_rows}
if not downgraded_symbols.issubset(waiver_symbols):
    raise SystemExit('FAIL: downgrade_policy includes symbol absent from waiver policy')
if '' in downgraded_symbols:
    raise SystemExit('FAIL: downgrade_policy includes empty symbol')

# selected_wave semantics must match rank/waiver policy.
expected_top50 = []
expected_top200 = []
for idx, row in enumerate(symbol_rows, start=1):
    symbol = str(row.get('symbol', ''))
    selected_wave = ranked_symbol_to_wave.get(symbol)
    if symbol in downgraded_symbols:
        if selected_wave != 'downgrade-policy':
            raise SystemExit(
                f'FAIL: downgraded symbol {symbol} must use selected_wave=downgrade-policy'
            )
        continue

    if idx <= 50:
        expected = 'Top50'
        expected_top50.append(symbol)
        expected_top200.append(symbol)
    elif idx <= 200:
        expected = 'Top200'
        expected_top200.append(symbol)
    else:
        expected = 'Backlog'

    if selected_wave != expected:
        raise SystemExit(
            f'FAIL: selected_wave mismatch for {symbol} at rank {idx}: expected {expected}, got {selected_wave}'
        )

if set(top50_symbols) != set(expected_top50):
    raise SystemExit('FAIL: implementation_waves.top50.symbols inconsistent with selected_wave/rank policy')
if set(top200_symbols) != set(expected_top200):
    raise SystemExit('FAIL: implementation_waves.top200.symbols inconsistent with selected_wave/rank policy')
if set(top50_symbols) & downgraded_symbols:
    raise SystemExit('FAIL: implementation_waves.top50.symbols must not include downgraded symbols')
if set(top200_symbols) & downgraded_symbols:
    raise SystemExit('FAIL: implementation_waves.top200.symbols must not include downgraded symbols')

# Summary consistency.
if to_int(summary.get('top_n', -1), -1) != len(symbol_rows):
    raise SystemExit('FAIL: summary.top_n must equal symbol_ranking_top_n length')
if to_int(summary.get('module_count', -1), -1) != len(module_rows):
    raise SystemExit('FAIL: summary.module_count mismatch')
if to_int(summary.get('wave_count', -1), -1) != len(wave_rows):
    raise SystemExit('FAIL: summary.wave_count mismatch')
if to_int(summary.get('candidate_symbols', -1), -1) < len(symbol_rows):
    raise SystemExit('FAIL: summary.candidate_symbols cannot be smaller than top_n list length')
if to_int(summary.get('remaining_after_top_n', -1), -1) < 0:
    raise SystemExit('FAIL: summary.remaining_after_top_n must be non-negative')
if to_int(summary.get('top50_size', -1), -1) != len(top50_symbols):
    raise SystemExit('FAIL: summary.top50_size mismatch')
if to_int(summary.get('top200_size', -1), -1) != len(top200_symbols):
    raise SystemExit('FAIL: summary.top200_size mismatch')
if to_int(summary.get('downgrade_symbol_count', -1), -1) != len(downgraded_rows):
    raise SystemExit('FAIL: summary.downgrade_symbol_count mismatch')

# Cross-check top blocker appears in module ranking and workload subsystem impact.
top_blocker = summary.get('top_blocker_module')
if candidate_count == 0:
    if 'top_blocker_module' not in summary:
        raise SystemExit('FAIL: summary.top_blocker_module is required')
    if top_blocker is not None:
        raise SystemExit('FAIL: summary.top_blocker_module must be null when no candidates remain')
else:
    if top_blocker not in {row.get('module') for row in module_rows}:
        raise SystemExit('FAIL: summary.top_blocker_module missing from module_ranking')
    subsystem_impact = workload.get('subsystem_impact', {})
    if top_blocker not in subsystem_impact:
        raise SystemExit(
            f'FAIL: summary.top_blocker_module {top_blocker!r} missing from workload_matrix subsystem_impact'
        )

report = {
    'schema_version': 'v1',
    'bead': 'bd-1x3.2',
    'checks': {
        'artifact_reproducible': 'pass',
        'ranking_consistency': 'pass',
        'wave_dependencies_acyclic': 'pass',
        'integration_hooks_present': 'pass',
        'implementation_waves_consistent': 'pass',
        'downgrade_policy_consistent': 'pass',
        'summary_consistency': 'pass',
    },
    'summary': {
        'top_n': len(symbol_rows),
        'candidate_symbols': int(summary.get('candidate_symbols', 0)),
        'module_count': len(module_rows),
        'wave_count': len(wave_rows),
        'top50_size': len(top50_symbols),
        'top200_size': len(top200_symbols),
        'downgrade_symbol_count': len(downgraded_rows),
        'top_blocker_module': top_blocker,
    },
}
report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(
    'PASS: workload API wave plan validated '
    f"(top_n={len(symbol_rows)}, candidates={summary.get('candidate_symbols')}, waves={len(wave_rows)})"
)
PY

python3 - "${TRACE_ID}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

trace_id, artifact_path, report_path, log_path = sys.argv[1:5]

event = {
    'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
    'trace_id': trace_id,
    'level': 'info',
    'event': 'workload_api_wave_plan_check',
    'bead_id': 'bd-1x3.2',
    'stream': 'conformance',
    'gate': 'check_workload_api_wave_plan',
    'mode': 'analysis',
    'api_family': 'planning',
    'symbol': 'top_n_wave_plan',
    'outcome': 'pass',
    'errno': 0,
    'latency_ns': 0,
    'artifact_refs': [artifact_path, report_path],
}

pathlib.Path(log_path).write_text(json.dumps(event, separators=(',', ':')) + '\n', encoding='utf-8')
print(f'PASS: wrote workload API wave plan log {log_path}')
print(json.dumps(event, separators=(',', ':')))
PY

echo "check_workload_api_wave_plan: PASS"
