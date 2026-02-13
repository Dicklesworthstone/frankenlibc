#!/usr/bin/env bash
# check_workload_api_wave_plan.sh — CI gate for bd-3mam
#
# Validates:
# 1) workload-ranked top-N wave-plan artifact is reproducible from source inputs.
# 2) ranking, wave dependencies, and summary fields are internally consistent.
# 3) integration hooks (setjmp/tls/threading/hard_parts) are present.
# 4) deterministic report + structured log artifacts are emitted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_workload_api_wave_plan.py"
ARTIFACT="${ROOT}/tests/conformance/workload_api_wave_plan.v1.json"
SUPPORT="${ROOT}/support_matrix.json"
WORKLOAD="${ROOT}/tests/conformance/workload_matrix.json"
CENSUS="${ROOT}/tests/conformance/callthrough_census.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/workload_api_wave_plan.report.json"
LOG="${OUT_DIR}/workload_api_wave_plan.log.jsonl"
TRACE_ID="bd-3mam-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"

for path in "${GEN}" "${SUPPORT}" "${WORKLOAD}" "${CENSUS}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: missing required input ${path}" >&2
    exit 1
  fi
done

if [[ ! -f "${ARTIFACT}" ]]; then
  (
    cd "${ROOT}"
    python3 "scripts/generate_workload_api_wave_plan.py" --output "tests/conformance/workload_api_wave_plan.v1.json" --top-n 25
  )
fi

(
  cd "${ROOT}"
  python3 "scripts/generate_workload_api_wave_plan.py" --output "tests/conformance/workload_api_wave_plan.v1.json" --top-n 25 --check
)

python3 - "${ARTIFACT}" "${SUPPORT}" "${WORKLOAD}" "${REPORT}" <<'PY'
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
support_path = pathlib.Path(sys.argv[2])
workload_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])

artifact = json.loads(artifact_path.read_text(encoding='utf-8'))
support = json.loads(support_path.read_text(encoding='utf-8'))
workload = json.loads(workload_path.read_text(encoding='utf-8'))

if artifact.get('schema_version') != 'v1':
    raise SystemExit('FAIL: schema_version must be v1')
if artifact.get('bead') != 'bd-3mam':
    raise SystemExit('FAIL: bead must be bd-3mam')

summary = artifact.get('summary', {})
module_rows = artifact.get('module_ranking', [])
symbol_rows = artifact.get('symbol_ranking_top_n', [])
wave_rows = artifact.get('wave_plan', [])

if not module_rows:
    raise SystemExit('FAIL: module_ranking must be non-empty')
if not symbol_rows:
    raise SystemExit('FAIL: symbol_ranking_top_n must be non-empty')
if not wave_rows:
    raise SystemExit('FAIL: wave_plan must be non-empty')

candidate_statuses = {'GlibcCallThrough', 'Stub'}
support_symbols = {
    str(row.get('symbol')): row
    for row in support.get('symbols', [])
    if row.get('status') in candidate_statuses
}

# Check symbol ranking order and schema.
prev_score = None
seen_symbols = set()
for idx, row in enumerate(symbol_rows, start=1):
    rank = row.get('rank')
    if rank != idx:
        raise SystemExit(f'FAIL: symbol rank mismatch at index {idx}: got {rank}')
    symbol = str(row.get('symbol'))
    module = str(row.get('module'))
    status = str(row.get('status'))
    score = float(row.get('score'))
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
    if prev_score is not None and score > prev_score + 1e-9:
        raise SystemExit('FAIL: symbol ranking is not sorted by descending score')
    prev_score = score

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

# Summary consistency.
if int(summary.get('top_n', -1)) != len(symbol_rows):
    raise SystemExit('FAIL: summary.top_n must equal symbol_ranking_top_n length')
if int(summary.get('module_count', -1)) != len(module_rows):
    raise SystemExit('FAIL: summary.module_count mismatch')
if int(summary.get('wave_count', -1)) != len(wave_rows):
    raise SystemExit('FAIL: summary.wave_count mismatch')
if int(summary.get('candidate_symbols', -1)) < len(symbol_rows):
    raise SystemExit('FAIL: summary.candidate_symbols cannot be smaller than top_n list length')
if int(summary.get('remaining_after_top_n', -1)) < 0:
    raise SystemExit('FAIL: summary.remaining_after_top_n must be non-negative')

# Cross-check top blocker appears in module ranking and workload subsystem impact.
top_blocker = summary.get('top_blocker_module')
if top_blocker not in {row.get('module') for row in module_rows}:
    raise SystemExit('FAIL: summary.top_blocker_module missing from module_ranking')
subsystem_impact = workload.get('subsystem_impact', {})
if top_blocker not in subsystem_impact:
    raise SystemExit(
        f'FAIL: summary.top_blocker_module {top_blocker!r} missing from workload_matrix subsystem_impact'
    )

report = {
    'schema_version': 'v1',
    'bead': 'bd-3mam',
    'checks': {
        'artifact_reproducible': 'pass',
        'ranking_consistency': 'pass',
        'wave_dependencies_acyclic': 'pass',
        'integration_hooks_present': 'pass',
        'summary_consistency': 'pass',
    },
    'summary': {
        'top_n': len(symbol_rows),
        'candidate_symbols': int(summary.get('candidate_symbols', 0)),
        'module_count': len(module_rows),
        'wave_count': len(wave_rows),
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
    'bead_id': 'bd-3mam',
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
