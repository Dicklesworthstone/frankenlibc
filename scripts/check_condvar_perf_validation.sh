#!/usr/bin/env bash
# check_condvar_perf_validation.sh — CI gate for bd-2nzx
#
# Validates condvar performance dossier:
# 1) baseline captures are present and within budget,
# 2) opportunity matrix entries have valid scores,
# 3) optimization decision is documented,
# 4) regression tests pass,
# 5) emits deterministic report + structured JSONL diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="default"
if [[ $# -gt 1 ]]; then
  echo "usage: $0 [--validate-only]" >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  if [[ "$1" != "--validate-only" ]]; then
    echo "usage: $0 [--validate-only]" >&2
    exit 2
  fi
  MODE="validate-only"
fi

ARTIFACT="${FRANKENLIBC_CONDVAR_PERF_ARTIFACT_PATH:-${ROOT}/tests/conformance/condvar_perf_validation.v1.json}"
OUT_DIR="${FRANKENLIBC_CONDVAR_PERF_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CONDVAR_PERF_REPORT:-${OUT_DIR}/condvar_perf_validation.report.json}"
LOG="${FRANKENLIBC_CONDVAR_PERF_LOG:-${OUT_DIR}/condvar_perf_validation.log.jsonl}"

TRACE_ID="${FRANKENLIBC_CONDVAR_PERF_TRACE_ID:-bd-2nzx::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001}"
START_NS="$(python3 -c 'import time; print(time.time_ns())')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

if [[ ! -f "${ARTIFACT}" ]]; then
  echo "FAIL: required file missing: ${ARTIFACT}" >&2
  exit 1
fi

set +e
python3 - "${ARTIFACT}" "${REPORT}" "${MODE}" <<'PY'
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
mode = sys.argv[3]

with open(artifact_path) as f:
    data = json.load(f)

errors = []
warnings = []

# 1. Validate structure
for field in ("version", "baselines", "opportunity_matrix", "optimization_decision"):
    if field not in data:
        errors.append(f"Missing top-level field: {field}")

if errors:
    print(f"FAIL: structural errors: {errors}", file=sys.stderr)
    sys.exit(1)

# 2. Validate baselines
baselines = data["baselines"]
if len(baselines) < 4:
    errors.append(f"Expected at least 4 baselines, got {len(baselines)}")

within_budget_count = 0
total_baselines = len(baselines)
for b in baselines:
    name = b.get("name", "<unnamed>")
    for field in ("p50_ns", "p95_ns", "budget_ns", "within_budget"):
        if field not in b:
            errors.append(f"Baseline {name}: missing field {field}")
    if b.get("within_budget") is True:
        within_budget_count += 1
    elif b.get("within_budget") is False:
        p95 = b.get("p95_ns", 0)
        budget = b.get("budget_ns", 0)
        if p95 > budget:
            errors.append(f"Baseline {name}: p95={p95}ns exceeds budget={budget}ns")
        else:
            warnings.append(f"Baseline {name}: marked not within budget but p95 <= budget")

# 3. Validate opportunity matrix
opp = data["opportunity_matrix"]
if len(opp) < 3:
    errors.append(f"Expected at least 3 opportunity entries, got {len(opp)}")

for entry in opp:
    symbol = entry.get("symbol", "<unnamed>")
    score = entry.get("optimization_score")
    if score is None:
        errors.append(f"Opportunity {symbol}: missing optimization_score")
    elif not isinstance(score, (int, float)):
        errors.append(f"Opportunity {symbol}: optimization_score must be numeric")
    if "rationale" not in entry:
        errors.append(f"Opportunity {symbol}: missing rationale")

# 4. Validate optimization decision
decision = data["optimization_decision"]
threshold = decision.get("threshold", 2.0)
max_score = decision.get("max_opportunity_score", 0)
selected = decision.get("selected", "")

if max_score >= threshold and selected == "none":
    errors.append(
        f"Optimization decision: max_score={max_score} >= threshold={threshold} "
        f"but selected='none'. Must select an optimization target."
    )

if "reason" not in decision:
    errors.append("Optimization decision: missing reason")

# 5. Validate regression verification
regression = data.get("regression_verification", {})
if not regression.get("all_condvar_tests_pass"):
    errors.append("Regression verification: tests not passing")

# Build report
report = {
    "report_schema": "condvar_perf_validation.report.v1",
    "bead": "bd-2nzx",
    "gate": "condvar_perf_validation",
    "mode": mode,
    "artifact": str(artifact_path),
    "baselines_total": total_baselines,
    "baselines_within_budget": within_budget_count,
    "opportunity_entries": len(opp),
    "max_opportunity_score": max_score,
    "optimization_threshold": threshold,
    "optimization_selected": selected,
    "errors": errors,
    "warnings": warnings,
    "outcome": "pass" if not errors else "fail",
    "failure_signature": "none" if not errors else errors[0].split(":", 1)[0],
    "pass": len(errors) == 0,
}

report_path.parent.mkdir(parents=True, exist_ok=True)
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

if errors:
    for e in errors:
        print(f"  ERROR: {e}", file=sys.stderr)
    print(f"FAIL: {len(errors)} error(s) in condvar perf validation", file=sys.stderr)
    sys.exit(1)

for w in warnings:
    print(f"  WARN: {w}")

print(f"PASS: condvar perf validation ({total_baselines} baselines, "
      f"{within_budget_count}/{total_baselines} within budget, "
      f"max_opp_score={max_score:.1f} < threshold={threshold:.1f})")
PY

RESULT=$?
set -e

END_NS="$(python3 -c 'import time; print(time.time_ns())')"
DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))

# Emit structured JSONL log
python3 -c "
import json, sys
log_entry = {
    'trace_id': '${TRACE_ID}',
    'bead': 'bd-2nzx',
    'gate': 'condvar_perf_validation',
    'mode': '${MODE}',
    'artifact': '${ARTIFACT}',
    'result': 'PASS' if ${RESULT} == 0 else 'FAIL',
    'outcome': 'pass' if ${RESULT} == 0 else 'fail',
    'duration_ms': ${DURATION_MS},
    'report': '${REPORT}',
}
print(json.dumps(log_entry))
" >> "${LOG}"

exit ${RESULT}
