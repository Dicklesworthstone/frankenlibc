#!/usr/bin/env bash
# e2e_perf_regression_scenario.sh — deterministic perf-gate E2E checks for bd-w2c3.8.3.
#
# Supports:
# - `--scenario regression` (default): injected baseline regression with attribution.
# - `--scenario overloaded`: forced overloaded-host auto-throttle path with report/log evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/perf_regression_attribution.v1.json"
SCENARIO="regression"

if [[ "${1:-}" == "--scenario" ]]; then
    SCENARIO="${2:-}"
fi

TMP_DIR="${FRANKENLIBC_PERF_SCENARIO_TMP_DIR:-${ROOT}/target/conformance/perf_regression_scenario_${SCENARIO}_$$}"
INJECTED="${TMP_DIR}/injected_results.json"
EVENT_LOG="${TMP_DIR}/perf_regression_events.jsonl"
REPORT_PATH="${TMP_DIR}/perf_gate.report.json"
OUT_LOG="${TMP_DIR}/perf_gate.out.log"

mkdir -p "${TMP_DIR}"

if [[ "${SCENARIO}" == "regression" ]]; then
cat >"${INJECTED}" <<'JSON'
{
  "runtime_math": {
    "strict": {
      "decide": 20000.000,
      "observe_fast": 1870.910,
      "decide_observe": 919.211
    },
    "hardened": {
      "decide": 173.265,
      "observe_fast": 2946.700,
      "decide_observe": 2987.025
    }
  },
  "membrane": {
    "strict": {
      "validate_known": 1910.433
    },
    "hardened": {
      "validate_known": 5966.235
    }
  }
}
JSON

    TRACE_ID="bd-w2c3.8.3::intentional-regression"
    set +e
    FRANKENLIBC_PERF_INJECT_RESULTS="${INJECTED}" \
    FRANKENLIBC_PERF_SKIP_OVERLOADED=0 \
    FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION=1 \
    FRANKENLIBC_PERF_ATTRIBUTION_POLICY_FILE="${POLICY}" \
    FRANKENLIBC_PERF_EVENT_LOG="${EVENT_LOG}" \
    FRANKENLIBC_PERF_REPORT="${REPORT_PATH}" \
    FRANKENLIBC_PERF_TRACE_ID="${TRACE_ID}" \
    bash "${ROOT}/scripts/perf_gate.sh" >"${OUT_LOG}" 2>&1
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
        echo "FAIL: intentional regression scenario expected perf_gate failure" >&2
        echo "--- perf_gate output ---" >&2
        cat "${OUT_LOG}" >&2
        exit 1
    fi

    python3 - "${EVENT_LOG}" "${REPORT_PATH}" "${POLICY}" "${TRACE_ID}" <<'PY'
import json
import sys

log_path, report_path, policy_path, trace_id = sys.argv[1:5]
with open(policy_path, encoding="utf-8") as f:
    policy = json.load(f)

required = set(policy.get("logging_contract", {}).get("required_fields", []))
rows = []
with open(log_path, encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception as exc:
            raise SystemExit(f"invalid jsonl row {i}: {exc}")

if not rows:
    raise SystemExit("no attribution log rows emitted")

errors = []
for idx, row in enumerate(rows):
    if row.get("event") != "benchmark_result":
        errors.append(f"row {idx}: unexpected event {row.get('event')!r}")
        continue
    for field in required:
        value = row.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"row {idx}: missing/empty {field}")
    if row.get("trace_id") != trace_id:
        errors.append(f"row {idx}: unexpected trace_id {row.get('trace_id')!r}")

regressions = [r for r in rows if r.get("regression_class") in ("baseline_regression", "baseline_and_budget_violation")]
if not regressions:
    errors.append("no baseline regression row found")

decide_rows = [r for r in regressions if r.get("benchmark_id") == "runtime_math/decide"]
if not decide_rows:
    errors.append("runtime_math/decide regression row missing")

for row in regressions:
    if row.get("suspect_component") in (None, "", "unknown_component"):
        errors.append(f"regression row missing mapped suspect_component: {row}")

with open(report_path, encoding="utf-8") as f:
    report = json.load(f)
if report.get("status") != "baseline_regression_detected":
    errors.append(f"unexpected report status: {report.get('status')!r}")
top = report.get("top_regressions", [])
if not any(entry.get("benchmark_id") == "runtime_math/decide" for entry in top):
    errors.append("report missing runtime_math/decide in top_regressions")

if errors:
    raise SystemExit(" ; ".join(errors))
PY

    echo "e2e_perf_regression_scenario: PASS"
    echo "intentional regression detected with attribution logs at ${EVENT_LOG}"
elif [[ "${SCENARIO}" == "overloaded" ]]; then
    TRACE_ID="bd-w2c3.8.3::auto-throttle"
    FRANKENLIBC_PERF_SKIP_OVERLOADED=1 \
    FRANKENLIBC_PERF_FORCE_LOAD1=7.50 \
    FRANKENLIBC_PERF_FORCE_CPUS=4 \
    FRANKENLIBC_PERF_MAX_LOAD_FACTOR=0.85 \
    FRANKENLIBC_PERF_FORCE_TOP_PROCESSES="111 root perf_gate 98.0 00:01;222 root cargo 87.0 00:02;" \
    FRANKENLIBC_PERF_ATTRIBUTION_POLICY_FILE="${POLICY}" \
    FRANKENLIBC_PERF_EVENT_LOG="${EVENT_LOG}" \
    FRANKENLIBC_PERF_REPORT="${REPORT_PATH}" \
    FRANKENLIBC_PERF_TRACE_ID="${TRACE_ID}" \
    bash "${ROOT}/scripts/perf_gate.sh" >"${OUT_LOG}" 2>&1

    python3 - "${EVENT_LOG}" "${REPORT_PATH}" "${POLICY}" "${TRACE_ID}" <<'PY'
import json
import sys

log_path, report_path, policy_path, trace_id = sys.argv[1:5]
with open(policy_path, encoding="utf-8") as f:
    policy = json.load(f)

required = set(policy.get("auto_throttle_policy", {}).get("required_log_fields", []))
with open(log_path, encoding="utf-8") as f:
    rows = [json.loads(line) for line in f if line.strip()]

if len(rows) != 1:
    raise SystemExit(f"expected exactly one throttle event, got {len(rows)}")
row = rows[0]
errors = []
for field in required:
    value = row.get(field)
    if value is None or (isinstance(value, str) and not value.strip()):
        errors.append(f"missing/empty {field}")
if row.get("trace_id") != trace_id:
    errors.append(f"unexpected trace_id {row.get('trace_id')!r}")
if row.get("event") != "auto_throttle":
    errors.append(f"unexpected event {row.get('event')!r}")
if row.get("host_state") != "overloaded":
    errors.append(f"unexpected host_state {row.get('host_state')!r}")

with open(report_path, encoding="utf-8") as f:
    report = json.load(f)
for field in policy.get("auto_throttle_policy", {}).get("required_report_fields", []):
    if field not in report or report[field] in (None, ""):
        errors.append(f"report missing {field}")
if report.get("status") != "auto_throttled":
    errors.append(f"unexpected report status {report.get('status')!r}")
if report.get("summary", {}).get("benchmark_events") != 0:
    errors.append("auto-throttled run should not record benchmark events")

if errors:
    raise SystemExit(" ; ".join(errors))
PY

    echo "e2e_perf_regression_scenario(overloaded): PASS"
    echo "overloaded-host auto-throttle logged at ${EVENT_LOG}"
else
    echo "unknown scenario: ${SCENARIO}" >&2
    exit 2
fi
