#!/usr/bin/env bash
# e2e_perf_regression_scenario.sh — deterministic intentional-regression check for bd-30o.3.
#
# This script injects synthetic observations into scripts/perf_gate.sh and verifies:
# 1) perf_gate detects a baseline regression (non-zero exit),
# 2) structured attribution logs include required fields,
# 3) runtime_math/decide is flagged with a regression class.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/perf_regression_attribution.v1.json"
TMP_DIR="$(mktemp -d)"
INJECTED="${TMP_DIR}/injected_results.json"
EVENT_LOG="${TMP_DIR}/perf_regression_events.jsonl"
OUT_LOG="${TMP_DIR}/perf_gate.out.log"
TRACE_ID="bd-30o.3::intentional-regression"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

cat >"${INJECTED}" <<'JSON'
{
  "runtime_math": {
    "strict": {
      "decide": 70.000,
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

set +e
FRANKENLIBC_PERF_INJECT_RESULTS="${INJECTED}" \
FRANKENLIBC_PERF_SKIP_OVERLOADED=0 \
FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION=1 \
FRANKENLIBC_PERF_ATTRIBUTION_POLICY_FILE="${POLICY}" \
FRANKENLIBC_PERF_EVENT_LOG="${EVENT_LOG}" \
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

python3 - "${EVENT_LOG}" "${POLICY}" "${TRACE_ID}" <<'PY'
import json
import sys

log_path, policy_path, trace_id = sys.argv[1:4]
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

if errors:
    raise SystemExit(" ; ".join(errors))
PY

echo "e2e_perf_regression_scenario: PASS"
echo "intentional regression detected with attribution logs at ${EVENT_LOG}"
