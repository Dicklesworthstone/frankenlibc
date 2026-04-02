#!/usr/bin/env bash
# check_pthread_extensions_native.sh — bead-scoped native pthread extension evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/conformance/pthread_extensions_native"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
TRACE_PATH="${RUN_DIR}/trace.jsonl"
REPORT_PATH="${RUN_DIR}/report.json"
INDEX_PATH="${RUN_DIR}/artifact_index.json"
TEST_FILE="pthread_abi_test"
mkdir -p "${RUN_DIR}"
: > "${TRACE_PATH}"

emit_trace() {
  local level="$1"
  local event="$2"
  local scenario_id="$3"
  local symbol="$4"
  local decision_path="$5"
  local outcome="$6"
  local errno_value="$7"
  local latency_ns="$8"
  local artifact_refs_json="$9"
  printf '{"timestamp":"%s","trace_id":"%s::%s","level":"%s","event":"%s","bead_id":"bd-zh1y.1.2","mode":"native","api_family":"pthread","symbol":"%s","decision_path":"%s","healing_action":"None","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":%s}\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")" \
    "bd-zh1y.1.2::${RUN_ID}" \
    "${scenario_id}" \
    "${level}" \
    "${event}" \
    "${symbol}" \
    "${decision_path}" \
    "${outcome}" \
    "${errno_value}" \
    "${latency_ns}" \
    "${artifact_refs_json}" >> "${TRACE_PATH}"
}

run_case() {
  local scenario_id="$1"
  local filter="$2"
  local decision_path="$3"
  local expected="$4"
  local safe_filter="${filter//[^A-Za-z0-9_.-]/_}"
  local log_path="${RUN_DIR}/${safe_filter}.log"
  local start_ns end_ns latency_ns rc level outcome errno_value refs_json
  refs_json="[\"scripts/check_pthread_extensions_native.sh\",\"crates/frankenlibc-abi/tests/pthread_abi_test.rs\",\"${log_path#${ROOT}/}\",\"${REPORT_PATH#${ROOT}/}\",\"${TRACE_PATH#${ROOT}/}\"]"

  start_ns="$(date +%s%N)"
  set +e
  FORCE_NATIVE_THREADING=1 FORCE_NATIVE_MUTEX=1 \
    rch exec -- cargo test -p frankenlibc-abi --test "${TEST_FILE}" "${filter}" -- --exact --nocapture --test-threads=1 \
    >"${log_path}" 2>&1
  rc=$?
  set -e
  end_ns="$(date +%s%N)"
  latency_ns=$((end_ns - start_ns))

  if [[ ${rc} -eq 0 ]]; then
    level="info"
    outcome="pass"
    errno_value=0
  else
    level="error"
    outcome="fail"
    errno_value=1
  fi

  emit_trace "${level}" "test_result" "${scenario_id}" "pthread_cond_clockwait" "${decision_path}" "${outcome}" "${errno_value}" "${latency_ns}" "${refs_json}"

  if [[ ${rc} -ne 0 ]]; then
    echo "FAIL: ${filter} (expected ${expected})" >&2
    echo "see ${log_path}" >&2
    return ${rc}
  fi
}

echo "=== pthread extension native gate (bd-zh1y.1.2) ==="

run_case \
  "realtime_immediate_timeout" \
  "cond_clockwait_realtime_immediate_timeout_on_managed_condvar" \
  "native_managed_condvar::clockwait::realtime::immediate_timeout" \
  "ETIMEDOUT"
run_case \
  "realtime_signal_before_deadline" \
  "cond_clockwait_realtime_future_signal_returns_zero_on_managed_condvar" \
  "native_managed_condvar::clockwait::realtime::signaled" \
  "0"
run_case \
  "monotonic_immediate_timeout" \
  "cond_clockwait_monotonic_immediate_timeout_on_managed_condvar" \
  "native_managed_condvar::clockwait::monotonic::immediate_timeout" \
  "ETIMEDOUT"
run_case \
  "monotonic_signal_before_deadline" \
  "cond_clockwait_monotonic_future_signal_returns_zero_on_managed_condvar" \
  "native_managed_condvar::clockwait::monotonic::signaled" \
  "0"

python3 - "${RUN_DIR}" "${TRACE_PATH}" "${REPORT_PATH}" "${INDEX_PATH}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
trace_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
index_path = Path(sys.argv[4])
root = run_dir.parents[3]

rows = []
with trace_path.open("r", encoding="utf-8") as fh:
    for raw in fh:
        raw = raw.strip()
        if raw:
            rows.append(json.loads(raw))

if len(rows) != 4:
    raise SystemExit(f"FAIL: expected 4 trace rows, saw {len(rows)}")
if any(row.get("outcome") != "pass" for row in rows):
    raise SystemExit("FAIL: expected all pthread extension native cases to pass")

report = {
    "schema_version": "v1",
    "bead": "bd-zh1y.1.2",
    "run_id": run_dir.name,
    "summary": {
        "total_cases": len(rows),
        "pass_count": sum(1 for row in rows if row.get("outcome") == "pass"),
        "fail_count": sum(1 for row in rows if row.get("outcome") != "pass"),
    },
    "cases": rows,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

artifacts = []
for path in sorted(run_dir.iterdir()):
    if not path.is_file():
        continue
    artifacts.append(
        {
            "path": path.relative_to(root).as_posix(),
            "kind": "jsonl" if path.suffix == ".jsonl" else "json" if path.suffix == ".json" else "log",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )

index = {
    "index_version": 1,
    "run_id": run_dir.name,
    "bead_id": "bd-zh1y.1.2",
    "generated_utc": rows[-1]["timestamp"],
    "artifacts": artifacts,
}
index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
PY

echo "trace=${TRACE_PATH}"
echo "report=${REPORT_PATH}"
echo "artifact_index=${INDEX_PATH}"
echo "check_pthread_extensions_native: PASS"
