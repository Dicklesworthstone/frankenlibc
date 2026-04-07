#!/usr/bin/env bash
# CI gate: elimination-backoff correctness + benchmark artifact validation for bd-29j3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
ARTIFACT_BASENAME="elimination_backoff"
LOG_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.log.jsonl"
REPORT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.test_output.log"
BENCH_OUT_DIR="${ROOT}/target/elimination_backoff"
BENCH_JSON="${BENCH_OUT_DIR}/elimination_benchmark.json"
RCH_CARGO_HOME="${RCH_CARGO_HOME:-}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/${ARTIFACT_BASENAME}_target}"
FORCE_LOCAL_GATE="${FRANKENLIBC_FORCE_LOCAL_ELIMINATION_GATE:-0}"
BEAD_ID="bd-29j3"

mkdir -p "${OUT_DIR}"
: > "${LOG_PATH}"
: > "${TEST_OUTPUT_PATH}"

now_iso_ms() {
  python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
PY
}

run_remote() {
  local command="$1"
  if [[ "${FORCE_LOCAL_GATE}" != "1" ]] && command -v rch >/dev/null 2>&1; then
    if [[ -n "${RCH_CARGO_HOME}" ]]; then
      rch exec -- env CARGO_HOME="${RCH_CARGO_HOME}" CARGO_TARGET_DIR="${RCH_TARGET_DIR}" ${command}
    else
      rch exec -- env CARGO_TARGET_DIR="${RCH_TARGET_DIR}" ${command}
    fi
  else
    if [[ -n "${RCH_CARGO_HOME}" ]]; then
      env CARGO_HOME="${RCH_CARGO_HOME}" CARGO_TARGET_DIR="${RCH_TARGET_DIR}" bash -lc "${command}"
    else
      env CARGO_TARGET_DIR="${RCH_TARGET_DIR}" bash -lc "${command}"
    fi
  fi
}

log_result() {
  local trace_suffix="$1"
  local stream="$2"
  local decision_path="$3"
  local outcome="$4"
  local errno_value="$5"
  local latency_ns="$6"
  shift 6
  local artifact_refs=("$@")
  local artifact_json
  artifact_json="$(printf '"%s",' "${artifact_refs[@]}")"
  artifact_json="[${artifact_json%,}]"
  printf '{"timestamp":"%s","trace_id":"%s::%s","level":"info","event":"elimination_backoff_gate","bead_id":"%s","mode":"shared","api_family":"malloc","symbol":"allocator_elimination","stream":"%s","decision_path":"%s","healing_action":"none","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":%s}\n' \
    "$(now_iso_ms)" "${BEAD_ID}" "${trace_suffix}" "${BEAD_ID}" "${stream}" "${decision_path}" "${outcome}" "${errno_value}" "${latency_ns}" "${artifact_json}" >> "${LOG_PATH}"
}

run_check() {
  local trace_suffix="$1"
  local stream="$2"
  local decision_path="$3"
  local command="$4"
  shift 4
  local artifact_refs=("$@")
  local start_ns end_ns latency_ns output errno_value outcome
  start_ns="$(date +%s%N)"
  if output="$(run_remote "${command}" 2>&1)"; then
    errno_value=0
    outcome="pass"
  else
    errno_value=1
    outcome="fail"
  fi
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"
  local command_prefix="rch exec -- env"
  if [[ "${FORCE_LOCAL_GATE}" == "1" ]] || ! command -v rch >/dev/null 2>&1; then
    command_prefix="env"
  fi
  printf '=== %s ===\ncommand: %s%s CARGO_TARGET_DIR=%s %s\n%s\n\n' \
    "${trace_suffix}" \
    "${command_prefix}" \
    "${RCH_CARGO_HOME:+ CARGO_HOME=${RCH_CARGO_HOME}}" \
    "${RCH_TARGET_DIR}" \
    "${command}" \
    "${output}" >> "${TEST_OUTPUT_PATH}"
  log_result "${trace_suffix}" "${stream}" "${decision_path}" "${outcome}" "${errno_value}" "${latency_ns}" "${artifact_refs[@]}"
  if [[ "${outcome}" != "pass" ]]; then
    echo "${output}" >&2
    return 1
  fi
}

if [[ "${FORCE_LOCAL_GATE}" == "1" ]]; then
  echo "WARN: FRANKENLIBC_FORCE_LOCAL_ELIMINATION_GATE=1; using local cargo fallback" >&2
elif ! command -v rch >/dev/null 2>&1; then
  echo "WARN: rch unavailable; using local cargo fallback" >&2
fi

run_check \
  "unit_tests" \
  "unit" \
  "scripts::check_elimination_backoff::unit_tests" \
  "cargo test --locked -p frankenlibc-core elimination --lib -- --nocapture --test-threads=1" \
  "crates/frankenlibc-core/src/malloc/elimination.rs" \
  "crates/frankenlibc-core/src/malloc/allocator.rs" \
  "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
  "target/conformance/${ARTIFACT_BASENAME}.test_output.log"

run_check \
  "allocator_integration" \
  "unit" \
  "scripts::check_elimination_backoff::allocator_integration" \
  "cargo test --locked -p frankenlibc-core free_matches_waiting_consumer_through_elimination --lib -- --exact --nocapture --test-threads=1" \
  "crates/frankenlibc-core/src/malloc/allocator.rs" \
  "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
  "target/conformance/${ARTIFACT_BASENAME}.test_output.log"

run_check \
  "benchmark" \
  "benchmark" \
  "scripts::check_elimination_backoff::benchmark" \
  "env FRANKENLIBC_ENABLE_ELIMINATION_BENCH=1 FRANKENLIBC_ELIMINATION_BENCH_OUT=${BENCH_OUT_DIR} cargo bench --locked -p frankenlibc-bench --bench elimination_bench -- --noplot" \
  "crates/frankenlibc-bench/benches/elimination_bench.rs" \
  "target/elimination_backoff/elimination_benchmark.json" \
  "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
  "target/conformance/${ARTIFACT_BASENAME}.test_output.log"

if [[ ! -f "${BENCH_JSON}" ]]; then
  echo "check_elimination_backoff: missing benchmark artifact ${BENCH_JSON}" >&2
  exit 1
fi

BENCH_JSON_ARG="${BENCH_JSON}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
python3 - <<'PY'
import json
import os
from pathlib import Path

bench_path = Path(os.environ["BENCH_JSON_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])
payload = json.loads(bench_path.read_text())
records = {row["label"]: row for row in payload["records"]}
elim = records["elimination"]
mutex = records["mutex_queue"]
improvement = float(payload["improvement_pct"])
meets_target = bool(payload["meets_target"])

report = {
    "schema_version": 1,
    "bead_id": "bd-29j3",
    "unit_tests": {
        "elimination_module": "pass",
        "allocator_integration": "pass",
    },
    "benchmark": {
        "elimination_ops_s": elim["throughput_ops_s"],
        "mutex_queue_ops_s": mutex["throughput_ops_s"],
        "improvement_pct": improvement,
        "meets_target": meets_target,
        "elimination_success_rate_ppm": elim["elimination_success_rate_ppm"],
    },
    "artifacts": [
        str(bench_path),
        str(report_path),
    ],
}
report_path.write_text(json.dumps(report, indent=2) + "\n")

if not meets_target:
    raise SystemExit(
        f"elimination benchmark improvement {improvement:.3f}% did not meet 20.0% target"
    )
PY

echo "OK: elimination backoff gate emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
echo "- ${BENCH_JSON}"
