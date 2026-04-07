#!/usr/bin/env bash
# CI gate: metadata RCU-vs-mutex benchmark artifact validation for bd-3aof.3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
ARTIFACT_BASENAME="metadata_read_benchmark"
LOG_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.log.jsonl"
REPORT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.report.json"
TEST_OUTPUT_PATH="${OUT_DIR}/${ARTIFACT_BASENAME}.test_output.log"
BENCH_OUT_DIR="${ROOT}/target/metadata_read_bench"
BENCH_JSON="${BENCH_OUT_DIR}/metadata_benchmark_report.v1.json"
RCH_CARGO_HOME="${RCH_CARGO_HOME:-}"
RCH_TARGET_DIR="${RCH_TARGET_DIR:-/tmp/${ARTIFACT_BASENAME}_target}"
FORCE_LOCAL_GATE="${FRANKENLIBC_FORCE_LOCAL_METADATA_GATE:-0}"
BEAD_ID="bd-3aof.3"
OPS_PER_THREAD="${FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD:-128}"
TRIALS="${FRANKENLIBC_METADATA_BENCH_TRIALS:-2}"
SAMPLE_STRIDE="${FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE:-8}"

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
  printf '{"timestamp":"%s","trace_id":"%s::%s","level":"info","event":"metadata_read_benchmark_gate","bead_id":"%s","mode":"shared","api_family":"metadata","symbol":"metadata_read_path","stream":"%s","decision_path":"%s","healing_action":"none","outcome":"%s","errno":%s,"latency_ns":%s,"artifact_refs":%s}\n' \
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
  echo "WARN: FRANKENLIBC_FORCE_LOCAL_METADATA_GATE=1; using local cargo fallback" >&2
elif ! command -v rch >/dev/null 2>&1; then
  echo "WARN: rch unavailable; using local cargo fallback" >&2
fi

run_check \
  "unit_tests" \
  "unit" \
  "scripts::check_metadata_read_benchmark::unit_tests" \
  "cargo test --locked -p frankenlibc-bench --lib -- --nocapture" \
  "crates/frankenlibc-bench/src/lib.rs" \
  "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
  "target/conformance/${ARTIFACT_BASENAME}.test_output.log"

run_check \
  "benchmark" \
  "benchmark" \
  "scripts::check_metadata_read_benchmark::benchmark" \
  "env FRANKENLIBC_ENABLE_METADATA_BENCH=1 FRANKENLIBC_METADATA_BENCH_OUT=${BENCH_OUT_DIR} FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD=${OPS_PER_THREAD} FRANKENLIBC_METADATA_BENCH_TRIALS=${TRIALS} FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE=${SAMPLE_STRIDE} cargo bench --locked -p frankenlibc-bench --bench metadata_read_bench -- --noplot" \
  "crates/frankenlibc-bench/benches/metadata_read_bench.rs" \
  "target/metadata_read_bench/metadata_benchmark_report.v1.json" \
  "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
  "target/conformance/${ARTIFACT_BASENAME}.test_output.log"

if [[ ! -f "${BENCH_JSON}" ]]; then
  echo "check_metadata_read_benchmark: missing benchmark artifact ${BENCH_JSON}" >&2
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

if payload.get("schema_version") != "v1":
    raise SystemExit("metadata benchmark schema_version must be v1")
if payload.get("bead_id") != "bd-3aof.3":
    raise SystemExit("metadata benchmark bead_id must be bd-3aof.3")

records = payload.get("records", [])
break_even = payload.get("break_even", [])
if len(records) != 210:
    raise SystemExit(f"expected 210 records, found {len(records)}")
if len(break_even) != 21:
    raise SystemExit(f"expected 21 break-even rows, found {len(break_even)}")

required_files = [
    bench_path,
    bench_path.parent / "throughput_vs_threads.dat",
    bench_path.parent / "latency_percentiles.dat",
    bench_path.parent / "break_even.dat",
    bench_path.parent / "throughput_vs_threads.gp",
    bench_path.parent / "latency_percentiles.gp",
    bench_path.parent / "break_even.gp",
    bench_path.parent / "throughput_vs_threads.svg",
    bench_path.parent / "latency_percentiles.svg",
    bench_path.parent / "break_even_ratio.svg",
]
missing = [str(path) for path in required_files if not path.exists()]
if missing:
    raise SystemExit(f"missing metadata bench artifacts: {missing}")

keyed = {}
for row in records:
    key = (row["operation"], row["read_ratio_pct"], row["thread_count"])
    keyed.setdefault(key, set()).add(row["implementation"])
    if row["throughput_ops_s"] <= 0:
        raise SystemExit(f"non-positive throughput for {key} {row['implementation']}")
    if row["sample_count"] <= 0:
        raise SystemExit(f"sample_count must be positive for {key} {row['implementation']}")
    if row["read_ops"] + row["write_ops"] != row["total_ops"]:
        raise SystemExit(f"read/write totals do not balance for {key} {row['implementation']}")

for key, impls in keyed.items():
    if impls != {"rcu", "mutex"}:
        raise SystemExit(f"missing implementation pair for {key}: {impls}")

nonnull_break_even = sum(1 for row in break_even if row["break_even_read_ratio_pct"] is not None)
high_read_wins = 0
by_tuple = {
    (row["implementation"], row["operation"], row["read_ratio_pct"], row["thread_count"]): row
    for row in records
}
for operation in ("thread_metadata", "size_class_lookup", "tls_cache_lookup"):
    for ratio in (100, 99):
        for threads in (32, 64):
            rcu = by_tuple.get(("rcu", operation, ratio, threads))
            mutex = by_tuple.get(("mutex", operation, ratio, threads))
            if rcu and mutex and rcu["throughput_ops_s"] >= mutex["throughput_ops_s"]:
                high_read_wins += 1

report = {
    "schema_version": "v1",
    "bead_id": "bd-3aof.3",
    "unit_tests": {
        "frankenlibc_bench_lib": "pass",
    },
    "benchmark": {
        "record_count": len(records),
        "break_even_count": len(break_even),
        "nonnull_break_even_count": nonnull_break_even,
        "high_read_wins": high_read_wins,
    },
    "artifacts": [str(path) for path in required_files] + [str(report_path)],
}
report_path.write_text(json.dumps(report, indent=2) + "\n")

if nonnull_break_even == 0:
    raise SystemExit("metadata benchmark did not produce any break-even row")
if high_read_wins < 3:
    raise SystemExit(f"expected at least 3 high-read RCU wins, found {high_read_wins}")
PY

echo "OK: metadata read benchmark gate emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"
echo "- ${BENCH_JSON}"
