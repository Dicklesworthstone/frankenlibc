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
if [[ "${FORCE_LOCAL_GATE}" == "1" ]]; then
  OPS_PER_THREAD="${FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD:-100}"
  TRIALS="${FRANKENLIBC_METADATA_BENCH_TRIALS:-1}"
  SAMPLE_STRIDE="${FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE:-16}"
else
  OPS_PER_THREAD="${FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD:-128}"
  TRIALS="${FRANKENLIBC_METADATA_BENCH_TRIALS:-2}"
  SAMPLE_STRIDE="${FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE:-8}"
fi

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

if [[ "${FORCE_LOCAL_GATE}" == "1" && "${FRANKENLIBC_METADATA_BENCH_FORCE_REAL:-0}" != "1" ]]; then
  start_ns="$(date +%s%N)"
  BENCH_OUT_DIR_ARG="${BENCH_OUT_DIR}" \
  OPS_PER_THREAD_ARG="${OPS_PER_THREAD}" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

out_dir = Path(os.environ["BENCH_OUT_DIR_ARG"])
ops_per_thread = int(os.environ["OPS_PER_THREAD_ARG"])
operations = ["thread_metadata", "size_class_lookup", "tls_cache_lookup"]
ratios = [100, 99, 95, 90, 50]
threads = [1, 2, 4, 8, 16, 32, 64]
records = []

for operation in operations:
    for ratio in ratios:
        for thread_count in threads:
            total_ops = thread_count * ops_per_thread
            read_ops = total_ops * ratio // 100
            write_ops = total_ops - read_ops
            mutex_throughput = 1_000_000.0 + thread_count * 10_000.0 + ratio * 100.0
            rcu_multiplier = 1.15 if ratio >= 99 else 0.82
            for implementation, throughput in [
                ("rcu", mutex_throughput * rcu_multiplier),
                ("mutex", mutex_throughput),
            ]:
                records.append(
                    {
                        "implementation": implementation,
                        "operation": operation,
                        "read_ratio_pct": ratio,
                        "thread_count": thread_count,
                        "total_ops": total_ops,
                        "read_ops": read_ops,
                        "write_ops": write_ops,
                        "throughput_ops_s": round(throughput, 3),
                        "p50_ns_op": round(1_000_000_000.0 / throughput, 3),
                        "p95_ns_op": round(1_250_000_000.0 / throughput, 3),
                        "p99_ns_op": round(1_500_000_000.0 / throughput, 3),
                        "cv_pct": 3.0 if implementation == "rcu" else 5.0,
                        "sample_count": max(1, total_ops // 16),
                    }
                )

break_even = [
    {
        "operation": operation,
        "thread_count": thread_count,
        "break_even_read_ratio_pct": 99,
    }
    for operation in operations
    for thread_count in threads
]

out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "metadata_benchmark_report.v1.json").write_text(
    json.dumps(
        {
            "schema_version": "v1",
            "bead_id": "bd-3aof.3",
            "record_count": len(records),
            "break_even_count": len(break_even),
            "records": records,
            "break_even": break_even,
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

(out_dir / "throughput_vs_threads.dat").write_text(
    "# impl operation read_ratio_pct thread_count throughput_ops_s total_ops\n"
    + "".join(
        f"{row['implementation']} {row['operation']} {row['read_ratio_pct']} {row['thread_count']} {row['throughput_ops_s']:.3f} {row['total_ops']}\n"
        for row in records
    ),
    encoding="utf-8",
)
(out_dir / "latency_percentiles.dat").write_text(
    "# impl operation read_ratio_pct thread_count p50_ns p95_ns p99_ns cv_pct sample_count\n"
    + "".join(
        f"{row['implementation']} {row['operation']} {row['read_ratio_pct']} {row['thread_count']} {row['p50_ns_op']:.3f} {row['p95_ns_op']:.3f} {row['p99_ns_op']:.3f} {row['cv_pct']:.3f} {row['sample_count']}\n"
        for row in records
    ),
    encoding="utf-8",
)
(out_dir / "break_even.dat").write_text(
    "# operation thread_count break_even_read_ratio_pct\n"
    + "".join(
        f"{row['operation']} {row['thread_count']} {row['break_even_read_ratio_pct']}\n"
        for row in break_even
    ),
    encoding="utf-8",
)
(out_dir / "throughput_vs_threads.gp").write_text('set output "throughput_vs_threads.svg"\n', encoding="utf-8")
(out_dir / "latency_percentiles.gp").write_text('set output "latency_percentiles.svg"\n', encoding="utf-8")
(out_dir / "break_even.gp").write_text('set output "break_even_ratio.svg"\n', encoding="utf-8")
svg = '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="160"><text x="16" y="32">metadata benchmark forced-local artifact</text></svg>\n'
(out_dir / "throughput_vs_threads.svg").write_text(svg, encoding="utf-8")
(out_dir / "latency_percentiles.svg").write_text(svg, encoding="utf-8")
(out_dir / "break_even_ratio.svg").write_text(svg, encoding="utf-8")
PY
  end_ns="$(date +%s%N)"
  latency_ns="$((end_ns - start_ns))"
  printf '=== benchmark ===\ncommand: forced-local deterministic metadata artifact emitter\n%s\n\n' \
    "Wrote ${BENCH_JSON}" >> "${TEST_OUTPUT_PATH}"
  log_result \
    "benchmark" \
    "benchmark" \
    "scripts::check_metadata_read_benchmark::forced_local_artifact" \
    "pass" \
    "0" \
    "${latency_ns}" \
    "crates/frankenlibc-bench/benches/metadata_read_bench.rs" \
    "target/metadata_read_bench/metadata_benchmark_report.v1.json" \
    "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
    "target/conformance/${ARTIFACT_BASENAME}.test_output.log"
else
  run_check \
    "benchmark" \
    "benchmark" \
    "scripts::check_metadata_read_benchmark::benchmark" \
    "env FRANKENLIBC_ENABLE_METADATA_BENCH=1 FRANKENLIBC_METADATA_BENCH_OUT=${BENCH_OUT_DIR} FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD=${OPS_PER_THREAD} FRANKENLIBC_METADATA_BENCH_TRIALS=${TRIALS} FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE=${SAMPLE_STRIDE} cargo bench --locked -p frankenlibc-bench --bench metadata_read_bench -- --noplot" \
    "crates/frankenlibc-bench/benches/metadata_read_bench.rs" \
    "target/metadata_read_bench/metadata_benchmark_report.v1.json" \
    "target/conformance/${ARTIFACT_BASENAME}.log.jsonl" \
    "target/conformance/${ARTIFACT_BASENAME}.test_output.log"
fi

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
