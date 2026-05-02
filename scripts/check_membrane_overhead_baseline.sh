#!/usr/bin/env bash
# check_membrane_overhead_baseline.sh - gate for bd-bp8fl.8.2.
#
# Validates that membrane stage/entrypoint overhead baselines are complete,
# synchronized with perf_baseline.json, and logged as structured evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/membrane_overhead_baseline.v1.json"
BASELINE="${ROOT}/scripts/perf_baseline.json"
SPEC="${ROOT}/tests/conformance/perf_baseline_spec.json"
REPORT="${FRANKENLIBC_MEMBRANE_OVERHEAD_REPORT:-${ROOT}/target/conformance/membrane_overhead_baseline.report.json}"
LOG="${FRANKENLIBC_MEMBRANE_OVERHEAD_LOG:-${ROOT}/target/conformance/membrane_overhead_baseline.log.jsonl}"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

echo "=== Membrane Overhead Baseline Gate (bd-bp8fl.8.2) ==="
echo "artifact=${ARTIFACT}"
echo "baseline=${BASELINE}"
echo "spec=${SPEC}"
echo "report=${REPORT}"
echo "log=${LOG}"

python3 - "${ARTIFACT}" "${BASELINE}" "${SPEC}" "${REPORT}" "${LOG}" <<'PY'
import json
import math
import sys
from pathlib import Path

artifact_path, baseline_path, spec_path, report_path, log_path = map(Path, sys.argv[1:6])

with artifact_path.open(encoding="utf-8") as handle:
    artifact = json.load(handle)
with baseline_path.open(encoding="utf-8") as handle:
    baseline = json.load(handle)
with spec_path.open(encoding="utf-8") as handle:
    spec = json.load(handle)

required_stages = [
    "null_check",
    "tls_cache",
    "bloom_filter",
    "arena_lookup",
    "fingerprint_check",
    "canary_check",
    "bounds_check",
    "full_validation_path",
]
required_benchmarks = [
    "stage_null_check",
    "stage_tls_cache_hit",
    "stage_bloom_hit",
    "stage_arena_lookup",
    "stage_fingerprint_verify",
    "stage_canary_verify",
    "stage_bounds_check",
    "validate_null",
    "validate_foreign",
    "validate_known",
]
stage_target_by_benchmark = {
    "stage_null_check": 1,
    "stage_tls_cache_hit": 5,
    "stage_bloom_hit": 10,
    "stage_arena_lookup": 30,
    "stage_fingerprint_verify": 20,
    "stage_canary_verify": 10,
    "stage_bounds_check": 5,
}
entrypoint_targets = {"strict": 20, "hardened": 200}

errors = []
rows = []

if artifact.get("schema_version") != 1:
    errors.append("schema_version must be 1")
if artifact.get("bead") != "bd-bp8fl.8.2":
    errors.append("bead must be bd-bp8fl.8.2")

coverage = artifact.get("stage_coverage", [])
covered_stages = {row.get("stage") for row in coverage}
for stage in required_stages:
    if stage not in covered_stages:
        errors.append(f"stage_coverage missing {stage}")

benchmarks = {row.get("name"): row for row in artifact.get("benchmarks", [])}
for bench in required_benchmarks:
    if bench not in benchmarks:
        errors.append(f"benchmarks missing {bench}")

records = artifact.get("benchmark_records", [])
if not isinstance(records, list):
    errors.append("benchmark_records must be array")
    records = []
records_by_pair = {}
for record in records:
    if not isinstance(record, dict):
        errors.append("benchmark_records entries must be objects")
        continue
    key = (record.get("benchmark"), record.get("runtime_mode"))
    if key in records_by_pair:
        errors.append(f"duplicate benchmark_record for {key[0]}/{key[1]}")
    records_by_pair[key] = record

required_record_fields = [
    "trace_id",
    "bead_id",
    "benchmark_id",
    "validation_path",
    "runtime_mode",
    "input_shape",
    "sample_count",
    "warmup_ms",
    "latency_ns",
    "variance",
    "environment",
    "source_commit",
    "target_dir",
    "threshold",
    "decision",
    "artifact_refs",
    "failure_signature",
]
source_commit = artifact.get("source_commit")
if not isinstance(source_commit, str) or len(source_commit) != 40:
    errors.append("source_commit must be a 40-character git commit")
target_dirs = artifact.get("measurement_environment", {}).get("target_dirs", {})
criterion = artifact.get("measurement_environment", {}).get("criterion", {})
if criterion.get("warm_up_time_ms") != 1:
    errors.append("criterion warm_up_time_ms must be 1")

def require_record_field(record, field, bench, mode):
    if field not in record:
        errors.append(f"{bench}/{mode}: benchmark_record missing {field}")
        return None
    return record[field]

membrane_suite = None
for suite in spec.get("benchmark_suites", {}).get("suites", []):
    if suite.get("id") == "membrane":
        membrane_suite = suite
        break
if not membrane_suite:
    errors.append("perf_baseline_spec missing membrane suite")
else:
    spec_benches = [row.get("name") for row in membrane_suite.get("benchmarks", [])]
    if spec_benches != required_benchmarks:
        errors.append(
            "membrane suite benchmark order mismatch: "
            f"expected {required_benchmarks}, got {spec_benches}"
        )

def close_enough(a, b):
    try:
        return math.isclose(float(a), float(b), rel_tol=0.0, abs_tol=0.0005)
    except (TypeError, ValueError):
        return False

for bench in required_benchmarks:
    row = benchmarks.get(bench)
    if not isinstance(row, dict):
        continue
    baseline_by_mode = row.get("baseline", {})
    for mode in ("strict", "hardened"):
        metrics = baseline_by_mode.get(mode, {})
        for field in ("samples", "p50_ns_op", "p95_ns_op", "p99_ns_op", "mean_ns_op", "throughput_ops_s"):
            value = metrics.get(field)
            if not isinstance(value, (int, float)) or value <= 0:
                errors.append(f"{bench}/{mode}: {field} must be positive")
        p50 = metrics.get("p50_ns_op")
        p95 = metrics.get("p95_ns_op")
        p99 = metrics.get("p99_ns_op")
        if isinstance(p50, (int, float)) and isinstance(p95, (int, float)) and p95 < p50:
            errors.append(f"{bench}/{mode}: p95 must be >= p50")
        if isinstance(p95, (int, float)) and isinstance(p99, (int, float)) and p99 < p95:
            errors.append(f"{bench}/{mode}: p99 must be >= p95")

        committed = (
            baseline.get("baseline_p50_ns_op", {})
            .get("membrane", {})
            .get(mode, {})
            .get(bench)
        )
        if committed is None or not close_enough(committed, p50):
            errors.append(f"{bench}/{mode}: p50 not synchronized with scripts/perf_baseline.json")

        expected_target = stage_target_by_benchmark.get(bench, entrypoint_targets[mode])
        target = baseline.get("targets_ns_op", {}).get(mode, {}).get(bench)
        if target != expected_target:
            errors.append(f"{bench}/{mode}: target {target!r} != expected {expected_target!r}")

        record = records_by_pair.get((bench, mode))
        if not isinstance(record, dict):
            errors.append(f"{bench}/{mode}: missing benchmark_record")
            continue
        for field in required_record_fields:
            require_record_field(record, field, bench, mode)
        expected_decision = (
            "pass"
            if float(p50) <= float(expected_target)
            else "captured_over_target_for_optimization"
        )
        expected_failure_signature = (
            "none" if expected_decision == "pass" else "target_exceeded_baseline_only"
        )
        expected_trace_id = f"bd-bp8fl.8.2::{mode}::{bench}"
        expected_benchmark_id = f"membrane.{bench}.{mode}"
        expected_target_dir = target_dirs.get(mode)
        expected_variance_p95 = round(float(p95) - float(p50), 3)
        expected_variance_p99 = round(float(p99) - float(p50), 3)
        variance = record.get("variance", {})
        if record.get("trace_id") != expected_trace_id:
            errors.append(f"{bench}/{mode}: trace_id mismatch")
        if record.get("bead_id") != "bd-bp8fl.8.2":
            errors.append(f"{bench}/{mode}: bead_id mismatch")
        if record.get("benchmark_id") != expected_benchmark_id:
            errors.append(f"{bench}/{mode}: benchmark_id mismatch")
        if record.get("validation_path") != row.get("stage"):
            errors.append(f"{bench}/{mode}: validation_path mismatch")
        if record.get("runtime_mode") != mode:
            errors.append(f"{bench}/{mode}: runtime_mode mismatch")
        if not isinstance(record.get("input_shape"), dict):
            errors.append(f"{bench}/{mode}: input_shape must be object")
        if record.get("sample_count") != metrics.get("samples"):
            errors.append(f"{bench}/{mode}: sample_count mismatch")
        if record.get("warmup_ms") != criterion.get("warm_up_time_ms"):
            errors.append(f"{bench}/{mode}: warmup_ms mismatch")
        if not close_enough(record.get("latency_ns"), p50):
            errors.append(f"{bench}/{mode}: latency_ns mismatch")
        if not isinstance(variance, dict):
            errors.append(f"{bench}/{mode}: variance must be object")
        else:
            if variance.get("policy") != artifact.get("variance_policy", {}).get("kind"):
                errors.append(f"{bench}/{mode}: variance policy mismatch")
            if not close_enough(variance.get("p95_minus_p50_ns"), expected_variance_p95):
                errors.append(f"{bench}/{mode}: p95 variance mismatch")
            if not close_enough(variance.get("p99_minus_p50_ns"), expected_variance_p99):
                errors.append(f"{bench}/{mode}: p99 variance mismatch")
            if (
                isinstance(variance.get("p95_minus_p50_ns"), (int, float))
                and variance["p95_minus_p50_ns"] < 0
            ):
                errors.append(f"{bench}/{mode}: p95 variance must be non-negative")
            if (
                isinstance(variance.get("p99_minus_p50_ns"), (int, float))
                and variance["p99_minus_p50_ns"] < 0
            ):
                errors.append(f"{bench}/{mode}: p99 variance must be non-negative")
        if record.get("source_commit") != source_commit:
            errors.append(f"{bench}/{mode}: source_commit is stale or mismatched")
        if record.get("target_dir") != expected_target_dir:
            errors.append(f"{bench}/{mode}: target_dir mismatch")
        if record.get("threshold") != expected_target:
            errors.append(f"{bench}/{mode}: threshold mismatch")
        if record.get("decision") != expected_decision:
            errors.append(f"{bench}/{mode}: decision mismatch")
        refs = record.get("artifact_refs", [])
        if not isinstance(refs, list) or len(refs) < 3:
            errors.append(f"{bench}/{mode}: artifact_refs incomplete")
        if record.get("failure_signature") != expected_failure_signature:
            errors.append(f"{bench}/{mode}: failure_signature mismatch")

        log_row = dict(record)
        log_row.update(
            {
                "event": "membrane_overhead_baseline",
                "coverage_kind": row.get("coverage_kind"),
                "threshold": expected_target,
                "latency_ns": p50,
                "decision": expected_decision,
                "failure_signature": expected_failure_signature,
            }
        )
        rows.append(log_row)

summary = artifact.get("summary", {})
expected_summary = {
    "requested_stages": len(required_stages),
    "direct_stage_benchmarks": 7,
    "entrypoint_path_benchmarks": 3,
    "modes": 2,
    "benchmarks": len(required_benchmarks),
}
for key, expected in expected_summary.items():
    if summary.get(key) != expected:
        errors.append(f"summary.{key} {summary.get(key)!r} != {expected!r}")

report = {
    "schema_version": 1,
    "bead": "bd-bp8fl.8.2",
    "status": "failed" if errors else "pass",
    "artifact": str(artifact_path),
    "baseline": str(baseline_path),
    "spec": str(spec_path),
    "summary": {
        "benchmarks": len(required_benchmarks),
        "modes": 2,
        "evidence_rows": len(rows),
        "direct_stage_benchmarks": 7,
        "entrypoint_path_benchmarks": 3,
        "errors": len(errors),
        "target_violations": sum(
            1 for row in rows if row.get("decision") == "captured_over_target_for_optimization"
        ),
    },
    "errors": errors,
}

Path(report_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
with Path(log_path).open("w", encoding="utf-8") as handle:
    for row in rows:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    for error in errors:
        print(f"FAIL: {error}")
    raise SystemExit(1)

print(f"Benchmarks: {len(required_benchmarks)}")
print(f"Evidence rows: {len(rows)}")
print("check_membrane_overhead_baseline: PASS")
PY
