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
    return math.isclose(float(a), float(b), rel_tol=0.0, abs_tol=0.0005)

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

        rows.append(
            {
                "bead_id": "bd-bp8fl.8.2",
                "event": "membrane_overhead_baseline",
                "mode": mode,
                "benchmark": bench,
                "coverage_kind": row.get("coverage_kind"),
                "stage": row.get("stage"),
                "p50_ns_op": p50,
                "p95_ns_op": p95,
                "p99_ns_op": p99,
                "target_ns_op": expected_target,
                "over_target_x": round(float(p50) / float(expected_target), 3),
                "source": str(artifact_path),
            }
        )

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
