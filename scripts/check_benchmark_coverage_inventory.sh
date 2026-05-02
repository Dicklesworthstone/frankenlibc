#!/usr/bin/env bash
# check_benchmark_coverage_inventory.sh - gate for bd-bp8fl.8.1.
#
# Generates a benchmark coverage inventory report and validates that it
# preserves the full optimization-planning scope: string, malloc, stdio,
# pthread, syscall, membrane, and runtime math coverage, with structured logs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="${FRANKENLIBC_BENCHMARK_COVERAGE_REPORT:-target/conformance/benchmark_coverage_inventory.report.json}"
LOG="${FRANKENLIBC_BENCHMARK_COVERAGE_LOG:-target/conformance/benchmark_coverage_inventory.log.jsonl}"

cd "$REPO_ROOT"

echo "=== Benchmark Coverage Inventory Gate (bd-bp8fl.8.1) ==="
echo "report=${REPORT}"
echo "log=${LOG}"

python3 scripts/generate_benchmark_coverage_inventory.py --self-test
python3 scripts/generate_benchmark_coverage_inventory.py \
  --check \
  --output tests/conformance/benchmark_coverage_inventory.v1.json \
  --target-dir "$(dirname "$REPORT")"

python3 scripts/generate_benchmark_coverage_inventory.py \
  --output "$REPORT" \
  --log "$LOG" \
  --target-dir "$(dirname "$REPORT")"

python3 - "$REPORT" "$LOG" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])

with report_path.open(encoding="utf-8") as handle:
    report = json.load(handle)

errors = []
required_families = {
    "string",
    "malloc",
    "stdio",
    "pthread",
    "syscall",
    "membrane",
}
expected_required_log_fields = {
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "benchmark_id",
    "coverage_state",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}

if report.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if report.get("bead") != "bd-bp8fl.8.1":
    errors.append("bead must be bd-bp8fl.8.1")
if not report.get("artifact_hash"):
    errors.append("artifact_hash must be present")

families = report.get("families", [])
family_ids = {row.get("family") for row in families}
missing_families = sorted(required_families - family_ids)
if missing_families:
    errors.append(f"missing required families: {missing_families}")

summary = report.get("summary", {})
if summary.get("required_family_count", 0) < len(required_families):
    errors.append("required_family_count is too small")
if "membrane" not in summary.get("fully_baselined_families", []):
    errors.append("membrane must remain fully baselined")
if "strict" not in summary.get("strict_hardened_modes_required", []):
    errors.append("strict mode must be required")
if "hardened" not in summary.get("strict_hardened_modes_required", []):
    errors.append("hardened mode must be required")
if not summary.get("missing_required_baseline_families"):
    errors.append("inventory should expose current missing required baselines")

for family in families:
    fid = family.get("family")
    if fid in required_families:
        if not family.get("workload_artifacts"):
            errors.append(f"{fid}: missing workload artifacts")
        if fid != "syscall" and not family.get("has_bench_file"):
            errors.append(f"{fid}: expected at least one bench file")
        if fid == "syscall" and family.get("coverage_state") != "gap":
            errors.append("syscall should remain a gap until a benchmark suite exists")
    for item in family.get("baseline_coverage", []):
        status = item.get("status")
        if status not in {"complete", "incomplete", "missing_spec_suite"}:
            errors.append(f"{fid}: invalid baseline status {status!r}")

bench_targets = report.get("bench_targets", [])
if summary.get("actual_bench_target_count") != len(bench_targets):
    errors.append("actual_bench_target_count does not match bench target rows")
inventory_rows = report.get("inventory_rows", [])
if summary.get("inventory_row_count") != len(inventory_rows):
    errors.append("inventory_row_count does not match inventory rows")
if summary.get("missing_owner_row_count") != 0:
    errors.append("inventory rows must all have owner beads")
if not summary.get("missing_inventory_row_count"):
    errors.append("inventory should expose current missing benchmark rows")

required_inventory_fields = set(report.get("required_inventory_row_fields", []))
expected_inventory_fields = {
    "row_id",
    "api_family",
    "symbol",
    "crate/module",
    "current_benchmark",
    "missing_benchmark_reason",
    "runtime_mode",
    "replacement_level",
    "user_workload_exposure",
    "baseline_artifact",
    "owner_bead",
    "benchmark_id",
    "coverage_state",
    "artifact_refs",
    "failure_signature",
}
if required_inventory_fields != expected_inventory_fields:
    errors.append("required_inventory_row_fields mismatch")

seen_rows = set()
for row in inventory_rows:
    missing = expected_inventory_fields - set(row)
    if missing:
        errors.append(f"{row.get('row_id', '<unknown>')}: missing inventory fields {sorted(missing)}")
    row_id = row.get("row_id")
    if row_id in seen_rows:
        errors.append(f"duplicate inventory row: {row_id}")
    seen_rows.add(row_id)
    if not str(row.get("owner_bead", "")).startswith("bd-"):
        errors.append(f"{row_id}: owner_bead must be present")
    if row.get("runtime_mode") not in {"strict", "hardened"}:
        errors.append(f"{row_id}: invalid runtime_mode")
    if row.get("coverage_state") not in {"covered", "gap"}:
        errors.append(f"{row_id}: invalid coverage_state")
    if not isinstance(row.get("current_benchmark"), dict):
        errors.append(f"{row_id}: current_benchmark must be object")
    if not isinstance(row.get("baseline_artifact"), dict):
        errors.append(f"{row_id}: baseline_artifact must be object")
    if not isinstance(row.get("user_workload_exposure"), dict):
        errors.append(f"{row_id}: user_workload_exposure must be object")

required_log_fields = set(report.get("required_log_fields", []))
if required_log_fields != expected_required_log_fields:
    errors.append("required_log_fields mismatch")

rows = []
with log_path.open(encoding="utf-8") as handle:
    for raw in handle:
        raw = raw.strip()
        if raw:
            rows.append(json.loads(raw))

if len(rows) != len(families):
    errors.append(f"log row count {len(rows)} != family count {len(families)}")

for row in rows:
    missing = expected_required_log_fields - set(row)
    if missing:
        errors.append(f"{row.get('api_family', '<unknown>')}: missing log fields {sorted(missing)}")
    if row.get("bead_id") != "bd-bp8fl.8.1":
        errors.append("log row bead_id mismatch")
    if row.get("oracle_kind") != "derived_inventory_gate":
        errors.append("log row oracle_kind mismatch")
    if row.get("runtime_mode") != "strict+hardened":
        errors.append("log row runtime_mode mismatch")
    if "benchmark_id" not in row:
        errors.append("log row benchmark_id missing")
    if "coverage_state" not in row:
        errors.append("log row coverage_state missing")

if errors:
    for error in errors:
        print(f"FAIL: {error}")
    raise SystemExit(1)

print(f"Families: {len(families)}")
print(f"Bench targets: {len(bench_targets)}")
print(f"Inventory rows: {len(inventory_rows)}")
print("Fully baselined:", ", ".join(summary.get("fully_baselined_families", [])))
print("Missing required baselines:", ", ".join(summary.get("missing_required_baseline_families", [])))
print("check_benchmark_coverage_inventory: PASS")
PY
