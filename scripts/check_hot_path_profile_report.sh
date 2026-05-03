#!/usr/bin/env bash
# check_hot_path_profile_report.sh - deterministic gate for bd-bp8fl.8.3.
#
# Builds the derived hot-path profile report, rejects stale committed
# artifacts, and verifies structured JSONL rows carry the profile evidence
# needed before optimization beads are created.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="${FRANKENLIBC_HOT_PATH_PROFILE_REPORT:-target/conformance/hot_path_profile_report.report.json}"
LOG="${FRANKENLIBC_HOT_PATH_PROFILE_LOG:-target/conformance/hot_path_profile_report.log.jsonl}"

cd "$REPO_ROOT"

echo "=== Hot Path Profile Report Gate (bd-bp8fl.8.3) ==="
echo "report=${REPORT}"
echo "log=${LOG}"

python3 scripts/generate_hot_path_profile_report.py --self-test
python3 scripts/generate_hot_path_profile_report.py \
  --check \
  --output tests/conformance/hot_path_profile_report.v1.json \
  --target-dir "$(dirname "$REPORT")"

python3 scripts/generate_hot_path_profile_report.py \
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
expected_profile_fields = {
    "profile_id",
    "workload_or_microbenchmark",
    "api_family",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "profile_tool",
    "sample_count",
    "hotness_score",
    "baseline_artifact",
    "parity_proof_refs",
    "host_baseline",
    "coverage_state",
    "artifact_refs",
    "failure_signature",
}
expected_log_fields = {
    "trace_id",
    "bead_id",
    "profile_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "hotness_score",
    "baseline_ref",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}

if report.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if report.get("bead") != "bd-bp8fl.8.3":
    errors.append("bead must be bd-bp8fl.8.3")
if not report.get("artifact_hash"):
    errors.append("artifact_hash must be present")

records = report.get("profile_records", [])
if not records:
    errors.append("profile_records must not be empty")

summary = report.get("summary", {})
if summary.get("profile_record_count") != len(records):
    errors.append("profile_record_count does not match profile_records")
if summary.get("measured_profile_record_count", 0) <= 0:
    errors.append("measured_profile_record_count must be positive")
if summary.get("missing_profile_record_count", 0) <= 0:
    errors.append("missing_profile_record_count must be positive")
if summary.get("host_comparison_available_count", 0) <= 0:
    errors.append("host_comparison_available_count must be positive")
if summary.get("host_comparison_limited_count", 0) <= 0:
    errors.append("host_comparison_limited_count must be positive")
if summary.get("membrane_over_target_record_count", 0) <= 0:
    errors.append("membrane_over_target_record_count must be positive")

profile_fields = set(report.get("required_profile_fields", []))
if profile_fields != expected_profile_fields:
    errors.append("required_profile_fields mismatch")
log_fields = set(report.get("required_log_fields", []))
if log_fields != expected_log_fields:
    errors.append("required_log_fields mismatch")

seen = set()
last_score = None
has_measured_host = False
has_limited_host = False
has_missing_gap = False
has_membrane_validate = False
for record in records:
    missing = expected_profile_fields - set(record)
    if missing:
        errors.append(f"{record.get('profile_id', '<unknown>')}: missing fields {sorted(missing)}")
    profile_id = record.get("profile_id")
    if profile_id in seen:
        errors.append(f"duplicate profile_id: {profile_id}")
    seen.add(profile_id)
    score = record.get("hotness_score")
    if not isinstance(score, (int, float)):
        errors.append(f"{profile_id}: hotness_score must be numeric")
    elif last_score is not None and score > last_score:
        errors.append(f"{profile_id}: records are not sorted descending")
    if isinstance(score, (int, float)):
        last_score = score
    if record.get("runtime_mode") not in {"strict", "hardened"}:
        errors.append(f"{profile_id}: invalid runtime_mode")
    if not isinstance(record.get("baseline_artifact"), dict):
        errors.append(f"{profile_id}: baseline_artifact must be object")
    if not record.get("parity_proof_refs"):
        errors.append(f"{profile_id}: missing parity proof refs")
    host = record.get("host_baseline", {})
    host_available = host.get("available") if isinstance(host, dict) else False
    if isinstance(host_available, bool) and host_available:
        has_measured_host = True
    if isinstance(host, dict) and not (isinstance(host_available, bool) and host_available) and host.get("limit"):
        has_limited_host = True
    if record.get("coverage_state") == "missing_profile":
        has_missing_gap = True
    if record.get("api_family") == "membrane" and str(record.get("symbol", "")).startswith("validate_"):
        has_membrane_validate = True

if not has_measured_host:
    errors.append("expected at least one measured raw host comparison")
if not has_limited_host:
    errors.append("expected at least one documented host comparison limit")
if not has_missing_gap:
    errors.append("expected missing profile gap rows")
if not has_membrane_validate:
    errors.append("expected membrane validate_* profile rows")
if not report.get("optimization_beads_to_create"):
    errors.append("optimization_beads_to_create must be non-empty")
if not report.get("deterministic_profiling_scripts"):
    errors.append("deterministic_profiling_scripts must be non-empty")

rows = []
with log_path.open(encoding="utf-8") as handle:
    for raw in handle:
        raw = raw.strip()
        if raw:
            rows.append(json.loads(raw))

if not rows:
    errors.append("structured log must not be empty")

for row in rows:
    missing = expected_log_fields - set(row)
    if missing:
        errors.append(f"{row.get('profile_id', '<unknown>')}: missing log fields {sorted(missing)}")
    if row.get("bead_id") != "bd-bp8fl.8.3":
        errors.append("log row bead_id mismatch")
    if not row.get("baseline_ref"):
        errors.append("log row baseline_ref missing")
    if not row.get("artifact_refs"):
        errors.append("log row artifact_refs missing")
    if row.get("target_dir") is None:
        errors.append("log row target_dir missing")

if errors:
    for error in errors:
        print(f"FAIL: {error}")
    raise SystemExit(1)

print(f"Profile records: {len(records)}")
print("Measured records:", summary.get("measured_profile_record_count"))
print("Missing profile rows:", summary.get("missing_profile_record_count"))
print("Host comparisons:", summary.get("host_comparison_available_count"))
print("Host comparison limits:", summary.get("host_comparison_limited_count"))
print("check_hot_path_profile_report: PASS")
PY
