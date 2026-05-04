#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${USER_ENVIRONMENT_COVERAGE_MATRIX:-$ROOT/tests/conformance/user_environment_coverage_matrix.v1.json}"
REPORT="${USER_ENVIRONMENT_COVERAGE_REPORT:-$ROOT/target/conformance/user_environment_coverage_matrix.report.json}"
LOG="${USER_ENVIRONMENT_COVERAGE_LOG:-$ROOT/target/conformance/user_environment_coverage_matrix.log.jsonl}"

python3 - "$ROOT" "$MATRIX" "$REPORT" "$LOG" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

errors = []
failure_signatures = []

REQUIRED_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "environment_id",
    "workload_id",
    "architecture",
    "runtime_mode",
    "replacement_level",
    "scenario_id",
    "expected",
    "actual",
    "errno",
    "status",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "reason_code",
    "failure_signature",
}


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def load_json(path, signature):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"{path}: {exc}", signature)
        return None


def rel(path):
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(path_text):
    return root / path_text


def current_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


matrix = load_json(matrix_path, "environment_matrix_unreadable")
if matrix is None:
    sys.exit(1)

if matrix.get("schema_version") != "v1" or matrix.get("bead") != "bd-bp8fl.10.7":
    fail("matrix must declare schema_version=v1 and bead=bd-bp8fl.10.7", "environment_matrix_bad_schema")

inputs = matrix.get("inputs", {})
workload_matrix = load_json(repo_path(inputs.get("workload_matrix", "")), "environment_matrix_missing_workload_matrix") if inputs.get("workload_matrix") else None
replacement_levels = load_json(repo_path(inputs.get("replacement_levels", "")), "environment_matrix_missing_replacement_levels") if inputs.get("replacement_levels") else None
for input_path in inputs.values():
    if not repo_path(input_path).is_file():
        fail(f"missing input artifact: {input_path}", "environment_matrix_missing_input")

workload_ids = {row.get("id") for row in workload_matrix.get("workloads", [])} if workload_matrix else set()
replacement_ids = {level.get("level") for level in replacement_levels.get("levels", [])} if replacement_levels else set()
reason_codes = {reason.get("id"): reason for reason in matrix.get("reason_codes", [])}
state_values = set(matrix.get("state_values", []))
evidence_states = set(matrix.get("evidence_states", []))
required_row_fields = set(matrix.get("required_row_fields", []))
required_log_fields = set(matrix.get("required_log_fields", []))

missing_log_fields = sorted(REQUIRED_LOG_FIELDS - required_log_fields)
if missing_log_fields:
    fail(f"required_log_fields missing {missing_log_fields}", "environment_matrix_log_contract_missing")

source_commit = current_commit()
freshness = matrix.get("freshness_policy", {})
expected_commit = freshness.get("source_commit")
if expected_commit not in {"current", source_commit}:
    fail(
        f"freshness_policy.source_commit={expected_commit!r} is not current {source_commit}",
        freshness.get("stale_failure_signature", "environment_matrix_stale_source_commit"),
    )

rows = matrix.get("rows", [])
if not isinstance(rows, list) or not rows:
    fail("rows must be a non-empty list", "environment_matrix_missing_rows")
    rows = []

architectures = set()
runtime_modes = set()
replacement_levels_seen = set()
states = set()
evidence_seen = set()
workloads_seen = set()
logs = []

pattern_hits = {
    "x86_64_l0_strict": False,
    "x86_64_l0_hardened": False,
    "aarch64_blocked_or_bringup": False,
    "resolver_online": False,
    "resolver_offline": False,
    "locale_variant": False,
    "filesystem_permission": False,
    "threaded_workload": False,
    "debug_profile": False,
}

claim_blocked_count = 0
flaky_count = 0
skipped_evidence_count = 0
stale_count = 0
unsupported_count = 0
support_claim_allowed_count = 0

for row in rows:
    environment_id = row.get("environment_id", "<missing>")
    missing_fields = sorted(field for field in required_row_fields if field not in row)
    if missing_fields:
        fail(f"{environment_id}: missing row fields {missing_fields}", "environment_matrix_row_contract_missing")

    architecture = row.get("architecture")
    runtime_mode = row.get("runtime_mode")
    replacement_level = row.get("replacement_level")
    workload_id = row.get("workload_id")
    state = row.get("state")
    evidence_state = row.get("evidence_state")
    reason_code = row.get("reason_code")
    support_status = row.get("support_status")
    support_claim_allowed = row.get("support_claim_allowed")

    architectures.add(architecture)
    runtime_modes.add(runtime_mode)
    replacement_levels_seen.add(replacement_level)
    states.add(state)
    evidence_seen.add(evidence_state)
    workloads_seen.add(workload_id)

    if workload_id not in workload_ids:
        fail(f"{environment_id}: unknown workload_id {workload_id}", "environment_matrix_unknown_workload")
    if replacement_level not in replacement_ids:
        fail(f"{environment_id}: unknown replacement_level {replacement_level}", "environment_matrix_unknown_replacement_level")
    if state not in state_values:
        fail(f"{environment_id}: invalid state {state}", "environment_matrix_invalid_state")
    if evidence_state not in evidence_states:
        fail(f"{environment_id}: invalid evidence_state {evidence_state}", "environment_matrix_invalid_evidence_state")
    if reason_code not in reason_codes:
        fail(f"{environment_id}: invalid reason_code {reason_code}", "environment_matrix_invalid_reason_code")

    if support_claim_allowed:
        support_claim_allowed_count += 1

    if row.get("status") == "claim_blocked":
        claim_blocked_count += 1
    if evidence_state == "flaky":
        flaky_count += 1
    if evidence_state == "skipped":
        skipped_evidence_count += 1
    if evidence_state == "stale":
        stale_count += 1
    if evidence_state == "unsupported":
        unsupported_count += 1

    category = reason_codes.get(reason_code, {}).get("category")
    if category in {"blocked", "flaky", "skipped", "stale", "unsupported"} and (
        support_status == "supported" or support_claim_allowed is True
    ):
        fail(f"{environment_id}: {category} row cannot merge into supported status", "environment_matrix_bad_support_merge")
    if state in {"blocked", "skipped"} and (support_status == "supported" or support_claim_allowed is True):
        fail(f"{environment_id}: {state} row cannot merge into supported status", "environment_matrix_bad_support_merge")
    if evidence_state in {"flaky", "skipped", "stale", "unsupported", "claim_blocked"} and (
        support_status == "supported" or support_claim_allowed is True
    ):
        fail(f"{environment_id}: {evidence_state} evidence cannot merge into supported status", "environment_matrix_bad_support_merge")
    if row.get("source_commit") not in {"current", source_commit} and support_status == "supported":
        fail(f"{environment_id}: stale source row cannot be supported", "environment_matrix_stale_supported_row")

    if architecture == "x86_64" and runtime_mode == "strict" and replacement_level == "L0":
        pattern_hits["x86_64_l0_strict"] = True
    if architecture == "x86_64" and runtime_mode == "hardened" and replacement_level == "L0":
        pattern_hits["x86_64_l0_hardened"] = True
    if architecture == "aarch64" and state == "blocked":
        pattern_hits["aarch64_blocked_or_bringup"] = True
    if row.get("network_state") == "online" and workload_id == "uwm-resolver-nss":
        pattern_hits["resolver_online"] = True
    if row.get("network_state") == "offline" and workload_id == "uwm-resolver-nss":
        pattern_hits["resolver_offline"] = True
    locale_values = row.get("locale_env_variables", {})
    if isinstance(locale_values, dict) and any(value == "C.UTF-8" for value in locale_values.values()):
        pattern_hits["locale_variant"] = True
    if "read_only" in str(row.get("filesystem_permission_model", "")):
        pattern_hits["filesystem_permission"] = True
    if int(row.get("thread_count", 0)) > 1 and workload_id == "uwm-threaded-service":
        pattern_hits["threaded_workload"] = True
    if row.get("build_profile") == "debug":
        pattern_hits["debug_profile"] = True

    logs.append(
        {
            "trace_id": f"bd-bp8fl.10.7::{environment_id}",
            "bead_id": "bd-bp8fl.10.7",
            "environment_id": environment_id,
            "workload_id": workload_id,
            "architecture": architecture,
            "runtime_mode": runtime_mode,
            "replacement_level": replacement_level,
            "scenario_id": row.get("scenario_id"),
            "expected": row.get("expected"),
            "actual": row.get("actual"),
            "errno": row.get("errno"),
            "status": row.get("status"),
            "latency_ns": row.get("latency_ns", 0),
            "artifact_refs": row.get("artifact_refs", []),
            "source_commit": source_commit,
            "target_dir": rel(report_path.parent),
            "reason_code": reason_code,
            "failure_signature": row.get("failure_signature"),
        }
    )

requirements = matrix.get("coverage_requirements", {})
for architecture in requirements.get("architectures", []):
    if architecture not in architectures:
        fail(f"missing architecture coverage: {architecture}", "environment_matrix_missing_architecture_coverage")
for runtime_mode in requirements.get("runtime_modes", []):
    if runtime_mode not in runtime_modes:
        fail(f"missing runtime mode coverage: {runtime_mode}", "environment_matrix_missing_runtime_mode_coverage")
for replacement_level in requirements.get("replacement_levels", []):
    if replacement_level not in replacement_levels_seen:
        fail(f"missing replacement level coverage: {replacement_level}", "environment_matrix_missing_replacement_level_coverage")
for state in requirements.get("states", []):
    if state not in states:
        fail(f"missing state coverage: {state}", "environment_matrix_missing_state_coverage")
for evidence_state in requirements.get("evidence_states", []):
    if evidence_state not in evidence_seen:
        fail(f"missing evidence state coverage: {evidence_state}", "environment_matrix_missing_evidence_state_coverage")
for pattern in requirements.get("environment_patterns", []):
    if not pattern_hits.get(pattern):
        fail(f"missing environment pattern coverage: {pattern}", "environment_matrix_missing_pattern_coverage")

summary = {
    "row_count": len(rows),
    "required_count": sum(1 for row in rows if row.get("state") == "required"),
    "blocked_count": sum(1 for row in rows if row.get("state") == "blocked"),
    "optional_count": sum(1 for row in rows if row.get("state") == "optional"),
    "skipped_count": sum(1 for row in rows if row.get("state") == "skipped"),
    "architecture_count": len(architectures),
    "workload_count": len(workloads_seen),
    "support_claim_allowed_count": support_claim_allowed_count,
    "claim_blocked_count": claim_blocked_count,
    "flaky_count": flaky_count,
    "skipped_evidence_count": skipped_evidence_count,
    "stale_count": stale_count,
    "unsupported_count": unsupported_count,
}

for key, expected_value in matrix.get("expected_current_summary", {}).items():
    if summary.get(key) != expected_value:
        fail(f"summary {key} expected {expected_value}, got {summary.get(key)}", "environment_matrix_summary_mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.7",
    "status": "pass" if not errors else "fail",
    "errors": errors,
    "failure_signatures": sorted(set(failure_signatures)),
    "source_commit": source_commit,
    "matrix_path": rel(matrix_path),
    "log_path": rel(log_path),
    "summary": summary,
    "coverage": {
        "architectures": sorted(architecture for architecture in architectures if architecture is not None),
        "runtime_modes": sorted(runtime_mode for runtime_mode in runtime_modes if runtime_mode is not None),
        "replacement_levels": sorted(level for level in replacement_levels_seen if level is not None),
        "states": sorted(state for state in states if state is not None),
        "evidence_states": sorted(state for state in evidence_seen if state is not None),
        "pattern_hits": pattern_hits,
    },
}

report_path.parent.mkdir(parents=True, exist_ok=True)
log_path.parent.mkdir(parents=True, exist_ok=True)

with report_path.open("w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")

with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))

if errors:
    sys.exit(1)
PY
