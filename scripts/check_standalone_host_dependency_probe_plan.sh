#!/usr/bin/env bash
# check_standalone_host_dependency_probe_plan.sh -- CI gate for bd-b92jd.1.1
#
# Validates the static probe plan that separates L0/L1 interpose evidence from
# L2/L3 standalone replacement evidence. The gate writes a JSON report and JSONL
# rows for downstream claim-control checks without requiring a release build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN="${FRANKENLIBC_STANDALONE_HOST_DEP_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_HOST_DEP_REPORT:-${OUT_DIR}/standalone_host_dependency_probe_plan.report.json}"
LOG="${FRANKENLIBC_STANDALONE_HOST_DEP_LOG:-${OUT_DIR}/standalone_host_dependency_probe_plan.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${PLAN}" "${REPORT}" "${LOG}" <<'PY'
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1]).resolve()
plan_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
if not plan_path.is_absolute():
    plan_path = root / plan_path
if not report_path.is_absolute():
    report_path = root / report_path
if not log_path.is_absolute():
    log_path = root / log_path

BEAD_ID = "bd-b92jd.1.1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "probe_id",
    "probe_type",
    "replacement_level",
    "evidence_boundary",
    "tool",
    "command",
    "expected",
    "actual_decision",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_PROBE_TYPES = {
    "l0_interpose_reference",
    "replace_artifact_presence",
    "dynamic_dependency_readelf",
    "ldd_host_glibc_scan",
    "undefined_symbol_nm",
    "version_script_export_nodes",
    "support_matrix_status_join",
    "replacement_profile_allowlist_join",
    "crt_startup_contract",
    "tls_init_destructor_contract",
    "atexit_on_exit_contract",
    "errno_tls_isolation_contract",
    "artifact_freshness",
    "negative_claim_control",
}
REQUIRED_PROBE_FIELDS = [
    "probe_id",
    "probe_type",
    "title",
    "replacement_level",
    "evidence_boundary",
    "tool",
    "command_argv",
    "input_artifacts",
    "target_artifacts",
    "expected",
    "current_status",
    "expected_decision",
    "actual_decision",
    "failure_signature",
    "blocks_promotion_to",
    "artifact_refs",
]
REQUIRED_FORGE_PROJECTION_FIELDS = {
    "claim_status",
    "source_commit",
    "artifact_state.status",
    "artifact_state.failure_signature",
    "artifact_state.host_glibc_dependency",
    "artifact_state.path",
    "artifact_state.sha256",
    "artifact_state.mtime",
    "artifact_state.dependency_breakdown.needed_libraries",
    "artifact_state.dependency_breakdown.host_direct_needed_libraries",
    "artifact_state.dependency_breakdown.host_resolved_libraries",
    "artifact_state.dependency_breakdown.undefined_unwind_symbols",
    "artifact_state.dependency_breakdown.undefined_glibc_symbols",
    "artifact_state.dependency_breakdown.undefined_tls_symbols",
    "artifact_state.dependency_breakdown.version_needs",
    "artifact_state.dependency_breakdown.host_version_requirements",
    "artifact_state.dependency_breakdown.blocking_reasons",
    "artifact_state.dependency_breakdown.blocker_catalog",
}
REQUIRED_FORGE_BLOCKING_REASON_TO_PROBE = {
    "host_needed_libraries_present": "readelf_dynamic_dependencies",
    "host_direct_needed_libraries_present": "readelf_dynamic_dependencies",
    "host_resolved_libraries_present": "ldd_host_glibc_scan",
    "host_loader_dependency": "ldd_host_glibc_scan",
    "host_libc_dependency": "ldd_host_glibc_scan",
    "libgcc_runtime_dependency": "readelf_dynamic_dependencies",
    "undefined_unwind_symbols": "nm_undefined_host_symbols",
    "undefined_glibc_symbols": "nm_undefined_host_symbols",
    "undefined_tls_symbols": "nm_undefined_host_symbols",
    "host_version_requirements": "version_script_export_nodes",
}
REQUIRED_FORGE_FAILURE_SIGNATURE_TO_NEGATIVE_TEST = {
    "standalone_artifact_missing": "missing_replace_artifact",
    "standalone_artifact_stale": "stale_source_commit",
    "host_glibc_dependency": "residual_host_glibc_dependency",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_host_dependency_probe_evidence",
    "host_dependency_probe_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_source_commit",
}
REQUIRED_BLOCKER_CATALOG_ROW_FIELDS = {
    "owner_surface",
    "severity",
    "evidence_fields",
    "next_action",
}
ALLOWED_LEVELS = {"L0", "L1", "L2", "L3"}
errors = []
log_rows = []


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


def is_hex_commit(value):
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def rel(path):
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def repo_path(ref, context, *, must_exist):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: artifact ref must be a non-empty string")
        return None
    path = Path(ref)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: artifact ref must stay repo-relative: {ref}")
        return None
    absolute = root / path
    if must_exist and not absolute.exists():
        errors.append(f"{context}: artifact ref does not exist: {ref}")
    return absolute


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


source_commit = current_commit()
plan_source_commit = ""
target_dir = os.environ.get("CARGO_TARGET_DIR", str(root / "target"))
plan = load_json(plan_path)
if not isinstance(plan, dict):
    plan = {}

if plan.get("schema_version") != "v1" or plan.get("bead") != BEAD_ID:
    errors.append("plan must declare schema_version=v1 and bead=bd-b92jd.1.1")
if not is_hex_commit(plan.get("source_commit")):
    errors.append("plan source_commit must be a 40-hex commit")
else:
    plan_source_commit = plan["source_commit"]
if plan.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match the standalone host dependency stale-source block contract")
if plan.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    errors.append("required_log_fields must match standalone host dependency log contract")

declared_probe_types = set(plan.get("required_probe_types", []))
if declared_probe_types != REQUIRED_PROBE_TYPES:
    errors.append(
        "required_probe_types mismatch: missing="
        + ",".join(sorted(REQUIRED_PROBE_TYPES - declared_probe_types))
        + " extra="
        + ",".join(sorted(declared_probe_types - REQUIRED_PROBE_TYPES))
    )

tool_requirements = plan.get("tool_requirements", [])
tool_names = {entry.get("tool") for entry in tool_requirements if isinstance(entry, dict)}
for required_tool in ["readelf", "ldd", "nm"]:
    if required_tool not in tool_names:
        errors.append(f"tool_requirements must include {required_tool}")

for key in [
    "support_matrix",
    "replacement_levels",
    "standalone_replacement_artifact",
    "replacement_profile",
    "host_dependency_inventory",
    "standalone_readiness_matrix",
    "l1_startup_tls_matrix",
    "version_script",
]:
    ref = plan.get("inputs", {}).get(key)
    repo_path(ref, f"inputs.{key}", must_exist=True)

standalone_artifact_ref = plan.get("inputs", {}).get("standalone_replacement_artifact")
standalone_artifact_path = repo_path(
    standalone_artifact_ref,
    "inputs.standalone_replacement_artifact",
    must_exist=True,
)
standalone_artifact_manifest = (
    load_json(standalone_artifact_path) if standalone_artifact_path else {}
)
standalone_required_report_fields = set(
    field
    for field in standalone_artifact_manifest.get("required_report_fields", [])
    if isinstance(field, str)
)
standalone_failure_signatures = set(
    entry.get("failure_signature")
    for entry in standalone_artifact_manifest.get("expected_failure_classifications", [])
    if isinstance(entry, dict)
)
standalone_blocker_catalog_contract = standalone_artifact_manifest.get("blocker_catalog_contract", {})
standalone_blocker_catalog_definitions = {}
if not isinstance(standalone_blocker_catalog_contract, dict):
    errors.append("standalone artifact blocker_catalog_contract must be an object")
else:
    required_catalog_fields = standalone_blocker_catalog_contract.get("required_row_fields")
    if (
        not isinstance(required_catalog_fields, list)
        or set(required_catalog_fields) != REQUIRED_BLOCKER_CATALOG_ROW_FIELDS
    ):
        errors.append("standalone artifact blocker_catalog_contract.required_row_fields mismatch")
    definitions = standalone_blocker_catalog_contract.get("definitions", {})
    if not isinstance(definitions, dict) or not definitions:
        errors.append("standalone artifact blocker_catalog_contract.definitions must be a non-empty object")
    else:
        standalone_blocker_catalog_definitions = definitions

negative_tests = plan.get("negative_claim_tests", [])
negative_signatures = set()
negative_test_ids = set()
if not isinstance(negative_tests, list) or len(negative_tests) < 5:
    errors.append("negative_claim_tests must include at least five fail-closed cases")
else:
    for test in negative_tests:
        if not isinstance(test, dict):
            errors.append("negative_claim_tests entries must be objects")
            continue
        test_id = test.get("id", "<missing>")
        if isinstance(test_id, str) and test_id:
            negative_test_ids.add(test_id)
        if test.get("expected_result") != "claim_blocked":
            errors.append(f"{test_id}: negative test must expect claim_blocked")
        signature = test.get("failure_signature")
        if not isinstance(signature, str) or not signature:
            errors.append(f"{test_id}: negative test must include failure_signature")
        else:
            negative_signatures.add(signature)
for required_signature in [
    "replace_artifact_missing",
    "source_commit_stale",
    "host_glibc_dependency_present",
    "startup_tls_obligation_missing",
    "replace_claim_conflict",
]:
    if required_signature not in negative_signatures:
        errors.append(f"negative_claim_tests missing {required_signature}")

probe_rows = plan.get("probe_rows", [])
seen_probe_ids = set()
probe_types_seen = Counter()
decision_counts = Counter()
tool_counts = Counter()
l2_l3_blocker_count = 0

if not isinstance(probe_rows, list) or not probe_rows:
    errors.append("probe_rows must be a non-empty array")
    probe_rows = []

for row in probe_rows:
    if not isinstance(row, dict):
        errors.append("probe row must be an object")
        continue
    probe_id = row.get("probe_id", "<missing>")
    for field in REQUIRED_PROBE_FIELDS:
        if field not in row:
            errors.append(f"{probe_id}: missing field {field}")

    if probe_id in seen_probe_ids:
        errors.append(f"{probe_id}: duplicate probe_id")
    seen_probe_ids.add(probe_id)

    probe_type = row.get("probe_type")
    if probe_type not in REQUIRED_PROBE_TYPES:
        errors.append(f"{probe_id}: unknown probe_type {probe_type}")
    else:
        probe_types_seen[probe_type] += 1

    levels = {
        level.strip()
        for level in str(row.get("replacement_level", "")).split(",")
        if level.strip()
    }
    if not levels or not levels <= ALLOWED_LEVELS:
        errors.append(f"{probe_id}: replacement_level must use L0,L1,L2,L3")

    command = row.get("command_argv")
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        errors.append(f"{probe_id}: command_argv must be a non-empty string array")

    tool = row.get("tool")
    if not isinstance(tool, str) or not tool:
        errors.append(f"{probe_id}: tool must be a non-empty string")
    else:
        tool_counts[tool] += 1
        if tool in {"readelf", "ldd", "nm"} and command and command[0] != tool:
            errors.append(f"{probe_id}: {tool} probe command must start with {tool}")

    for ref in row.get("input_artifacts", []):
        repo_path(ref, f"{probe_id}.input_artifacts", must_exist=True)
    for ref in row.get("artifact_refs", []):
        repo_path(ref, f"{probe_id}.artifact_refs", must_exist=True)

    target_artifacts = row.get("target_artifacts", [])
    if not isinstance(target_artifacts, list):
        errors.append(f"{probe_id}: target_artifacts must be an array")
        target_artifacts = []
    target_artifacts_exist = True
    for ref in target_artifacts:
        target_path = repo_path(ref, f"{probe_id}.target_artifacts", must_exist=False)
        if target_path is not None and not target_path.exists():
            target_artifacts_exist = False

    expected_decision = row.get("expected_decision")
    actual_decision = row.get("actual_decision")
    decision_counts[actual_decision] += 1
    if expected_decision != actual_decision:
        errors.append(f"{probe_id}: expected_decision and actual_decision conflict")

    has_replace_level = bool(levels & {"L2", "L3"})
    if has_replace_level and actual_decision == "claim_blocked":
        l2_l3_blocker_count += 1
    if has_replace_level and row.get("current_status") == "blocked" and actual_decision != "claim_blocked":
        errors.append(f"{probe_id}: blocked L2/L3 probe must remain claim_blocked")
    if has_replace_level and actual_decision != "claim_blocked" and not target_artifacts_exist:
        errors.append(f"{probe_id}: L2/L3 pass row requires materialized target artifacts")
    if has_replace_level and actual_decision == "claim_blocked" and not row.get("blocks_promotion_to"):
        errors.append(f"{probe_id}: claim_blocked replacement probe must list blocked levels")
    if actual_decision == "claim_blocked" and row.get("failure_signature") in {"", "none", None}:
        errors.append(f"{probe_id}: claim_blocked probe must include a failure_signature")

    artifact_refs = list(row.get("artifact_refs", []))
    artifact_refs.extend([rel(report_path), rel(log_path)])
    log_row = {
        "trace_id": f"{BEAD_ID}::{probe_id}",
        "bead_id": BEAD_ID,
        "probe_id": probe_id,
        "probe_type": probe_type,
        "replacement_level": row.get("replacement_level"),
        "evidence_boundary": row.get("evidence_boundary"),
        "tool": tool,
        "command": command,
        "expected": row.get("expected"),
        "actual_decision": actual_decision,
        "source_commit": source_commit,
        "target_dir": target_dir,
        "artifact_refs": artifact_refs,
        "failure_signature": row.get("failure_signature"),
        "current_status": row.get("current_status"),
        "blocks_promotion_to": row.get("blocks_promotion_to", []),
    }
    missing_log_fields = [field for field in REQUIRED_LOG_FIELDS if field not in log_row]
    if missing_log_fields:
        errors.append(f"{probe_id}: log row missing {missing_log_fields}")
    log_rows.append(log_row)

missing_probe_types = sorted(REQUIRED_PROBE_TYPES - set(probe_types_seen))
if missing_probe_types:
    errors.append("missing probe type rows: " + ", ".join(missing_probe_types))

projection = plan.get("current_forge_blocker_projection")
forge_projection_field_count = 0
forge_projection_blocking_reason_count = 0
forge_projection_blocker_catalog_row_count = 0
forge_projection_failure_signature_count = 0
if not isinstance(projection, dict):
    errors.append("current_forge_blocker_projection must be an object")
else:
    if projection.get("source_artifact") != standalone_artifact_ref:
        errors.append(
            "current_forge_blocker_projection.source_artifact must match inputs.standalone_replacement_artifact"
        )
    if projection.get("decision") != "projection_only_claims_remain_blocked":
        errors.append("current_forge_blocker_projection.decision must remain projection_only_claims_remain_blocked")

    projected_fields = projection.get("projected_report_fields", [])
    if not isinstance(projected_fields, list) or not projected_fields:
        errors.append("current_forge_blocker_projection.projected_report_fields must be a non-empty array")
        projected_fields = []
    projected_field_set = set()
    for field in projected_fields:
        if not isinstance(field, str) or not field:
            errors.append("current_forge_blocker_projection.projected_report_fields entries must be strings")
            continue
        projected_field_set.add(field)
        if field not in standalone_required_report_fields:
            errors.append(
                f"current_forge_blocker_projection.projected_report_fields unknown standalone report field: {field}"
            )
    missing_projected_fields = sorted(REQUIRED_FORGE_PROJECTION_FIELDS - projected_field_set)
    if missing_projected_fields:
        errors.append(
            "current_forge_blocker_projection.projected_report_fields missing "
            + ",".join(missing_projected_fields)
        )
    forge_projection_field_count = len(projected_field_set)

    reason_map = projection.get("blocking_reason_to_probe_id", {})
    if not isinstance(reason_map, dict) or not reason_map:
        errors.append("current_forge_blocker_projection.blocking_reason_to_probe_id must be a non-empty object")
        reason_map = {}
    for reason, expected_probe_id in REQUIRED_FORGE_BLOCKING_REASON_TO_PROBE.items():
        actual_probe_id = reason_map.get(reason)
        if actual_probe_id is None:
            errors.append(f"current_forge_blocker_projection.blocking_reason_to_probe_id missing {reason}")
        elif actual_probe_id != expected_probe_id:
            errors.append(
                f"current_forge_blocker_projection.blocking_reason_to_probe_id.{reason} must map to {expected_probe_id}"
            )
    for reason, probe_id in reason_map.items():
        if reason not in REQUIRED_FORGE_BLOCKING_REASON_TO_PROBE:
            errors.append(f"current_forge_blocker_projection.blocking_reason_to_probe_id has unexpected reason {reason}")
        if probe_id not in seen_probe_ids:
            errors.append(
                f"current_forge_blocker_projection.blocking_reason_to_probe_id.{reason} references unknown probe {probe_id}"
            )
    forge_projection_blocking_reason_count = len(reason_map)

    catalog_rows = projection.get("blocker_catalog_required_rows", {})
    if not isinstance(catalog_rows, dict) or not catalog_rows:
        errors.append("current_forge_blocker_projection.blocker_catalog_required_rows must be a non-empty object")
        catalog_rows = {}
    for reason in REQUIRED_FORGE_BLOCKING_REASON_TO_PROBE:
        row = catalog_rows.get(reason)
        if row is None:
            errors.append(f"current_forge_blocker_projection.blocker_catalog_required_rows missing {reason}")
            continue
        if not isinstance(row, dict):
            errors.append(f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason} must be an object")
            continue
        missing_fields = sorted(REQUIRED_BLOCKER_CATALOG_ROW_FIELDS - set(row))
        if missing_fields:
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason} missing "
                + ",".join(missing_fields)
            )
        owner_surface = row.get("owner_surface")
        if not isinstance(owner_surface, str) or not owner_surface:
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason}.owner_surface must be non-empty"
            )
        if row.get("severity") != "claim_blocking":
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason}.severity must be claim_blocking"
            )
        evidence_fields = row.get("evidence_fields")
        if (
            not isinstance(evidence_fields, list)
            or not evidence_fields
            or not all(isinstance(field, str) and field for field in evidence_fields)
        ):
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason}.evidence_fields must be non-empty strings"
            )
        next_action = row.get("next_action")
        if not isinstance(next_action, str) or not next_action:
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason}.next_action must be non-empty"
            )
        expected_row = standalone_blocker_catalog_definitions.get(reason)
        if not isinstance(expected_row, dict):
            errors.append(
                f"standalone artifact blocker_catalog_contract.definitions missing {reason}"
            )
        elif row != expected_row:
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows.{reason} does not match standalone manifest contract"
            )
    for reason in catalog_rows:
        if reason not in reason_map:
            errors.append(
                f"current_forge_blocker_projection.blocker_catalog_required_rows has unexpected reason {reason}"
            )
    forge_projection_blocker_catalog_row_count = len(catalog_rows)

    failure_map = projection.get("failure_signature_to_negative_test", {})
    if not isinstance(failure_map, dict) or not failure_map:
        errors.append("current_forge_blocker_projection.failure_signature_to_negative_test must be a non-empty object")
        failure_map = {}
    for signature, expected_test_id in REQUIRED_FORGE_FAILURE_SIGNATURE_TO_NEGATIVE_TEST.items():
        actual_test_id = failure_map.get(signature)
        if actual_test_id is None:
            errors.append(
                f"current_forge_blocker_projection.failure_signature_to_negative_test missing {signature}"
            )
        elif actual_test_id != expected_test_id:
            errors.append(
                f"current_forge_blocker_projection.failure_signature_to_negative_test.{signature} must map to {expected_test_id}"
            )
    for signature, test_id in failure_map.items():
        if signature not in standalone_failure_signatures:
            errors.append(
                f"current_forge_blocker_projection.failure_signature_to_negative_test unknown standalone failure {signature}"
            )
        if test_id not in negative_test_ids:
            errors.append(
                f"current_forge_blocker_projection.failure_signature_to_negative_test.{signature} references unknown negative test {test_id}"
            )
    forge_projection_failure_signature_count = len(failure_map)

summary = {
    "probe_count": len(probe_rows),
    "required_probe_type_count": len(REQUIRED_PROBE_TYPES),
    "claim_blocked_count": decision_counts.get("claim_blocked", 0),
    "l2_l3_blocker_count": l2_l3_blocker_count,
    "negative_claim_test_count": len(negative_tests) if isinstance(negative_tests, list) else 0,
    "forge_projection_field_count": forge_projection_field_count,
    "forge_projection_blocking_reason_count": forge_projection_blocking_reason_count,
    "forge_projection_blocker_catalog_row_count": forge_projection_blocker_catalog_row_count,
    "forge_projection_failure_signature_count": forge_projection_failure_signature_count,
    "tool_count": len(tool_counts),
    "probe_counts_by_type": dict(sorted(probe_types_seen.items())),
    "decision_counts": dict(sorted((str(key), value) for key, value in decision_counts.items())),
    "tool_counts": dict(sorted(tool_counts.items())),
}

declared_summary = plan.get("summary", {})
for key in [
    "probe_count",
    "required_probe_type_count",
    "claim_blocked_count",
    "l2_l3_blocker_count",
    "negative_claim_test_count",
    "forge_projection_field_count",
    "forge_projection_blocking_reason_count",
    "forge_projection_blocker_catalog_row_count",
    "forge_projection_failure_signature_count",
    "tool_count",
]:
    if declared_summary.get(key) != summary[key]:
        errors.append(f"summary.{key} must be {summary[key]}; found {declared_summary.get(key)}")

log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": "pass" if not errors else "fail",
    "errors": errors,
    "plan": rel(plan_path),
    "plan_source_commit": plan_source_commit,
    "source_commit": source_commit,
    "source_commit_freshness": {
        "status": "current" if plan_source_commit == source_commit else "stale",
        "recorded_source_commit_field": EXPECTED_FRESHNESS_POLICY["recorded_source_commit_field"],
        "comparison_target": EXPECTED_FRESHNESS_POLICY["comparison_target"],
        "stale_result": EXPECTED_FRESHNESS_POLICY["stale_result"],
        "host_dependency_probe_evidence_allowed_when_stale": EXPECTED_FRESHNESS_POLICY[
            "host_dependency_probe_evidence_allowed_when_stale"
        ],
        "rejected_evidence_kind": EXPECTED_FRESHNESS_POLICY["rejected_evidence_kind"],
    },
    "target_dir": target_dir,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "summary": summary,
    "required_log_fields": REQUIRED_LOG_FIELDS,
    "artifact_refs": [
        rel(plan_path),
        "scripts/check_standalone_host_dependency_probe_plan.sh",
        rel(report_path),
        rel(log_path),
    ],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
