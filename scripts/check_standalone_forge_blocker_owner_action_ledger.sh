#!/usr/bin/env bash
# check_standalone_forge_blocker_owner_action_ledger.sh -- CI gate for bd-zyck1.93
#
# Validates that every current standalone forge blocking reason has an owner,
# source surface, evidence command, negative control, and first safe action.
# Resolved reasons may remain as catalog history, but their current blocker
# values must be empty so stale values cannot masquerade as live evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="${FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER:-${ROOT}/tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json}"
PLAN="${FRANKENLIBC_STANDALONE_HOST_DEP_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER_REPORT:-${OUT_DIR}/standalone_forge_blocker_owner_action_ledger.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${LEDGER}" "${PLAN}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1]).resolve()
ledger_path = Path(sys.argv[2])
plan_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
if not ledger_path.is_absolute():
    ledger_path = root / ledger_path
if not plan_path.is_absolute():
    plan_path = root / plan_path
if not report_path.is_absolute():
    report_path = root / report_path

BEAD_ID = "bd-zyck1.93"
REQUIRED_ROW_FIELDS = {
    "blocking_reason",
    "owner_surface",
    "catalog_owner_surface",
    "primary_probe_id",
    "primary_evidence_command",
    "negative_control_test",
    "likely_code_config_files",
    "validation_path",
    "first_safe_action",
    "exit_criteria",
    "current_blocker_values",
}
REQUIRED_OWNER_SURFACES = {
    "runtime_linkage",
    "direct_dynamic_dependencies",
    "loader_resolution",
    "loader_startup",
    "libc_surface",
    "compiler_runtime",
    "unwind_runtime",
    "tls_startup",
    "glibc_symbol_surface",
    "symbol_versioning",
}
EXPECTED_INPUTS = {
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
    "standalone_replacement_artifact": "tests/conformance/standalone_replacement_artifact.v1.json",
    "standalone_readiness_matrix": "tests/conformance/standalone_readiness_proof_matrix.v1.json",
    "standalone_link_run_smoke": "tests/conformance/standalone_link_run_smoke.v1.json",
    "l1_crt_startup_tls_matrix": "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json",
    "version_script": "crates/frankenlibc-abi/version_scripts/libc.map",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_owner_action_ledger_evidence",
    "owner_action_ledger_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_owner_action_ledger",
}
EXPECTED_COVERAGE_POLICY = {
    "source_snapshot": (
        "tests/conformance/standalone_host_dependency_probe_plan.v1.json#"
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot.blocking_reasons"
    ),
    "expected_current_blocking_reason_count": 0,
    "row_key": "blocking_reason",
    "missing_blocker_row_result": "fail_closed",
    "extra_blocker_row_result": "allowed_when_cataloged_historical",
    "missing_owner_surface_result": "fail_closed",
    "missing_validation_path_result": "fail_closed",
    "missing_first_safe_action_result": "fail_closed",
    "promotion_allowed": False,
}
errors = []


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


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


def source_commit_marker_is_current(value, head):
    return value == "current" or (head != "unknown" and value == head)


def repo_path(ref, context, *, must_exist=True):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: path must be a non-empty string")
        return None
    path = Path(ref)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: path must stay repo-relative: {ref}")
        return None
    absolute = root / path
    if must_exist and not absolute.exists():
        errors.append(f"{context}: path does not exist: {ref}")
    return absolute


def string_list(value, context, *, min_len=1):
    if not isinstance(value, list) or len(value) < min_len:
        errors.append(f"{context}: must be a list with at least {min_len} entries")
        return []
    result = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{idx}]: must be a non-empty string")
        else:
            result.append(item)
    return result


def object_value(value, context):
    if not isinstance(value, dict):
        errors.append(f"{context}: must be an object")
        return {}
    return value


head = current_commit()
ledger = load_json(ledger_path)
plan = load_json(plan_path)
if not isinstance(ledger, dict):
    ledger = {}
if not isinstance(plan, dict):
    plan = {}

if ledger.get("schema_version") != "v1" or ledger.get("bead") != BEAD_ID:
    errors.append("ledger must declare schema_version=v1 and bead=bd-zyck1.93")
if ledger.get("manifest_id") != "standalone_forge_blocker_owner_action_ledger":
    errors.append("manifest_id must be standalone_forge_blocker_owner_action_ledger")
source_commit = ledger.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("ledger source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("ledger source_commit must be 'current' or match current git HEAD")
if ledger.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match owner-action stale-source contract")
if ledger.get("coverage_policy") != EXPECTED_COVERAGE_POLICY:
    errors.append("coverage_policy must match fail-closed owner-action coverage contract")

inputs = object_value(ledger.get("inputs"), "inputs")
if inputs != EXPECTED_INPUTS:
    errors.append("inputs must match the standalone blocker owner-action input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(inputs.get(key), f"inputs.{key}", must_exist=True)

declared_row_fields = set(string_list(ledger.get("required_row_fields"), "required_row_fields"))
if declared_row_fields != REQUIRED_ROW_FIELDS:
    errors.append("required_row_fields mismatch")
declared_owner_surfaces = set(string_list(ledger.get("required_owner_surfaces"), "required_owner_surfaces"))
if declared_owner_surfaces != REQUIRED_OWNER_SURFACES:
    errors.append("required_owner_surfaces mismatch")

projection = object_value(plan.get("current_forge_blocker_projection"), "plan.current_forge_blocker_projection")
snapshot = object_value(
    projection.get("current_forge_blocker_value_snapshot"),
    "plan.current_forge_blocker_projection.current_forge_blocker_value_snapshot",
)
current_reasons = string_list(
    snapshot.get("blocking_reasons"),
    "current_forge_blocker_value_snapshot.blocking_reasons",
    min_len=EXPECTED_COVERAGE_POLICY["expected_current_blocking_reason_count"],
)
reason_set = set(current_reasons)
if len(reason_set) != EXPECTED_COVERAGE_POLICY["expected_current_blocking_reason_count"]:
    errors.append(
        "current forge snapshot unique blocking reason count must match coverage_policy"
    )

reason_to_probe = object_value(projection.get("blocking_reason_to_probe_id"), "blocking_reason_to_probe_id")
catalog = object_value(projection.get("blocker_catalog_required_rows"), "blocker_catalog_required_rows")
negative_test_ids = {
    entry.get("id")
    for entry in plan.get("negative_claim_tests", [])
    if isinstance(entry, dict) and isinstance(entry.get("id"), str)
}
probe_rows = {
    row.get("probe_id"): row
    for row in plan.get("probe_rows", [])
    if isinstance(row, dict) and isinstance(row.get("probe_id"), str)
}

owner_paths = object_value(ledger.get("owner_surface_validation_paths"), "owner_surface_validation_paths")
for owner in sorted(REQUIRED_OWNER_SURFACES):
    path = object_value(owner_paths.get(owner), f"owner_surface_validation_paths.{owner}")
    string_list(path.get("primary_command"), f"owner_surface_validation_paths.{owner}.primary_command")
    string_list(path.get("required_report_fields"), f"owner_surface_validation_paths.{owner}.required_report_fields")

rows = ledger.get("ledger_rows")
if not isinstance(rows, list):
    errors.append("ledger_rows must be an array")
    rows = []
row_by_reason = {}
owner_counts = Counter()
for index, row in enumerate(rows):
    if not isinstance(row, dict):
        errors.append(f"ledger_rows[{index}]: must be an object")
        continue
    reason = row.get("blocking_reason")
    context = f"ledger_rows[{reason or index}]"
    missing_fields = REQUIRED_ROW_FIELDS - set(row)
    for field in sorted(missing_fields):
        errors.append(f"{context}: missing field {field}")
    if not isinstance(reason, str) or not reason:
        errors.append(f"{context}: blocking_reason must be a non-empty string")
        continue
    if reason in row_by_reason:
        errors.append(f"ledger_rows: duplicate blocking_reason {reason}")
    row_by_reason[reason] = row
    owner = row.get("owner_surface")
    if not isinstance(owner, str) or not owner:
        errors.append(f"{context}.owner_surface: must be a non-empty string")
    elif owner not in REQUIRED_OWNER_SURFACES:
        errors.append(f"{context}.owner_surface: unknown owner surface {owner}")
    else:
        owner_counts[owner] += 1

    catalog_owner = row.get("catalog_owner_surface")
    expected_catalog = catalog.get(reason, {}) if isinstance(catalog, dict) else {}
    if not expected_catalog:
        errors.append(f"{context}: reason is neither current nor cataloged historical blocker")
    expected_catalog_owner = expected_catalog.get("owner_surface") if isinstance(expected_catalog, dict) else None
    if catalog_owner != expected_catalog_owner:
        errors.append(f"{context}.catalog_owner_surface must match blocker catalog owner {expected_catalog_owner}")
    if owner != expected_catalog_owner:
        errors.append(f"{context}.owner_surface must match live action-row owner {expected_catalog_owner}")

    expected_probe = reason_to_probe.get(reason) if isinstance(reason_to_probe, dict) else None
    if row.get("primary_probe_id") != expected_probe:
        errors.append(f"{context}.primary_probe_id must map to {expected_probe}")
    probe = probe_rows.get(row.get("primary_probe_id"), {})
    expected_command = probe.get("command_argv") if isinstance(probe, dict) else None
    if row.get("primary_evidence_command") != expected_command:
        errors.append(f"{context}.primary_evidence_command must match probe command_argv")

    if row.get("negative_control_test") not in negative_test_ids:
        errors.append(f"{context}.negative_control_test must reference a plan negative_claim_tests id")
    for path_ref in string_list(row.get("likely_code_config_files"), f"{context}.likely_code_config_files"):
        repo_path(path_ref, f"{context}.likely_code_config_files", must_exist=True)
    validation_path = object_value(row.get("validation_path"), f"{context}.validation_path")
    string_list(validation_path.get("command"), f"{context}.validation_path.command")
    if validation_path.get("negative_control") != row.get("negative_control_test"):
        errors.append(f"{context}.validation_path.negative_control must match negative_control_test")
    if validation_path.get("expected_blocking_reason_absent") != reason:
        errors.append(f"{context}.validation_path.expected_blocking_reason_absent must match blocking_reason")
    if not isinstance(row.get("first_safe_action"), str) or not row.get("first_safe_action"):
        errors.append(f"{context}.first_safe_action must be a non-empty string")
    string_list(row.get("exit_criteria"), f"{context}.exit_criteria")
    current_blocker_values = string_list(
        row.get("current_blocker_values"),
        f"{context}.current_blocker_values",
        min_len=1 if reason in reason_set else 0,
    )
    if reason not in reason_set and current_blocker_values:
        errors.append(f"{context}.current_blocker_values must be empty for resolved blockers")

for reason in sorted(reason_set - set(row_by_reason)):
    errors.append(f"ledger_rows missing current forge blocker reason {reason}")
for owner in sorted(REQUIRED_OWNER_SURFACES - set(owner_counts)):
    errors.append(f"required owner surface has no ledger row: {owner}")

summary = object_value(ledger.get("summary"), "summary")
if summary.get("current_blocking_reason_count") != len(reason_set):
    errors.append("summary.current_blocking_reason_count mismatch")
if summary.get("ledger_row_count") != len(rows):
    errors.append("summary.ledger_row_count mismatch")
if summary.get("required_owner_surface_count") != len(REQUIRED_OWNER_SURFACES):
    errors.append("summary.required_owner_surface_count mismatch")
if summary.get("promotion_allowed") is not False:
    errors.append("summary.promotion_allowed must be false")
if summary.get("next_consumer") != "bd-zyck1.94":
    errors.append("summary.next_consumer must be bd-zyck1.94")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "current_blocking_reason_count": len(reason_set),
    "ledger_row_count": len(rows),
    "owner_surface_counts": dict(sorted(owner_counts.items())),
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
