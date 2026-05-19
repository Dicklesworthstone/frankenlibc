#!/usr/bin/env bash
# check_standalone_blocker_burndown_progress_rollup.sh -- CI gate for bd-zyck1.94
#
# Validates the compact standalone blocker progress rollup and emits a report
# that materializes current values and exit criteria from source artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROLLUP="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP:-${ROOT}/tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json}"
PLAN="${FRANKENLIBC_STANDALONE_HOST_DEP_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
VERSION_BURNDOWN="${FRANKENLIBC_STANDALONE_VERSION_BURNDOWN:-${ROOT}/tests/conformance/standalone_host_version_requirement_burndown.v1.json}"
OWNER_LEDGER="${FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER:-${ROOT}/tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json}"
OWNED_UNWIND="${FRANKENLIBC_STANDALONE_OWNED_UNWIND_EXPERIMENT:-${ROOT}/tests/conformance/standalone_owned_unwind_experiment.v1.json}"
TLS_REMOVAL="${FRANKENLIBC_STANDALONE_TLS_REMOVAL_EXPERIMENT:-${ROOT}/tests/conformance/standalone_tls_removal_experiment.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_REPORT:-${OUT_DIR}/standalone_blocker_burndown_progress_rollup.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${ROLLUP}" "${PLAN}" "${VERSION_BURNDOWN}" "${OWNER_LEDGER}" "${OWNED_UNWIND}" "${TLS_REMOVAL}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

root = Path(sys.argv[1]).resolve()
rollup_path = Path(sys.argv[2])
plan_path = Path(sys.argv[3])
version_path = Path(sys.argv[4])
owner_path = Path(sys.argv[5])
owned_unwind_path = Path(sys.argv[6])
tls_removal_path = Path(sys.argv[7])
report_path = Path(sys.argv[8])
for name in ["rollup_path", "plan_path", "version_path", "owner_path", "owned_unwind_path", "tls_removal_path", "report_path"]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

BEAD_ID = "bd-zyck1.94"
EXPECTED_INPUTS = {
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
    "standalone_host_version_requirement_burndown": "tests/conformance/standalone_host_version_requirement_burndown.v1.json",
    "standalone_forge_blocker_owner_action_ledger": "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json",
    "standalone_owned_unwind_experiment": "tests/conformance/standalone_owned_unwind_experiment.v1.json",
    "standalone_tls_removal_experiment": "tests/conformance/standalone_tls_removal_experiment.v1.json",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_blocker_burndown_rollup",
    "rollup_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_standalone_blocker_burndown_rollup",
}
EXPECTED_ROLLUP_POLICY = {
    "source_of_truth": [
        "standalone_host_dependency_probe_plan.current_forge_blocker_projection.current_forge_blocker_value_snapshot",
        "standalone_host_dependency_probe_plan.current_forge_blocker_projection.blocker_action_required_rows",
        "standalone_forge_blocker_owner_action_ledger.ledger_rows",
        "standalone_host_version_requirement_burndown.version_requirement_matrix",
        "standalone_owned_unwind_experiment.summary",
        "standalone_tls_removal_experiment.summary",
    ],
    "duplicate_source_values_in_manifest": False,
    "checker_report_materializes_values": True,
    "checker_report_materializes_action_rows": True,
    "per_reason_action_row_report_fields": [
        "blocking_reason",
        "owner_surface",
        "primary_probe_id",
        "evidence_fields",
        "current_blocker_values",
        "exit_criteria",
        "promotion_allowed",
    ],
    "promotion_allowed": False,
    "claim_status_until_all_categories_exit": "claim_blocked",
    "missing_category_result": "fail_closed",
    "missing_version_provider_result": "fail_closed",
    "stale_or_partial_source_refresh_result": "fail_closed",
}
REQUIRED_ROLLUP_ROW_FIELDS = {
    "category_id",
    "owner_surfaces",
    "source_blocking_reasons",
    "current_reason_count",
    "last_known_value_count",
    "value_source",
    "exit_criteria_source",
    "status_until_exit",
}
LIVE_ACTION_VALUE_SOURCE = (
    "standalone_host_dependency_probe_plan.current_forge_blocker_projection."
    "blocker_action_required_rows.current_blocker_values"
)
LIVE_ACTION_EXIT_CRITERIA_SOURCE = (
    "standalone_host_dependency_probe_plan.current_forge_blocker_projection."
    "blocker_action_required_rows.exit_criteria"
)
REQUIRED_ACTION_ROW_REPORT_FIELDS = set(
    EXPECTED_ROLLUP_POLICY["per_reason_action_row_report_fields"]
)
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


def repo_path(ref, context):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: path must be a non-empty string")
        return
    path = Path(ref)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: path must stay repo-relative: {ref}")
        return
    if not (root / path).exists():
        errors.append(f"{context}: path does not exist: {ref}")


def matrix_requirement_id(row):
    provider = row.get("provider_library")
    version = row.get("version_node")
    if isinstance(provider, str) and isinstance(version, str):
        return f"{provider}:{version}"
    return None


def expected_live_action_values(reason, snapshot):
    if reason == "host_needed_libraries_present":
        return string_list(snapshot.get("host_needed_libraries"), "snapshot.host_needed_libraries")
    if reason == "host_direct_needed_libraries_present":
        return string_list(
            snapshot.get("host_direct_needed_libraries"),
            "snapshot.host_direct_needed_libraries",
        )
    if reason == "host_resolved_libraries_present":
        return string_list(
            snapshot.get("host_resolved_libraries"),
            "snapshot.host_resolved_libraries",
        )
    if reason == "host_loader_dependency":
        return [
            value
            for value in string_list(
                snapshot.get("host_needed_libraries"),
                "snapshot.host_needed_libraries",
            )
            if "ld-linux" in value
        ]
    if reason == "host_libc_dependency":
        return [
            value
            for value in string_list(
                snapshot.get("host_needed_libraries"),
                "snapshot.host_needed_libraries",
            )
            if "libc.so" in value
        ]
    if reason == "libgcc_runtime_dependency":
        return [
            *[
                value
                for value in string_list(
                    snapshot.get("host_needed_libraries"),
                    "snapshot.host_needed_libraries",
                )
                if "libgcc_s.so" in value
            ],
            *[
                value
                for value in string_list(
                    snapshot.get("host_version_requirements"),
                    "snapshot.host_version_requirements",
                )
                if value.startswith("libgcc_s.so")
            ],
        ]
    if reason == "undefined_unwind_symbols":
        return string_list(snapshot.get("undefined_unwind_symbols"), "snapshot.undefined_unwind_symbols")
    if reason == "undefined_glibc_symbols":
        return string_list(snapshot.get("undefined_glibc_symbols"), "snapshot.undefined_glibc_symbols")
    if reason == "undefined_tls_symbols":
        return string_list(snapshot.get("undefined_tls_symbols"), "snapshot.undefined_tls_symbols")
    if reason == "host_version_requirements":
        return string_list(snapshot.get("host_version_requirements"), "snapshot.host_version_requirements")
    errors.append(f"unknown live action reason {reason}")
    return []


def owned_unwind_live_dependency_contract_report(expected_lane):
    local_errors = []

    def add_error(message):
        errors.append(message)
        local_errors.append(message)

    contract = owned_unwind.get("live_dependency_evidence_contract")
    if not isinstance(contract, dict):
        add_error("owned_unwind.live_dependency_evidence_contract: must be an object")
        contract = {}

    def contract_list(field, context):
        value = contract.get(field)
        if not isinstance(value, list) or not value:
            add_error(f"{context}: must be a non-empty list")
            return []
        result = []
        for idx, item in enumerate(value):
            if not isinstance(item, str) or not item:
                add_error(f"{context}[{idx}]: must be a non-empty string")
            else:
                result.append(item)
        return result

    forbidden_needed = contract_list(
        "forbidden_needed_libraries",
        "owned_unwind.live_dependency_evidence_contract.forbidden_needed_libraries",
    )
    forbidden_providers = contract_list(
        "forbidden_version_providers",
        "owned_unwind.live_dependency_evidence_contract.forbidden_version_providers",
    )
    forbidden_prefixes = contract_list(
        "forbidden_undefined_symbol_prefixes",
        "owned_unwind.live_dependency_evidence_contract.forbidden_undefined_symbol_prefixes",
    )
    lane_id = contract.get("lane_id")
    if lane_id != expected_lane:
        add_error("owned_unwind.live_dependency_evidence_contract.lane_id must match owned unwind experiment lane")
    if contract.get("expected_undefined_unwind_symbol_count") != 0:
        add_error("owned_unwind.live_dependency_evidence_contract.expected_undefined_unwind_symbol_count must be 0")
    if "libgcc_s.so.1" not in forbidden_needed:
        add_error("owned_unwind.live_dependency_evidence_contract must forbid libgcc_s.so.1 needed libraries")
    if "libgcc_s.so.1" not in forbidden_providers:
        add_error("owned_unwind.live_dependency_evidence_contract must forbid libgcc_s.so.1 version providers")
    if "_Unwind_" not in forbidden_prefixes:
        add_error("owned_unwind.live_dependency_evidence_contract must forbid _Unwind_ undefined symbol prefixes")
    if contract.get("status_on_violation") != "fail_closed":
        add_error("owned_unwind.live_dependency_evidence_contract.status_on_violation must be fail_closed")
    if contract.get("promotion_allowed_on_pass") is not False:
        add_error("owned_unwind.live_dependency_evidence_contract.promotion_allowed_on_pass must be false")

    return {
        "contract_validation_status": "pass" if not local_errors else "fail",
        "source": "standalone_owned_unwind_experiment.live_dependency_evidence_contract",
        "lane_id": lane_id,
        "expected_undefined_unwind_symbol_count": contract.get("expected_undefined_unwind_symbol_count"),
        "forbidden_needed_libraries": forbidden_needed,
        "forbidden_version_providers": forbidden_providers,
        "forbidden_undefined_symbol_prefixes": forbidden_prefixes,
        "status_on_violation": contract.get("status_on_violation"),
        "promotion_allowed_on_pass": contract.get("promotion_allowed_on_pass"),
        "status_until_default_forge_consumes_evidence": "claim_blocked",
        "errors": local_errors,
    }


head = current_commit()
rollup = load_json(rollup_path)
plan = load_json(plan_path)
version_burndown = load_json(version_path)
owner_ledger = load_json(owner_path)
owned_unwind = load_json(owned_unwind_path)
tls_removal = load_json(tls_removal_path)
for value_name in ["rollup", "plan", "version_burndown", "owner_ledger", "owned_unwind", "tls_removal"]:
    if not isinstance(locals()[value_name], dict):
        locals()[value_name] = {}

if rollup.get("schema_version") != "v1" or rollup.get("bead") != BEAD_ID:
    errors.append("rollup must declare schema_version=v1 and bead=bd-zyck1.94")
if rollup.get("manifest_id") != "standalone_blocker_burndown_progress_rollup":
    errors.append("manifest_id must be standalone_blocker_burndown_progress_rollup")
source_commit = rollup.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("rollup source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("rollup source_commit must be 'current' or match current git HEAD")
if rollup.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match rollup stale-source contract")
if rollup.get("rollup_policy") != EXPECTED_ROLLUP_POLICY:
    errors.append("rollup_policy must match compact fail-closed progress contract")
inputs = object_value(rollup.get("inputs"), "inputs")
if inputs != EXPECTED_INPUTS:
    errors.append("inputs must match standalone blocker rollup input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(inputs.get(key), f"inputs.{key}")

declared_fields = set(string_list(rollup.get("required_rollup_row_fields"), "required_rollup_row_fields"))
if declared_fields != REQUIRED_ROLLUP_ROW_FIELDS:
    errors.append("required_rollup_row_fields mismatch")

projection = object_value(plan.get("current_forge_blocker_projection"), "current_forge_blocker_projection")
snapshot = object_value(
    projection.get("current_forge_blocker_value_snapshot"),
    "current_forge_blocker_value_snapshot",
)
current_reasons = set(string_list(snapshot.get("blocking_reasons"), "snapshot.blocking_reasons", min_len=10))
if len(current_reasons) != 10:
    errors.append("current forge snapshot must expose ten unique blocking reasons")

action_rows = projection.get("blocker_action_required_rows", {})
if not isinstance(action_rows, dict) or not action_rows:
    errors.append("current_forge_blocker_projection.blocker_action_required_rows must be a non-empty object")
    action_rows = {}
live_action_by_reason = {}
for reason in sorted(current_reasons):
    row = action_rows.get(reason)
    context = f"current_forge_blocker_projection.blocker_action_required_rows.{reason}"
    if row is None:
        errors.append(f"current_forge_blocker_projection.blocker_action_required_rows missing {reason}")
        continue
    if not isinstance(row, dict):
        errors.append(f"{context} must be an object")
        continue
    if row.get("blocking_reason") != reason:
        errors.append(f"{context}.blocking_reason mismatch")
    if row.get("promotion_allowed") is not False:
        errors.append(f"{context}.promotion_allowed must be false")
    live_values = string_list(row.get("current_blocker_values"), f"{context}.current_blocker_values")
    if live_values != expected_live_action_values(reason, snapshot):
        errors.append(f"{context}.current_blocker_values must match snapshot blocker values")
    string_list(row.get("exit_criteria"), f"{context}.exit_criteria")
    live_action_by_reason[reason] = row
for reason in sorted(set(action_rows) - current_reasons):
    errors.append(f"current_forge_blocker_projection.blocker_action_required_rows has unexpected reason {reason}")

owner_rows = owner_ledger.get("ledger_rows", [])
if not isinstance(owner_rows, list):
    errors.append("owner ledger ledger_rows must be an array")
    owner_rows = []
owner_by_reason = {}
reasons_by_owner = defaultdict(list)
for row in owner_rows:
    if not isinstance(row, dict):
        errors.append("owner ledger row must be an object")
        continue
    reason = row.get("blocking_reason")
    owner = row.get("owner_surface")
    if isinstance(reason, str):
        owner_by_reason[reason] = row
    if isinstance(reason, str) and isinstance(owner, str):
        reasons_by_owner[owner].append(reason)
for reason in sorted(current_reasons - set(owner_by_reason)):
    errors.append(f"owner ledger missing current blocker reason {reason}")

progress_rows = rollup.get("progress_categories", [])
if not isinstance(progress_rows, list):
    errors.append("progress_categories must be an array")
    progress_rows = []
rollup_reason_set = set()
category_counts = Counter()
materialized_categories = []
for row in progress_rows:
    if not isinstance(row, dict):
        errors.append("progress category row must be an object")
        continue
    category = row.get("category_id")
    context = f"progress_categories[{category or '<missing>'}]"
    missing = REQUIRED_ROLLUP_ROW_FIELDS - set(row)
    for field in sorted(missing):
        errors.append(f"{context}: missing field {field}")
    if not isinstance(category, str) or not category:
        errors.append(f"{context}: category_id must be a non-empty string")
        continue
    category_counts[category] += 1
    if category_counts[category] > 1:
        errors.append(f"progress_categories duplicate category_id {category}")
    owner_surfaces = string_list(row.get("owner_surfaces"), f"{context}.owner_surfaces")
    reasons = string_list(row.get("source_blocking_reasons"), f"{context}.source_blocking_reasons")
    expected_reasons = sorted(reasons_by_owner.get(category, []))
    if sorted(reasons) != expected_reasons:
        errors.append(f"{context}.source_blocking_reasons must match owner ledger rows for {category}")
    if owner_surfaces != [category]:
        errors.append(f"{context}.owner_surfaces must contain only {category}")
    if row.get("current_reason_count") != len(reasons):
        errors.append(f"{context}.current_reason_count mismatch")
    values = []
    unique_values = []
    seen_values = set()
    exit_criteria = []
    materialized_action_rows = []
    for reason in reasons:
        rollup_reason_set.add(reason)
        action_row = live_action_by_reason.get(reason, {})
        if action_row.get("owner_surface") != category:
            errors.append(
                f"{context}.{reason}.owner_surface must match progress category {category}"
            )
        action_values = string_list(
            action_row.get("current_blocker_values"),
            f"blocker_action_required_rows.{reason}.current_blocker_values",
        )
        action_exit_criteria = string_list(
            action_row.get("exit_criteria"),
            f"blocker_action_required_rows.{reason}.exit_criteria",
        )
        values.extend(action_values)
        for value in action_values:
            if value not in seen_values:
                seen_values.add(value)
                unique_values.append(value)
        exit_criteria.extend(action_exit_criteria)
        materialized_action_row = {
            "blocking_reason": action_row.get("blocking_reason"),
            "owner_surface": action_row.get("owner_surface"),
            "primary_probe_id": action_row.get("primary_probe_id"),
            "evidence_fields": action_row.get("evidence_fields"),
            "current_blocker_values": action_values,
            "exit_criteria": action_exit_criteria,
            "promotion_allowed": action_row.get("promotion_allowed"),
        }
        missing_report_fields = REQUIRED_ACTION_ROW_REPORT_FIELDS - set(materialized_action_row)
        if missing_report_fields:
            errors.append(f"{context}.{reason}.materialized_action_row missing report fields")
        materialized_action_rows.append(materialized_action_row)
    if row.get("last_known_value_count") != len(values):
        errors.append(f"{context}.last_known_value_count mismatch")
    if row.get("value_source") != LIVE_ACTION_VALUE_SOURCE:
        errors.append(f"{context}.value_source mismatch")
    if row.get("exit_criteria_source") != LIVE_ACTION_EXIT_CRITERIA_SOURCE:
        errors.append(f"{context}.exit_criteria_source mismatch")
    if row.get("status_until_exit") != "claim_blocked":
        errors.append(f"{context}.status_until_exit must be claim_blocked")
    materialized_categories.append(
        {
            "category_id": category,
            "owner_surfaces": owner_surfaces,
            "source_blocking_reasons": reasons,
            "current_reason_count": len(reasons),
            "last_known_values": values,
            "last_known_value_count": len(values),
            "unique_current_values": unique_values,
            "unique_current_value_count": len(unique_values),
            "blocker_action_rows": materialized_action_rows,
            "target_exit_criteria": exit_criteria,
            "status_until_exit": "claim_blocked",
        }
    )

if rollup_reason_set != current_reasons:
    errors.append("progress_categories must cover every current blocker reason exactly through owner ledger")

matrix_rows = version_burndown.get("version_requirement_matrix", [])
if not isinstance(matrix_rows, list):
    errors.append("version_requirement_matrix must be an array")
    matrix_rows = []
requirements_by_provider = defaultdict(list)
for row in matrix_rows:
    if not isinstance(row, dict):
        errors.append("version requirement row must be an object")
        continue
    requirement_id = matrix_requirement_id(row)
    provider = row.get("provider_library")
    if not isinstance(requirement_id, str) or row.get("requirement_id") != requirement_id:
        errors.append("version requirement row requirement_id must equal provider:version")
        continue
    requirements_by_provider[provider].append(requirement_id)

provider_rows = rollup.get("version_provider_rollup", [])
if not isinstance(provider_rows, list):
    errors.append("version_provider_rollup must be an array")
    provider_rows = []
provider_seen = set()
materialized_providers = []
for row in provider_rows:
    if not isinstance(row, dict):
        errors.append("version provider row must be an object")
        continue
    provider = row.get("provider_library")
    context = f"version_provider_rollup[{provider or '<missing>'}]"
    if not isinstance(provider, str) or not provider:
        errors.append(f"{context}.provider_library must be a non-empty string")
        continue
    if provider in provider_seen:
        errors.append(f"version_provider_rollup duplicate provider {provider}")
    provider_seen.add(provider)
    expected_ids = sorted(requirements_by_provider.get(provider, []))
    actual_ids = string_list(row.get("source_requirement_ids"), f"{context}.source_requirement_ids")
    if sorted(actual_ids) != expected_ids:
        errors.append(f"{context}.source_requirement_ids must match version matrix provider rows")
    if row.get("requirement_count") != len(expected_ids):
        errors.append(f"{context}.requirement_count mismatch")
    if row.get("source_matrix") != "standalone_host_version_requirement_burndown.version_requirement_matrix":
        errors.append(f"{context}.source_matrix mismatch")
    mapped_categories = string_list(row.get("mapped_progress_categories"), f"{context}.mapped_progress_categories")
    for category in mapped_categories:
        if category not in category_counts:
            errors.append(f"{context}.mapped_progress_categories references missing category {category}")
    if row.get("status_until_exit") != "claim_blocked":
        errors.append(f"{context}.status_until_exit must be claim_blocked")
    materialized_providers.append(
        {
            "provider_library": provider,
            "source_requirement_ids": actual_ids,
            "requirement_count": len(expected_ids),
            "mapped_progress_categories": mapped_categories,
            "status_until_exit": "claim_blocked",
        }
    )
if provider_seen != set(requirements_by_provider):
    errors.append("version_provider_rollup must cover every version matrix provider")

partial_rows = rollup.get("partial_burndown_experiments", [])
if not isinstance(partial_rows, list):
    errors.append("partial_burndown_experiments must be an array")
    partial_rows = []
owned_summary = object_value(owned_unwind.get("summary"), "owned_unwind.summary")
owned_policy = object_value(owned_unwind.get("report_policy"), "owned_unwind.report_policy")
if owned_unwind.get("manifest_id") != "standalone-owned-unwind-experiment":
    errors.append("owned_unwind manifest_id must be standalone-owned-unwind-experiment")
if owned_summary.get("report_only") is not True:
    errors.append("owned_unwind summary.report_only must be true")
if owned_summary.get("promotion_allowed") is not False:
    errors.append("owned_unwind summary.promotion_allowed must be false")
if owned_summary.get("default_forge_path_unchanged") is not True:
    errors.append("owned_unwind summary.default_forge_path_unchanged must be true")
if owned_summary.get("claim_status") != "report_only":
    errors.append("owned_unwind summary.claim_status must remain report_only")
owned_lanes = owned_unwind.get("experiment_lanes", [])
if not isinstance(owned_lanes, list):
    errors.append("owned_unwind.experiment_lanes must be an array")
    owned_lanes = []
owned_lane_ids = {
    lane.get("lane_id")
    for lane in owned_lanes
    if isinstance(lane, dict) and isinstance(lane.get("lane_id"), str)
}
tls_summary = object_value(tls_removal.get("summary"), "tls_removal.summary")
tls_policy = object_value(tls_removal.get("report_policy"), "tls_removal.report_policy")
if tls_removal.get("manifest_id") != "standalone-tls-removal-experiment":
    errors.append("tls_removal manifest_id must be standalone-tls-removal-experiment")
if tls_policy.get("report_only") is not True:
    errors.append("tls_removal report_policy.report_only must be true")
if tls_policy.get("promotion_allowed") is not False:
    errors.append("tls_removal report_policy.promotion_allowed must be false")
if tls_summary.get("promotion_allowed") is not False:
    errors.append("tls_removal summary.promotion_allowed must be false")
if tls_summary.get("default_forge_path_unchanged") is not True:
    errors.append("tls_removal summary.default_forge_path_unchanged must be true")
if tls_summary.get("claim_status") != "claim_blocked":
    errors.append("tls_removal summary.claim_status must remain claim_blocked")
tls_lanes = tls_removal.get("experiment_lanes", [])
if not isinstance(tls_lanes, list):
    errors.append("tls_removal.experiment_lanes must be an array")
    tls_lanes = []
tls_lane_ids = {
    lane.get("lane_id")
    for lane in tls_lanes
    if isinstance(lane, dict) and isinstance(lane.get("lane_id"), str)
}
partial_specs = {
    "owned-unwind-stub-experiment": {
        "source_manifest": EXPECTED_INPUTS["standalone_owned_unwind_experiment"],
        "summary": owned_summary,
        "policy": owned_policy,
        "lane_ids": owned_lane_ids,
        "baseline_count_field": "blocker_symbol_count_baseline",
        "experiment_count_field": "blocker_symbol_count_owned_unwind_when_complete",
        "evidence_source": "standalone_owned_unwind_experiment.summary.blocker_symbol_count_owned_unwind_when_complete",
        "live_dependency_contract_source": "standalone_owned_unwind_experiment.live_dependency_evidence_contract",
        "requires_live_dependency_contract": True,
        "label": "owned unwind",
    },
    "owned-tls-cache-source-surface-experiment": {
        "source_manifest": EXPECTED_INPUTS["standalone_tls_removal_experiment"],
        "summary": tls_summary,
        "policy": tls_policy,
        "lane_ids": tls_lane_ids,
        "baseline_count_field": "tls_blocker_symbol_count_baseline",
        "experiment_count_field": "tls_blocker_symbol_count_owned_tls_cache_when_complete",
        "evidence_source": "standalone_tls_removal_experiment.summary.tls_blocker_symbol_count_owned_tls_cache_when_complete",
        "label": "TLS removal",
    },
}
materialized_partial_experiments = []
partial_reduced_count = 0
partial_seen = set()
for row in partial_rows:
    if not isinstance(row, dict):
        errors.append("partial burndown experiment row must be an object")
        continue
    experiment_id = row.get("experiment_id")
    context = f"partial_burndown_experiments[{experiment_id or '<missing>'}]"
    if not isinstance(experiment_id, str) or not experiment_id:
        errors.append(f"{context}.experiment_id must be a non-empty string")
        continue
    if experiment_id in partial_seen:
        errors.append(f"partial_burndown_experiments duplicate experiment_id {experiment_id}")
    partial_seen.add(experiment_id)
    spec = partial_specs.get(experiment_id)
    if spec is None:
        errors.append(f"{context}.experiment_id is not a recognized partial experiment")
        continue
    category = row.get("category_id")
    if category not in category_counts:
        errors.append(f"{context}.category_id references missing category {category}")
    if row.get("source_manifest") != spec["source_manifest"]:
        errors.append(f"{context}.source_manifest must reference {spec['source_manifest']}")
    if row.get("baseline_lane") != spec["summary"].get("baseline_lane"):
        errors.append(f"{context}.baseline_lane must match {spec['label']} summary")
    if row.get("experiment_lane") != spec["summary"].get("experiment_lane"):
        errors.append(f"{context}.experiment_lane must match {spec['label']} summary")
    if row.get("baseline_lane") not in spec["lane_ids"] or row.get("experiment_lane") not in spec["lane_ids"]:
        errors.append(f"{context}.lanes must exist in {spec['label']} manifest")
    if row.get("evidence_mode") != spec["policy"].get("required_mode"):
        errors.append(f"{context}.evidence_mode must match {spec['label']} required_mode")
    for bool_field in ["report_only", "default_forge_path_unchanged"]:
        if row.get(bool_field) is not True:
            errors.append(f"{context}.{bool_field} must be true")
    for bool_field in ["promotion_allowed", "replacement_level_change_allowed"]:
        if row.get(bool_field) is not False:
            errors.append(f"{context}.{bool_field} must be false")
    baseline_count = spec["summary"].get(spec["baseline_count_field"])
    experiment_count = spec["summary"].get(spec["experiment_count_field"])
    if row.get("baseline_value_count") != baseline_count:
        errors.append(f"{context}.baseline_value_count must match {spec['label']} summary")
    if row.get("experiment_value_count") != experiment_count:
        errors.append(f"{context}.experiment_value_count must match {spec['label']} summary")
    reduced = (
        baseline_count - experiment_count
        if isinstance(baseline_count, int) and isinstance(experiment_count, int)
        else None
    )
    if row.get("reduced_value_count") != reduced:
        errors.append(f"{context}.reduced_value_count must equal baseline minus experiment")
    if row.get("evidence_source") != spec["evidence_source"]:
        errors.append(f"{context}.evidence_source mismatch")
    if row.get("status_until_default_forge_consumes_evidence") != "claim_blocked":
        errors.append(f"{context}.status_until_default_forge_consumes_evidence must be claim_blocked")
    live_contract_report = None
    if spec.get("requires_live_dependency_contract"):
        if row.get("live_dependency_contract_source") != spec["live_dependency_contract_source"]:
            errors.append(f"{context}.live_dependency_contract_source mismatch")
        if row.get("live_dependency_contract_required") is not True:
            errors.append(f"{context}.live_dependency_contract_required must be true")
        if row.get("live_dependency_contract_status_until_default_forge_consumes_evidence") != "claim_blocked":
            errors.append(
                f"{context}.live_dependency_contract_status_until_default_forge_consumes_evidence must be claim_blocked"
            )
        live_contract_report = owned_unwind_live_dependency_contract_report(row.get("experiment_lane"))
    if isinstance(row.get("reduced_value_count"), int):
        partial_reduced_count += row["reduced_value_count"]
    materialized = {
        "experiment_id": experiment_id,
        "category_id": category,
        "baseline_lane": row.get("baseline_lane"),
        "experiment_lane": row.get("experiment_lane"),
        "baseline_value_count": row.get("baseline_value_count"),
        "experiment_value_count": row.get("experiment_value_count"),
        "reduced_value_count": row.get("reduced_value_count"),
        "report_only": True,
        "status_until_default_forge_consumes_evidence": "claim_blocked",
    }
    if live_contract_report is not None:
        materialized["live_dependency_contract"] = live_contract_report
    materialized_partial_experiments.append(materialized)
if partial_seen != set(partial_specs):
    errors.append("partial_burndown_experiments must cover owned-unwind and TLS-removal experiments")

summary = object_value(rollup.get("summary"), "summary")
last_known_value_count = sum(row["last_known_value_count"] for row in materialized_categories)
summary_expectations = {
    "current_blocking_reason_count": len(current_reasons),
    "progress_category_count": len(materialized_categories),
    "blocked_progress_category_count": len(materialized_categories),
    "partial_burndown_experiment_count": len(materialized_partial_experiments),
    "report_only_reduced_value_count": partial_reduced_count,
    "last_known_value_count": last_known_value_count,
    "host_version_requirement_count": sum(len(ids) for ids in requirements_by_provider.values()),
    "version_provider_count": len(requirements_by_provider),
}
for field, expected in summary_expectations.items():
    if summary.get(field) != expected:
        errors.append(f"summary.{field} mismatch")
if summary.get("promotion_allowed") is not False:
    errors.append("summary.promotion_allowed must be false")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "claim_status": snapshot.get("claim_status"),
    "progress_categories": materialized_categories,
    "version_provider_rollup": materialized_providers,
    "partial_burndown_experiments": materialized_partial_experiments,
    "summary": {
        **summary_expectations,
        "promotion_allowed": False,
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
