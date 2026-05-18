#!/usr/bin/env bash
# Fail-closed preflight for cargo validation lanes that must use rch remotely.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RCH_PREFLIGHT_CONTRACT:-${ROOT}/tests/conformance/rch_remote_admissibility_preflight.v1.json}"
OUT_DIR="${FRANKENLIBC_RCH_PREFLIGHT_OUT_DIR:-${ROOT}/target/rch-remote-admissibility}"
REPORT="${FRANKENLIBC_RCH_PREFLIGHT_REPORT:-${OUT_DIR}/rch_remote_admissibility.report.json}"
LOG="${FRANKENLIBC_RCH_PREFLIGHT_LOG:-${OUT_DIR}/rch_remote_admissibility.log.jsonl}"
APPROVAL_PACKET_SCRIPT="${ROOT}/scripts/generate_rch_pressure_approval_packet.sh"
APPROVAL_PACKET_REPORT="${FRANKENLIBC_RCH_PACKET_REPORT:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.report.json}"
APPROVAL_PACKET_MARKDOWN="${FRANKENLIBC_RCH_PACKET_MARKDOWN:-${ROOT}/target/rch-pressure-approval-packet/rch_pressure_approval_packet.approval.md}"
DEFAULT_COMMAND="cargo test -p frankenlibc-harness --test standalone_owned_unwind_experiment_test -- --nocapture"

mkdir -p "${OUT_DIR}"

if [[ $# -gt 0 ]]; then
  VALIDATION_COMMAND="$*"
else
  VALIDATION_COMMAND="${FRANKENLIBC_RCH_PREFLIGHT_CMD:-${DEFAULT_COMMAND}}"
fi

DRY_RUN_OUTPUT_FILE="${FRANKENLIBC_RCH_PREFLIGHT_DRY_RUN_OUTPUT:-}"
DRY_RUN_STDOUT="${OUT_DIR}/rch_diagnose_dry_run.out"
DRY_RUN_STDERR="${OUT_DIR}/rch_diagnose_dry_run.err"
DRY_RUN_STATUS="${OUT_DIR}/rch_diagnose_dry_run.status"

if [[ -n "${DRY_RUN_OUTPUT_FILE}" ]]; then
  cp "${DRY_RUN_OUTPUT_FILE}" "${DRY_RUN_STDOUT}"
  : >"${DRY_RUN_STDERR}"
  printf '0\n' >"${DRY_RUN_STATUS}"
else
  set +e
  env \
    RCH_REQUIRE_REMOTE=1 \
    RCH_TEST_SLOTS="${RCH_TEST_SLOTS:-1}" \
    RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-30}" \
    RCH_PRIORITY="${RCH_PRIORITY:-high}" \
    rch diagnose --dry-run "${VALIDATION_COMMAND}" >"${DRY_RUN_STDOUT}" 2>"${DRY_RUN_STDERR}"
  status=$?
  set -e
  printf '%s\n' "${status}" >"${DRY_RUN_STATUS}"
fi

python3 - "${ROOT}" "${CONTRACT}" "${VALIDATION_COMMAND}" "${DRY_RUN_STDOUT}" "${DRY_RUN_STDERR}" "${DRY_RUN_STATUS}" "${REPORT}" "${LOG}" "${APPROVAL_PACKET_SCRIPT}" "${APPROVAL_PACKET_REPORT}" "${APPROVAL_PACKET_MARKDOWN}" <<'PY'
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
VALIDATION_COMMAND = sys.argv[3]
DRY_RUN_STDOUT = pathlib.Path(sys.argv[4])
DRY_RUN_STDERR = pathlib.Path(sys.argv[5])
DRY_RUN_STATUS = pathlib.Path(sys.argv[6])
REPORT = pathlib.Path(sys.argv[7])
LOG = pathlib.Path(sys.argv[8])
APPROVAL_PACKET_SCRIPT = pathlib.Path(sys.argv[9])
APPROVAL_PACKET_REPORT = pathlib.Path(sys.argv[10])
APPROVAL_PACKET_MARKDOWN = pathlib.Path(sys.argv[11])

contract_errors: list[str] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def read_status(path: pathlib.Path) -> int | None:
    try:
        return int(read_text(path).strip())
    except ValueError:
        return None


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        contract_errors.append(f"{path}: {exc}")
        return {}
    if not isinstance(loaded, dict):
        contract_errors.append(f"{path}: contract must be a JSON object")
        return {}
    return loaded


def load_optional_json(path: pathlib.Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return loaded if isinstance(loaded, dict) else None


def current_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def is_hex_commit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def source_commit_current(value: Any, head: str) -> bool:
    return value == "current" or (head != "unknown" and value == head)


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def repo_path(value: Any, context: str, *, must_exist: bool = True) -> None:
    if not isinstance(value, str) or not value:
        contract_errors.append(f"{context}: must be a non-empty repo-relative path")
        return
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        contract_errors.append(f"{context}: path must stay repo-relative: {value}")
        return
    if must_exist and not (ROOT / path).exists():
        contract_errors.append(f"{context}: missing path {value}")


def string_list(value: Any, context: str, *, min_len: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < min_len:
        contract_errors.append(f"{context}: must be a list with at least {min_len} entries")
        return []
    result: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item:
            contract_errors.append(f"{context}[{idx}]: must be a non-empty string")
        else:
            result.append(item)
    return result


def configured_report_fields(contract: dict[str, Any]) -> list[str]:
    report_contract = contract.get("report_contract", {})
    if not isinstance(report_contract, dict):
        contract_errors.append("report_contract: must be an object")
        return []
    fields = report_contract.get("must_materialize", [])
    if not isinstance(fields, list):
        contract_errors.append("report_contract.must_materialize: must be a list")
        return []
    return [field for field in fields if isinstance(field, str) and field]


def missing_report_fields(contract: dict[str, Any], report: dict[str, Any]) -> list[str]:
    return [field for field in configured_report_fields(contract) if field not in report]


def report_contract_errors(
    contract: dict[str, Any],
    actual_report_path: pathlib.Path,
    actual_log_path: pathlib.Path,
) -> list[str]:
    local_errors: list[str] = []
    report_contract = contract.get("report_contract", {})
    if not isinstance(report_contract, dict):
        return ["report_contract_not_object"]
    expected_output = report_contract.get("output_path")
    if not isinstance(expected_output, str) or not expected_output:
        local_errors.append("report_contract_output_path_missing")
    else:
        path = pathlib.Path(expected_output)
        if path.is_absolute() or ".." in path.parts:
            local_errors.append("report_contract_output_path_not_repo_relative")
        elif rel(actual_report_path) != expected_output:
            local_errors.append("report_contract_output_path_mismatch")
    expected_log = report_contract.get("log_path")
    if not isinstance(expected_log, str) or not expected_log:
        local_errors.append("report_contract_log_path_missing")
    else:
        path = pathlib.Path(expected_log)
        if path.is_absolute() or ".." in path.parts:
            local_errors.append("report_contract_log_path_not_repo_relative")
        elif rel(actual_log_path) != expected_log:
            local_errors.append("report_contract_log_path_mismatch")
    return local_errors


def classify_status(signatures: list[str], dry_run_status: int | None) -> str:
    if signatures:
        return "blocked"
    if dry_run_status not in (0, None):
        return "diagnose_failed"
    return "admissible"


def current_blocked_field(
    contract: dict[str, Any],
    report_status: str,
    signatures: list[str],
) -> str:
    cfg = contract.get("current_blocked_state", {})
    if not isinstance(cfg, dict):
        return "not_current_blocked_state"
    preflight = contract.get("preflight_contract", {})
    blocked_status = preflight.get("blocked_status", "blocked") if isinstance(preflight, dict) else "blocked"
    required = set(
        item
        for item in cfg.get("required_failure_signatures", [])
        if isinstance(item, str) and item
    )
    if report_status == blocked_status and required and required.issubset(set(signatures)):
        return str(cfg.get("expected_field_value", "blocked"))
    if report_status == blocked_status:
        return "blocked_missing_required_signatures"
    return "not_current_blocked_state"


def current_blocked_errors(contract: dict[str, Any], report: dict[str, Any]) -> list[str]:
    cfg = contract.get("current_blocked_state", {})
    preflight = contract.get("preflight_contract", {})
    if not isinstance(cfg, dict) or not isinstance(preflight, dict):
        return []
    blocked_status = preflight.get("blocked_status", "blocked")
    expected = cfg.get("expected_field_value", "blocked")
    required = set(
        item
        for item in cfg.get("required_failure_signatures", [])
        if isinstance(item, str) and item
    )
    signatures = set(report.get("failure_signatures", []))
    field = report.get("status_on_current_blocked_state")
    is_current_blocked = report.get("status") == blocked_status and required.issubset(signatures)
    local_errors: list[str] = []
    if is_current_blocked and field != expected:
        local_errors.append("current_blocked_state_mismatch")
    if field == expected and not is_current_blocked:
        local_errors.append("current_blocked_required_signature_missing")
    return local_errors


def approval_readiness_errors(rows: Any) -> list[str]:
    if rows is None:
        return []
    if not isinstance(rows, list):
        return ["approval_readiness_not_list"]
    errors: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"approval_readiness_{index}_not_object")
            continue
        if row.get("safe_to_run_without_user_approval") is not False:
            errors.append(f"approval_readiness_{index}_claims_safe_without_user_approval")
        if row.get("exact_user_approval_required") is not True:
            errors.append(f"approval_readiness_{index}_missing_explicit_user_approval_gate")
        if row.get("cleanup_executed") is not False:
            errors.append(f"approval_readiness_{index}_claims_cleanup_executed")
    return errors


def approval_packet_summary(packet: dict[str, Any] | None, head: str) -> dict[str, Any]:
    if packet is None:
        return {
            "status": "not_generated",
            "operator_next_action": "generate_approval_packet",
            "operator_next_command": str(APPROVAL_PACKET_SCRIPT),
            "packet_candidate_diagnostics": {
                "status": "not_generated",
                "candidate_count": 0,
                "critical_worker_count": 0,
                "diagnostic_summary": "No pressure approval packet has been generated for this checkout.",
                "next_action": "generate_approval_packet",
            },
            "approval_boundary": {
                "explicit_user_text_required_before_cleanup": "The user must provide written approval naming exact paths and commands before cleanup can run.",
                "commands_not_executed": [],
                "safe_to_run_without_user_approval": False,
                "cleanup_executed": False,
            },
            "report_path": rel(APPROVAL_PACKET_REPORT),
            "markdown_path": rel(APPROVAL_PACKET_MARKDOWN),
            "current_head": head,
            "packet_head_commit": None,
            "fresh_for_current_head": False,
            "selected_candidate_count": 0,
            "ready_for_explicit_user_approval_count": 0,
            "current_ready_for_explicit_user_approval_count": 0,
            "ready_candidate_paths": [],
            "current_ready_candidate_paths": [],
            "current_ready_candidate_summaries": [],
            "current_ready_worker_ids": [],
            "current_ready_candidate_count_by_worker": {},
            "safe_to_run_without_user_approval": False,
            "cleanup_executed": False,
            "contract_errors": [],
        }
    rows = packet.get("approval_readiness")
    readiness_rows = rows if isinstance(rows, list) else []
    ready_rows = [
        row
        for row in readiness_rows
        if isinstance(row, dict)
        and row.get("approval_state") == "ready_for_explicit_user_approval"
        and isinstance(row.get("path"), str)
    ]
    ready_paths = [
        str(row.get("path"))
        for row in ready_rows
    ]
    repo_state = packet.get("repo_state")
    repo_state = repo_state if isinstance(repo_state, dict) else {}
    packet_head = repo_state.get("head_commit")
    fresh_for_current_head = isinstance(packet_head, str) and packet_head == head
    any_safe_without_approval = any(
        isinstance(row, dict) and row.get("safe_to_run_without_user_approval") is not False
        for row in readiness_rows
    )
    any_cleanup_executed = any(
        isinstance(row, dict) and row.get("cleanup_executed") is not False
        for row in readiness_rows
    )
    diagnostics = packet.get("no_candidate_diagnostics")
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    packet_candidate_diagnostics = {
        "status": diagnostics.get("status", "missing"),
        "candidate_count": diagnostics.get("candidate_count"),
        "critical_worker_count": diagnostics.get("critical_worker_count"),
        "diagnostic_summary": diagnostics.get(
            "diagnostic_summary",
            "Pressure packet did not include candidate-discovery diagnostics.",
        ),
        "next_action": diagnostics.get("next_action", "inspect_approval_packet_blockers"),
    }
    approval_request = packet.get("approval_request")
    approval_request = approval_request if isinstance(approval_request, dict) else {}
    commands_not_executed = approval_request.get("commands_not_executed")
    approval_boundary = {
        "explicit_user_text_required_before_cleanup": approval_request.get(
            "explicit_user_text_required_before_cleanup",
            "The user must provide written approval naming exact paths and commands before cleanup can run.",
        ),
        "commands_not_executed": commands_not_executed if isinstance(commands_not_executed, list) else [],
        "safe_to_run_without_user_approval": False,
        "cleanup_executed": False,
    }
    if fresh_for_current_head and ready_paths:
        operator_next_action = "request_explicit_cleanup_approval_for_current_ready_paths"
        operator_next_command = None
        current_ready_paths = ready_paths
        current_ready_summaries = [
            {
                "worker_id": row.get("worker_id"),
                "host": row.get("host"),
                "path": row.get("path"),
                "candidate_rank": row.get("candidate_rank"),
                "recommendation_kinds": row.get("recommendation_kinds")
                if isinstance(row.get("recommendation_kinds"), list)
                else [],
                "read_only_check_count": row.get("read_only_check_count"),
                "read_only_check_results_collected": row.get("read_only_check_results_collected"),
                "read_only_check_results_passed": row.get("read_only_check_results_passed"),
                "read_only_checks_passed": row.get("read_only_checks_passed"),
                "blocked_by": row.get("blocked_by") if isinstance(row.get("blocked_by"), list) else [],
                "exact_user_approval_required": row.get("exact_user_approval_required"),
                "safe_to_run_without_user_approval": row.get("safe_to_run_without_user_approval"),
                "cleanup_executed": row.get("cleanup_executed"),
                "next_action": row.get("next_action"),
            }
            for row in ready_rows
        ]
    elif fresh_for_current_head:
        operator_next_action = str(packet_candidate_diagnostics["next_action"])
        operator_next_command = str(APPROVAL_PACKET_MARKDOWN)
        current_ready_paths = []
        current_ready_summaries = []
    else:
        operator_next_action = "regenerate_approval_packet_for_current_head"
        operator_next_command = str(APPROVAL_PACKET_SCRIPT)
        current_ready_paths = []
        current_ready_summaries = []
    current_ready_worker_counts: dict[str, int] = {}
    for summary in current_ready_summaries:
        worker_id = summary.get("worker_id")
        if not isinstance(worker_id, str) or not worker_id:
            continue
        current_ready_worker_counts[worker_id] = current_ready_worker_counts.get(worker_id, 0) + 1
    return {
        "status": "available_current" if fresh_for_current_head else "stale_for_current_head",
        "operator_next_action": operator_next_action,
        "operator_next_command": operator_next_command,
        "packet_candidate_diagnostics": packet_candidate_diagnostics,
        "approval_boundary": approval_boundary,
        "packet_id": packet.get("packet_id"),
        "generated_at_utc": packet.get("generated_at_utc"),
        "report_path": rel(APPROVAL_PACKET_REPORT),
        "markdown_path": rel(APPROVAL_PACKET_MARKDOWN),
        "current_head": head,
        "packet_head_commit": packet_head,
        "packet_branch": repo_state.get("branch"),
        "packet_dirty_summary": repo_state.get("dirty_summary") if isinstance(repo_state.get("dirty_summary"), list) else [],
        "packet_untracked_summary": repo_state.get("untracked_summary") if isinstance(repo_state.get("untracked_summary"), list) else [],
        "fresh_for_current_head": fresh_for_current_head,
        "selected_candidate_count": len(readiness_rows),
        "ready_for_explicit_user_approval_count": len(ready_paths),
        "current_ready_for_explicit_user_approval_count": len(ready_paths) if fresh_for_current_head else 0,
        "ready_candidate_paths": ready_paths,
        "current_ready_candidate_paths": current_ready_paths,
        "current_ready_candidate_summaries": current_ready_summaries,
        "current_ready_worker_ids": sorted(current_ready_worker_counts),
        "current_ready_candidate_count_by_worker": current_ready_worker_counts,
        "safe_to_run_without_user_approval": any_safe_without_approval,
        "cleanup_executed": any_cleanup_executed,
        "contract_errors": approval_readiness_errors(rows),
    }


def validate_contract(contract: dict[str, Any], head: str) -> None:
    if contract.get("schema_version") != "v1":
        contract_errors.append("contract schema_version must be v1")
    if contract.get("manifest_id") != "rch_remote_admissibility_preflight":
        contract_errors.append("contract manifest_id mismatch")
    if contract.get("bead") != "bd-fmnv9":
        contract_errors.append("contract bead must be bd-fmnv9")
    if contract.get("upstream_bead") != "bd-xkykd":
        contract_errors.append("contract upstream_bead must be bd-xkykd")
    source_commit = contract.get("source_commit")
    if not (source_commit == "current" or is_hex_commit(source_commit)):
        contract_errors.append("contract source_commit must be 'current' or 40-hex")
    elif not source_commit_current(source_commit, head):
        contract_errors.append("contract source_commit is stale")
    expected_inputs = {
        "checker": "scripts/check_rch_remote_admissibility.sh",
        "approval_packet_generator": "scripts/generate_rch_pressure_approval_packet.sh",
    }
    if contract.get("inputs") != expected_inputs:
        contract_errors.append("contract inputs mismatch")
    for key, value in expected_inputs.items():
        repo_path(contract.get("inputs", {}).get(key), f"inputs.{key}")
    preflight = contract.get("preflight_contract", {})
    if not isinstance(preflight, dict):
        contract_errors.append("preflight_contract: must be an object")
        preflight = {}
    for field in [
        "admissible_status",
        "blocked_status",
        "diagnose_failed_status",
        "required_remote_env",
        "local_fallback_policy",
    ]:
        if not isinstance(preflight.get(field), str) or not preflight.get(field):
            contract_errors.append(f"preflight_contract.{field}: must be a non-empty string")
    string_list(preflight.get("allowed_statuses"), "preflight_contract.allowed_statuses", min_len=3)
    current_cfg = contract.get("current_blocked_state", {})
    if not isinstance(current_cfg, dict):
        contract_errors.append("current_blocked_state: must be an object")
    else:
        string_list(current_cfg.get("required_failure_signatures"), "current_blocked_state.required_failure_signatures")
        if current_cfg.get("expected_field_value") != preflight.get("blocked_status", "blocked"):
            contract_errors.append("current_blocked_state.expected_field_value must match blocked_status")
    configured_report_fields(contract)
    contract_errors.extend(report_contract_errors(contract, REPORT, LOG))
    for idx, control in enumerate(contract.get("negative_controls", [])):
        if not isinstance(control, dict):
            contract_errors.append(f"negative_controls[{idx}]: must be an object")


stdout = read_text(DRY_RUN_STDOUT)
stderr = read_text(DRY_RUN_STDERR)
dry_run_status = read_status(DRY_RUN_STATUS)
combined = f"{stdout}\n{stderr}"

failure_signatures: list[str] = []
if "[RCH] local" in combined:
    failure_signatures.append("local_fallback_marker")
if "remote required; refusing local fallback" in combined:
    failure_signatures.append("remote_required_refusal")
if "Skip:" in stdout and "worker selection" in stdout.lower():
    failure_signatures.append("worker_selection_skipped")
elif "Skip: no admissible workers" in stdout:
    failure_signatures.append("worker_selection_skipped")
if "no admissible workers" in combined:
    failure_signatures.append("no_admissible_workers")
if "critical_pressure" in combined:
    failure_signatures.append("critical_pressure")
if "RCH-E100" in combined:
    failure_signatures.append("RCH-E100")
if "Would offload:" not in stdout:
    failure_signatures.append("missing_offload_classification")
elif "YES" not in stdout:
    failure_signatures.append("not_classified_for_offload")

status = classify_status(failure_signatures, dry_run_status)
exit_code = 0 if status == "admissible" else 2

head = current_commit()
contract = load_json(CONTRACT)
validate_contract(contract, head)
preflight_contract = contract.get("preflight_contract", {})
if not isinstance(preflight_contract, dict):
    preflight_contract = {}
report_contract_fields = configured_report_fields(contract)
status_on_current_blocked_state = current_blocked_field(contract, status, sorted(set(failure_signatures)))

negative_results: list[dict[str, Any]] = []
for control in contract.get("negative_controls", []):
    if not isinstance(control, dict):
        continue
    control_id = control.get("control_id")
    expected = control.get("expected_decision")
    observed = "unknown_negative_control"
    if control_id == "local_fallback_signature_blocks":
        observed = classify_status(["local_fallback_marker"], 0)
    elif control_id == "diagnose_failure_blocks":
        observed = classify_status([], 1)
    elif control_id == "admissible_without_failures_passes":
        observed = classify_status([], 0)
    elif control_id == "missing_report_field_fails":
        observed = (
            "missing_report_field"
            if missing_report_fields(contract, {"status": status})
            else "no_missing_report_field"
        )
    elif control_id == "output_path_mismatch_fails":
        mutated = copy.deepcopy(contract)
        mutated.setdefault("report_contract", {})["output_path"] = "target/rch-remote-admissibility/wrong.report.json"
        observed_errors = report_contract_errors(mutated, REPORT, LOG)
        observed = (
            "report_contract_output_path_mismatch"
            if "report_contract_output_path_mismatch" in observed_errors
            else ",".join(observed_errors)
        )
    elif control_id == "log_path_mismatch_fails":
        mutated = copy.deepcopy(contract)
        mutated.setdefault("report_contract", {})["log_path"] = "target/rch-remote-admissibility/wrong.log.jsonl"
        observed_errors = report_contract_errors(mutated, REPORT, LOG)
        observed = (
            "report_contract_log_path_mismatch"
            if "report_contract_log_path_mismatch" in observed_errors
            else ",".join(observed_errors)
        )
    elif control_id == "missing_required_signature_current_state_fails":
        synthetic_report = {
            "status": preflight_contract.get("blocked_status", "blocked"),
            "failure_signatures": ["critical_pressure"],
            "status_on_current_blocked_state": preflight_contract.get("blocked_status", "blocked"),
        }
        observed_errors = current_blocked_errors(contract, synthetic_report)
        observed = (
            "current_blocked_required_signature_missing"
            if "current_blocked_required_signature_missing" in observed_errors
            else ",".join(observed_errors)
        )
    elif control_id == "approval_readiness_claims_safe_without_permission_fails":
        observed_errors = approval_readiness_errors(
            [
                {
                    "safe_to_run_without_user_approval": True,
                    "exact_user_approval_required": True,
                    "cleanup_executed": False,
                }
            ]
        )
        observed = (
            "approval_readiness_claims_safe_without_user_approval"
            if any("claims_safe_without_user_approval" in item for item in observed_errors)
            else ",".join(observed_errors)
        )
    elif control_id == "stale_approval_packet_has_no_current_ready_candidates":
        synthetic = {
            "packet_id": "synthetic-stale-packet",
            "generated_at_utc": "2000-01-01T00:00:00Z",
            "repo_state": {"head_commit": "0" * 40, "branch": "main"},
            "approval_readiness": [
                {
                    "path": "/data/projects/example/target",
                    "approval_state": "ready_for_explicit_user_approval",
                    "safe_to_run_without_user_approval": False,
                    "exact_user_approval_required": True,
                    "cleanup_executed": False,
                }
            ],
        }
        summary = approval_packet_summary(synthetic, "1" * 40)
        observed = (
            "stale_for_current_head"
            if summary.get("status") == "stale_for_current_head"
            and summary.get("current_ready_for_explicit_user_approval_count") == 0
            and summary.get("current_ready_candidate_paths") == []
            and summary.get("current_ready_candidate_summaries") == []
            and summary.get("current_ready_worker_ids") == []
            and summary.get("current_ready_candidate_count_by_worker") == {}
            and summary.get("operator_next_action") == "regenerate_approval_packet_for_current_head"
            else str(summary)
        )
    elif control_id == "packet_candidate_diagnostics_missing_is_reported":
        synthetic = {
            "packet_id": "synthetic-current-packet-without-diagnostics",
            "repo_state": {"head_commit": head, "branch": "main"},
            "approval_readiness": [],
        }
        summary = approval_packet_summary(synthetic, head)
        diagnostics = summary.get("packet_candidate_diagnostics")
        observed = (
            "packet_candidate_diagnostics_missing"
            if isinstance(diagnostics, dict)
            and diagnostics.get("status") == "missing"
            and summary.get("operator_next_action") == "inspect_approval_packet_blockers"
            else str(summary)
        )
    elif control_id == "approval_boundary_never_claims_cleanup_execution":
        synthetic = {
            "packet_id": "synthetic-current-packet-with-boundary",
            "repo_state": {"head_commit": head, "branch": "main"},
            "approval_readiness": [],
            "approval_request": {
                "explicit_user_text_required_before_cleanup": "approval required",
                "commands_not_executed": ["no deletion command executed"],
            },
        }
        summary = approval_packet_summary(synthetic, head)
        boundary = summary.get("approval_boundary")
        observed = (
            "approval_boundary_never_claims_cleanup_execution"
            if isinstance(boundary, dict)
            and boundary.get("safe_to_run_without_user_approval") is False
            and boundary.get("cleanup_executed") is False
            and boundary.get("commands_not_executed") == ["no deletion command executed"]
            else str(summary)
        )
    else:
        contract_errors.append(f"unknown negative control {control_id}")
    passed = observed == expected
    if not passed:
        contract_errors.append(f"negative_control_failed:{control_id}: expected {expected}, got {observed}")
    negative_results.append(
        {
            "control_id": control_id,
            "expected_decision": expected,
            "observed_decision": observed,
            "status": "pass" if passed else "fail",
        }
    )

approval_packet = load_optional_json(APPROVAL_PACKET_REPORT)
approval_summary = approval_packet_summary(approval_packet, head)

report: dict[str, Any] = {
    "schema_version": "rch_remote_admissibility_preflight.v1",
    "bead": "bd-xkykd",
    "contract_bead": "bd-fmnv9",
    "generated_at_utc": utc_now(),
    "source_commit": contract.get("source_commit"),
    "current_head": head,
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "validation_command": VALIDATION_COMMAND,
    "required_remote_env": preflight_contract.get("required_remote_env", "RCH_REQUIRE_REMOTE=1"),
    "dry_run": {
        "stdout_path": rel(DRY_RUN_STDOUT),
        "stderr_path": rel(DRY_RUN_STDERR),
        "exit_status": dry_run_status,
        "would_offload_seen": "Would offload:" in stdout,
        "worker_selection_skipped": "Skip:" in stdout,
    },
    "status": status,
    "failure_signatures": sorted(set(failure_signatures)),
    "approval_packet_command": str(APPROVAL_PACKET_SCRIPT),
    "approval_packet_report_path": rel(APPROVAL_PACKET_REPORT),
    "approval_packet_markdown_path": rel(APPROVAL_PACKET_MARKDOWN),
    "approval_readiness_summary": approval_summary,
    "operator_message": (
        "Remote rch admissibility is blocked. Follow approval_readiness_summary.operator_next_action before attempting cargo validation."
        if status != "admissible"
        else "Remote rch admissibility preflight passed."
    ),
    "local_fallback_policy": preflight_contract.get(
        "local_fallback_policy",
        "[RCH] local is never accepted as validation proof.",
    ),
    "status_on_current_blocked_state": status_on_current_blocked_state,
    "report_contract_fields": report_contract_fields,
    "negative_controls": negative_results,
    "contract_status": "pass",
    "contract_errors": [],
}
contract_errors.extend(current_blocked_errors(contract, report))
contract_errors.extend(f"approval_packet:{item}" for item in approval_summary.get("contract_errors", []))
missing_fields = missing_report_fields(contract, report)
if missing_fields:
    contract_errors.append(f"missing_report_field:{','.join(missing_fields)}")
allowed_statuses = set(
    item
    for item in preflight_contract.get("allowed_statuses", [])
    if isinstance(item, str) and item
)
if allowed_statuses and status not in allowed_statuses:
    contract_errors.append(f"status_not_allowed:{status}")
if report.get("required_remote_env") != "RCH_REQUIRE_REMOTE=1":
    contract_errors.append("required_remote_env_mismatch")
if "[RCH] local" not in str(report.get("local_fallback_policy", "")):
    contract_errors.append("local_fallback_policy_mismatch")
report["contract_status"] = "pass" if not contract_errors else "fail"
report["contract_errors"] = contract_errors

event = {
    "schema_version": "rch_remote_admissibility_preflight.event.v1",
    "trace_id": "bd-xkykd::rch-remote-admissibility",
    "generated_at_utc": report["generated_at_utc"],
    "status": status,
    "contract_status": report["contract_status"],
    "failure_signatures": report["failure_signatures"],
    "validation_command": VALIDATION_COMMAND,
}

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

if status == "admissible":
    print(f"rch remote admissibility preflight passed for: {VALIDATION_COMMAND}")
else:
    ready_count = approval_summary.get("current_ready_for_explicit_user_approval_count", 0)
    approval_packet_status = approval_summary.get("status", "unknown")
    operator_next_action = approval_summary.get("operator_next_action", "unknown")
    operator_next_command = approval_summary.get("operator_next_command")
    operator_hint = (
        f" operator_next_command={operator_next_command}."
        if isinstance(operator_next_command, str) and operator_next_command
        else ""
    )
    print(
        "rch remote admissibility preflight blocked; follow "
        f"operator_next_action={operator_next_action}."
        f"{operator_hint} "
        f"approval_packet_status={approval_packet_status}. "
        f"approval_ready_candidates={ready_count}. "
        f"failure_signatures={','.join(report['failure_signatures'])}",
        file=sys.stderr,
    )
if contract_errors:
    print(
        "rch remote admissibility preflight contract failed: "
        + "; ".join(contract_errors),
        file=sys.stderr,
    )
    sys.exit(1)
sys.exit(exit_code)
PY
