#!/usr/bin/env bash
# Fail-closed preflight for cargo validation lanes that must use rch remotely.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RCH_PREFLIGHT_CONTRACT:-${ROOT}/tests/conformance/rch_remote_admissibility_preflight.v1.json}"
OUT_DIR="${FRANKENLIBC_RCH_PREFLIGHT_OUT_DIR:-${ROOT}/target/rch-remote-admissibility}"
REPORT="${FRANKENLIBC_RCH_PREFLIGHT_REPORT:-${OUT_DIR}/rch_remote_admissibility.report.json}"
LOG="${FRANKENLIBC_RCH_PREFLIGHT_LOG:-${OUT_DIR}/rch_remote_admissibility.log.jsonl}"
APPROVAL_PACKET_SCRIPT="${ROOT}/scripts/generate_rch_pressure_approval_packet.sh"
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

python3 - "${ROOT}" "${CONTRACT}" "${VALIDATION_COMMAND}" "${DRY_RUN_STDOUT}" "${DRY_RUN_STDERR}" "${DRY_RUN_STATUS}" "${REPORT}" "${LOG}" "${APPROVAL_PACKET_SCRIPT}" <<'PY'
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
    "operator_message": (
        "Remote rch admissibility is blocked. Generate an approval packet before attempting cargo validation."
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
    print(
        "rch remote admissibility preflight blocked; run "
        f"{APPROVAL_PACKET_SCRIPT} for an approval packet. "
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
