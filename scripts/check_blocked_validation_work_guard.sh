#!/usr/bin/env bash
# Emit a fail-closed no-cargo guard for RCH-blocked validation queues.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_BLOCKED_VALIDATION_GUARD_CONTRACT:-${ROOT}/tests/conformance/blocked_validation_work_guard.v1.json}"
TRACKER="${FRANKENLIBC_TRACKER_JSONL:-${ROOT}/.beads/issues.jsonl}"
READINESS_CHECKER="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_CHECKER:-${ROOT}/scripts/check_tracker_jsonl_degraded_readiness.sh}"
READINESS_REPORT="${FRANKENLIBC_TRACKER_JSONL_DEGRADED_REPORT:-${ROOT}/target/conformance/tracker_jsonl_degraded_readiness.report.json}"
RCH_CHECKER="${FRANKENLIBC_RCH_PREFLIGHT_CHECKER:-${ROOT}/scripts/check_rch_remote_admissibility.sh}"
RCH_REPORT="${FRANKENLIBC_RCH_PREFLIGHT_REPORT:-${ROOT}/target/rch-remote-admissibility/rch_remote_admissibility.report.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_BLOCKED_VALIDATION_GUARD_REPORT:-${OUT_DIR}/blocked_validation_work_guard.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

bash "${READINESS_CHECKER}" --validate-only >/dev/null
set +e
env RCH_REQUIRE_REMOTE=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS="${RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS:-30}" \
  bash "${RCH_CHECKER}" "cargo check -p frankenlibc-abi --features=standalone" >/dev/null 2>&1
rch_status=$?
set -e
if [[ "${rch_status}" != "0" && "${rch_status}" != "2" ]]; then
  echo "unexpected RCH preflight exit status ${rch_status}" >&2
  exit "${rch_status}"
fi

python3 - "${ROOT}" "${CONTRACT}" "${TRACKER}" "${READINESS_REPORT}" "${RCH_REPORT}" "${REPORT}" <<'PY'
import copy
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2])
tracker_path = Path(sys.argv[3])
readiness_report_path = Path(sys.argv[4])
rch_report_path = Path(sys.argv[5])
report_path = Path(sys.argv[6])
for name in [
    "contract_path",
    "tracker_path",
    "readiness_report_path",
    "rch_report_path",
    "report_path",
]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

errors = []


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


def load_jsonl(path):
    rows = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except Exception as exc:
                    errors.append(f"{path}:{line_no}: invalid json: {exc}")
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except Exception as exc:
        errors.append(f"{path}: {exc}")
    return rows


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


def git_status_short_lines():
    try:
        output = subprocess.check_output(
            ["git", "status", "--short", "--untracked-files=all"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    return [line for line in output.splitlines() if line.strip()]


def status_path(line):
    if not isinstance(line, str) or len(line) < 4:
        return None
    raw = line[3:].strip()
    if " -> " in raw:
        raw = raw.rsplit(" -> ", 1)[1].strip()
    return raw.strip('"') or None


def is_validation_path(path, guard):
    prefixes = guard.get("dirty_validation_path_prefixes", [])
    files = guard.get("dirty_validation_path_files", [])
    if not isinstance(prefixes, list):
        prefixes = []
    if not isinstance(files, list):
        files = []
    return any(isinstance(prefix, str) and path.startswith(prefix) for prefix in prefixes) or path in {
        item for item in files if isinstance(item, str)
    }


def dirty_validation_paths(status_lines, guard):
    rows = []
    seen = set()
    for line in status_lines:
        path = status_path(line)
        if path is None or not is_validation_path(path, guard):
            continue
        key = (line[:2].strip() or "modified", path)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"status_code": key[0], "path": path})
    return sorted(rows, key=lambda row: (row["path"], row["status_code"]))


def is_hex_commit(value):
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def source_commit_current(value, head):
    return value == "current" or (head != "unknown" and value == head)


def repo_path(value, context):
    if not isinstance(value, str) or not value:
        errors.append(f"{context}: must be a non-empty repo-relative path")
        return
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: path must stay repo-relative: {value}")
        return
    if not (root / path).exists():
        errors.append(f"{context}: missing path {value}")


def repo_relative(path):
    try:
        return path.resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


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


def configured_report_fields(contract):
    report_contract = contract.get("report_contract", {})
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize", [])
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def missing_report_fields(contract, report):
    return [field for field in configured_report_fields(contract) if field not in report]


def report_contract_errors(contract, actual_report_path, expected_status):
    local_errors = []
    report_contract = contract.get("report_contract", {})
    if not isinstance(report_contract, dict):
        return ["report_contract_not_object"]
    expected_output = report_contract.get("output_path")
    if not isinstance(expected_output, str) or not expected_output:
        local_errors.append("report_contract_output_path_missing")
    else:
        path = Path(expected_output)
        if path.is_absolute() or ".." in path.parts:
            local_errors.append("report_contract_output_path_not_repo_relative")
        elif repo_relative(actual_report_path) != expected_output:
            local_errors.append("report_contract_output_path_mismatch")
    expected_current = report_contract.get("status_on_current_blocked_state")
    if expected_current != expected_status:
        local_errors.append("status_on_current_blocked_state_mismatch")
    return local_errors


def active_bd716_dependents(rows, guard):
    blocker_id = guard.get("blocking_issue_id")
    dep_type = guard.get("blocked_issue_dependency_type")
    active_statuses = set(guard.get("active_statuses", []))
    dependents = []
    for row in rows:
        if row.get("id") == blocker_id or row.get("status") not in active_statuses:
            continue
        dependencies = row.get("dependencies", [])
        if not isinstance(dependencies, list):
            continue
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            dep_id = dep.get("depends_on_id") or dep.get("id")
            kind = dep.get("type") or dep.get("dependency_type")
            if dep_id == blocker_id and kind == dep_type:
                dependents.append(
                    {
                        "id": row.get("id"),
                        "title": row.get("title"),
                        "status": row.get("status"),
                        "priority": row.get("priority"),
                        "assignee": row.get("assignee"),
                    }
                )
                break
    return sorted(dependents, key=lambda item: (item.get("priority") is None, item.get("priority"), item.get("id") or ""))


def decide(readiness, rch, dependents, guard):
    stale_in_progress = readiness.get("stale_in_progress", [])
    if not isinstance(stale_in_progress, list):
        stale_in_progress = []
    safe_ready = readiness.get("safe_ready", [])
    if not isinstance(safe_ready, list):
        safe_ready = []
    signatures = set(rch.get("failure_signatures", []))
    required_signatures = set(guard.get("required_blocked_failure_signatures", []))
    rch_status = rch.get("status")
    rch_blocked = rch_status == guard.get("blocked_rch_status") and required_signatures.issubset(signatures)
    if stale_in_progress:
        return guard.get("decision_when_stale_in_progress_exists")
    if safe_ready:
        return guard.get("decision_when_safe_ready_exists")
    if rch_status == "admissible":
        return guard.get("decision_when_rch_admissible")
    if rch_blocked and dependents:
        return guard.get("decision_when_rch_blocked_and_dependents_waiting")
    return "no_guard_needed"


head = current_commit()
contract = load_json(contract_path)
rows = load_jsonl(tracker_path)
readiness = load_json(readiness_report_path)
rch = load_json(rch_report_path)

if contract.get("schema_version") != "v1":
    errors.append("contract schema_version must be v1")
if contract.get("manifest_id") != "blocked_validation_work_guard":
    errors.append("contract manifest_id mismatch")
if contract.get("bead") != "bd-bqh1f":
    errors.append("contract bead must be bd-bqh1f")
source_commit = contract.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("contract source_commit must be 'current' or 40-hex")
elif not source_commit_current(source_commit, head):
    errors.append("contract source_commit is stale")

expected_inputs = {
    "tracker_jsonl": ".beads/issues.jsonl",
    "tracker_jsonl_degraded_readiness_checker": "scripts/check_tracker_jsonl_degraded_readiness.sh",
    "rch_remote_admissibility_checker": "scripts/check_rch_remote_admissibility.sh",
    "tracker_jsonl_degraded_readiness_report": "target/conformance/tracker_jsonl_degraded_readiness.report.json",
    "rch_remote_admissibility_report": "target/rch-remote-admissibility/rch_remote_admissibility.report.json",
}
if contract.get("inputs") != expected_inputs:
    errors.append("contract inputs mismatch")
for key, value in expected_inputs.items():
    repo_path(contract.get("inputs", {}).get(key), f"inputs.{key}")

guard = contract.get("guard_contract", {})
if not isinstance(guard, dict):
    errors.append("guard_contract must be object")
    guard = {}
required = set(string_list(guard.get("required_blocked_failure_signatures"), "guard_contract.required_blocked_failure_signatures"))
string_list(guard.get("dirty_validation_path_prefixes"), "guard_contract.dirty_validation_path_prefixes")
string_list(guard.get("dirty_validation_path_files"), "guard_contract.dirty_validation_path_files")
signatures = set(rch.get("failure_signatures", []))
if rch.get("status") == guard.get("blocked_rch_status") and not required.issubset(signatures):
    errors.append("blocked RCH report missing required failure signatures")
if readiness.get("status") != "pass":
    errors.append("tracker degraded readiness report must pass")
if not isinstance(readiness.get("safe_ready"), list):
    errors.append("readiness.safe_ready must be an array")
if not isinstance(readiness.get("permissioned_ready"), list):
    errors.append("readiness.permissioned_ready must be an array")

dependents = active_bd716_dependents(rows, guard)
decision = decide(readiness, rch, dependents, guard)
dirty_paths = dirty_validation_paths(git_status_short_lines(), guard)
expected_current = guard.get("decision_when_rch_blocked_and_dependents_waiting")
if decision != expected_current:
    errors.append(f"current guard decision {decision!r} did not match expected blocked decision {expected_current!r}")
contract_report_errors = report_contract_errors(contract, report_path, "pass")
errors.extend(contract_report_errors)
must_materialize = string_list(
    contract.get("report_contract", {}).get("must_materialize"),
    "report_contract.must_materialize",
)

negative_results = []
for control in contract.get("negative_controls", []):
    if not isinstance(control, dict):
        errors.append("negative control row must be object")
        continue
    control_id = control.get("control_id")
    expected_decision = control.get("expected_decision")
    mutated_readiness = copy.deepcopy(readiness)
    mutated_rch = copy.deepcopy(rch)
    mutated_dependents = copy.deepcopy(dependents)
    mutated_contract = copy.deepcopy(contract)

    if control_id == "rch_admissible_changes_decision":
        mutated_rch["status"] = "admissible"
        mutated_rch["failure_signatures"] = []
    elif control_id == "output_path_mismatch_fails":
        mutated_contract.setdefault("report_contract", {})["output_path"] = "target/conformance/wrong_guard_path.json"
        observed_errors = report_contract_errors(mutated_contract, report_path, "pass")
        observed = (
            "report_contract_output_path_mismatch"
            if "report_contract_output_path_mismatch" in observed_errors
            else ",".join(observed_errors)
        )
        passed = observed == expected_decision
        if not passed:
            errors.append(f"negative_control_failed:{control_id}: expected {expected_decision}, got {observed}")
        negative_results.append(
            {
                "control_id": control_id,
                "expected_decision": expected_decision,
                "observed_decision": observed,
                "status": "pass" if passed else "fail",
            }
        )
        continue
    elif control_id == "bad_current_status_fails":
        mutated_contract.setdefault("report_contract", {})["status_on_current_blocked_state"] = "fail"
        observed_errors = report_contract_errors(mutated_contract, report_path, "pass")
        observed = (
            "status_on_current_blocked_state_mismatch"
            if "status_on_current_blocked_state_mismatch" in observed_errors
            else ",".join(observed_errors)
        )
        passed = observed == expected_decision
        if not passed:
            errors.append(f"negative_control_failed:{control_id}: expected {expected_decision}, got {observed}")
        negative_results.append(
            {
                "control_id": control_id,
                "expected_decision": expected_decision,
                "observed_decision": observed,
                "status": "pass" if passed else "fail",
            }
        )
        continue
    elif control_id == "missing_report_field_fails":
        observed = (
            "missing_report_field"
            if missing_report_fields(contract, {"decision": decision})
            else "no_missing_report_field"
        )
        passed = observed == expected_decision
        if not passed:
            errors.append(f"negative_control_failed:{control_id}: expected {expected_decision}, got {observed}")
        negative_results.append(
            {
                "control_id": control_id,
                "expected_decision": expected_decision,
                "observed_decision": observed,
                "status": "pass" if passed else "fail",
            }
        )
        continue
    elif control_id == "safe_ready_changes_decision":
        mutated_readiness["safe_ready"] = [
            {
                "id": "bd-example-safe-ready",
                "title": "synthetic safe ready row",
                "status": "open",
                "permission_required": False,
            }
        ]
    elif control_id == "stale_in_progress_changes_decision":
        mutated_readiness["stale_in_progress"] = [
            {
                "id": "bd-example-stale",
                "title": "synthetic stale in-progress row",
                "status": "in_progress",
                "latest_activity_source": "updated_at",
            }
        ]
    elif control_id == "no_waiting_dependents_removes_guard":
        mutated_dependents = []
    elif control_id == "dirty_validation_path_counted":
        synthetic_dirty = dirty_validation_paths(
            [
                " M crates/frankenlibc-abi/src/resolv_abi.rs",
                "?? tests/conformance/synthetic_validation_manifest.v1.json",
                "?? =",
            ],
            guard,
        )
        observed = "dirty_validation_path_counted" if len(synthetic_dirty) == 2 else f"dirty_count_{len(synthetic_dirty)}"
        passed = observed == expected_decision
        if not passed:
            errors.append(f"negative_control_failed:{control_id}: expected {expected_decision}, got {observed}")
        negative_results.append(
            {
                "control_id": control_id,
                "expected_decision": expected_decision,
                "observed_decision": observed,
                "status": "pass" if passed else "fail",
            }
        )
        continue
    else:
        errors.append(f"unknown negative control {control_id}")
        continue

    observed = decide(mutated_readiness, mutated_rch, mutated_dependents, guard)
    passed = observed == expected_decision
    if not passed:
        errors.append(f"negative_control_failed:{control_id}: expected {expected_decision}, got {observed}")
    negative_results.append(
        {
            "control_id": control_id,
            "expected_decision": expected_decision,
            "observed_decision": observed,
            "status": "pass" if passed else "fail",
        }
    )

safe_ready = readiness.get("safe_ready") if isinstance(readiness.get("safe_ready"), list) else []
permissioned_ready = (
    readiness.get("permissioned_ready") if isinstance(readiness.get("permissioned_ready"), list) else []
)
stale_in_progress = (
    readiness.get("stale_in_progress") if isinstance(readiness.get("stale_in_progress"), list) else []
)
report = {
    "schema_version": "blocked_validation_work_guard.report.v1",
    "bead": "bd-bqh1f",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "current_head": head,
    "report_path": repo_relative(report_path),
    "status_on_current_blocked_state": contract.get("report_contract", {}).get("status_on_current_blocked_state"),
    "decision": decision,
    "safe_ready_count": len(safe_ready),
    "safe_ready_ids": [row.get("id") for row in safe_ready if isinstance(row, dict)],
    "permissioned_ready_count": len(permissioned_ready),
    "permissioned_ready_ids": [row.get("id") for row in permissioned_ready if isinstance(row, dict)],
    "stale_in_progress_count": len(stale_in_progress),
    "stale_in_progress_ids": [row.get("id") for row in stale_in_progress if isinstance(row, dict)],
    "rch_status": rch.get("status"),
    "failure_signatures": sorted(signatures),
    "blocked_validation_issue_ids": [row.get("id") for row in dependents],
    "blocked_validation_issues": dependents,
    "dirty_validation_path_count": len(dirty_paths),
    "dirty_validation_paths": dirty_paths,
    "dirty_validation_blocked": bool(dirty_paths and decision == expected_current),
    "allowed_next_actions": guard.get("allowed_next_actions_when_blocked", []),
    "forbidden_next_actions": guard.get("forbidden_next_actions_when_blocked", []),
    "report_contract_fields": must_materialize,
    "negative_controls": negative_results,
    "errors": errors,
}
missing_fields = missing_report_fields(contract, report)
if missing_fields:
    errors.append(f"missing_report_field:{','.join(missing_fields)}")
report["status"] = "pass" if not errors else "fail"
report["errors"] = errors
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
