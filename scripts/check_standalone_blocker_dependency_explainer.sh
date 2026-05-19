#!/usr/bin/env bash
# Validate the standalone blocker dependency explainer for bd-i1fwe.
# Refreshed by bd-kh0jc after the bd-716tv RCH blocker retired.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STANDALONE_BLOCKER_EXPLAINER:-${ROOT}/tests/conformance/standalone_blocker_dependency_explainer.v1.json}"
DAG="${FRANKENLIBC_STANDALONE_BLOCKER_DAG:-${ROOT}/tests/conformance/standalone_blocker_burndown_dag.v1.json}"
ROLLUP="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP:-${ROOT}/tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json}"
ROLLUP_CHECKER="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_CHECKER:-${ROOT}/scripts/check_standalone_blocker_burndown_progress_rollup.sh}"
ROLLUP_REPORT="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_REPORT:-${ROOT}/target/conformance/standalone_blocker_burndown_progress_rollup.report.json}"
UNWINDER_SURFACE="${FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE:-${ROOT}/tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json}"
TLS_SURFACE="${FRANKENLIBC_STANDALONE_OWNED_TLS_SURFACE:-${ROOT}/tests/conformance/standalone_owned_tls_startup_surface.v1.json}"
TRACKER="${FRANKENLIBC_TRACKER_JSONL:-${ROOT}/.beads/issues.jsonl}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_BLOCKER_EXPLAINER_REPORT:-${OUT_DIR}/standalone_blocker_dependency_explainer.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${CONTRACT}" "${DAG}" "${ROLLUP}" "${ROLLUP_CHECKER}" "${ROLLUP_REPORT}" "${UNWINDER_SURFACE}" "${TLS_SURFACE}" "${TRACKER}" "${REPORT}" <<'PY'
import copy
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2])
dag_path = Path(sys.argv[3])
rollup_path = Path(sys.argv[4])
rollup_checker_path = Path(sys.argv[5])
rollup_report_path = Path(sys.argv[6])
unwinder_surface_path = Path(sys.argv[7])
tls_surface_path = Path(sys.argv[8])
tracker_path = Path(sys.argv[9])
report_path = Path(sys.argv[10])

for name in [
    "contract_path",
    "dag_path",
    "rollup_path",
    "rollup_checker_path",
    "rollup_report_path",
    "unwinder_surface_path",
    "tls_surface_path",
    "tracker_path",
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


def load_jsonl_by_id(path):
    result = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    errors.append(f"{path}:{line_no}: invalid json: {exc}")
                    continue
                row_id = row.get("id")
                if isinstance(row_id, str) and row_id:
                    result[row_id] = row
    except Exception as exc:
        errors.append(f"{path}: {exc}")
    return result


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


def list_of_strings(value, context, *, min_len=1):
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


def issue_depends_on(issue, dependency_id, dep_type):
    deps = issue.get("dependencies", [])
    if not isinstance(deps, list):
        return False
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        candidate_id = dep.get("depends_on_id") or dep.get("id")
        candidate_type = dep.get("type") or dep.get("dependency_type")
        if candidate_id == dependency_id and candidate_type == dep_type:
            return True
    return False


def validate_live_action_row_sources(contract, rollup, surfaces):
    local_errors = []
    rows = []
    source_contract = contract.get("live_action_row_source_contract", {})
    required_sources = source_contract.get("required_sources", [])
    if not isinstance(required_sources, list) or not required_sources:
        local_errors.append("live_action_row_sources_missing")
        return local_errors, rows

    experiments = rollup.get("partial_burndown_experiments", [])
    if not isinstance(experiments, list):
        experiments = []

    for spec in required_sources:
        if not isinstance(spec, dict):
            local_errors.append("live_action_row_source_not_object")
            continue
        category_id = spec.get("category_id")
        experiment_id = spec.get("experiment_id")
        surface_input = spec.get("surface_input")
        expected_manifest = spec.get("surface_manifest_id")
        expected_source_row = spec.get("source_action_row")
        surface = surfaces.get(surface_input)
        if not isinstance(surface, dict):
            local_errors.append(f"surface_missing:{category_id}")
            surface = {}
        if surface.get("manifest_id") != expected_manifest:
            local_errors.append(f"surface_manifest_mismatch:{category_id}")

        observed_source_row = surface.get("source_action_row")
        if not isinstance(observed_source_row, str) or not observed_source_row:
            local_errors.append(f"source_action_row_missing:{category_id}")
        elif observed_source_row != expected_source_row:
            local_errors.append(f"source_action_row_drift:{category_id}")

        policy = surface.get("report_policy", {})
        if not isinstance(policy, dict):
            local_errors.append(f"surface_report_policy_missing:{category_id}")
            policy = {}
        if policy.get("report_only") is not True:
            local_errors.append(f"surface_not_report_only:{category_id}")
        if policy.get("promotion_allowed") is not False:
            local_errors.append(f"surface_allows_promotion:{category_id}")
        if policy.get("default_forge_path_change_allowed") is not False:
            local_errors.append(f"surface_allows_default_forge_change:{category_id}")

        summary = surface.get("summary", {})
        if not isinstance(summary, dict):
            local_errors.append(f"surface_summary_missing:{category_id}")
            summary = {}
        if summary.get("owned_surface_ready") is not spec.get("owned_surface_ready"):
            local_errors.append(f"surface_ready_state_mismatch:{category_id}")
        if summary.get("promotion_allowed") is not spec.get("promotion_allowed"):
            local_errors.append(f"surface_summary_promotion_mismatch:{category_id}")

        experiment = next(
            (
                row
                for row in experiments
                if isinstance(row, dict)
                and row.get("experiment_id") == experiment_id
                and row.get("category_id") == category_id
            ),
            None,
        )
        if experiment is None:
            local_errors.append(f"rollup_experiment_missing_live_source:{category_id}")
            experiment = {}

        rows.append(
            {
                "category_id": category_id,
                "experiment_id": experiment_id,
                "rollup_source_manifest": experiment.get("source_manifest"),
                "surface_input": surface_input,
                "surface_manifest_id": surface.get("manifest_id"),
                "source_manifest": spec.get("source_manifest"),
                "source_action_row": observed_source_row,
                "report_only": policy.get("report_only"),
                "promotion_allowed": policy.get("promotion_allowed"),
                "owned_surface_ready": summary.get("owned_surface_ready"),
            }
        )

    return local_errors, rows


def validate_state(contract, dag, rollup, rollup_report, tracker, surfaces):
    local_errors = []

    target_contract = contract.get("target_issue_contract", {})
    claim_contract = contract.get("standalone_claim_contract", {})
    target_id = target_contract.get("target_issue_id")
    blocker_id = target_contract.get("retired_blocker_issue_id")
    dep_type = target_contract.get("retired_dependency_type")

    target_issue = tracker.get(target_id)
    blocker_issue = tracker.get(blocker_id)
    if not isinstance(target_issue, dict):
        local_errors.append("target_issue_missing")
        target_issue = {}
    if not isinstance(blocker_issue, dict):
        local_errors.append("required_blocker_issue_missing")
        blocker_issue = {}

    expected_target_status = target_contract.get("target_issue_must_remain_status")
    if target_issue.get("status") != expected_target_status:
        local_errors.append("target_status_not_in_progress")
    expected_blocker_status = target_contract.get("retired_blocker_issue_status")
    if blocker_issue.get("status") != expected_blocker_status:
        local_errors.append("retired_blocker_status_not_closed")
    if issue_depends_on(target_issue, blocker_id, dep_type):
        local_errors.append("target_has_retired_dependency")

    if rollup_report.get("status") != "pass":
        local_errors.append("rollup_report_not_pass")
    expected_claim = claim_contract.get("rollup_claim_status")
    if rollup_report.get("claim_status") != expected_claim:
        local_errors.append("standalone_claim_status_not_blocked")

    summary = rollup_report.get("summary", {})
    if summary.get("promotion_allowed") is not False:
        local_errors.append("rollup_allows_promotion")
    if summary.get("current_blocking_reason_count", 0) < claim_contract.get(
        "minimum_current_blocking_reason_count", 0
    ):
        local_errors.append("too_few_current_blocking_reasons")
    if summary.get("blocked_progress_category_count", 0) < claim_contract.get(
        "minimum_blocked_progress_category_count", 0
    ):
        local_errors.append("too_few_blocked_progress_categories")

    dag_nodes = dag.get("nodes", [])
    if not isinstance(dag_nodes, list):
        local_errors.append("dag_nodes_not_array")
        dag_nodes = []
    required_key = claim_contract.get("required_dag_dedupe_key")
    dag_node = next(
        (node for node in dag_nodes if isinstance(node, dict) and node.get("dedupe_key") == required_key),
        None,
    )
    if dag_node is None:
        local_errors.append("required_dag_node_missing")
        dag_node = {}
    if dag_node.get("validation_lane") != claim_contract.get("required_validation_lane"):
        local_errors.append("dag_validation_lane_mismatch")
    if dag_node.get("suggested_title") != target_issue.get("title"):
        local_errors.append("dag_target_title_mismatch")

    required_experiments = set(
        list_of_strings(
            claim_contract.get("required_partial_experiments"),
            "standalone_claim_contract.required_partial_experiments",
        )
    )
    rollup_experiments = rollup.get("partial_burndown_experiments", [])
    if not isinstance(rollup_experiments, list):
        local_errors.append("rollup_partial_experiments_not_array")
        rollup_experiments = []
    experiment_ids = {
        row.get("experiment_id")
        for row in rollup_experiments
        if isinstance(row, dict) and isinstance(row.get("experiment_id"), str)
    }
    if experiment_ids != required_experiments:
        local_errors.append("partial_experiment_set_mismatch")
    for row in rollup_experiments:
        if not isinstance(row, dict):
            local_errors.append("partial_experiment_row_not_object")
            continue
        experiment_id = row.get("experiment_id", "<missing>")
        if row.get("report_only") is not True:
            local_errors.append(f"partial_experiment_not_report_only:{experiment_id}")
        if row.get("default_forge_path_unchanged") is not True:
            local_errors.append(f"partial_experiment_changes_default_forge:{experiment_id}")
        if row.get("promotion_allowed") is not False:
            local_errors.append("partial_experiment_allows_promotion")
        if row.get("replacement_level_change_allowed") is not False:
            local_errors.append(f"partial_experiment_allows_replacement_change:{experiment_id}")
        if row.get("status_until_default_forge_consumes_evidence") != "claim_blocked":
            local_errors.append(f"partial_experiment_not_claim_blocked:{experiment_id}")

    live_errors, live_rows = validate_live_action_row_sources(contract, rollup, surfaces)
    local_errors.extend(live_errors)

    return local_errors, live_rows


head = current_commit()
contract = load_json(contract_path)
dag = load_json(dag_path)
rollup = load_json(rollup_path)
tracker = load_jsonl_by_id(tracker_path)
surfaces = {
    "standalone_owned_unwinder_symbol_surface": load_json(unwinder_surface_path),
    "standalone_owned_tls_startup_surface": load_json(tls_surface_path),
}

if contract.get("schema_version") != "v1":
    errors.append("contract schema_version must be v1")
if contract.get("manifest_id") != "standalone_blocker_dependency_explainer":
    errors.append("contract manifest_id mismatch")
if contract.get("bead") != "bd-i1fwe":
    errors.append("contract bead must be bd-i1fwe")
if contract.get("refresh_bead") != "bd-kh0jc":
    errors.append("contract refresh_bead must be bd-kh0jc")
source_commit = contract.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("contract source_commit must be 'current' or 40-hex")
elif not source_commit_current(source_commit, head):
    errors.append("contract source_commit is stale")

inputs = contract.get("inputs", {})
expected_inputs = {
    "tracker_jsonl": ".beads/issues.jsonl",
    "standalone_blocker_burndown_dag": "tests/conformance/standalone_blocker_burndown_dag.v1.json",
    "standalone_blocker_burndown_progress_rollup": "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json",
    "standalone_blocker_burndown_progress_rollup_checker": "scripts/check_standalone_blocker_burndown_progress_rollup.sh",
    "standalone_owned_unwinder_symbol_surface": "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json",
    "standalone_owned_tls_startup_surface": "tests/conformance/standalone_owned_tls_startup_surface.v1.json",
}
if inputs != expected_inputs:
    errors.append("contract inputs mismatch")
for key, value in expected_inputs.items():
    repo_path(inputs.get(key), f"inputs.{key}")

if rollup_checker_path.exists():
    run = subprocess.run(
        ["bash", str(rollup_checker_path)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if run.returncode != 0:
        errors.append(f"rollup checker failed: {run.stderr.strip() or run.stdout.strip()}")
else:
    errors.append(f"rollup checker missing: {rollup_checker_path}")

rollup_report = load_json(rollup_report_path)
state_errors, live_action_row_sources = validate_state(
    contract,
    dag,
    rollup,
    rollup_report,
    tracker,
    surfaces,
)
errors.extend(state_errors)

negative_results = []
for control in contract.get("negative_controls", []):
    if not isinstance(control, dict):
        errors.append("negative control row must be an object")
        continue
    control_id = control.get("control_id")
    expected_error = control.get("expected_error")
    mutated_contract = copy.deepcopy(contract)
    mutated_dag = copy.deepcopy(dag)
    mutated_rollup = copy.deepcopy(rollup)
    mutated_report = copy.deepcopy(rollup_report)
    mutated_tracker = copy.deepcopy(tracker)
    mutated_surfaces = copy.deepcopy(surfaces)

    if control_id == "retired_dependency_reintroduced_fails":
        target_id = contract["target_issue_contract"]["target_issue_id"]
        blocker_id = contract["target_issue_contract"]["retired_blocker_issue_id"]
        dep_type = contract["target_issue_contract"]["retired_dependency_type"]
        target = mutated_tracker.setdefault(target_id, {})
        target.setdefault("dependencies", []).append(
            {
                "issue_id": target_id,
                "depends_on_id": blocker_id,
                "type": dep_type,
            }
        )
    elif control_id == "target_closed_before_claim_exit_fails":
        target_id = contract["target_issue_contract"]["target_issue_id"]
        mutated_tracker.setdefault(target_id, {})["status"] = "closed"
    elif control_id == "retired_blocker_reopened_fails":
        blocker_id = contract["target_issue_contract"]["retired_blocker_issue_id"]
        mutated_tracker.setdefault(blocker_id, {})["status"] = "in_progress"
    elif control_id == "report_only_experiment_promotion_fails":
        if mutated_rollup.get("partial_burndown_experiments"):
            mutated_rollup["partial_burndown_experiments"][0]["promotion_allowed"] = True
    elif control_id == "missing_live_action_row_source_fails":
        mutated_surfaces["standalone_owned_unwinder_symbol_surface"].pop("source_action_row", None)
    elif control_id == "drifted_live_action_row_source_fails":
        mutated_surfaces["standalone_owned_tls_startup_surface"][
            "source_action_row"
        ] = "standalone_forge_blocker_owner_action_ledger.current_blocker_values.undefined_tls_symbols"
    else:
        errors.append(f"unknown negative control {control_id}")
        continue

    control_errors, _ = validate_state(
        mutated_contract,
        mutated_dag,
        mutated_rollup,
        mutated_report,
        mutated_tracker,
        mutated_surfaces,
    )
    passed = expected_error in control_errors
    if not passed:
        errors.append(f"negative_control_failed:{control_id}: expected {expected_error}")
    negative_results.append(
        {
            "control_id": control_id,
            "expected_error": expected_error,
            "observed_errors": control_errors,
            "status": "pass" if passed else "fail",
        }
    )

target_id = contract.get("target_issue_contract", {}).get("target_issue_id")
blocker_id = contract.get("target_issue_contract", {}).get("required_blocker_issue_id")
if blocker_id is None:
    blocker_id = contract.get("target_issue_contract", {}).get("retired_blocker_issue_id")
target_issue = tracker.get(target_id, {})
blocker_issue = tracker.get(blocker_id, {})
retired_edge_present = issue_depends_on(
    target_issue,
    blocker_id,
    contract.get("target_issue_contract", {}).get("retired_dependency_type"),
)
required_key = contract.get("standalone_claim_contract", {}).get("required_dag_dedupe_key")
dag_node = next(
    (
        node
        for node in dag.get("nodes", [])
        if isinstance(node, dict) and node.get("dedupe_key") == required_key
    ),
    {},
)

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": contract.get("bead"),
    "refresh_bead": contract.get("refresh_bead"),
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "target_issue": {
        "id": target_id,
        "title": target_issue.get("title"),
        "status": target_issue.get("status"),
        "priority": target_issue.get("priority"),
    },
    "blocker_dependency": {
        "id": blocker_id,
        "title": blocker_issue.get("title"),
        "status": blocker_issue.get("status"),
        "dependency_type": contract.get("target_issue_contract", {}).get("retired_dependency_type"),
        "relationship": "retired",
        "edge_present": retired_edge_present,
    },
    "standalone_claim_state": {
        "rollup_report": str(rollup_report_path.relative_to(root)),
        "claim_status": rollup_report.get("claim_status"),
        "summary": rollup_report.get("summary", {}),
    },
    "dag_node": {
        "dedupe_key": dag_node.get("dedupe_key"),
        "validation_lane": dag_node.get("validation_lane"),
        "first_safe_action": dag_node.get("first_safe_action"),
        "exit_criteria": dag_node.get("exit_criteria"),
    },
    "partial_burndown_experiments": rollup.get("partial_burndown_experiments", []),
    "live_action_row_sources": live_action_row_sources,
    "closure_blockers": contract.get("report_contract", {}).get("closure_blocker_reasons", []),
    "negative_controls": negative_results,
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
