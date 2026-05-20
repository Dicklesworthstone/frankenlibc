#!/usr/bin/env bash
# check_release_claim_control_completion_contract.sh - bd-w2c3.10.4 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_CONTRACT:-$ROOT/tests/conformance/release_claim_control_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_REPORT:-$OUT_DIR/release_claim_control_completion_contract.report.json}"
LOG="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_COMPLETION_LOG:-$OUT_DIR/release_claim_control_completion_contract.log.jsonl}"
CURRENT_CLAIM_REPORT="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_CURRENT_CLAIM_REPORT:-$OUT_DIR/release_claim_control_completion_contract.current_claim.report.json}"
CURRENT_CLAIM_LOG="${FRANKENLIBC_RELEASE_CLAIM_CONTROL_CURRENT_CLAIM_LOG:-$OUT_DIR/release_claim_control_completion_contract.current_claim.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$CURRENT_CLAIM_REPORT")" "$(dirname "$CURRENT_CLAIM_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
CURRENT_CLAIM_REPORT="$CURRENT_CLAIM_REPORT" \
CURRENT_CLAIM_LOG="$CURRENT_CLAIM_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
CURRENT_CLAIM_REPORT = pathlib.Path(os.environ["CURRENT_CLAIM_REPORT"])
CURRENT_CLAIM_LOG = pathlib.Path(os.environ["CURRENT_CLAIM_LOG"])

EXPECTED_SCHEMA = "release_claim_control_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "release_claim_control_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-w2c3.10.4-release-claim-control-completion-contract"
ORIGINAL_BEAD = "bd-w2c3.10"
COMPLETION_BEAD = "bd-w2c3.10.4"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_TEST_REFS_BY_ITEM = {
    "tests.unit.primary": {
        "status_progression_consistent",
        "claim_drift_guard_consistent_with_readme_and_release_policy",
        "maintenance_report_schema_complete",
        "current_l0_release_policy_passes_without_l1_evidence",
        "current_l1_release_policy_passes_with_objective_evidence_bundle",
        "manifest_binds_release_claim_control_completion_items",
    },
    "tests.e2e.primary": {
        "l3_release_tag_without_standalone_matrix_fails_closed",
        "dossier_validator_produces_valid_report",
        "claim_reconciliation_gate_passes",
        "closure_sweep_passes",
        "checker_validates_release_claim_control_contract_and_emits_report_log",
    },
}
REQUIRED_E2E_COMMANDS = {
    "bash scripts/check_replacement_levels.sh",
    "bash scripts/check_support_matrix_maintenance.sh",
    "bash scripts/check_release_dossier.sh",
    "bash scripts/check_claim_reconciliation.sh",
    "bash scripts/check_closure_sweep.sh",
    "scripts/release/check_replacement_claim_evidence.sh --report <report> --log <log>",
    "bash scripts/check_release_claim_control_completion_contract.sh",
}
REQUIRED_EVENTS = {
    "release_claim_control_manifest_verified",
    "replacement_levels_policy_verified",
    "support_matrix_maintenance_bound",
    "release_dossier_policy_bound",
    "claim_reconciliation_bound",
    "closure_protocol_bound",
    "release_claim_current_policy_replayed",
    "release_claim_control_completion_contract_pass",
}
FAIL_EVENT = "release_claim_control_completion_contract_fail"
EXPECTED_RELEASE_CLAIM_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "release_claim_id",
    "replacement_level",
    "required_evidence",
    "present_evidence",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, dict[str, Any]] = {}
release_control_summary: dict[str, Any] = {}


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be an object")
            continue
        rows.append(row)
    return rows


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def artifact_path(path_text: Any, context: str, must_be_file: bool = True) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {rel(path)}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "release_claim_control_completion_contract_failed",
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(
    item: dict[str, Any],
    item_id: str,
    artifacts: dict[str, str],
    source_cache: dict[str, str],
) -> list[str]:
    found: list[str] = []
    refs = item.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"missing_item_bindings.{item_id}.required_test_refs must be a non-empty array")
        return found
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in artifacts:
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if source_id not in source_cache:
            source_cache[source_id] = source_text(artifacts[source_id], f"test_source.{source_id}")
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.rsplit("::", 1)[1] for item in found}
    missing_names = sorted(REQUIRED_TEST_REFS_BY_ITEM.get(item_id, set()) - found_names)
    if missing_names:
        err(f"missing_item_bindings.{item_id}.required_test_refs missing required bindings {missing_names}")
    commands = as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
    if item_id == "tests.e2e.primary":
        missing_commands = sorted(REQUIRED_E2E_COMMANDS - set(commands))
        if missing_commands:
            err(f"missing_item_bindings.{item_id}.required_commands missing required commands {missing_commands}")
    for command in commands:
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"missing_item_bindings.{item_id} cargo command must be rch-backed: {command}")
    return found


def expect_exact(actual: Any, expected: Any, context: str) -> None:
    require(actual == expected, f"{context} expected {expected!r}, got {actual!r}")


def validate_summary_fields(actual: dict[str, Any], expected: dict[str, Any], context: str) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for key, expected_value in expected.items():
        actual_value = actual.get(key)
        expect_exact(actual_value, expected_value, f"{context}.{key}")
        observed[key] = actual_value
    return observed


def verify_script_reference(name: str, script_ref: str, required_tokens: list[str]) -> dict[str, Any]:
    script_text = source_text(script_ref, f"source_gate_results.{name}.script")
    missing_tokens = [token for token in required_tokens if token not in script_text]
    result = {
        "command": f"bash {script_ref}",
        "status": "pass" if not missing_tokens else "fail",
        "exit_code": 0 if not missing_tokens else 1,
        "validation_mode": "binding_only",
        "missing_tokens": missing_tokens,
    }
    if missing_tokens:
        err(f"{name} source gate script is missing expected tokens {missing_tokens}")
    source_gate_results[name] = result
    return result


def run_current_release_claim_gate() -> dict[str, Any]:
    cmd = [
        str(ROOT / "scripts/release/check_replacement_claim_evidence.sh"),
        "--report",
        str(CURRENT_CLAIM_REPORT),
        "--log",
        str(CURRENT_CLAIM_LOG),
    ]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    gate = {
        "command": "scripts/release/check_replacement_claim_evidence.sh --report <report> --log <log>",
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "stdout_tail": result.stdout[-2000:],
        "stderr_tail": result.stderr[-2000:],
        "validation_mode": "executed_current_policy",
        "report": rel(CURRENT_CLAIM_REPORT),
        "log": rel(CURRENT_CLAIM_LOG),
    }
    source_gate_results["release_claim_current_policy"] = gate
    if result.returncode != 0:
        err("release claim current policy gate failed")
    return gate


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
required = manifest.get("required_release_control_contract", {})
if not isinstance(required, dict):
    err("required_release_control_contract must be an object")
    required = {}

missing_items_seen: set[str] = set()
source_cache: dict[str, str] = {}
test_refs: dict[str, list[str]] = {}
for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if not isinstance(item_id, str):
        err("missing_item_bindings entry missing id")
        continue
    missing_items_seen.add(item_id)
    test_refs[item_id] = validate_test_refs(item, item_id, artifacts, source_cache)
require(missing_items_seen == REQUIRED_MISSING_ITEMS, "missing_item_bindings must close exactly unit and e2e primary items")

append_event(
    "release_claim_control_manifest_verified",
    "pass" if not errors else "fail",
    [rel(CONTRACT)],
    {"missing_items": sorted(missing_items_seen), "test_refs": test_refs},
)

levels_path = artifact_path(artifacts.get("replacement_levels_contract"), "source_artifacts.replacement_levels_contract")
levels = load_json(levels_path, "replacement levels") if levels_path else {}
levels_req = required.get("replacement_levels", {})
if not isinstance(levels_req, dict):
    err("required_release_control_contract.replacement_levels must be an object")
    levels_req = {}
expect_exact(levels.get("schema_version"), levels_req.get("schema_version"), "replacement_levels.schema_version")
expect_exact(levels.get("bead"), levels_req.get("bead"), "replacement_levels.bead")
expect_exact(levels.get("current_level"), levels_req.get("current_level"), "replacement_levels.current_level")
policy = levels.get("release_tag_policy", {})
if not isinstance(policy, dict):
    err("replacement_levels.release_tag_policy must be an object")
    policy = {}
expect_exact(policy.get("current_release_level"), levels_req.get("current_release_level"), "replacement_levels.release_tag_policy.current_release_level")
expect_exact(policy.get("current_release_tag_example"), levels_req.get("current_release_tag_example"), "replacement_levels.release_tag_policy.current_release_tag_example")
level_status = {
    item.get("level"): item.get("status")
    for item in levels.get("levels", [])
    if isinstance(item, dict)
}
for level, expected in levels_req.get("level_status", {}).items():
    expect_exact(level_status.get(level), expected, f"replacement_levels.level_status.{level}")
assessment = levels.get("current_assessment", {})
if not isinstance(assessment, dict):
    err("replacement_levels.current_assessment must be an object")
    assessment = {}
release_control_summary["replacement_levels"] = validate_summary_fields(
    assessment,
    levels_req.get("current_assessment", {}),
    "replacement_levels.current_assessment",
)
release_control_summary["replacement_levels"].update(
    {
        "current_level": levels.get("current_level"),
        "current_release_level": policy.get("current_release_level"),
        "current_release_tag_example": policy.get("current_release_tag_example"),
        "level_status": level_status,
    }
)
append_event(
    "replacement_levels_policy_verified",
    "pass" if not errors else "fail",
    [artifacts.get("replacement_levels_contract", "")],
    release_control_summary["replacement_levels"],
)

support_report_path = artifact_path(artifacts.get("support_matrix_report"), "source_artifacts.support_matrix_report")
support_report = load_json(support_report_path, "support matrix maintenance report") if support_report_path else {}
support_req = required.get("support_matrix_maintenance", {})
if not isinstance(support_req, dict):
    err("required_release_control_contract.support_matrix_maintenance must be an object")
    support_req = {}
expect_exact(support_report.get("schema_version"), support_req.get("schema_version"), "support_matrix_report.schema_version")
expect_exact(support_report.get("bead"), support_req.get("bead"), "support_matrix_report.bead")
support_summary = support_report.get("summary", {})
if not isinstance(support_summary, dict):
    err("support_matrix_report.summary must be an object")
    support_summary = {}
release_control_summary["support_matrix_maintenance"] = validate_summary_fields(
    support_summary,
    support_req.get("summary", {}),
    "support_matrix_report.summary",
)
dashboard = support_report.get("coverage_dashboard", {})
if not isinstance(dashboard, dict):
    err("support_matrix_report.coverage_dashboard must be an object")
    dashboard = {}
expect_exact(dashboard.get("native_coverage_pct"), support_req.get("native_coverage_pct"), "support_matrix_report.coverage_dashboard.native_coverage_pct")
status_counts = dashboard.get("status_counts", {})
if not isinstance(status_counts, dict):
    err("support_matrix_report.coverage_dashboard.status_counts must be an object")
    status_counts = {}
for status, expected in support_req.get("status_counts", {}).items():
    expect_exact(status_counts.get(status), expected, f"support_matrix_report.status_counts.{status}")
release_control_summary["support_matrix_maintenance"].update(
    {"native_coverage_pct": dashboard.get("native_coverage_pct"), "status_counts": status_counts}
)
verify_script_reference(
    "support_matrix_maintenance",
    artifacts.get("support_matrix_checker", "scripts/check_support_matrix_maintenance.sh"),
    ["generate_support_matrix_maintenance.py", "canonical_stable_sections"],
)
append_event(
    "support_matrix_maintenance_bound",
    "pass" if source_gate_results.get("support_matrix_maintenance", {}).get("status") == "pass" else "fail",
    [artifacts.get("support_matrix_report", ""), artifacts.get("support_matrix_checker", "")],
    release_control_summary["support_matrix_maintenance"],
)

dossier_path = artifact_path(artifacts.get("release_dossier_report"), "source_artifacts.release_dossier_report")
dossier = load_json(dossier_path, "release dossier report") if dossier_path else {}
dossier_req = required.get("release_dossier", {})
if not isinstance(dossier_req, dict):
    err("required_release_control_contract.release_dossier must be an object")
    dossier_req = {}
expect_exact(dossier.get("schema_version"), dossier_req.get("schema_version"), "release_dossier.schema_version")
expect_exact(dossier.get("bead"), dossier_req.get("bead"), "release_dossier.bead")
expect_exact(dossier.get("status"), dossier_req.get("status"), "release_dossier.status")
expect_exact(dossier.get("verdict"), dossier_req.get("verdict"), "release_dossier.verdict")
dossier_summary = dossier.get("summary", {})
if not isinstance(dossier_summary, dict):
    err("release_dossier.summary must be an object")
    dossier_summary = {}
release_control_summary["release_dossier"] = validate_summary_fields(
    dossier_summary,
    dossier_req.get("summary", {}),
    "release_dossier.summary",
)
release_control_summary["release_dossier"].update(
    {"status": dossier.get("status"), "verdict": dossier.get("verdict")}
)
verify_script_reference(
    "release_dossier",
    artifacts.get("release_dossier_checker", "scripts/check_release_dossier.sh"),
    ["release_dossier_validator.py", "critical_missing"],
)
append_event(
    "release_dossier_policy_bound",
    "pass" if source_gate_results.get("release_dossier", {}).get("status") == "pass" else "fail",
    [artifacts.get("release_dossier_report", ""), artifacts.get("release_dossier_checker", "")],
    release_control_summary["release_dossier"],
)

claim_path = artifact_path(artifacts.get("claim_reconciliation_report"), "source_artifacts.claim_reconciliation_report")
claim = load_json(claim_path, "claim reconciliation report") if claim_path else {}
claim_req = required.get("claim_reconciliation", {})
if not isinstance(claim_req, dict):
    err("required_release_control_contract.claim_reconciliation must be an object")
    claim_req = {}
expect_exact(claim.get("schema_version"), claim_req.get("schema_version"), "claim_reconciliation.schema_version")
expect_exact(claim.get("bead"), claim_req.get("bead"), "claim_reconciliation.bead")
expect_exact(claim.get("status"), claim_req.get("status"), "claim_reconciliation.status")
claim_summary = claim.get("summary", {})
if not isinstance(claim_summary, dict):
    err("claim_reconciliation.summary must be an object")
    claim_summary = {}
release_control_summary["claim_reconciliation"] = validate_summary_fields(
    claim_summary,
    claim_req.get("summary", {}),
    "claim_reconciliation.summary",
)
release_control_summary["claim_reconciliation"].update({"status": claim.get("status")})
verify_script_reference(
    "claim_reconciliation",
    artifacts.get("claim_reconciliation_checker", "scripts/check_claim_reconciliation.sh"),
    ["claim_reconciliation.py", "PASS: No contradictions"],
)
append_event(
    "claim_reconciliation_bound",
    "pass" if source_gate_results.get("claim_reconciliation", {}).get("status") == "pass" else "fail",
    [artifacts.get("claim_reconciliation_report", ""), artifacts.get("claim_reconciliation_checker", "")],
    release_control_summary["claim_reconciliation"],
)

closure_path = artifact_path(artifacts.get("closure_sweep_report"), "source_artifacts.closure_sweep_report")
closure = load_json(closure_path, "closure sweep report") if closure_path else {}
closure_req = required.get("closure_sweep", {})
if not isinstance(closure_req, dict):
    err("required_release_control_contract.closure_sweep must be an object")
    closure_req = {}
expect_exact(closure.get("schema_version"), closure_req.get("schema_version"), "closure_sweep.schema_version")
expect_exact(closure.get("bead"), closure_req.get("bead"), "closure_sweep.bead")
expect_exact(closure.get("status"), closure_req.get("status"), "closure_sweep.status")
expect_exact(closure.get("drift_gates_status"), closure_req.get("drift_gates_status"), "closure_sweep.drift_gates_status")
closure_summary = closure.get("summary", {})
if not isinstance(closure_summary, dict):
    err("closure_sweep.summary must be an object")
    closure_summary = {}
release_control_summary["closure_sweep"] = validate_summary_fields(
    closure_summary,
    closure_req.get("summary", {}),
    "closure_sweep.summary",
)
release_control_summary["closure_sweep"].update(
    {"status": closure.get("status"), "drift_gates_status": closure.get("drift_gates_status")}
)
verify_script_reference(
    "closure_sweep",
    artifacts.get("closure_sweep_checker", "scripts/check_closure_sweep.sh"),
    ["closure_sweep.py", "drift_gates_status"],
)
append_event(
    "closure_protocol_bound",
    "pass" if source_gate_results.get("closure_sweep", {}).get("status") == "pass" else "fail",
    [artifacts.get("closure_sweep_report", ""), artifacts.get("closure_sweep_checker", "")],
    release_control_summary["closure_sweep"],
)

run_current_release_claim_gate()
current_claim_report = load_json(CURRENT_CLAIM_REPORT, "current release claim report")
current_claim_log = load_jsonl(CURRENT_CLAIM_LOG, "current release claim log")
claim_gate_req = required.get("release_claim_gate", {})
if not isinstance(claim_gate_req, dict):
    err("required_release_control_contract.release_claim_gate must be an object")
    claim_gate_req = {}
expect_exact(current_claim_report.get("schema_version"), claim_gate_req.get("schema_version"), "release_claim_gate.schema_version")
expect_exact(current_claim_report.get("bead"), claim_gate_req.get("bead"), "release_claim_gate.bead")
expect_exact(current_claim_report.get("status"), claim_gate_req.get("current_status"), "release_claim_gate.status")
expect_exact(current_claim_report.get("current_release_level"), claim_gate_req.get("current_release_level"), "release_claim_gate.current_release_level")
claims = current_claim_report.get("claims", [])
if not isinstance(claims, list) or len(claims) != 1:
    err("release_claim_gate current report must contain exactly one claim")
    current_claim = {}
else:
    current_claim = claims[0] if isinstance(claims[0], dict) else {}
required_log_fields = set(as_string_list(claim_gate_req.get("required_log_fields"), "release_claim_gate.required_log_fields"))
missing_log_fields = sorted(EXPECTED_RELEASE_CLAIM_LOG_FIELDS - required_log_fields)
if missing_log_fields:
    err(f"release_claim_gate.required_log_fields missing required fields {missing_log_fields}")
for field in required_log_fields:
    require(field in current_claim, f"release_claim_gate.current_claim missing {field}")
for index, row in enumerate(current_claim_log):
    for field in required_log_fields:
        require(field in row, f"release_claim_gate.log[{index}] missing {field}")
expect_exact(current_claim.get("release_claim_id"), claim_gate_req.get("current_release_claim_id"), "release_claim_gate.current_claim.release_claim_id")
expect_exact(current_claim.get("replacement_level"), claim_gate_req.get("current_release_level"), "release_claim_gate.current_claim.replacement_level")
expect_exact(current_claim.get("actual_decision"), claim_gate_req.get("current_actual_decision"), "release_claim_gate.current_claim.actual_decision")
expect_exact(current_claim.get("expected_decision"), claim_gate_req.get("current_expected_decision"), "release_claim_gate.current_claim.expected_decision")
release_control_summary["release_claim_gate"] = {
    "status": current_claim_report.get("status"),
    "current_level": current_claim_report.get("current_level"),
    "current_release_level": current_claim_report.get("current_release_level"),
    "claim_count": current_claim_report.get("claim_count"),
    "failed_claim_count": current_claim_report.get("failed_claim_count"),
    "current_release_claim_id": current_claim.get("release_claim_id"),
    "current_actual_decision": current_claim.get("actual_decision"),
    "current_expected_decision": current_claim.get("expected_decision"),
}
append_event(
    "release_claim_current_policy_replayed",
    "pass" if source_gate_results.get("release_claim_current_policy", {}).get("status") == "pass" else "fail",
    [rel(CURRENT_CLAIM_REPORT), rel(CURRENT_CLAIM_LOG)],
    release_control_summary["release_claim_gate"],
)

status = "pass" if not errors else "fail"
append_event(
    "release_claim_control_completion_contract_pass" if status == "pass" else FAIL_EVENT,
    status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {"error_count": len(errors), "summary_keys": sorted(release_control_summary.keys())},
)

event_names = {event["event"] for event in events if event.get("status") == "pass"}
missing_events = sorted(REQUIRED_EVENTS - event_names) if status == "pass" else []
if missing_events:
    err(f"missing required pass events {missing_events}")
    status = "fail"
if status == "pass" and any(event["event"] == FAIL_EVENT for event in events):
    err(f"forbidden pass event emitted: {FAIL_EVENT}")
    status = "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": EXPECTED_MANIFEST,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "release_control_summary": release_control_summary,
    "source_gate_results": source_gate_results,
    "current_claim_report": rel(CURRENT_CLAIM_REPORT),
    "current_claim_log": rel(CURRENT_CLAIM_LOG),
    "events": events,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

if status == "pass":
    print(
        "release_claim_control_completion_contract: PASS "
        f"current_level={release_control_summary.get('replacement_levels', {}).get('current_level')} "
        f"claim_status={release_control_summary.get('release_claim_gate', {}).get('status')} "
        f"closure_ready={release_control_summary.get('closure_sweep', {}).get('closure_ready')}"
    )
    raise SystemExit(0)

print(f"release_claim_control_completion_contract: FAIL errors={len(errors)}")
for message in errors:
    print(f"  - {message}")
raise SystemExit(1)
PY
