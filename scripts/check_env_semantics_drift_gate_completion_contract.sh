#!/usr/bin/env bash
# check_env_semantics_drift_gate_completion_contract.sh -- bd-29b.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ENV_SEMANTICS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/env_semantics_drift_gate_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ENV_SEMANTICS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_ENV_SEMANTICS_COMPLETION_REPORT:-${OUT_DIR}/env_semantics_drift_gate_completion_contract.report.json}"
LOG="${FRANKENLIBC_ENV_SEMANTICS_COMPLETION_LOG:-${OUT_DIR}/env_semantics_drift_gate_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]

SCHEMA = "env_semantics_drift_gate_completion_contract.v1"
BEAD_ID = "bd-29b.3.1"
ORIGINAL_BEAD = "bd-29b.3"
TRACE_ID = "bd-29b.3.1::env-semantics-drift-gate::completion::v1"
REQUIRED_ARTIFACT_IDS = {
    "docs_mismatch_report",
    "docs_env_gate",
    "docs_env_test",
    "mode_semantics_matrix",
    "mode_semantics_gate",
    "mode_semantics_test",
    "mode_contract_lock",
    "mode_contract_gate",
    "mode_contract_test",
    "runtime_config",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_env_semantics_unit_and_e2e_sources",
    "checker_accepts_env_semantics_completion_contract",
    "completion_contract_runs_base_env_semantics_gates",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_mode_contract_allowed_value_drift",
    "checker_rejects_mode_semantics_family_drift",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "unresolved_env_drift",
    "mode_semantics_drift",
    "mode_contract_drift",
    "base_gate_failed",
    "missing_completion_contract",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_test_binding",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(contract_path)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "env_semantics_drift_gate_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": source_commit,
        "target_dir": rel(out_dir),
        "failure_signature": failure_signature,
        **fields,
    }


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def missing(required: set[str], actual: set[str]) -> list[str]:
    return sorted(required - actual)


def source_contains(path_text: str, needles: set[str], signature: str) -> None:
    try:
        text = resolve(path_text).read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def run_gate(path_text: str, markers: set[str], signature: str) -> None:
    try:
        output = subprocess.run(
            ["bash", str(resolve(path_text))],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        add_error(signature, f"{path_text} could not run: {exc}")
        return
    combined = output.stdout + "\n" + output.stderr
    if output.returncode != 0:
        add_error(signature, f"{path_text} failed rc={output.returncode}: {combined}")
    for marker in sorted(markers):
        if marker not in combined:
            add_error(signature, f"{path_text} output missing marker: {marker}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("env_semantics_drift_gate_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "env_semantics_drift_gate_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": status,
        "summary": {**summary, "event_count": len(events)},
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: env semantics drift gate completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: env semantics drift gate completion contract "
        f"families={summary.get('total_families', 0)} "
        f"heals={summary.get('total_heals_call_sites', 0)} "
        f"anchors={summary.get('anchor_count', 0)} "
        f"bindings={summary.get('binding_count', 0)}"
    )


contract = load_json(contract_path, "contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_by_id: dict[str, dict[str, Any]] = {}
for artifact in as_array(contract.get("source_artifacts"), "source_artifacts"):
    row = as_object(artifact, "source_artifacts[]")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("malformed_contract", "source_artifacts[].id must be non-empty")
        continue
    if not isinstance(path_text, str) or not path_text:
        add_error("malformed_contract", f"source_artifacts[{artifact_id}].path must be non-empty")
        continue
    source_by_id[artifact_id] = row
    artifact_refs.add(path_text)
    if not resolve(path_text).is_file():
        add_error("missing_source_artifact", f"{artifact_id} source artifact missing: {path_text}")
    if not isinstance(row.get("evidence"), str) or len(row.get("evidence", "").strip()) < 20:
        add_error("malformed_contract", f"{artifact_id} evidence must be descriptive")

missing_artifacts = missing(REQUIRED_ARTIFACT_IDS, set(source_by_id))
if missing_artifacts:
    add_error("missing_source_artifact", f"missing source artifact ids: {missing_artifacts}")
events.append(
    event(
        "source_artifacts_validated",
        "fail" if missing_artifacts else "pass",
        "missing_source_artifact" if missing_artifacts else "none",
        artifact_count=len(source_by_id),
    )
)

completion = as_object(contract.get("completion_contract"), "completion_contract", "missing_completion_contract")
shape_errors_before = len(errors)
missing_items = string_set(completion.get("missing_item_ids"), "completion_contract.missing_item_ids", "missing_completion_contract")
if missing_items != REQUIRED_MISSING_ITEMS:
    add_error("missing_completion_contract", "completion_contract.missing_item_ids must contain unit and e2e")
required_drift = as_object(completion.get("required_drift_summary"), "completion_contract.required_drift_summary", "missing_completion_contract")
required_mode_semantics = as_object(completion.get("required_mode_semantics"), "completion_contract.required_mode_semantics", "missing_completion_contract")
required_mode_contract = as_object(completion.get("required_mode_contract"), "completion_contract.required_mode_contract", "missing_completion_contract")
required_gate_markers = as_object(completion.get("required_gate_markers"), "completion_contract.required_gate_markers", "missing_completion_contract")
events.append(
    event(
        "completion_contract_shape_validated",
        "fail" if len(errors) != shape_errors_before else "pass",
        "missing_completion_contract" if len(errors) != shape_errors_before else "none",
        missing_items=sorted(missing_items),
    )
)

drift_report = load_json(
    resolve(source_by_id.get("docs_mismatch_report", {}).get("path", "")),
    "docs_mismatch_report",
    "unresolved_env_drift",
)
drift_errors_before = len(errors)
drift_summary = as_object(drift_report.get("summary"), "docs_mismatch_report.summary", "unresolved_env_drift")
for key in (
    "missing_in_docs_count",
    "missing_in_code_count",
    "semantic_drift_count",
    "unresolved_ambiguous_count",
):
    if int(drift_summary.get(key, 0)) != int(required_drift.get(key, 0)):
        add_error("unresolved_env_drift", f"docs/code drift {key}={drift_summary.get(key)}")
if as_array(drift_report.get("unresolved_ambiguous"), "docs_mismatch_report.unresolved_ambiguous", "unresolved_env_drift"):
    add_error("unresolved_env_drift", "unresolved_ambiguous must be empty")
events.append(
    event(
        "env_drift_report_validated",
        "fail" if len(errors) != drift_errors_before else "pass",
        "unresolved_env_drift" if len(errors) != drift_errors_before else "none",
        total_classifications=drift_summary.get("total_classifications", 0),
    )
)

mode_matrix = load_json(
    resolve(source_by_id.get("mode_semantics_matrix", {}).get("path", "")),
    "mode_semantics_matrix",
    "mode_semantics_drift",
)
matrix_errors_before = len(errors)
families = as_array(mode_matrix.get("families"), "mode_semantics_matrix.families", "mode_semantics_drift")
modes = as_object(mode_matrix.get("modes"), "mode_semantics_matrix.modes", "mode_semantics_drift")
required_modes = string_set(required_mode_semantics.get("required_modes"), "required_mode_semantics.required_modes", "missing_completion_contract")
if missing(required_modes, set(modes.keys())):
    add_error("mode_semantics_drift", f"mode semantics matrix missing modes: {missing(required_modes, set(modes.keys()))}")
matrix_summary = as_object(mode_matrix.get("summary"), "mode_semantics_matrix.summary", "mode_semantics_drift")
if int(matrix_summary.get("total_families", 0)) != int(required_mode_semantics.get("total_families", 0)):
    add_error("mode_semantics_drift", f"total_families={matrix_summary.get('total_families')}")
if len(families) != int(matrix_summary.get("total_families", 0)):
    add_error("mode_semantics_drift", "families length does not match summary.total_families")
if int(matrix_summary.get("families_with_healing", 0)) < int(required_mode_semantics.get("families_with_healing_min", 0)):
    add_error("mode_semantics_drift", f"families_with_healing={matrix_summary.get('families_with_healing')}")
if int(matrix_summary.get("total_heals_call_sites", 0)) < int(required_mode_semantics.get("total_heals_call_sites_min", 0)):
    add_error("mode_semantics_drift", f"total_heals_call_sites={matrix_summary.get('total_heals_call_sites')}")
for family in families:
    row = as_object(family, "mode_semantics_matrix.families[]", "mode_semantics_drift")
    name = row.get("family", "<unknown>")
    for key in ("family", "module", "heals_call_sites", "symbols", "strict_behavior", "hardened_behavior"):
        if key not in row:
            add_error("mode_semantics_drift", f"{name}: missing {key}")
    if not as_array(row.get("symbols"), f"{name}.symbols", "mode_semantics_drift"):
        add_error("mode_semantics_drift", f"{name}: symbols must not be empty")
    if not as_object(row.get("strict_behavior"), f"{name}.strict_behavior", "mode_semantics_drift"):
        add_error("mode_semantics_drift", f"{name}: strict_behavior must not be empty")
    if not as_object(row.get("hardened_behavior"), f"{name}.hardened_behavior", "mode_semantics_drift"):
        add_error("mode_semantics_drift", f"{name}: hardened_behavior must not be empty")
events.append(
    event(
        "mode_semantics_matrix_validated",
        "fail" if len(errors) != matrix_errors_before else "pass",
        "mode_semantics_drift" if len(errors) != matrix_errors_before else "none",
        total_families=len(families),
        total_heals_call_sites=matrix_summary.get("total_heals_call_sites", 0),
    )
)

mode_contract = load_json(
    resolve(source_by_id.get("mode_contract_lock", {}).get("path", "")),
    "mode_contract_lock",
    "mode_contract_drift",
)
config_path = source_by_id.get("runtime_config", {}).get("path", "")
config_text = resolve(config_path).read_text(encoding="utf-8") if config_path else ""
contract_errors_before = len(errors)
env_contract = as_object(mode_contract.get("env_contract"), "mode_contract_lock.env_contract", "mode_contract_drift")
if env_contract.get("env_key") != required_mode_contract.get("env_key"):
    add_error("mode_contract_drift", "env_contract.env_key drift")
if env_contract.get("allowed_values") != required_mode_contract.get("allowed_values"):
    add_error("mode_contract_drift", f"allowed_values drift: {env_contract.get('allowed_values')}")
if env_contract.get("default_value") != required_mode_contract.get("default_value"):
    add_error("mode_contract_drift", "default_value drift")
mutability = str(env_contract.get("mutability", "")).lower()
if str(required_mode_contract.get("mutability_contains", "")).lower() not in mutability:
    add_error("mode_contract_drift", f"mutability drift: {env_contract.get('mutability')}")
anchors = as_array(mode_contract.get("startup_reentrant_test_anchors"), "mode_contract_lock.startup_reentrant_test_anchors", "mode_contract_drift")
anchor_names = {row.get("name") for row in anchors if isinstance(row, dict)}
required_anchors = string_set(required_mode_contract.get("required_anchors"), "required_mode_contract.required_anchors", "missing_completion_contract")
if missing(required_anchors, {name for name in anchor_names if isinstance(name, str)}):
    add_error("mode_contract_drift", f"missing anchors: {missing(required_anchors, {name for name in anchor_names if isinstance(name, str)})}")
for anchor in required_anchors:
    if f"fn {anchor}" not in config_text:
        add_error("mode_contract_drift", f"config.rs missing anchor test {anchor}")
for required_text in ('"strict"', '"hardened"', "SafetyLevel::Strict", "SafetyLevel::Hardened"):
    if required_text not in config_text:
        add_error("mode_contract_drift", f"config.rs missing {required_text}")
events.append(
    event(
        "mode_contract_lock_validated",
        "fail" if len(errors) != contract_errors_before else "pass",
        "mode_contract_drift" if len(errors) != contract_errors_before else "none",
        anchor_count=len(anchors),
    )
)

gate_errors_before = len(errors)
gate_specs = [
    ("docs_env_gate", "docs_env_gate", "base_gate_failed"),
    ("mode_semantics_gate", "mode_semantics_gate", "base_gate_failed"),
    ("mode_contract_gate", "mode_contract_gate", "base_gate_failed"),
]
for artifact_id, marker_key, signature in gate_specs:
    markers = string_set(required_gate_markers.get(marker_key), f"required_gate_markers.{marker_key}", "missing_completion_contract")
    path_text = source_by_id.get(artifact_id, {}).get("path", "")
    run_gate(path_text, markers, signature)
events.append(
    event(
        "base_env_semantics_gates_replayed",
        "fail" if len(errors) != gate_errors_before else "pass",
        "base_gate_failed" if len(errors) != gate_errors_before else "none",
        gate_count=3,
    )
)

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "missing_completion_contract")
binding_by_item: dict[str, dict[str, Any]] = {}
for binding in bindings:
    row = as_object(binding, "missing_item_bindings[]", "missing_completion_contract")
    item = row.get("missing_item_id")
    if isinstance(item, str):
        binding_by_item[item] = row
for item in REQUIRED_MISSING_ITEMS:
    if item not in binding_by_item:
        add_error("missing_unit_binding" if item == "tests.unit.primary" else "missing_e2e_binding", f"missing binding for {item}")
for item, signature in (("tests.unit.primary", "missing_unit_binding"), ("tests.e2e.primary", "missing_e2e_binding")):
    row = binding_by_item.get(item, {})
    impl_refs = string_set(row.get("implementation_refs"), f"{item}.implementation_refs", signature)
    test_refs = string_set(row.get("test_refs"), f"{item}.test_refs", signature)
    runtime_validation = string_set(row.get("runtime_validation"), f"{item}.runtime_validation", signature)
    if not impl_refs or not test_refs or not runtime_validation:
        add_error(signature, f"{item} binding must include implementation_refs, test_refs, and runtime_validation")
events.append(
    event(
        "missing_item_bindings_validated",
        "fail" if any(e["failure_signature"] in {"missing_unit_binding", "missing_e2e_binding"} for e in errors) else "pass",
        primary_signature() if any(e["failure_signature"] in {"missing_unit_binding", "missing_e2e_binding"} for e in errors) else "none",
        binding_count=len(binding_by_item),
    )
)

test_errors_before = len(errors)
source_contains(source_by_id.get("docs_env_test", {}).get("path", ""), {"mismatch_summary_counts_are_zero", "gate_script_passes"}, "missing_test_binding")
source_contains(source_by_id.get("mode_semantics_test", {}).get("path", ""), {"heals_call_sites_match_source", "behaviors_have_matching_scenarios"}, "missing_test_binding")
source_contains(source_by_id.get("mode_contract_test", {}).get("path", ""), {"startup_reentrant_anchors_are_declared", "gate_script_passes_and_emits_provenance_artifacts"}, "missing_test_binding")
source_contains(source_by_id.get("completion_harness_test", {}).get("path", ""), REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
required_test_functions = as_object(contract.get("required_test_functions"), "required_test_functions", "missing_test_binding")
positive_tests = string_set(required_test_functions.get("positive"), "required_test_functions.positive", "missing_test_binding")
negative_tests = string_set(required_test_functions.get("negative"), "required_test_functions.negative", "missing_test_binding")
if missing(REQUIRED_POSITIVE_TESTS, positive_tests):
    add_error("missing_test_binding", f"missing positive test declarations: {missing(REQUIRED_POSITIVE_TESTS, positive_tests)}")
if missing(REQUIRED_NEGATIVE_TESTS, negative_tests):
    add_error("missing_test_binding", f"missing negative test declarations: {missing(REQUIRED_NEGATIVE_TESTS, negative_tests)}")
events.append(
    event(
        "test_surfaces_validated",
        "fail" if len(errors) != test_errors_before else "pass",
        "missing_test_binding" if len(errors) != test_errors_before else "none",
    )
)

finish(
    {
        "total_classifications": drift_summary.get("total_classifications", 0),
        "total_families": len(families),
        "families_with_healing": matrix_summary.get("families_with_healing", 0),
        "total_heals_call_sites": matrix_summary.get("total_heals_call_sites", 0),
        "anchor_count": len(anchors),
        "binding_count": len(binding_by_item),
        "source_artifact_count": len(source_by_id),
    }
)
PY
