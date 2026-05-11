#!/usr/bin/env bash
# check_runtime_env_inventory_completion_contract.sh -- bd-29b.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_ENV_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/runtime_env_inventory_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_ENV_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_ENV_COMPLETION_REPORT:-${OUT_DIR}/runtime_env_inventory_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_ENV_COMPLETION_LOG:-${OUT_DIR}/runtime_env_inventory_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
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

SCHEMA = "runtime_env_inventory_completion_contract.v1"
BEAD_ID = "bd-29b.1.1"
ORIGINAL_BEAD = "bd-29b.1"
TRACE_ID = "bd-29b.1.1::runtime-env-inventory::completion::v1"
REQUIRED_ARTIFACT_IDS = {
    "runtime_env_inventory",
    "runtime_env_generator",
    "runtime_env_gate",
    "runtime_env_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_METADATA_FIELDS = {
    "default_value",
    "allowed_values",
    "parse_rule",
    "mutability",
    "mode_impact",
    "owner",
    "safety_impact",
}
REQUIRED_GENERATOR_SURFACES = {"scan_sources", "build_inventory", "canonical_json", "SEMANTICS"}
REQUIRED_GATE_SURFACES = {
    "generate_runtime_env_inventory.py",
    "--check",
    "unknown_or_ambiguous_count",
    "PASS: runtime env inventory gate",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_runtime_env_inventory_unit_and_e2e_sources",
    "checker_accepts_runtime_env_inventory_completion_contract",
    "completion_contract_runs_base_inventory_gate",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_incomplete_missing_item_set",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_inventory_contract",
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
    return "runtime_env_inventory_completion_contract_failed"


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
    path = resolve(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"cannot read {path_text}: {exc}")
        return
    for needle in sorted(needles):
        if needle not in text:
            add_error(signature, f"{path_text} missing required text: {needle}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("runtime_env_inventory_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "runtime_env_inventory_completion_contract_failed",
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
        print(f"FAIL: runtime env inventory completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: runtime env inventory completion contract "
        f"keys={summary.get('total_keys', 0)} bindings={summary.get('binding_count', 0)}"
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

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not artifact_id:
        add_error("malformed_contract", "source_artifacts[].id must be a non-empty string")
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
completion_errors_before = len(errors)
missing_items = string_set(completion.get("missing_item_ids"), "completion_contract.missing_item_ids", "missing_completion_contract")
if missing_items != REQUIRED_MISSING_ITEMS:
    add_error("missing_completion_contract", "completion_contract.missing_item_ids must contain unit and e2e")
metadata_fields = string_set(completion.get("required_metadata_fields"), "completion_contract.required_metadata_fields", "missing_completion_contract")
missing_metadata = missing(REQUIRED_METADATA_FIELDS, metadata_fields)
if missing_metadata:
    add_error("missing_completion_contract", f"missing required metadata fields: {missing_metadata}")
generator_surfaces = string_set(completion.get("required_generator_surfaces"), "completion_contract.required_generator_surfaces", "missing_completion_contract")
if missing(REQUIRED_GENERATOR_SURFACES, generator_surfaces):
    add_error("missing_completion_contract", "completion_contract must list generator surfaces")
gate_surfaces = string_set(completion.get("required_gate_behavior"), "completion_contract.required_gate_behavior", "missing_completion_contract")
if not gate_surfaces:
    add_error("missing_completion_contract", "completion_contract.required_gate_behavior must not be empty")
events.append(
    event(
        "completion_contract_shape_validated",
        "fail" if len(errors) != completion_errors_before else "pass",
        "missing_completion_contract" if len(errors) != completion_errors_before else "none",
        missing_items=sorted(missing_items),
    )
)

inventory_path = source_by_id.get("runtime_env_inventory", {}).get("path", "")
inventory = load_json(resolve(inventory_path), "runtime_env_inventory", "missing_inventory_contract") if inventory_path else {}
inventory_errors_before = len(errors)
if inventory.get("schema_version") != "v1":
    add_error("missing_inventory_contract", "inventory schema_version must be v1")
if inventory.get("generator") != "scripts/generate_runtime_env_inventory.py":
    add_error("missing_inventory_contract", "inventory generator path mismatch")
summary = as_object(inventory.get("summary"), "inventory.summary", "missing_inventory_contract")
if summary.get("total_keys", 0) < 25:
    add_error("missing_inventory_contract", "inventory must retain at least 25 keys")
if summary.get("keys_with_reads", 0) < 1 or summary.get("keys_with_writes", 0) < 1:
    add_error("missing_inventory_contract", "inventory must include read and write coverage")
if summary.get("unknown_or_ambiguous_count") != 0:
    add_error("missing_inventory_contract", "unknown_or_ambiguous_count must be zero")
unknown = as_array(inventory.get("unknown_or_ambiguous"), "inventory.unknown_or_ambiguous", "missing_inventory_contract")
if unknown:
    add_error("missing_inventory_contract", "unknown_or_ambiguous must be empty")
entries = as_array(inventory.get("inventory"), "inventory.inventory", "missing_inventory_contract")
for entry in entries:
    row = as_object(entry, "inventory.inventory[]", "missing_inventory_contract")
    key = row.get("env_key")
    if not isinstance(key, str) or not key.startswith("FRANKENLIBC_"):
        add_error("missing_inventory_contract", f"invalid env_key: {key!r}")
    metadata = as_object(row.get("metadata"), f"{key}.metadata", "missing_inventory_contract")
    missing_fields = missing(REQUIRED_METADATA_FIELDS, set(metadata))
    if missing_fields:
        add_error("missing_inventory_contract", f"{key}: missing metadata fields {missing_fields}")
    accesses = as_array(row.get("accesses"), f"{key}.accesses", "missing_inventory_contract")
    if not accesses:
        add_error("missing_inventory_contract", f"{key}: accesses must not be empty")
events.append(
    event(
        "inventory_metadata_validated",
        "fail" if len(errors) != inventory_errors_before else "pass",
        "missing_inventory_contract" if len(errors) != inventory_errors_before else "none",
        total_keys=summary.get("total_keys", 0),
        unknown_or_ambiguous_count=summary.get("unknown_or_ambiguous_count"),
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

generator_path = source_by_id.get("runtime_env_generator", {}).get("path", "")
gate_path = source_by_id.get("runtime_env_gate", {}).get("path", "")
harness_test_path = source_by_id.get("runtime_env_harness_test", {}).get("path", "")
completion_test_path = source_by_id.get("completion_harness_test", {}).get("path", "")
test_errors_before = len(errors)
if generator_path:
    source_contains(generator_path, REQUIRED_GENERATOR_SURFACES, "missing_completion_contract")
if gate_path:
    source_contains(gate_path, REQUIRED_GATE_SURFACES, "missing_e2e_binding")
if harness_test_path:
    source_contains(
        harness_test_path,
        {"inventory_file_exists_and_has_schema", "gate_script_passes", "expected_key_set_matches_inventory"},
        "missing_test_binding",
    )
required_test_functions = as_object(contract.get("required_test_functions"), "required_test_functions", "missing_test_binding")
positive_tests = string_set(required_test_functions.get("positive"), "required_test_functions.positive", "missing_test_binding")
negative_tests = string_set(required_test_functions.get("negative"), "required_test_functions.negative", "missing_test_binding")
missing_positive = missing(REQUIRED_POSITIVE_TESTS, positive_tests)
missing_negative = missing(REQUIRED_NEGATIVE_TESTS, negative_tests)
if missing_positive:
    add_error("missing_test_binding", f"missing positive test declarations: {missing_positive}")
if missing_negative:
    add_error("missing_test_binding", f"missing negative test declarations: {missing_negative}")
if completion_test_path:
    source_contains(completion_test_path, REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS, "missing_test_binding")
events.append(
    event(
        "test_surfaces_validated",
        "fail" if len(errors) != test_errors_before else "pass",
        "missing_test_binding" if len(errors) != test_errors_before else "none",
    )
)

finish(
    {
        "total_keys": summary.get("total_keys", 0),
        "keys_with_reads": summary.get("keys_with_reads", 0),
        "keys_with_writes": summary.get("keys_with_writes", 0),
        "unknown_or_ambiguous_count": summary.get("unknown_or_ambiguous_count", 0),
        "binding_count": len(binding_by_item),
        "source_artifact_count": len(source_by_id),
    }
)
PY
