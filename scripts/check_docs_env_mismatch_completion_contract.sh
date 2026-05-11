#!/usr/bin/env bash
# check_docs_env_mismatch_completion_contract.sh -- bd-29b.2.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_DOCS_ENV_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/docs_env_mismatch_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_DOCS_ENV_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_DOCS_ENV_COMPLETION_REPORT:-${OUT_DIR}/docs_env_mismatch_completion_contract.report.json}"
LOG="${FRANKENLIBC_DOCS_ENV_COMPLETION_LOG:-${OUT_DIR}/docs_env_mismatch_completion_contract.log.jsonl}"
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

SCHEMA = "docs_env_mismatch_completion_contract.v1"
BEAD_ID = "bd-29b.2.1"
ORIGINAL_BEAD = "bd-29b.2"
TRACE_ID = "bd-29b.2.1::docs-env-mismatch::completion::v1"
REQUIRED_ARTIFACT_IDS = {
    "docs_env_inventory",
    "docs_mismatch_report",
    "docs_source_map",
    "docs_trace",
    "docs_env_generator",
    "docs_env_gate",
    "docs_env_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_GENERATOR_SURFACES = {
    "collect_docs_mentions",
    "build_docs_inventory",
    "classify_mismatches",
    "build_docs_governance_artifacts",
    "canonical_json",
    "canonical_jsonl",
}
REQUIRED_GATE_SURFACES = {
    "generate_docs_env_mismatch_report.py",
    "--check",
    "PASS: docs/code mismatch report reconciled",
    "PASS: docs source-of-truth map validated",
}
REQUIRED_BASE_TESTS = {
    "docs_inventory_exists_and_has_expected_shape",
    "mismatch_report_is_fully_classified",
    "mismatch_summary_counts_are_zero",
    "unresolved_ambiguous_is_empty",
    "source_of_truth_map_covers_major_surfaces",
    "governed_sections_have_sources_owners_and_triggers",
    "governance_trace_rows_cover_every_section",
    "gate_script_passes",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_docs_env_unit_and_e2e_sources",
    "checker_accepts_docs_env_mismatch_completion_contract",
    "completion_contract_runs_base_docs_env_gate",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_e2e_binding",
    "checker_rejects_unresolved_mismatch_report",
    "checker_rejects_missing_governance_surface",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_docs_inventory",
    "unresolved_docs_mismatch",
    "missing_governance_surface",
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
    return "docs_env_mismatch_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def load_jsonl(path: Path, context: str, signature: str) -> list[Any]:
    rows: list[Any] = []
    try:
        artifact_refs.add(rel(path))
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip():
                rows.append(json.loads(line))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
    return rows


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
        events.append(event("docs_env_mismatch_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "docs_env_mismatch_completion_contract_failed",
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
        print(f"FAIL: docs env mismatch completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: docs env mismatch completion contract "
        f"docs_keys={summary.get('docs_keys', 0)} "
        f"code_keys={summary.get('code_keys', 0)} "
        f"surfaces={summary.get('surface_count', 0)} "
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
generator_surfaces = string_set(completion.get("required_generator_surfaces"), "completion_contract.required_generator_surfaces", "missing_completion_contract")
if missing(REQUIRED_GENERATOR_SURFACES, generator_surfaces):
    add_error("missing_completion_contract", "completion_contract must list generator surfaces")
gate_surfaces = string_set(completion.get("required_gate_behavior"), "completion_contract.required_gate_behavior", "missing_completion_contract")
if missing(REQUIRED_GATE_SURFACES, gate_surfaces):
    add_error("missing_completion_contract", "completion_contract must list gate pass markers")
required_docs = as_object(completion.get("required_docs_summary"), "completion_contract.required_docs_summary", "missing_completion_contract")
required_report = as_object(completion.get("required_report_summary"), "completion_contract.required_report_summary", "missing_completion_contract")
required_governance = as_object(completion.get("required_governance"), "completion_contract.required_governance", "missing_completion_contract")
events.append(
    event(
        "completion_contract_shape_validated",
        "fail" if len(errors) != completion_errors_before else "pass",
        "missing_completion_contract" if len(errors) != completion_errors_before else "none",
        missing_items=sorted(missing_items),
    )
)

docs_inventory_path = source_by_id.get("docs_env_inventory", {}).get("path", "")
docs_inventory = load_json(resolve(docs_inventory_path), "docs_env_inventory", "missing_docs_inventory") if docs_inventory_path else {}
inventory_errors_before = len(errors)
if docs_inventory.get("schema_version") != "v1":
    add_error("missing_docs_inventory", "docs inventory schema_version must be v1")
if docs_inventory.get("generator") != "scripts/generate_docs_env_mismatch_report.py":
    add_error("missing_docs_inventory", "docs inventory generator path mismatch")
docs_summary = as_object(docs_inventory.get("summary"), "docs_inventory.summary", "missing_docs_inventory")
docs_files = set(row for row in as_array(docs_inventory.get("docs_files"), "docs_inventory.docs_files", "missing_docs_inventory") if isinstance(row, str))
required_docs_files = string_set(required_docs.get("required_docs_files"), "required_docs_summary.required_docs_files", "missing_completion_contract")
if missing(required_docs_files, docs_files):
    add_error("missing_docs_inventory", f"docs inventory missing docs files: {missing(required_docs_files, docs_files)}")
if int(docs_summary.get("total_keys", 0)) < int(required_docs.get("total_keys_min", 0)):
    add_error("missing_docs_inventory", "docs inventory total_keys below completion threshold")
if int(docs_summary.get("total_mentions", 0)) < int(required_docs.get("total_mentions_min", 0)):
    add_error("missing_docs_inventory", "docs inventory total_mentions below completion threshold")
docs_keys = as_array(docs_inventory.get("keys"), "docs_inventory.keys", "missing_docs_inventory")
inventory_env_keys = {row.get("env_key") for row in docs_keys if isinstance(row, dict)}
required_env_keys = string_set(required_docs.get("required_env_keys"), "required_docs_summary.required_env_keys", "missing_completion_contract")
if missing(required_env_keys, {key for key in inventory_env_keys if isinstance(key, str)}):
    add_error("missing_docs_inventory", f"docs inventory missing required env keys: {missing(required_env_keys, {key for key in inventory_env_keys if isinstance(key, str)})}")
for entry in docs_keys:
    row = as_object(entry, "docs_inventory.keys[]", "missing_docs_inventory")
    key = row.get("env_key")
    if not isinstance(key, str) or not key.startswith("FRANKENLIBC_"):
        add_error("missing_docs_inventory", f"invalid docs env_key: {key!r}")
    if int(row.get("mention_count", 0)) < 1:
        add_error("missing_docs_inventory", f"{key}: mention_count must be positive")
    mentions = as_array(row.get("mentions"), f"{key}.mentions", "missing_docs_inventory")
    if not mentions:
        add_error("missing_docs_inventory", f"{key}: mentions must not be empty")
events.append(
    event(
        "docs_inventory_validated",
        "fail" if len(errors) != inventory_errors_before else "pass",
        "missing_docs_inventory" if len(errors) != inventory_errors_before else "none",
        total_keys=docs_summary.get("total_keys", 0),
        total_mentions=docs_summary.get("total_mentions", 0),
    )
)

mismatch_report_path = source_by_id.get("docs_mismatch_report", {}).get("path", "")
mismatch_report = load_json(resolve(mismatch_report_path), "docs_mismatch_report", "unresolved_docs_mismatch") if mismatch_report_path else {}
report_errors_before = len(errors)
if mismatch_report.get("schema_version") != "v1":
    add_error("unresolved_docs_mismatch", "mismatch report schema_version must be v1")
if mismatch_report.get("generator") != "scripts/generate_docs_env_mismatch_report.py":
    add_error("unresolved_docs_mismatch", "mismatch report generator path mismatch")
report_summary = as_object(mismatch_report.get("summary"), "mismatch_report.summary", "unresolved_docs_mismatch")
for key in ("docs_keys", "code_keys"):
    if int(report_summary.get(key, 0)) < int(required_report.get(f"{key}_min", 0)):
        add_error("unresolved_docs_mismatch", f"mismatch report {key} below completion threshold")
for key in (
    "missing_in_docs_count",
    "missing_in_code_count",
    "semantic_drift_count",
    "unresolved_ambiguous_count",
):
    if int(report_summary.get(key, 0)) != int(required_report.get(key, 0)):
        add_error("unresolved_docs_mismatch", f"mismatch report {key}={report_summary.get(key)}")
classifications = as_array(mismatch_report.get("classifications"), "mismatch_report.classifications", "unresolved_docs_mismatch")
if int(report_summary.get("total_classifications", len(classifications))) != len(classifications):
    add_error("unresolved_docs_mismatch", "mismatch report total_classifications does not match classifications length")
unresolved = as_array(mismatch_report.get("unresolved_ambiguous"), "mismatch_report.unresolved_ambiguous", "unresolved_docs_mismatch")
if unresolved:
    add_error("unresolved_docs_mismatch", "mismatch report unresolved_ambiguous must be empty")
for row in classifications:
    item = as_object(row, "mismatch_report.classifications[]", "unresolved_docs_mismatch")
    if not item.get("remediation_action"):
        add_error("unresolved_docs_mismatch", f"{item.get('env_key')}: missing remediation_action")
events.append(
    event(
        "docs_mismatch_report_validated",
        "fail" if len(errors) != report_errors_before else "pass",
        "unresolved_docs_mismatch" if len(errors) != report_errors_before else "none",
        docs_keys=report_summary.get("docs_keys", 0),
        code_keys=report_summary.get("code_keys", 0),
        classifications=len(classifications),
    )
)

source_map_path = source_by_id.get("docs_source_map", {}).get("path", "")
trace_path = source_by_id.get("docs_trace", {}).get("path", "")
source_map = load_json(resolve(source_map_path), "docs_source_map", "missing_governance_surface") if source_map_path else {}
trace_rows = load_jsonl(resolve(trace_path), "docs_trace", "missing_governance_surface") if trace_path else []
governance_errors_before = len(errors)
if source_map.get("schema_version") != "v1":
    add_error("missing_governance_surface", "source map schema_version must be v1")
surfaces = as_array(source_map.get("surfaces"), "source_map.surfaces", "missing_governance_surface")
surface_ids = {row.get("surface_id") for row in surfaces if isinstance(row, dict)}
required_surfaces = string_set(required_governance.get("required_surfaces"), "required_governance.required_surfaces", "missing_completion_contract")
missing_surfaces = missing(required_surfaces, {sid for sid in surface_ids if isinstance(sid, str)})
if missing_surfaces:
    add_error("missing_governance_surface", f"missing required surfaces: {missing_surfaces}")
map_summary = as_object(source_map.get("summary"), "source_map.summary", "missing_governance_surface")
if int(map_summary.get("surface_count", 0)) < int(required_governance.get("surface_count_min", 0)):
    add_error("missing_governance_surface", "source map surface_count below completion threshold")
if int(map_summary.get("missing_section_count", -1)) != int(required_governance.get("missing_section_count", 0)):
    add_error("missing_governance_surface", f"source map missing_section_count={map_summary.get('missing_section_count')}")
section_count = 0
for surface in surfaces:
    surface_obj = as_object(surface, "source_map.surfaces[]", "missing_governance_surface")
    sid = surface_obj.get("surface_id", "<unknown>")
    sections = as_array(surface_obj.get("sections"), f"{sid}.sections", "missing_governance_surface")
    section_count += len(sections)
    for section in sections:
        row = as_object(section, f"{sid}.sections[]", "missing_governance_surface")
        section_id = row.get("section_id", "<unknown>")
        for key in ("owner", "review_policy", "freshness_status"):
            if not row.get(key):
                add_error("missing_governance_surface", f"{sid}/{section_id}: missing {key}")
        if row.get("freshness_status") != "fresh":
            add_error("missing_governance_surface", f"{sid}/{section_id}: freshness_status={row.get('freshness_status')}")
        for key in ("backing_paths", "source_artifacts", "update_triggers"):
            if not as_array(row.get(key), f"{sid}/{section_id}.{key}", "missing_governance_surface"):
                add_error("missing_governance_surface", f"{sid}/{section_id}: missing {key}")
        if as_array(row.get("missing_inputs"), f"{sid}/{section_id}.missing_inputs", "missing_governance_surface"):
            add_error("missing_governance_surface", f"{sid}/{section_id}: missing_inputs must be empty")
required_trace_fields = string_set(required_governance.get("required_trace_fields"), "required_governance.required_trace_fields", "missing_completion_contract")
if len(trace_rows) != section_count:
    add_error("missing_governance_surface", f"trace row count mismatch: expected {section_count}, got {len(trace_rows)}")
for idx, row in enumerate(trace_rows, start=1):
    trace = as_object(row, f"trace row {idx}", "missing_governance_surface")
    for key in sorted(required_trace_fields):
        value = trace.get(key)
        if value in ("", [], None):
            add_error("missing_governance_surface", f"trace row {idx}: missing {key}")
events.append(
    event(
        "docs_governance_validated",
        "fail" if len(errors) != governance_errors_before else "pass",
        "missing_governance_surface" if len(errors) != governance_errors_before else "none",
        surface_count=len(surfaces),
        section_count=section_count,
        trace_rows=len(trace_rows),
    )
)

gate_path = source_by_id.get("docs_env_gate", {}).get("path", "")
gate_errors_before = len(errors)
if gate_path:
    try:
        output = subprocess.run(
            ["bash", str(resolve(gate_path))],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
        if output.returncode != 0:
            add_error("base_gate_failed", f"{gate_path} failed rc={output.returncode}: {output.stdout} {output.stderr}")
        for marker in ("PASS: docs/code mismatch report reconciled", "PASS: docs source-of-truth map validated"):
            if marker not in output.stdout:
                add_error("base_gate_failed", f"{gate_path} output missing marker: {marker}")
    except Exception as exc:
        add_error("base_gate_failed", f"{gate_path} could not run: {exc}")
events.append(
    event(
        "base_docs_env_gate_replayed",
        "fail" if len(errors) != gate_errors_before else "pass",
        "base_gate_failed" if len(errors) != gate_errors_before else "none",
        gate_path=gate_path,
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

generator_path = source_by_id.get("docs_env_generator", {}).get("path", "")
harness_test_path = source_by_id.get("docs_env_harness_test", {}).get("path", "")
completion_test_path = source_by_id.get("completion_harness_test", {}).get("path", "")
test_errors_before = len(errors)
if generator_path:
    source_contains(generator_path, REQUIRED_GENERATOR_SURFACES, "missing_completion_contract")
if gate_path:
    source_contains(gate_path, REQUIRED_GATE_SURFACES, "base_gate_failed")
if harness_test_path:
    source_contains(harness_test_path, REQUIRED_BASE_TESTS, "missing_test_binding")
required_base_tests = string_set(contract.get("required_base_test_functions"), "required_base_test_functions", "missing_test_binding")
if missing(REQUIRED_BASE_TESTS, required_base_tests):
    add_error("missing_test_binding", f"missing base test declarations: {missing(REQUIRED_BASE_TESTS, required_base_tests)}")
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
        "docs_keys": report_summary.get("docs_keys", 0),
        "code_keys": report_summary.get("code_keys", 0),
        "docs_inventory_keys": docs_summary.get("total_keys", 0),
        "docs_inventory_mentions": docs_summary.get("total_mentions", 0),
        "classification_count": len(classifications),
        "unresolved_ambiguous_count": len(unresolved),
        "surface_count": len(surfaces),
        "section_count": section_count,
        "trace_rows": len(trace_rows),
        "binding_count": len(binding_by_item),
        "source_artifact_count": len(source_by_id),
    }
)
PY
