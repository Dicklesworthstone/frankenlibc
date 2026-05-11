#!/usr/bin/env bash
# runtime_math_classification_matrix_completion_contract - bd-2k6b.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_CONTRACT:-$ROOT/tests/conformance/runtime_math_classification_matrix_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_MATRIX:-$ROOT/tests/runtime_math/runtime_math_classification_matrix.v1.json}"
GOVERNANCE="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_GOVERNANCE:-$ROOT/tests/conformance/math_governance.json}"
LINKAGE="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_LINKAGE:-$ROOT/tests/runtime_math/runtime_math_linkage.v1.json}"
MANIFEST="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_MANIFEST:-$ROOT/tests/runtime_math/production_kernel_manifest.v1.json}"
CLASSIFICATION_REPORT="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_CLASSIFICATION_REPORT:-$ROOT/target/conformance/runtime_math_classification_matrix.report.json}"
CLASSIFICATION_LOG="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_CLASSIFICATION_LOG:-$ROOT/target/conformance/runtime_math_classification_matrix.log.jsonl}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_OUT_DIR:-$ROOT/target/conformance/runtime_math_classification_matrix_completion_contract}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_CLASSIFICATION_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
GOVERNANCE="$GOVERNANCE" \
LINKAGE="$LINKAGE" \
MANIFEST="$MANIFEST" \
CLASSIFICATION_REPORT="$CLASSIFICATION_REPORT" \
CLASSIFICATION_LOG="$CLASSIFICATION_LOG" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
MATRIX = pathlib.Path(os.environ["MATRIX"])
GOVERNANCE = pathlib.Path(os.environ["GOVERNANCE"])
LINKAGE = pathlib.Path(os.environ["LINKAGE"])
MANIFEST = pathlib.Path(os.environ["MANIFEST"])
CLASSIFICATION_REPORT = pathlib.Path(os.environ["CLASSIFICATION_REPORT"])
CLASSIFICATION_LOG = pathlib.Path(os.environ["CLASSIFICATION_LOG"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_math_classification_matrix_completion_contract.v1"
EXPECTED_BEAD = "bd-2k6b.1"
EXPECTED_ORIGINAL_BEAD = "bd-2k6b"
EXPECTED_TRACE_ID = "bd-2k6b.1::runtime-math-classification-matrix::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary"}
EXPECTED_ARTIFACT_IDS = {
    "classification_matrix",
    "classification_gate",
    "classification_test",
    "math_governance",
    "runtime_math_linkage",
    "production_kernel_manifest",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_runtime_math_classification_unit_item",
    "checker_accepts_runtime_math_classification_completion_contract",
    "checker_replays_classification_gate_and_log",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_unit_binding",
    "checker_rejects_matrix_count_drift",
    "checker_rejects_classification_log_drift",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def err(message: str) -> None:
    errors.append(message)


def emit(event: str, **fields: Any) -> None:
    timestamp = now()
    row = {
        "event": event,
        "level": "info",
        "timestamp": timestamp,
        "trace_id": EXPECTED_TRACE_ID,
    }
    row.update(fields)
    events.append(row)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


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


def repo_path(value: Any, context: str, *, must_exist: bool = True) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_exist and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


def as_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        err(f"{context} must be an object")
        return {}
    return value


def as_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        err(f"{context} must be an array")
        return []
    return value


def int_field(obj: dict[str, Any], key: str, context: str) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        err(f"{context}.{key} must be an integer")
        return 0
    return value


def expect_eq(actual: Any, expected: Any, context: str, code: str) -> None:
    if actual != expected:
        err(f"{code}: {context} expected {expected!r}, got {actual!r}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text


def source_text(path_text: str, context: str) -> str:
    path = repo_path(path_text, context)
    if path is None or not path.is_file():
        err(f"{context} must reference a file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def run_base_gate(required_gate: dict[str, Any]) -> None:
    command = required_gate.get("command")
    marker = required_gate.get("pass_marker")
    if command != "bash scripts/check_runtime_math_classification_matrix.sh":
        err("base_gate_drift: required gate command mismatch")
        return
    result = subprocess.run(
        ["bash", "scripts/check_runtime_math_classification_matrix.sh"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        err(f"base_gate_drift: classification gate failed with exit {result.returncode}: {output[-2000:]}")
        return
    if not isinstance(marker, str) or marker not in output:
        err(f"base_gate_drift: classification gate missing marker {marker!r}")
        return
    emit("classification_gate_replayed", marker=marker)


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    expect_eq(manifest.get("schema_version"), EXPECTED_SCHEMA, "schema_version", "contract_identity")
    expect_eq(manifest.get("bead_id"), EXPECTED_BEAD, "bead_id", "contract_identity")
    expect_eq(manifest.get("original_bead"), EXPECTED_ORIGINAL_BEAD, "original_bead", "contract_identity")
    expect_eq(manifest.get("trace_id"), EXPECTED_TRACE_ID, "trace_id", "contract_identity")

    artifact_ids: set[str] = set()
    for index, artifact in enumerate(as_list(manifest.get("source_artifacts"), "source_artifacts")):
        artifact_obj = as_object(artifact, f"source_artifacts[{index}]")
        artifact_id = artifact_obj.get("id")
        if isinstance(artifact_id, str):
            artifact_ids.add(artifact_id)
        else:
            err(f"source_artifacts[{index}].id must be a string")
            continue
        for key in ("kind", "evidence"):
            if not isinstance(artifact_obj.get(key), str) or not artifact_obj[key]:
                err(f"source_artifacts.{artifact_id}.{key} must be a non-empty string")
        repo_path(artifact_obj.get("path"), f"source_artifacts.{artifact_id}.path")
    if artifact_ids != EXPECTED_ARTIFACT_IDS:
        err(f"source_artifacts ids mismatch: expected={sorted(EXPECTED_ARTIFACT_IDS)} got={sorted(artifact_ids)}")
    emit("source_artifacts_validated", count=len(artifact_ids))

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing = {item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids") if isinstance(item, str)}
    if missing != EXPECTED_MISSING_ITEMS:
        err(f"completion_contract.missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing)}")

    required_functions = as_object(manifest.get("required_test_functions"), "required_test_functions")
    positive = {item for item in as_list(required_functions.get("positive"), "required_test_functions.positive") if isinstance(item, str)}
    negative = {item for item in as_list(required_functions.get("negative"), "required_test_functions.negative") if isinstance(item, str)}
    if positive != REQUIRED_POSITIVE_TESTS:
        err(f"required_test_functions.positive mismatch: expected={sorted(REQUIRED_POSITIVE_TESTS)} got={sorted(positive)}")
    if negative != REQUIRED_NEGATIVE_TESTS:
        err(f"required_test_functions.negative mismatch: expected={sorted(REQUIRED_NEGATIVE_TESTS)} got={sorted(negative)}")
    return contract


def validate_matrix(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    expect_eq(matrix.get("schema_version"), "v1", "classification_matrix.schema_version", "matrix_identity_drift")
    expect_eq(matrix.get("bead"), EXPECTED_ORIGINAL_BEAD, "classification_matrix.bead", "matrix_identity_drift")

    modules = as_list(matrix.get("modules"), "classification_matrix.modules")
    expect_eq(len(modules), int_field(required, "total_modules", "required_matrix"), "classification_matrix.modules length", "matrix_count_drift")

    seen: set[str] = set()
    class_counts = {"production_core": 0, "production_monitor": 0, "research": 0}
    link_counts = {"Production": 0, "ResearchOnly": 0}
    allowed_classes = {item for item in as_list(required.get("allowed_classifications"), "required_matrix.allowed_classifications") if isinstance(item, str)}
    allowed_linkage = {item for item in as_list(required.get("allowed_linkage_statuses"), "required_matrix.allowed_linkage_statuses") if isinstance(item, str)}
    research_in_prod = 0

    for index, row in enumerate(modules):
        row_obj = as_object(row, f"classification_matrix.modules[{index}]")
        module = row_obj.get("module")
        if not isinstance(module, str) or not module:
            err(f"matrix_schema_drift: row {index} missing module")
            continue
        if module in seen:
            err(f"matrix_schema_drift: duplicate module {module}")
        seen.add(module)
        classification = row_obj.get("classification")
        linkage_status = row_obj.get("linkage_status")
        if classification not in allowed_classes:
            err(f"matrix_schema_drift: {module} invalid classification {classification!r}")
        if linkage_status not in allowed_linkage:
            err(f"matrix_schema_drift: {module} invalid linkage_status {linkage_status!r}")
        if classification in class_counts:
            class_counts[classification] += 1
        if linkage_status in link_counts:
            link_counts[linkage_status] += 1
        for field in ("rationale", "rationale_ref", "decision_target", "decision_target_ref"):
            if not isinstance(row_obj.get(field), str) or not row_obj[field]:
                err(f"matrix_schema_drift: {module} missing {field}")
        if not isinstance(row_obj.get("in_production_manifest"), bool):
            err(f"matrix_schema_drift: {module} in_production_manifest must be bool")
        if not isinstance(row_obj.get("in_research_only_manifest"), bool):
            err(f"matrix_schema_drift: {module} in_research_only_manifest must be bool")
        if classification == "research" and row_obj.get("in_production_manifest") is True:
            research_in_prod += 1
        transition = as_object(row_obj.get("transition"), f"classification_matrix.modules.{module}.transition")
        stage = transition.get("target_stage")
        if classification == "research":
            if stage not in {"research_only", "deprecated", "removed"}:
                err(f"matrix_schema_drift: {module} research transition stage drift")
            if not isinstance(transition.get("note"), str) or not transition["note"].strip():
                err(f"matrix_schema_drift: {module} research transition note missing")
        elif classification in {"production_core", "production_monitor"} and stage != "production":
            err(f"matrix_schema_drift: {module} production transition stage drift")

    required_class_counts = as_object(required.get("classification_counts"), "required_matrix.classification_counts")
    required_link_counts = as_object(required.get("linkage_status_counts"), "required_matrix.linkage_status_counts")
    expect_eq(class_counts, required_class_counts, "classification_counts", "matrix_count_drift")
    expect_eq(link_counts, required_link_counts, "linkage_status_counts", "matrix_count_drift")

    summary = as_object(matrix.get("summary"), "classification_matrix.summary")
    expect_eq(summary.get("total_modules"), len(seen), "summary.total_modules", "matrix_count_drift")
    expect_eq(summary.get("classification_counts"), class_counts, "summary.classification_counts", "matrix_count_drift")
    expect_eq(summary.get("linkage_status_counts"), link_counts, "summary.linkage_status_counts", "matrix_count_drift")
    expect_eq(summary.get("production_manifest_modules"), int_field(required, "production_manifest_modules", "required_matrix"), "summary.production_manifest_modules", "matrix_count_drift")
    expect_eq(summary.get("research_only_manifest_modules"), int_field(required, "research_only_manifest_modules", "required_matrix"), "summary.research_only_manifest_modules", "matrix_count_drift")
    expect_eq(summary.get("research_modules_currently_in_production_manifest"), research_in_prod, "summary.research_modules_currently_in_production_manifest", "matrix_count_drift")
    emit("classification_matrix_validated", total_modules=len(seen), **class_counts)
    return {
        "total_modules": len(seen),
        "production_core": class_counts["production_core"],
        "production_monitor": class_counts["production_monitor"],
        "research": class_counts["research"],
    }


def validate_source_consistency(matrix: dict[str, Any], governance: dict[str, Any], linkage: dict[str, Any], manifest: dict[str, Any]) -> None:
    matrix_modules = {row.get("module") for row in as_list(matrix.get("modules"), "classification_matrix.modules") if isinstance(row, dict) and isinstance(row.get("module"), str)}
    gov_modules = set()
    for entries in as_object(governance.get("classifications"), "math_governance.classifications").values():
        for entry in as_list(entries, "math_governance.classifications.*"):
            if isinstance(entry, dict) and isinstance(entry.get("module"), str):
                gov_modules.add(entry["module"])
    link_modules = set(as_object(linkage.get("modules"), "runtime_math_linkage.modules").keys())
    prod_modules = {item for item in as_list(manifest.get("production_modules"), "production_kernel_manifest.production_modules") if isinstance(item, str)}
    research_modules = {item for item in as_list(manifest.get("research_only_modules"), "production_kernel_manifest.research_only_modules") if isinstance(item, str)}
    expected = gov_modules | link_modules | prod_modules | research_modules
    if matrix_modules != expected:
        err(f"matrix_source_drift: module set mismatch missing={sorted(expected - matrix_modules)} extra={sorted(matrix_modules - expected)}")
    expect_eq(manifest.get("classification_matrix_ref"), "tests/runtime_math/runtime_math_classification_matrix.v1.json", "production_kernel_manifest.classification_matrix_ref", "matrix_source_drift")
    emit("classification_sources_validated", module_count=len(matrix_modules))


def validate_gate_outputs(required_gate: dict[str, Any], required_log_fields: list[Any]) -> dict[str, Any]:
    gate_report = load_json(CLASSIFICATION_REPORT, "classification gate report")
    expect_eq(gate_report.get("ok"), True, "classification_gate_report.ok", "classification_report_drift")
    expect_eq(gate_report.get("module_count"), 69, "classification_gate_report.module_count", "classification_report_drift")
    expected_fields = {item for item in required_log_fields if isinstance(item, str)}
    rows = []
    try:
        lines = [line for line in CLASSIFICATION_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:
        err(f"classification_log_drift: classification log unreadable: {rel(CLASSIFICATION_LOG)}: {exc}")
        lines = []
    for line_no, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            err(f"classification_log_drift: log line {line_no} invalid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"classification_log_drift: log line {line_no} must be object")
            continue
        missing = expected_fields - set(row)
        if missing:
            err(f"classification_log_drift: log line {line_no} missing fields {sorted(missing)}")
        expect_eq(row.get("event"), "runtime_math.classification_decision", f"log line {line_no} event", "classification_log_drift")
        expect_eq(row.get("outcome"), "pass", f"log line {line_no} outcome", "classification_log_drift")
        rows.append(row)
    expected_count = gate_report.get("module_count")
    if len(rows) != expected_count:
        err(f"classification_log_drift: expected {expected_count} rows, got {len(rows)}")
    expect_eq(rel(CLASSIFICATION_REPORT), required_gate.get("report_path"), "classification report path", "classification_report_drift")
    expect_eq(rel(CLASSIFICATION_LOG), required_gate.get("log_path"), "classification log path", "classification_log_drift")
    emit("classification_gate_outputs_validated", report=rel(CLASSIFICATION_REPORT), log=rel(CLASSIFICATION_LOG), rows=len(rows))
    return {"log_rows": len(rows), "gate_ok": gate_report.get("ok")}


def validate_missing_item_binding(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids = {binding.get("missing_item_id") for binding in bindings if isinstance(binding, dict)}
    if ids != EXPECTED_MISSING_ITEMS:
        if "tests.unit.primary" not in ids:
            err("missing_unit_binding: tests.unit.primary")
        err(f"missing_item_bindings ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")
    for binding in bindings:
        binding_obj = as_object(binding, "missing_item_bindings.entry")
        missing_item_id = binding_obj.get("missing_item_id")
        for field in ("implementation_refs", "test_refs", "runtime_validation"):
            values = as_list(binding_obj.get(field), f"missing_item_bindings.{missing_item_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{missing_item_id}.{field} must be non-empty")
            for value in values:
                if not isinstance(value, str) or not value:
                    err(f"missing_item_bindings.{missing_item_id}.{field} must contain non-empty strings")
                    continue
                if field in {"implementation_refs", "test_refs"} and "::" not in value:
                    repo_path(value, f"missing_item_bindings.{missing_item_id}.{field}")
    emit("missing_item_binding_validated", count=len(ids))
    return len(ids)


def validate_test_surfaces(contract: dict[str, Any]) -> None:
    test_source = source_text(
        "crates/frankenlibc-harness/tests/runtime_math_classification_matrix_test.rs",
        "classification_test",
    )
    for name in as_list(contract.get("required_unit_test_functions"), "completion_contract.required_unit_test_functions"):
        if not isinstance(name, str) or not function_exists(test_source, name):
            err(f"unit_test_surface_drift: missing classification matrix test {name!r}")

    completion_source = source_text(
        "crates/frankenlibc-harness/tests/runtime_math_classification_matrix_completion_contract_test.rs",
        "completion_harness_test",
    )
    for name in REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS:
        if not function_exists(completion_source, name):
            err(f"completion_test_surface_drift: missing completion test {name}")
    emit("test_surfaces_validated", unit_tests=len(as_list(contract.get("required_unit_test_functions"), "completion_contract.required_unit_test_functions")))


def write_outputs(status: str, summary: dict[str, Any]) -> None:
    report = {
        "schema_version": EXPECTED_SCHEMA,
        "status": status,
        "generated_at": now(),
        "contract": rel(CONTRACT),
        "summary": summary,
        "errors": errors,
        "events": [row["event"] for row in events],
    }
    write_json(REPORT, report)
    timestamp = now()
    write_jsonl(
        LOG,
        events
        + [
            {
                "event": "runtime_math_classification_matrix_completion_summary",
                "level": "info" if status == "pass" else "error",
                "status": status,
                "summary": summary,
                "timestamp": timestamp,
                "trace_id": EXPECTED_TRACE_ID,
            }
        ],
    )


def fail(summary: dict[str, Any] | None = None) -> int:
    write_outputs("fail", summary or {})
    for message in errors:
        print(message, file=sys.stderr)
    return 1


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    contract = validate_manifest(manifest)
    if errors:
        return fail()

    required_matrix = as_object(contract.get("required_matrix"), "completion_contract.required_matrix")
    required_gate = as_object(contract.get("required_gate"), "completion_contract.required_gate")
    required_log_fields = as_list(contract.get("required_log_fields"), "completion_contract.required_log_fields")

    matrix = load_json(MATRIX, "classification matrix")
    matrix_summary = validate_matrix(matrix, required_matrix)
    if errors:
        return fail(matrix_summary)

    governance = load_json(GOVERNANCE, "math governance")
    linkage = load_json(LINKAGE, "runtime math linkage")
    manifest_source = load_json(MANIFEST, "production kernel manifest")
    validate_source_consistency(matrix, governance, linkage, manifest_source)
    if errors:
        return fail(matrix_summary)

    binding_count = validate_missing_item_binding(manifest)
    if errors:
        return fail({**matrix_summary, "binding_count": binding_count})

    run_base_gate(required_gate)
    gate_summary = validate_gate_outputs(required_gate, required_log_fields)
    validate_test_surfaces(contract)

    summary = {**matrix_summary, **gate_summary, "binding_count": binding_count}
    if errors:
        return fail(summary)

    emit("runtime_math_classification_matrix_completion_validated", **summary)
    write_outputs("pass", summary)
    print(
        "PASS: runtime_math classification matrix completion contract "
        f"modules={summary['total_modules']} "
        f"core={summary['production_core']} "
        f"monitor={summary['production_monitor']} "
        f"research={summary['research']} "
        f"log_rows={summary['log_rows']} "
        f"bindings={summary['binding_count']}"
    )
    return 0


raise SystemExit(main())
PY
