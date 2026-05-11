#!/usr/bin/env bash
# fixture_capture_pipeline_completion_contract - bd-2hh.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/fixture_capture_pipeline_completion_contract.v1.json}"
PIPELINE_REPORT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_PIPELINE_REPORT:-$ROOT/tests/conformance/fixture_pipeline.v1.json}"
UNIT_REPORT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_UNIT_REPORT:-$ROOT/tests/conformance/fixture_unit_tests.v1.json}"
SCHEMA_CONTRACT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_SCHEMA_CONTRACT:-$ROOT/tests/conformance/fixture_schema_validation.v1.json}"
EXECUTOR_GOLDEN_CONTRACT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_EXECUTOR_GOLDEN_CONTRACT:-$ROOT/tests/conformance/fixture_executor_ownership_and_golden.v1.json}"
VERIFY_GOLDEN_SUITE="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_VERIFY_GOLDEN_SUITE:-$ROOT/tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json}"
OUT_DIR="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_OUT_DIR:-$ROOT/target/conformance/fixture_capture_pipeline_completion_contract}"
REPORT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"
GENERATED_PIPELINE="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_PIPELINE:-$OUT_DIR/fixture_pipeline.generated.v1.json}"
GENERATED_UNIT="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_UNIT:-$OUT_DIR/fixture_unit_tests.generated.v1.json}"
GENERATED_UNIT_LOG="${FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_GENERATED_UNIT_LOG:-$OUT_DIR/fixture_unit_tests.generated.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GENERATED_PIPELINE")" "$(dirname "$GENERATED_UNIT")" "$(dirname "$GENERATED_UNIT_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
PIPELINE_REPORT="$PIPELINE_REPORT" \
UNIT_REPORT="$UNIT_REPORT" \
SCHEMA_CONTRACT="$SCHEMA_CONTRACT" \
EXECUTOR_GOLDEN_CONTRACT="$EXECUTOR_GOLDEN_CONTRACT" \
VERIFY_GOLDEN_SUITE="$VERIFY_GOLDEN_SUITE" \
REPORT="$REPORT" \
LOG="$LOG" \
GENERATED_PIPELINE="$GENERATED_PIPELINE" \
GENERATED_UNIT="$GENERATED_UNIT" \
GENERATED_UNIT_LOG="$GENERATED_UNIT_LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
PIPELINE_REPORT = pathlib.Path(os.environ["PIPELINE_REPORT"])
UNIT_REPORT = pathlib.Path(os.environ["UNIT_REPORT"])
SCHEMA_CONTRACT = pathlib.Path(os.environ["SCHEMA_CONTRACT"])
EXECUTOR_GOLDEN_CONTRACT = pathlib.Path(os.environ["EXECUTOR_GOLDEN_CONTRACT"])
VERIFY_GOLDEN_SUITE = pathlib.Path(os.environ["VERIFY_GOLDEN_SUITE"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GENERATED_PIPELINE = pathlib.Path(os.environ["GENERATED_PIPELINE"])
GENERATED_UNIT = pathlib.Path(os.environ["GENERATED_UNIT"])
GENERATED_UNIT_LOG = pathlib.Path(os.environ["GENERATED_UNIT_LOG"])

EXPECTED_SCHEMA = "fixture_capture_pipeline_completion_contract.v1"
EXPECTED_BEAD = "bd-2hh.1.1"
EXPECTED_ORIGINAL_BEAD = "bd-2hh.1"
EXPECTED_TRACE_ID = "bd-2hh.1.1::fixture-capture-pipeline::completion::v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "tests.conformance.primary",
}
EXPECTED_SOURCE_ARTIFACT_IDS = {
    "capture_impl",
    "fixture_loader_impl",
    "fixture_runner_impl",
    "fixture_exec_boundary",
    "fixture_pipeline_report",
    "fixture_pipeline_generator",
    "fixture_pipeline_gate",
    "fixture_pipeline_test",
    "fixture_unit_report",
    "fixture_unit_generator",
    "fixture_unit_gate",
    "fixture_unit_test",
    "fixture_schema_contract",
    "fixture_schema_gate",
    "fixture_schema_test",
    "fixture_executor_golden_contract",
    "fixture_executor_golden_gate",
    "fixture_executor_golden_test",
    "fixture_verify_golden_suite",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_fixture_capture_completion_items",
    "checker_accepts_fixture_capture_completion_contract",
    "completion_contract_generates_pipeline_and_unit_probes",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_golden_binding",
    "checker_rejects_fixture_pipeline_count_drift",
    "checker_rejects_golden_suite_failure_drift",
}
SOURCE_TEST_ANCHORS = {
    "crates/frankenlibc-harness/tests/conformance_fixture_pipeline_test.rs": {
        "pipeline_report_generates_successfully",
        "pipeline_fixtures_have_valid_format",
        "pipeline_sufficient_cases",
    },
    "crates/frankenlibc-harness/tests/conformance_fixture_unit_tests_test.rs": {
        "fixture_unit_determinism_verified",
        "fixture_unit_regression_baseline_populated",
        "fixture_unit_log_emission_contains_required_fields",
    },
    "crates/frankenlibc-harness/tests/fixture_schema_validation_test.rs": {
        "checker_passes_for_current_fixture_corpus",
        "checker_rejects_missing_expected_errno_where_required",
    },
    "crates/frankenlibc-harness/tests/fixture_executor_ownership_and_golden_test.rs": {
        "golden_manifest_matches_current_execute_fixture_case_outputs",
        "checker_rejects_missing_golden_case",
    },
    "crates/frankenlibc-harness/tests/fixture_capture_pipeline_completion_contract_test.rs": (
        REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS
    ),
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
        "ts": timestamp,
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


def number_field(obj: dict[str, Any], key: str, context: str) -> float:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        err(f"{context}.{key} must be numeric")
        return 0.0
    return float(value)


def expect_eq(actual: Any, expected: Any, context: str, code: str) -> None:
    if actual != expected:
        err(f"{code}: {context} expected {expected!r}, got {actual!r}")


def expect_ge(actual: int | float, minimum: int | float, context: str, code: str) -> None:
    if actual < minimum:
        err(f"{code}: {context} expected >= {minimum!r}, got {actual!r}")


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}" in text or f"def {name}" in text


def run_command(command: list[str], *, marker: str | None = None, label: str) -> subprocess.CompletedProcess[str] | None:
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    except Exception as exc:
        err(f"{label} failed to start: {exc}")
        return None
    output = result.stdout + result.stderr
    if result.returncode != 0:
        err(f"{label} failed with exit {result.returncode}: {output[-2000:]}")
        return result
    if marker is not None and marker not in output:
        err(f"{label} missing marker {marker!r}: {output[-2000:]}")
    return result


def generate_pipeline_probe() -> dict[str, Any]:
    result = run_command(
        [
            "python3",
            "scripts/generate_conformance_fixture_pipeline.py",
            "-o",
            str(GENERATED_PIPELINE),
        ],
        label="fixture_pipeline_probe",
    )
    if result is not None and result.returncode == 0:
        emit("fixture_pipeline_probe_generated", path=rel(GENERATED_PIPELINE))
    return load_json(GENERATED_PIPELINE, "generated fixture pipeline probe")


def generate_unit_probe() -> dict[str, Any]:
    result = run_command(
        [
            "python3",
            "scripts/generate_conformance_fixture_unit_tests.py",
            "-o",
            str(GENERATED_UNIT),
            "--timestamp",
            "2026-05-11T00:00:00Z",
            "--log",
            str(GENERATED_UNIT_LOG),
        ],
        label="fixture_unit_probe",
    )
    if result is not None and result.returncode == 0:
        emit("fixture_unit_probe_generated", report=rel(GENERATED_UNIT), log=rel(GENERATED_UNIT_LOG))
    return load_json(GENERATED_UNIT, "generated fixture unit probe")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    expect_eq(manifest.get("schema_version"), EXPECTED_SCHEMA, "schema_version", "contract_identity")
    expect_eq(manifest.get("bead_id"), EXPECTED_BEAD, "bead_id", "contract_identity")
    expect_eq(manifest.get("original_bead"), EXPECTED_ORIGINAL_BEAD, "original_bead", "contract_identity")
    expect_eq(manifest.get("trace_id"), EXPECTED_TRACE_ID, "trace_id", "contract_identity")

    source_artifacts = as_list(manifest.get("source_artifacts"), "source_artifacts")
    ids: set[str] = set()
    for index, artifact in enumerate(source_artifacts):
        artifact_obj = as_object(artifact, f"source_artifacts[{index}]")
        artifact_id = artifact_obj.get("id")
        if not isinstance(artifact_id, str) or not artifact_id:
            err(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        ids.add(artifact_id)
        for key in ("kind", "evidence"):
            if not isinstance(artifact_obj.get(key), str) or not artifact_obj[key]:
                err(f"source_artifacts.{artifact_id}.{key} must be a non-empty string")
        repo_path(artifact_obj.get("path"), f"source_artifacts.{artifact_id}.path")

    missing_ids = EXPECTED_SOURCE_ARTIFACT_IDS - ids
    extra_ids = ids - EXPECTED_SOURCE_ARTIFACT_IDS
    if missing_ids or extra_ids:
        err(f"source_artifacts ids mismatch: missing={sorted(missing_ids)} extra={sorted(extra_ids)}")
    emit("source_artifacts_validated", count=len(ids))

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = set()
    for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids"):
        if isinstance(item, str):
            missing_items.add(item)
        else:
            err("completion_contract.missing_item_ids must contain strings")
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_contract.missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    required_functions = as_object(manifest.get("required_test_functions"), "required_test_functions")
    positive = {item for item in as_list(required_functions.get("positive"), "required_test_functions.positive") if isinstance(item, str)}
    negative = {item for item in as_list(required_functions.get("negative"), "required_test_functions.negative") if isinstance(item, str)}
    if positive != REQUIRED_POSITIVE_TESTS:
        err(f"required_test_functions.positive mismatch: expected={sorted(REQUIRED_POSITIVE_TESTS)} got={sorted(positive)}")
    if negative != REQUIRED_NEGATIVE_TESTS:
        err(f"required_test_functions.negative mismatch: expected={sorted(REQUIRED_NEGATIVE_TESTS)} got={sorted(negative)}")

    return contract


def validate_pipeline_report(report: dict[str, Any], required: dict[str, Any], label: str) -> dict[str, Any]:
    actual_fixture_files = len(sorted((ROOT / "tests/conformance/fixtures").glob("*.json")))
    expect_eq(actual_fixture_files, int_field(required, "total_fixture_files", "required_fixture_pipeline"), "fixture corpus file count", "fixture_pipeline_drift")

    summary = as_object(report.get("summary"), f"{label}.summary")
    expect_eq(int_field(summary, "total_fixture_files", f"{label}.summary"), int_field(required, "total_fixture_files", "required_fixture_pipeline"), f"{label}.summary.total_fixture_files", "fixture_pipeline_drift")
    total_cases = int_field(summary, "total_fixture_cases", f"{label}.summary")
    unique_symbols = int_field(summary, "unique_symbols_in_fixtures", f"{label}.summary")
    symbols_with_fixtures = int_field(summary, "symbols_with_fixtures", f"{label}.summary")
    coverage_pct = number_field(summary, "coverage_pct", f"{label}.summary")
    expect_ge(total_cases, int_field(required, "total_fixture_cases_min", "required_fixture_pipeline"), f"{label}.summary.total_fixture_cases", "fixture_pipeline_drift")
    expect_ge(unique_symbols, int_field(required, "unique_symbols_in_fixtures_min", "required_fixture_pipeline"), f"{label}.summary.unique_symbols_in_fixtures", "fixture_pipeline_drift")
    expect_ge(symbols_with_fixtures, int_field(required, "symbols_with_fixtures_min", "required_fixture_pipeline"), f"{label}.summary.symbols_with_fixtures", "fixture_pipeline_drift")
    expect_eq(int_field(summary, "fixture_format_issues", f"{label}.summary"), int_field(required, "fixture_format_issues", "required_fixture_pipeline"), f"{label}.summary.fixture_format_issues", "fixture_pipeline_drift")
    expect_ge(coverage_pct, number_field(required, "coverage_pct_min", "required_fixture_pipeline"), f"{label}.summary.coverage_pct", "fixture_pipeline_drift")
    return {
        "total_fixture_files": int_field(summary, "total_fixture_files", f"{label}.summary"),
        "total_fixture_cases": total_cases,
        "unique_symbols_in_fixtures": unique_symbols,
        "symbols_with_fixtures": symbols_with_fixtures,
    }


def validate_unit_report(report: dict[str, Any], required: dict[str, Any], label: str) -> dict[str, Any]:
    summary = as_object(report.get("summary"), f"{label}.summary")
    expect_eq(int_field(summary, "total_fixture_files", f"{label}.summary"), int_field(required, "total_fixture_files", "required_fixture_unit"), f"{label}.summary.total_fixture_files", "fixture_unit_drift")
    expect_eq(int_field(summary, "valid_fixture_files", f"{label}.summary"), int_field(required, "valid_fixture_files", "required_fixture_unit"), f"{label}.summary.valid_fixture_files", "fixture_unit_drift")
    expect_eq(int_field(summary, "invalid_fixture_files", f"{label}.summary"), int_field(required, "invalid_fixture_files", "required_fixture_unit"), f"{label}.summary.invalid_fixture_files", "fixture_unit_drift")
    total_cases = int_field(summary, "total_cases", f"{label}.summary")
    expect_ge(total_cases, int_field(required, "total_cases_min", "required_fixture_unit"), f"{label}.summary.total_cases", "fixture_unit_drift")
    expect_eq(int_field(summary, "total_issues", f"{label}.summary"), int_field(required, "total_issues", "required_fixture_unit"), f"{label}.summary.total_issues", "fixture_unit_drift")
    expect_eq(int_field(summary, "total_warnings", f"{label}.summary"), int_field(required, "total_warnings", "required_fixture_unit"), f"{label}.summary.total_warnings", "fixture_unit_drift")
    unique_families = int_field(summary, "unique_families", f"{label}.summary")
    unique_symbols = int_field(summary, "unique_symbols", f"{label}.summary")
    expect_ge(unique_families, int_field(required, "unique_families_min", "required_fixture_unit"), f"{label}.summary.unique_families", "fixture_unit_drift")
    expect_ge(unique_symbols, int_field(required, "unique_symbols_min", "required_fixture_unit"), f"{label}.summary.unique_symbols", "fixture_unit_drift")
    expect_eq(summary.get("determinism_verified"), required.get("determinism_verified"), f"{label}.summary.determinism_verified", "fixture_unit_drift")

    regression = as_object(report.get("regression_detection"), f"{label}.regression_detection")
    expect_eq(regression.get("status"), required.get("regression_status"), f"{label}.regression_detection.status", "fixture_unit_drift")
    digest = regression.get("baseline_fixture_digest")
    if not isinstance(digest, str) or len(digest) != int_field(required, "baseline_digest_length", "required_fixture_unit"):
        err(f"fixture_unit_drift: {label}.regression_detection.baseline_fixture_digest length drift")
    return {
        "total_fixture_files": int_field(summary, "total_fixture_files", f"{label}.summary"),
        "total_cases": total_cases,
        "unique_families": unique_families,
        "unique_symbols": unique_symbols,
    }


def validate_schema_contract(contract: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    inventory = as_object(contract.get("expected_inventory"), "fixture_schema_validation.expected_inventory")
    for key, expected in required.items():
        expect_eq(inventory.get(key), expected, f"fixture_schema_validation.expected_inventory.{key}", "fixture_schema_drift")
    emit("fixture_schema_inventory_validated", standard_case_count=inventory.get("standard_case_count"))
    return inventory


def validate_golden_contract(contract: dict[str, Any], suite: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    golden_manifest = as_object(contract.get("golden_manifest"), "fixture_executor_ownership_and_golden.golden_manifest")
    cases = as_list(golden_manifest.get("cases"), "fixture_executor_ownership_and_golden.golden_manifest.cases")
    expect_eq(len(cases), int_field(required, "executor_case_count", "required_golden"), "fixture_executor_golden case count", "fixture_golden_drift")
    for index, case in enumerate(cases):
        case_obj = as_object(case, f"fixture_executor_golden.cases[{index}]")
        digest = case_obj.get("expected_sha256") or case_obj.get("canonical_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            err(f"fixture_golden_drift: fixture_executor_golden.cases[{index}].expected_sha256 must be 64 lowercase hex")

    expect_eq(suite.get("total"), int_field(required, "verify_suite_total", "required_golden"), "fixture_verify_golden_suite.total", "fixture_golden_drift")
    expect_eq(suite.get("passed"), int_field(required, "verify_suite_passed", "required_golden"), "fixture_verify_golden_suite.passed", "fixture_golden_drift")
    expect_eq(suite.get("failed"), int_field(required, "verify_suite_failed", "required_golden"), "fixture_verify_golden_suite.failed", "fixture_golden_drift")
    expect_eq(suite.get("skipped"), int_field(required, "verify_suite_skipped", "required_golden"), "fixture_verify_golden_suite.skipped", "fixture_golden_drift")
    emit("fixture_golden_contract_validated", cases=len(cases), suite_total=suite.get("total"))
    return {"executor_case_count": len(cases), "suite_total": suite.get("total")}


def replay_base_gates(required: dict[str, Any]) -> None:
    markers = as_object(required.get("required_gate_markers"), "completion_contract.required_gate_markers")
    schema_markers = [item for item in as_list(markers.get("fixture_schema_gate"), "required_gate_markers.fixture_schema_gate") if isinstance(item, str)]
    golden_markers = [item for item in as_list(markers.get("fixture_executor_golden_gate"), "required_gate_markers.fixture_executor_golden_gate") if isinstance(item, str)]
    for marker in schema_markers:
        run_command(["bash", "scripts/check_fixture_schema_validation.sh", "--validate-only"], marker=marker, label="fixture_schema_gate")
    for marker in golden_markers:
        run_command(["bash", "scripts/check_fixture_executor_ownership_and_golden.sh", "--validate-only"], marker=marker, label="fixture_executor_golden_gate")
    emit("base_fixture_gates_replayed", schema_markers=len(schema_markers), golden_markers=len(golden_markers))


def validate_missing_item_bindings(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids: set[str] = set()
    for index, binding in enumerate(bindings):
        binding_obj = as_object(binding, f"missing_item_bindings[{index}]")
        missing_item_id = binding_obj.get("missing_item_id")
        if isinstance(missing_item_id, str):
            ids.add(missing_item_id)
        else:
            err(f"missing_item_bindings[{index}].missing_item_id must be a string")
            continue
        for field in ("implementation_refs", "test_refs", "runtime_validation"):
            values = as_list(binding_obj.get(field), f"missing_item_bindings.{missing_item_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{missing_item_id}.{field} must be non-empty")
            for value in values:
                if not isinstance(value, str) or not value:
                    err(f"missing_item_bindings.{missing_item_id}.{field} must contain non-empty strings")
                    continue
                if field in {"implementation_refs", "test_refs"} and "::" not in value and not value.endswith(".sh --validate-only"):
                    repo_path(value, f"missing_item_bindings.{missing_item_id}.{field}")
    if ids != EXPECTED_MISSING_ITEMS:
        if "tests.golden.primary" not in ids:
            err("missing_golden_binding: tests.golden.primary")
        err(f"missing_item_bindings ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")
    emit("missing_item_bindings_validated", count=len(ids))
    return len(ids)


def validate_test_surfaces() -> None:
    for path_text, required_names in SOURCE_TEST_ANCHORS.items():
        text = source_text(path_text, f"test_surface.{path_text}")
        for name in required_names:
            if not function_exists(text, name):
                err(f"test_surface_drift: {path_text} missing {name}")
    emit("test_surfaces_validated", file_count=len(SOURCE_TEST_ANCHORS))


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
                "event": "fixture_capture_pipeline_completion_summary",
                "level": "info" if status == "pass" else "error",
                "status": status,
                "summary": summary,
                "timestamp": timestamp,
                "trace_id": EXPECTED_TRACE_ID,
                "ts": timestamp,
            }
        ],
    )


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    contract = validate_manifest(manifest)
    if errors:
        write_outputs("fail", {})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    required_pipeline = as_object(contract.get("required_fixture_pipeline"), "completion_contract.required_fixture_pipeline")
    required_unit = as_object(contract.get("required_fixture_unit"), "completion_contract.required_fixture_unit")
    required_schema = as_object(contract.get("required_schema_inventory"), "completion_contract.required_schema_inventory")
    required_golden = as_object(contract.get("required_golden"), "completion_contract.required_golden")

    pipeline_report = load_json(PIPELINE_REPORT, "fixture pipeline report")
    pipeline_summary = validate_pipeline_report(pipeline_report, required_pipeline, "fixture_pipeline_report")
    emit("fixture_pipeline_report_validated", **pipeline_summary)
    if errors:
        write_outputs("fail", pipeline_summary)
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    generated_pipeline = generate_pipeline_probe()
    generated_pipeline_summary = validate_pipeline_report(generated_pipeline, required_pipeline, "generated_fixture_pipeline_report")
    if errors:
        write_outputs("fail", {**pipeline_summary, "generated_pipeline": generated_pipeline_summary})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    unit_report = load_json(UNIT_REPORT, "fixture unit report")
    unit_summary = validate_unit_report(unit_report, required_unit, "fixture_unit_report")
    emit("fixture_unit_report_validated", **unit_summary)
    if errors:
        write_outputs("fail", {**pipeline_summary, **{"unit_total_cases": unit_summary.get("total_cases")}})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    generated_unit = generate_unit_probe()
    generated_unit_summary = validate_unit_report(generated_unit, required_unit, "generated_fixture_unit_report")
    if GENERATED_UNIT_LOG.is_file():
        log_rows = [line for line in GENERATED_UNIT_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(log_rows) < 2:
            err("fixture_unit_drift: generated fixture unit log must contain at least two JSONL rows")
        for line_no, line in enumerate(log_rows, 1):
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                err(f"fixture_unit_drift: generated fixture unit log line {line_no} is invalid JSON: {exc}")
                break
    else:
        err(f"fixture_unit_drift: generated fixture unit log missing: {rel(GENERATED_UNIT_LOG)}")
    if errors:
        write_outputs("fail", {**pipeline_summary, "generated_unit": generated_unit_summary})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    schema_contract = load_json(SCHEMA_CONTRACT, "fixture schema validation contract")
    schema_inventory = validate_schema_contract(schema_contract, required_schema)
    executor_golden_contract = load_json(EXECUTOR_GOLDEN_CONTRACT, "fixture executor golden contract")
    verify_golden_suite = load_json(VERIFY_GOLDEN_SUITE, "fixture verify golden suite")
    golden_summary = validate_golden_contract(executor_golden_contract, verify_golden_suite, required_golden)
    if errors:
        write_outputs("fail", {**pipeline_summary, **unit_summary, **golden_summary})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    binding_count = validate_missing_item_bindings(manifest)
    if errors:
        write_outputs("fail", {**pipeline_summary, **unit_summary, **golden_summary, "binding_count": binding_count})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    replay_base_gates(contract)
    validate_test_surfaces()

    source_count = len(as_list(manifest.get("source_artifacts"), "source_artifacts"))
    summary = {
        "total_fixture_files": pipeline_summary["total_fixture_files"],
        "total_fixture_cases": pipeline_summary["total_fixture_cases"],
        "unit_total_cases": unit_summary["total_cases"],
        "schema_standard_case_count": schema_inventory.get("standard_case_count"),
        "golden_case_count": golden_summary["executor_case_count"],
        "suite_total": golden_summary["suite_total"],
        "binding_count": binding_count,
        "source_artifact_count": source_count,
    }
    if errors:
        write_outputs("fail", summary)
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    emit("fixture_capture_pipeline_completion_contract_validated", **summary)
    write_outputs("pass", summary)
    print(
        "PASS: fixture capture pipeline completion contract "
        f"files={summary['total_fixture_files']} "
        f"pipeline_cases={summary['total_fixture_cases']} "
        f"unit_cases={summary['unit_total_cases']} "
        f"golden_cases={summary['golden_case_count']} "
        f"bindings={summary['binding_count']}"
    )
    return 0


raise SystemExit(main())
PY
