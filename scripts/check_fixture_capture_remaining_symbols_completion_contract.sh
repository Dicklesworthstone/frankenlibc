#!/usr/bin/env bash
# check_fixture_capture_remaining_symbols_completion_contract.sh - bd-l93x.1.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/fixture_capture_remaining_symbols_completion_contract.v1.json}"
SYMBOL_MATRIX="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_SYMBOL_MATRIX:-$ROOT/tests/conformance/symbol_fixture_coverage.v1.json}"
PER_SYMBOL_REPORT="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_PER_SYMBOL_REPORT:-$ROOT/tests/conformance/per_symbol_fixture_tests.v1.json}"
PIPELINE_REPORT="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_PIPELINE_REPORT:-$ROOT/tests/conformance/fixture_pipeline.v1.json}"
GOLDEN_SUITE="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GOLDEN_SUITE:-$ROOT/tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json}"
OUT_DIR="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_OUT_DIR:-$ROOT/target/conformance/fixture_capture_remaining_symbols_completion_contract}"
REPORT="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_LOG:-$OUT_DIR/events.jsonl}"
GENERATED_PER_SYMBOL="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GENERATED_PER_SYMBOL:-$OUT_DIR/per_symbol_fixture_tests.generated.v1.json}"
GATE_DIR="${FRANKENLIBC_FIXTURE_REMAINING_SYMBOLS_GATE_DIR:-$OUT_DIR/source_gates}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GENERATED_PER_SYMBOL")" "$GATE_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
SYMBOL_MATRIX="$SYMBOL_MATRIX" \
PER_SYMBOL_REPORT="$PER_SYMBOL_REPORT" \
PIPELINE_REPORT="$PIPELINE_REPORT" \
GOLDEN_SUITE="$GOLDEN_SUITE" \
REPORT="$REPORT" \
LOG="$LOG" \
GENERATED_PER_SYMBOL="$GENERATED_PER_SYMBOL" \
GATE_DIR="$GATE_DIR" \
python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
SYMBOL_MATRIX = pathlib.Path(os.environ["SYMBOL_MATRIX"])
PER_SYMBOL_REPORT = pathlib.Path(os.environ["PER_SYMBOL_REPORT"])
PIPELINE_REPORT = pathlib.Path(os.environ["PIPELINE_REPORT"])
GOLDEN_SUITE = pathlib.Path(os.environ["GOLDEN_SUITE"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GENERATED_PER_SYMBOL = pathlib.Path(os.environ["GENERATED_PER_SYMBOL"])
GATE_DIR = pathlib.Path(os.environ["GATE_DIR"])

EXPECTED_SCHEMA = "fixture_capture_remaining_symbols_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "fixture_capture_remaining_symbols_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-l93x.1.1-fixture-capture-remaining-symbols-completion-contract"
EXPECTED_BEAD = "bd-l93x.1.1"
EXPECTED_ORIGINAL_BEAD = "bd-l93x.1"
EXPECTED_TRACE_ID = "bd-l93x.1.1::fixture-capture-remaining-symbols::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.golden.primary", "telemetry.primary"}
REQUIRED_SOURCE_ARTIFACTS = {
    "symbol_fixture_coverage_matrix",
    "symbol_fixture_coverage_gate",
    "symbol_fixture_coverage_harness",
    "per_symbol_fixture_report",
    "per_symbol_fixture_generator",
    "per_symbol_fixture_gate",
    "per_symbol_fixture_harness",
    "fixture_pipeline_report",
    "fixture_capture_pipeline_completion_contract",
    "fixture_capture_pipeline_completion_gate",
    "fixture_capture_pipeline_completion_harness",
    "golden_fixture_protocol",
    "golden_fixture_protocol_completion_contract",
    "golden_fixture_protocol_completion_gate",
    "golden_fixture_protocol_completion_harness",
    "golden_fixture_verify_suite",
    "completion_checker",
    "completion_harness",
}
PASS_EVENTS = {
    "fixture_remaining_symbol_sources_validated",
    "fixture_remaining_symbol_matrix_validated",
    "fixture_remaining_symbol_report_validated",
    "fixture_remaining_symbol_probe_generated",
    "fixture_remaining_symbol_golden_validated",
    "fixture_remaining_symbol_bindings_validated",
    "fixture_remaining_symbol_source_gates_replayed",
    "fixture_remaining_symbol_completion_contract_pass",
}
FAIL_EVENT = "fixture_remaining_symbol_completion_contract_fail"
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_golden_and_telemetry_items",
    "checker_accepts_remaining_symbols_contract",
    "checker_generates_per_symbol_probe",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_telemetry_binding",
    "checker_rejects_understated_fixture_case_inventory",
    "checker_rejects_golden_suite_failure_drift",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "scenario_id",
    "mode",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "decision_path",
    "outcome",
    "errno",
    "latency_ns",
    "source_commit",
    "failure_signature",
    "artifact_refs",
    "details",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "manifest_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "source_artifacts",
    "source_gate_results",
    "events",
    "errors",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, dict[str, Any]] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def base_event(event: str, level: str, outcome: str, **details: Any) -> dict[str, Any]:
    timestamp = now()
    return {
        "timestamp": timestamp,
        "ts": timestamp,
        "trace_id": EXPECTED_TRACE_ID,
        "level": level,
        "event": event,
        "bead_id": EXPECTED_BEAD,
        "stream": "conformance",
        "gate": "fixture_capture_remaining_symbols_completion_contract",
        "scenario_id": event,
        "mode": "strict",
        "api_family": "conformance_fixture",
        "symbol": "remaining_fixture_symbols",
        "oracle_kind": "completion_contract",
        "expected": "pass",
        "actual": outcome,
        "decision_path": "contract->artifact->gate->telemetry",
        "outcome": outcome,
        "errno": 0,
        "latency_ns": 0,
        "source_commit": SOURCE_COMMIT,
        "failure_signature": "" if outcome == "pass" else "; ".join(errors[:3]),
        "artifact_refs": [
            rel(CONTRACT),
            rel(SYMBOL_MATRIX),
            rel(PER_SYMBOL_REPORT),
            rel(GOLDEN_SUITE),
        ],
        "details": details,
    }


def emit(event: str, **details: Any) -> None:
    events.append(base_event(event, "info", "pass", **details))


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


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def source_text(path_text: str, context: str) -> str:
    path = repo_path(path_text, context)
    if path is None or not path.is_file():
        err(f"{context} must reference a file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}" in text or f"def {name}" in text


def expect_eq(actual: Any, expected: Any, context: str, code: str) -> None:
    if actual != expected:
        err(f"{code}: {context} expected {expected!r}, got {actual!r}")


def expect_ge(actual: int, minimum: int, context: str, code: str) -> None:
    if actual < minimum:
        err(f"{code}: {context} expected >= {minimum!r}, got {actual!r}")


def expect_le(actual: int, maximum: int, context: str, code: str) -> None:
    if actual > maximum:
        err(f"{code}: {context} expected <= {maximum!r}, got {actual!r}")


def run_command(
    command: list[str],
    *,
    marker: str,
    label: str,
    env_overrides: dict[str, str] | None = None,
) -> None:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    output_path = GATE_DIR / f"{label}.out"
    output_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    source_gate_results[label] = {
        "command": " ".join(command),
        "exit_code": result.returncode,
        "output": rel(output_path),
        "marker": marker,
    }
    if result.returncode != 0:
        err(f"source_gate_failed: {label} exit={result.returncode}: {(result.stdout + result.stderr)[-2000:]}")
    if marker not in (result.stdout + result.stderr):
        err(f"source_gate_marker_missing: {label} marker={marker!r}")


def generate_per_symbol_probe(required: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["python3", "scripts/generate_per_symbol_fixture_tests.py", "-o", str(GENERATED_PER_SYMBOL)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    source_gate_results["per_symbol_fixture_probe"] = {
        "command": "python3 scripts/generate_per_symbol_fixture_tests.py -o " + rel(GENERATED_PER_SYMBOL),
        "exit_code": result.returncode,
        "output_tail": (result.stdout + result.stderr)[-2000:],
    }
    if result.returncode != 0:
        err(f"per_symbol_fixture_probe failed with exit {result.returncode}: {(result.stdout + result.stderr)[-2000:]}")
        return {}
    generated = load_json(GENERATED_PER_SYMBOL, "generated per-symbol fixture report")
    summary = validate_per_symbol_report(generated, required, "generated_per_symbol_fixture_report")
    emit("fixture_remaining_symbol_probe_generated", path=rel(GENERATED_PER_SYMBOL), **summary)
    return summary


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    expect_eq(manifest.get("schema_version"), EXPECTED_SCHEMA, "schema_version", "contract_identity")
    expect_eq(manifest.get("manifest_id"), EXPECTED_MANIFEST, "manifest_id", "contract_identity")
    expect_eq(manifest.get("bead_id"), EXPECTED_BEAD, "bead_id", "contract_identity")
    expect_eq(manifest.get("original_bead"), EXPECTED_ORIGINAL_BEAD, "original_bead", "contract_identity")
    expect_eq(manifest.get("trace_id"), EXPECTED_TRACE_ID, "trace_id", "contract_identity")

    artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
    artifact_keys = set(artifacts)
    if artifact_keys != REQUIRED_SOURCE_ARTIFACTS:
        err(f"source_artifacts mismatch: missing={sorted(REQUIRED_SOURCE_ARTIFACTS - artifact_keys)} extra={sorted(artifact_keys - REQUIRED_SOURCE_ARTIFACTS)}")
    for key, path_text in artifacts.items():
        repo_path(path_text, f"source_artifacts.{key}")
    emit("fixture_remaining_symbol_sources_validated", source_artifact_count=len(artifact_keys))

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = {item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids") if isinstance(item, str)}
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_contract.missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    required_functions = as_object(manifest.get("required_test_functions"), "required_test_functions")
    positive = {item for item in as_list(required_functions.get("positive"), "required_test_functions.positive") if isinstance(item, str)}
    negative = {item for item in as_list(required_functions.get("negative"), "required_test_functions.negative") if isinstance(item, str)}
    if positive != REQUIRED_POSITIVE_TESTS:
        err(f"required_test_functions.positive mismatch: expected={sorted(REQUIRED_POSITIVE_TESTS)} got={sorted(positive)}")
    if negative != REQUIRED_NEGATIVE_TESTS:
        err(f"required_test_functions.negative mismatch: expected={sorted(REQUIRED_NEGATIVE_TESTS)} got={sorted(negative)}")

    telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
    expect_eq(telemetry.get("report_schema_version"), EXPECTED_REPORT_SCHEMA, "telemetry_contract.report_schema_version", "telemetry_contract")
    report_fields = {item for item in as_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields") if isinstance(item, str)}
    log_fields = {item for item in as_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields") if isinstance(item, str)}
    required_events = {item for item in as_list(telemetry.get("required_events"), "telemetry_contract.required_events") if isinstance(item, str)}
    if not REQUIRED_REPORT_FIELDS.issubset(report_fields):
        err(f"telemetry_contract missing report fields: {sorted(REQUIRED_REPORT_FIELDS - report_fields)}")
    if not REQUIRED_LOG_FIELDS.issubset(log_fields):
        err(f"telemetry_contract missing log fields: {sorted(REQUIRED_LOG_FIELDS - log_fields)}")
    if required_events != PASS_EVENTS:
        err(f"telemetry_contract.required_events mismatch: expected={sorted(PASS_EVENTS)} got={sorted(required_events)}")
    return contract


def validate_symbol_matrix(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    summary = as_object(matrix.get("summary"), "symbol_fixture_coverage.summary")
    target_statuses = summary.get("target_statuses")
    expect_eq(target_statuses, required.get("target_statuses"), "symbol_fixture_coverage.summary.target_statuses", "symbol_fixture_drift")
    total = int_field(summary, "total_exported_symbols", "symbol_fixture_coverage.summary")
    covered = int_field(summary, "covered_exported_symbols", "symbol_fixture_coverage.summary")
    uncovered = int_field(summary, "target_uncovered_symbols", "symbol_fixture_coverage.summary")
    expect_ge(total, int_field(required, "minimum_total_exported_symbols", "required_symbol_fixture_coverage"), "symbol_fixture_coverage.summary.total_exported_symbols", "symbol_fixture_drift")
    expect_ge(covered, int_field(required, "minimum_covered_exported_symbols", "required_symbol_fixture_coverage"), "symbol_fixture_coverage.summary.covered_exported_symbols", "symbol_fixture_drift")
    expect_ge(uncovered, int_field(required, "minimum_explicit_uncovered_symbols", "required_symbol_fixture_coverage"), "symbol_fixture_coverage.summary.target_uncovered_symbols", "symbol_fixture_drift")
    symbols = as_list(matrix.get("symbols"), "symbol_fixture_coverage.symbols")
    if len(symbols) < total:
        err(f"symbol_fixture_drift: symbols rows expected at least {total}, got {len(symbols)}")
    return {"total_exported_symbols": total, "covered_exported_symbols": covered, "target_uncovered_symbols": uncovered}


def validate_per_symbol_report(report: dict[str, Any], required: dict[str, Any], label: str) -> dict[str, Any]:
    summary = as_object(report.get("summary"), f"{label}.summary")
    total_symbols = int_field(summary, "total_symbols", f"{label}.summary")
    symbols_with_fixtures = int_field(summary, "symbols_with_fixtures", f"{label}.summary")
    total_fixture_files = int_field(summary, "total_fixture_files", f"{label}.summary")
    total_cases = int_field(summary, "total_cases", f"{label}.summary")
    total_format_issues = int_field(summary, "total_format_issues", f"{label}.summary")
    symbols_with_edge_cases = int_field(summary, "symbols_with_edge_cases", f"{label}.summary")
    symbols_with_errno_checks = int_field(summary, "symbols_with_errno_checks", f"{label}.summary")
    uncovered_action_count = int_field(summary, "uncovered_action_count", f"{label}.summary")
    expect_ge(total_symbols, int_field(required, "minimum_total_symbols", "required_per_symbol_fixture_report"), f"{label}.summary.total_symbols", "per_symbol_fixture_drift")
    expect_ge(symbols_with_fixtures, int_field(required, "minimum_symbols_with_fixtures", "required_per_symbol_fixture_report"), f"{label}.summary.symbols_with_fixtures", "per_symbol_fixture_drift")
    expect_ge(total_fixture_files, int_field(required, "minimum_total_fixture_files", "required_per_symbol_fixture_report"), f"{label}.summary.total_fixture_files", "per_symbol_fixture_drift")
    expect_ge(total_cases, int_field(required, "minimum_total_cases", "required_per_symbol_fixture_report"), f"{label}.summary.total_cases", "per_symbol_fixture_drift")
    expect_le(total_format_issues, int_field(required, "maximum_total_format_issues", "required_per_symbol_fixture_report"), f"{label}.summary.total_format_issues", "per_symbol_fixture_drift")
    expect_ge(symbols_with_edge_cases, int_field(required, "minimum_symbols_with_edge_cases", "required_per_symbol_fixture_report"), f"{label}.summary.symbols_with_edge_cases", "per_symbol_fixture_drift")
    expect_ge(symbols_with_errno_checks, int_field(required, "minimum_symbols_with_errno_checks", "required_per_symbol_fixture_report"), f"{label}.summary.symbols_with_errno_checks", "per_symbol_fixture_drift")
    expect_ge(uncovered_action_count, int_field(required, "minimum_uncovered_action_count", "required_per_symbol_fixture_report"), f"{label}.summary.uncovered_action_count", "per_symbol_fixture_drift")
    actions = as_list(report.get("uncovered_action_list"), f"{label}.uncovered_action_list")
    if len(actions) != uncovered_action_count:
        err(f"per_symbol_fixture_drift: {label}.uncovered_action_list length expected {uncovered_action_count}, got {len(actions)}")
    for index, action in enumerate(actions[:10]):
        action_obj = as_object(action, f"{label}.uncovered_action_list[{index}]")
        for key in ("symbol", "module", "status", "action"):
            if not isinstance(action_obj.get(key), str) or not action_obj[key]:
                err(f"per_symbol_fixture_drift: {label}.uncovered_action_list[{index}].{key} must be a non-empty string")
    return {
        "total_symbols": total_symbols,
        "symbols_with_fixtures": symbols_with_fixtures,
        "total_fixture_files": total_fixture_files,
        "total_cases": total_cases,
        "uncovered_action_count": uncovered_action_count,
    }


def validate_pipeline_report(report: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    summary = as_object(report.get("summary"), "fixture_pipeline.summary")
    fixture_files = int_field(summary, "total_fixture_files", "fixture_pipeline.summary")
    fixture_cases = int_field(summary, "total_fixture_cases", "fixture_pipeline.summary")
    unique_symbols = int_field(summary, "unique_symbols_in_fixtures", "fixture_pipeline.summary")
    symbols_with_fixtures = int_field(summary, "symbols_with_fixtures", "fixture_pipeline.summary")
    format_issues = int_field(summary, "fixture_format_issues", "fixture_pipeline.summary")
    expect_ge(fixture_files, int_field(required, "minimum_total_fixture_files", "required_fixture_pipeline"), "fixture_pipeline.summary.total_fixture_files", "fixture_pipeline_drift")
    expect_ge(fixture_cases, int_field(required, "minimum_total_fixture_cases", "required_fixture_pipeline"), "fixture_pipeline.summary.total_fixture_cases", "fixture_pipeline_drift")
    expect_ge(unique_symbols, int_field(required, "minimum_unique_symbols_in_fixtures", "required_fixture_pipeline"), "fixture_pipeline.summary.unique_symbols_in_fixtures", "fixture_pipeline_drift")
    expect_ge(symbols_with_fixtures, int_field(required, "minimum_symbols_with_fixtures", "required_fixture_pipeline"), "fixture_pipeline.summary.symbols_with_fixtures", "fixture_pipeline_drift")
    expect_le(format_issues, int_field(required, "maximum_fixture_format_issues", "required_fixture_pipeline"), "fixture_pipeline.summary.fixture_format_issues", "fixture_pipeline_drift")
    return {"pipeline_cases": fixture_cases, "unique_symbols_in_fixtures": unique_symbols}


def validate_golden_suite(suite: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    for key in ("total", "passed", "failed", "skipped"):
        expect_eq(suite.get(key), required.get(key), f"fixture_verify_golden_suite.{key}", "golden_fixture_drift")
    return {
        "golden_total": int(suite.get("total", 0)),
        "golden_passed": int(suite.get("passed", 0)),
        "golden_failed": int(suite.get("failed", 0)),
        "golden_skipped": int(suite.get("skipped", 0)),
    }


def validate_bindings(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids: set[str] = set()
    for index, binding in enumerate(bindings):
        binding_obj = as_object(binding, f"missing_item_bindings[{index}]")
        binding_id = binding_obj.get("id")
        if isinstance(binding_id, str):
            ids.add(binding_id)
        else:
            err(f"missing_item_bindings[{index}].id must be a string")
            continue
        for field in ("implementation_refs", "test_refs", "runtime_validation"):
            values = as_list(binding_obj.get(field), f"missing_item_bindings.{binding_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{binding_id}.{field} must be non-empty")
            for value in values:
                if not isinstance(value, str) or not value:
                    err(f"missing_item_bindings.{binding_id}.{field} must contain non-empty strings")
                    continue
                if field in {"implementation_refs", "test_refs"} and "::" not in value:
                    repo_path(value, f"missing_item_bindings.{binding_id}.{field}")
    if ids != EXPECTED_MISSING_ITEMS:
        if "telemetry.primary" not in ids:
            err("missing_telemetry_binding: telemetry.primary")
        if "tests.golden.primary" not in ids:
            err("missing_golden_binding: tests.golden.primary")
        err(f"missing_item_bindings ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")

    test_surfaces = {
        "crates/frankenlibc-harness/tests/fixture_capture_remaining_symbols_completion_contract_test.rs": REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS,
        "crates/frankenlibc-harness/tests/per_symbol_fixture_tests_test.rs": {
            "per_symbol_schema_complete",
            "per_symbol_coverage_adequate",
            "per_symbol_uncovered_actions_present",
        },
        "crates/frankenlibc-harness/tests/golden_fixture_protocol_completion_contract_test.rs": {
            "checker_validates_golden_fixture_protocol_contract",
            "checker_rejects_missing_golden_artifact_binding",
        },
    }
    for path_text, names in test_surfaces.items():
        text = source_text(path_text, f"test_surface.{path_text}")
        for name in names:
            if not function_exists(text, name):
                err(f"test_surface_drift: {path_text} missing {name}")
    emit("fixture_remaining_symbol_bindings_validated", binding_count=len(ids), test_surface_count=len(test_surfaces))
    return len(ids)


def replay_source_gates(required: dict[str, Any]) -> None:
    markers = as_object(required.get("required_source_gate_markers"), "completion_contract.required_source_gate_markers")
    run_command(["bash", "scripts/check_symbol_fixture_coverage.sh"], marker=str(markers.get("symbol_fixture_coverage_gate", "")), label="symbol_fixture_coverage_gate")
    pipeline_out = GATE_DIR / "fixture_capture_pipeline_completion"
    run_command(
        ["bash", "scripts/check_fixture_capture_pipeline_completion_contract.sh"],
        marker=str(markers.get("fixture_capture_pipeline_completion_gate", "")),
        label="fixture_capture_pipeline_completion_gate",
        env_overrides={
            "FRANKENLIBC_FIXTURE_CAPTURE_COMPLETION_OUT_DIR": str(pipeline_out),
        },
    )
    golden_out = GATE_DIR / "golden_fixture_protocol_completion"
    run_command(
        ["bash", "scripts/check_golden_fixture_protocol_completion_contract.sh"],
        marker=str(markers.get("golden_fixture_protocol_completion_gate", "")),
        label="golden_fixture_protocol_completion_gate",
        env_overrides={
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_OUT_DIR": str(golden_out),
        },
    )
    emit("fixture_remaining_symbol_source_gates_replayed", gate_count=3)


def write_outputs(status: str, summary: dict[str, Any]) -> None:
    event_names = [row["event"] for row in events]
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": EXPECTED_MANIFEST,
        "source_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_BEAD,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "summary": summary,
        "source_artifacts": as_object(load_json(CONTRACT, "completion contract").get("source_artifacts"), "source_artifacts") if CONTRACT.exists() else {},
        "source_gate_results": source_gate_results,
        "events": event_names,
        "errors": errors,
    }
    write_json(REPORT, report)
    final_event = FAIL_EVENT if status != "pass" else "fixture_remaining_symbol_completion_contract_pass"
    final_level = "error" if status != "pass" else "info"
    final = base_event(final_event, final_level, status if status in {"pass", "fail", "error", "skip", "timeout"} else "error", summary=summary)
    write_jsonl(LOG, events + [final])


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    contract = validate_manifest(manifest)
    if errors:
        write_outputs("fail", {})
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    required_symbol = as_object(contract.get("required_symbol_fixture_coverage"), "completion_contract.required_symbol_fixture_coverage")
    required_per_symbol = as_object(contract.get("required_per_symbol_fixture_report"), "completion_contract.required_per_symbol_fixture_report")
    required_pipeline = as_object(contract.get("required_fixture_pipeline"), "completion_contract.required_fixture_pipeline")
    required_golden = as_object(contract.get("required_golden_fixture_suite"), "completion_contract.required_golden_fixture_suite")

    symbol_summary = validate_symbol_matrix(load_json(SYMBOL_MATRIX, "symbol fixture coverage matrix"), required_symbol)
    emit("fixture_remaining_symbol_matrix_validated", **symbol_summary)
    per_symbol_summary = validate_per_symbol_report(load_json(PER_SYMBOL_REPORT, "per-symbol fixture report"), required_per_symbol, "per_symbol_fixture_report")
    emit("fixture_remaining_symbol_report_validated", **per_symbol_summary)
    pipeline_summary = validate_pipeline_report(load_json(PIPELINE_REPORT, "fixture pipeline report"), required_pipeline)
    generated_summary = generate_per_symbol_probe(required_per_symbol)
    golden_summary = validate_golden_suite(load_json(GOLDEN_SUITE, "golden fixture verify suite"), required_golden)
    emit("fixture_remaining_symbol_golden_validated", **golden_summary)
    binding_count = validate_bindings(manifest)
    if not errors:
        replay_source_gates(contract)

    summary = {
        **symbol_summary,
        **per_symbol_summary,
        **pipeline_summary,
        **golden_summary,
        "generated_total_cases": generated_summary.get("total_cases"),
        "binding_count": binding_count,
    }
    if errors:
        write_outputs("fail", summary)
        for message in errors:
            print(message, file=sys.stderr)
        return 1

    write_outputs("pass", summary)
    print(
        "PASS: fixture capture remaining-symbol completion contract "
        f"symbols={summary['total_exported_symbols']} "
        f"covered={summary['covered_exported_symbols']} "
        f"uncovered_actions={summary['uncovered_action_count']} "
        f"cases={summary['total_cases']} "
        f"golden_total={summary['golden_total']} "
        f"bindings={summary['binding_count']}"
    )
    return 0


raise SystemExit(main())
PY
