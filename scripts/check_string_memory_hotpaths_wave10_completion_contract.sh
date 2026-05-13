#!/usr/bin/env bash
# check_string_memory_hotpaths_wave10_completion_contract.sh -- bd-c2qqr completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STRING_WAVE10_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/string_memory_hotpaths_wave10_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRING_WAVE10_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/string_memory_hotpaths_wave10_completion}"
REPORT="${FRANKENLIBC_STRING_WAVE10_COMPLETION_REPORT:-${OUT_DIR}/string_memory_hotpaths_wave10_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRING_WAVE10_COMPLETION_LOG:-${OUT_DIR}/string_memory_hotpaths_wave10_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

SCHEMA = "string_memory_hotpaths_wave10_completion_contract.v1"
REPORT_SCHEMA = "string_memory_hotpaths_wave10_completion_contract.report.v1"
BEAD_ID = "bd-c2qqr"
TRACE_ID = "bd-c2qqr::string-memory-hotpaths-wave10::completion::v1"
CAMPAIGN_ID = "fcq-string-memory-hotpaths"
WAVE_ID = "wave-10-string-memory-hotpaths"
FIXTURE_PATH = "tests/conformance/fixtures/string_memory_hotpaths_wave10.json"
FIXTURE_FILE = "string_memory_hotpaths_wave10.json"
AMBIENT_POLICY = "forbid_pointer_locale_or_process_buffer_capture"
REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "string_wave10_fixture",
    "fixture_executor",
    "string_wave10_harness_test",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "fixture_coverage_prioritizer",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_EVENTS = {
    "source_artifacts_validated",
    "string_wave10_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "string_wave10_completion_contract_validated",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "string_wave10_fixture_symbol_coverage",
    "string_wave10_fixture_mode_coverage",
    "string_wave10_fixture_schema",
    "coverage_accounting_drift",
    "completed_symbol_still_claimed",
    "non_rch_validation_command",
    "missing_validation_command",
    "missing_test_binding",
    "missing_telemetry_event",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(CONTRACT)}
summary: dict[str, Any] = {
    "string_wave10_symbol_count": 0,
    "required_mode_count": 0,
    "fixture_case_count": 0,
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "string_wave10_completion_contract_failed"


def load_json(path: pathlib.Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def read_text(path: pathlib.Path, context: str, signature: str) -> str:
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"{context}: cannot read {rel(path)}: {exc}")
        return ""


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
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
        "source_commit": SOURCE_COMMIT,
        "target_dir": rel(OUT_DIR),
        "failure_signature": failure_signature,
        **fields,
    }


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def mark_check(start_errors: int, event_name: str, signature: str, **fields: Any) -> None:
    failed = len(errors) > start_errors
    events.append(event(event_name, "fail" if failed else "pass", signature if failed else "none", **fields))


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    start_errors = len(errors)
    result: dict[str, dict[str, Any]] = {}
    for row in as_array(contract.get("source_artifacts"), "source_artifacts"):
        obj = as_object(row, "source_artifacts[]")
        artifact_id = obj.get("id")
        path = obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", "source artifact id must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            add_error("malformed_contract", f"source artifact {artifact_id} path must be non-empty")
            continue
        result[artifact_id] = obj
        if obj.get("kind") != "tracker" and not resolve(path).exists():
            add_error("missing_source_artifact", f"source artifact {artifact_id} missing path {path}")
    missing = sorted(REQUIRED_ARTIFACT_IDS - set(result))
    if missing:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing}")
    mark_check(start_errors, "source_artifacts_validated", "missing_source_artifact", artifact_count=len(result))
    return result


def validate_top_level(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", "schema_version mismatch")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", "bead_id mismatch")
    if contract.get("trace_id") != TRACE_ID:
        add_error("malformed_contract", "trace_id mismatch")
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    if completion.get("campaign_id") != CAMPAIGN_ID:
        add_error("malformed_contract", "campaign_id mismatch")
    if completion.get("wave_id") != WAVE_ID:
        add_error("malformed_contract", "wave_id mismatch")
    if completion.get("fixture_file") != FIXTURE_PATH:
        add_error("malformed_contract", "fixture_file mismatch")
    if completion.get("ambient_state_policy") != AMBIENT_POLICY:
        add_error("malformed_contract", "ambient policy mismatch")
    return completion


def validate_fixture(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    fixture = as_object(load_json(resolve(FIXTURE_PATH), "fixture", "string_wave10_fixture_schema"), "fixture")
    required_symbols = string_set(
        completion.get("required_first_wave_symbols"),
        "completion_contract.required_first_wave_symbols",
        "malformed_contract",
    )
    required_modes = string_set(
        completion.get("required_modes"),
        "completion_contract.required_modes",
        "malformed_contract",
    )
    summary["string_wave10_symbol_count"] = len(required_symbols)
    summary["required_mode_count"] = len(required_modes)
    cases = as_array(fixture.get("cases"), "fixture.cases", "string_wave10_fixture_schema")
    summary["fixture_case_count"] = len(cases)
    if fixture.get("family") != "string_memory_hotpaths_wave10":
        add_error("string_wave10_fixture_schema", "fixture family mismatch")
    campaign = as_object(fixture.get("campaign"), "fixture.campaign", "string_wave10_fixture_schema")
    fixture_symbols = string_set(
        campaign.get("first_wave_symbols"),
        "fixture.campaign.first_wave_symbols",
        "string_wave10_fixture_symbol_coverage",
    )
    if fixture_symbols != required_symbols:
        add_error(
            "string_wave10_fixture_symbol_coverage",
            f"fixture symbols {sorted(fixture_symbols)} != contract symbols {sorted(required_symbols)}",
        )
    if campaign.get("wave_id") != WAVE_ID:
        add_error("string_wave10_fixture_schema", "fixture wave_id mismatch")
    if campaign.get("ambient_state_policy") != AMBIENT_POLICY:
        add_error("string_wave10_fixture_schema", "fixture ambient policy mismatch")
    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    for case in cases:
        obj = as_object(case, "fixture.cases[]", "string_wave10_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str) and symbol in modes_by_symbol:
            modes_by_symbol[symbol].add(mode)
    missing_modes = {
        symbol: sorted(required_modes - modes)
        for symbol, modes in modes_by_symbol.items()
        if not required_modes <= modes
    }
    if missing_modes:
        add_error("string_wave10_fixture_mode_coverage", f"missing fixture modes: {missing_modes}")
    expected_count = completion.get("expected_fixture_case_count")
    if expected_count != len(cases):
        add_error("string_wave10_fixture_schema", f"fixture case count {len(cases)} != expected {expected_count}")
    mark_check(
        start_errors,
        "string_wave10_fixture_validated",
        "string_wave10_fixture_symbol_coverage",
        symbol_count=len(required_symbols),
        case_count=len(cases),
    )


def validate_coverage(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    required_symbols = string_set(
        completion.get("required_first_wave_symbols"),
        "completion_contract.required_first_wave_symbols",
        "malformed_contract",
    )
    expected = as_object(completion.get("expected_coverage"), "completion_contract.expected_coverage")
    symbol_coverage = as_object(
        load_json(ROOT / "tests/conformance/symbol_fixture_coverage.v1.json", "symbol fixture coverage", "coverage_accounting_drift"),
        "symbol_fixture_coverage",
    )
    per_symbol = as_object(
        load_json(ROOT / "tests/conformance/per_symbol_fixture_tests.v1.json", "per-symbol fixture tests", "coverage_accounting_drift"),
        "per_symbol_fixture_tests",
    )
    prioritizer = as_object(
        load_json(ROOT / "tests/conformance/fixture_coverage_prioritizer.v1.json", "fixture coverage prioritizer", "coverage_accounting_drift"),
        "fixture_coverage_prioritizer",
    )
    symbol_rows = {
        row.get("symbol"): row
        for row in as_array(symbol_coverage.get("symbols"), "symbol_fixture_coverage.symbols", "coverage_accounting_drift")
        if isinstance(row, dict)
    }
    per_symbol_rows = {
        row.get("symbol"): row
        for row in as_array(per_symbol.get("per_symbol_report"), "per_symbol_fixture_tests.per_symbol_report", "coverage_accounting_drift")
        if isinstance(row, dict)
    }
    for symbol in sorted(required_symbols):
        row = as_object(symbol_rows.get(symbol), f"symbol coverage row {symbol}", "coverage_accounting_drift")
        if not row.get("covered"):
            add_error("coverage_accounting_drift", f"{symbol} is not covered in symbol fixture coverage")
        if FIXTURE_FILE not in row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} missing {FIXTURE_FILE} in symbol fixture coverage")
        if set(row.get("fixture_modes", [])) != {"strict", "hardened"}:
            add_error("coverage_accounting_drift", f"{symbol} missing strict+hardened fixture modes")
        per_row = as_object(per_symbol_rows.get(symbol), f"per-symbol row {symbol}", "coverage_accounting_drift")
        if not per_row.get("has_fixtures") or FIXTURE_FILE not in per_row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} missing {FIXTURE_FILE} per-symbol fixture accounting")
    families = {
        row.get("module"): row
        for row in as_array(symbol_coverage.get("families"), "symbol_fixture_coverage.families", "coverage_accounting_drift")
        if isinstance(row, dict)
    }
    string_family = as_object(families.get("string_abi"), "string_abi coverage family", "coverage_accounting_drift")
    summary_row = as_object(symbol_coverage.get("summary"), "symbol_fixture_coverage.summary", "coverage_accounting_drift")
    per_summary = as_object(per_symbol.get("summary"), "per_symbol_fixture_tests.summary", "coverage_accounting_drift")
    comparisons = [
        ("string_target_covered", string_family.get("target_covered")),
        ("string_target_uncovered", string_family.get("target_uncovered")),
        ("string_current_coverage_pct", string_family.get("target_coverage_pct")),
        ("total_target_covered", summary_row.get("target_covered_symbols")),
        ("total_target_uncovered", summary_row.get("target_uncovered_symbols")),
        ("per_symbol_symbols_with_fixtures", per_summary.get("symbols_with_fixtures")),
        ("per_symbol_total_cases", per_summary.get("total_cases")),
    ]
    for key, actual in comparisons:
        if expected.get(key) != actual:
            add_error("coverage_accounting_drift", f"{key}: expected {expected.get(key)} actual {actual}")
    campaigns = as_array(prioritizer.get("campaigns"), "fixture_coverage_prioritizer.campaigns", "coverage_accounting_drift")
    campaign = next((row for row in campaigns if isinstance(row, dict) and row.get("campaign_id") == CAMPAIGN_ID), {})
    next_symbols = set(as_array(campaign.get("first_wave_symbols"), "string prioritizer first_wave_symbols", "coverage_accounting_drift"))
    overlap = sorted(required_symbols & next_symbols)
    if overlap:
        add_error("completed_symbol_still_claimed", f"completed wave-10 symbols still listed as next work: {overlap}")
    mark_check(
        start_errors,
        "coverage_accounting_validated",
        "coverage_accounting_drift",
        target_covered=summary_row.get("target_covered_symbols"),
        target_uncovered=summary_row.get("target_uncovered_symbols"),
    )


def validate_commands(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    commands = string_set(completion.get("required_validation_commands"), "completion_contract.required_validation_commands", "missing_validation_command")
    required_needles = [
        "cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave10_completion_contract_test",
        "cargo check -p frankenlibc-harness --test string_memory_hotpaths_wave10_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test string_memory_hotpaths_wave10_completion_contract_test -- -D warnings",
        "cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave10_conformance_test",
    ]
    for needle in required_needles:
        if not any(needle in command for command in commands):
            add_error("missing_validation_command", f"missing validation command containing {needle}")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            add_error("non_rch_validation_command", f"cargo validation command must use rch exec: {command}")
        if "RCH_FORCE_REMOTE=true" not in command:
            add_error("non_rch_validation_command", f"validation command must force remote rch: {command}")
    mark_check(start_errors, "validation_commands_validated", "non_rch_validation_command", command_count=len(commands))


def validate_tests(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    test_source = read_text(
        ROOT / "crates/frankenlibc-harness/tests/string_memory_hotpaths_wave10_completion_contract_test.rs",
        "completion harness test",
        "missing_test_binding",
    )
    required = string_set(completion.get("required_positive_tests"), "required_positive_tests", "missing_test_binding")
    required |= string_set(completion.get("required_negative_tests"), "required_negative_tests", "missing_test_binding")
    missing = [name for name in sorted(required) if f"fn {name}" not in test_source]
    if missing:
        add_error("missing_test_binding", f"completion harness missing tests: {missing}")
    mark_check(start_errors, "test_surfaces_validated", "missing_test_binding", test_count=len(required))


def validate_telemetry(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    declared = string_set(completion.get("required_telemetry_events"), "required_telemetry_events", "missing_telemetry_event")
    missing = sorted(REQUIRED_EVENTS - declared)
    if missing:
        add_error("missing_telemetry_event", f"missing required telemetry events: {missing}")
    mark_check(start_errors, "telemetry_contract_validated", "missing_telemetry_event", event_count=len(declared))


contract = as_object(load_json(CONTRACT, "completion contract"), "completion contract")
completion = validate_top_level(contract)
artifact_map(contract)
validate_fixture(completion)
validate_coverage(completion)
validate_commands(completion)
validate_tests(completion)
validate_telemetry(completion)
status = "fail" if errors else "pass"
events.append(event("string_wave10_completion_contract_validated", status, primary_signature() if errors else "none"))

report = {
    "schema_version": REPORT_SCHEMA,
    "bead_id": BEAD_ID,
    "trace_id": TRACE_ID,
    "status": status,
    "source_commit": SOURCE_COMMIT,
    "summary": summary,
    "events": events,
    "errors": errors,
    "artifact_refs": sorted(artifact_refs),
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(1)

print(json.dumps(report, indent=2, sort_keys=True))
PY
