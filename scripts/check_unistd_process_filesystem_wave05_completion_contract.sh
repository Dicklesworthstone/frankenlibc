#!/usr/bin/env bash
# check_unistd_process_filesystem_wave05_completion_contract.sh -- bd-waaa6.2 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_UNISTD_WAVE05_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/unistd_process_filesystem_wave05_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_UNISTD_WAVE05_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/unistd_process_filesystem_wave05_completion}"
REPORT="${FRANKENLIBC_UNISTD_WAVE05_COMPLETION_REPORT:-${OUT_DIR}/unistd_process_filesystem_wave05_completion_contract.report.json}"
LOG="${FRANKENLIBC_UNISTD_WAVE05_COMPLETION_LOG:-${OUT_DIR}/unistd_process_filesystem_wave05_completion_contract.events.jsonl}"
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

SCHEMA = "unistd_process_filesystem_wave05_completion_contract.v1"
REPORT_SCHEMA = "unistd_process_filesystem_wave05_completion_contract.report.v1"
BEAD_ID = "bd-waaa6.2"
TRACE_ID = "bd-waaa6.2::unistd-process-filesystem-wave05::completion::v1"
CAMPAIGN_ID = "fcq-unistd-process-filesystem"
WAVE_ID = "wave-05-unistd-process-filesystem-argp-codeset-process-fd"
FIXTURE_PATH = "tests/conformance/fixtures/unistd_process_filesystem_wave05.json"
FIXTURE_FILE = "unistd_process_filesystem_wave05.json"
HARNESS_TEST = "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave05_conformance_test.rs"
COMPLETION_TEST = "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave05_completion_contract_test.rs"
CHECKER_PATH = "scripts/check_unistd_process_filesystem_wave05_completion_contract.sh"
AMBIENT_POLICY = "forbid_ambient_argv_textdomain_heap_signal_path_cwd_capability_or_mode_metadata"
REQUIRED_LOG_FIELDS = ["symbol", "mode", "expected", "actual", "failure_signature"]
REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "unistd_wave05_fixture",
    "fixture_executor",
    "unistd_wave05_harness_test",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "fixture_coverage_prioritizer",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_EVENTS = {
    "source_artifacts_validated",
    "unistd_wave05_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "unistd_wave05_completion_contract_validated",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "unistd_wave05_fixture_symbol_coverage",
    "unistd_wave05_fixture_mode_coverage",
    "unistd_wave05_fixture_schema",
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
    "unistd_wave05_symbol_count": 0,
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
    return "unistd_wave05_completion_contract_failed"


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
    if completion.get("source_fixture_commit") != "34db374d":
        add_error("malformed_contract", "source_fixture_commit mismatch")
    if completion.get("coverage_refresh_commit") != "ecce67b8":
        add_error("malformed_contract", "coverage_refresh_commit mismatch")
    if completion.get("coverage_close_commit") != "a617bf00":
        add_error("malformed_contract", "coverage_close_commit mismatch")
    if completion.get("fixture_file") != FIXTURE_PATH:
        add_error("malformed_contract", "fixture_file mismatch")
    if completion.get("harness_test") != HARNESS_TEST:
        add_error("malformed_contract", "harness_test mismatch")
    if completion.get("ambient_state_policy") != AMBIENT_POLICY:
        add_error("malformed_contract", "ambient policy mismatch")
    return completion


def validate_fixture(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    fixture = as_object(load_json(resolve(FIXTURE_PATH), "fixture", "unistd_wave05_fixture_schema"), "fixture")
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
    summary["unistd_wave05_symbol_count"] = len(required_symbols)
    summary["required_mode_count"] = len(required_modes)
    cases = as_array(fixture.get("cases"), "fixture.cases", "unistd_wave05_fixture_schema")
    summary["fixture_case_count"] = len(cases)
    if fixture.get("family") != "unistd/process-filesystem":
        add_error("unistd_wave05_fixture_schema", "fixture family mismatch")
    if fixture.get("structured_log_fields") != REQUIRED_LOG_FIELDS:
        add_error("unistd_wave05_fixture_schema", "fixture structured log fields mismatch")
    campaign = as_object(fixture.get("campaign"), "fixture.campaign", "unistd_wave05_fixture_schema")
    if campaign.get("campaign_id") != CAMPAIGN_ID:
        add_error("unistd_wave05_fixture_schema", "fixture campaign_id mismatch")
    if campaign.get("wave_id") != WAVE_ID:
        add_error("unistd_wave05_fixture_schema", "fixture wave_id mismatch")
    if campaign.get("ambient_state_policy") != AMBIENT_POLICY:
        add_error("unistd_wave05_fixture_schema", "fixture ambient_state_policy mismatch")
    fixture_symbols = string_set(
        campaign.get("first_wave_symbols"),
        "fixture.campaign.first_wave_symbols",
        "unistd_wave05_fixture_symbol_coverage",
    )
    if fixture_symbols != required_symbols:
        add_error(
            "unistd_wave05_fixture_symbol_coverage",
            f"fixture symbols {sorted(fixture_symbols)} differ from contract {sorted(required_symbols)}",
        )
    if len(cases) != completion.get("expected_fixture_case_count"):
        add_error("unistd_wave05_fixture_schema", "fixture case count mismatch")
    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    for row in cases:
        obj = as_object(row, "fixture.cases[]", "unistd_wave05_fixture_schema")
        function = obj.get("function")
        mode = obj.get("mode")
        if isinstance(function, str) and isinstance(mode, str):
            modes_by_symbol.setdefault(function, set()).add(mode)
    for symbol in required_symbols:
        if modes_by_symbol.get(symbol, set()) != required_modes:
            add_error(
                "unistd_wave05_fixture_mode_coverage",
                f"{symbol} modes {sorted(modes_by_symbol.get(symbol, set()))} != {sorted(required_modes)}",
            )
    mark_check(
        start_errors,
        "unistd_wave05_fixture_validated",
        "unistd_wave05_fixture_schema",
        symbol_count=len(required_symbols),
        fixture_case_count=len(cases),
    )


def validate_coverage(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    required_symbols = string_set(
        completion.get("required_first_wave_symbols"),
        "completion_contract.required_first_wave_symbols",
        "malformed_contract",
    )
    required_modes = string_set(completion.get("required_modes"), "completion_contract.required_modes", "malformed_contract")
    expected = as_object(completion.get("expected_coverage"), "completion_contract.expected_coverage")
    coverage = as_object(
        load_json(ROOT / "tests/conformance/symbol_fixture_coverage.v1.json", "symbol fixture coverage", "coverage_accounting_drift"),
        "symbol fixture coverage",
        "coverage_accounting_drift",
    )
    per_symbol = as_object(
        load_json(ROOT / "tests/conformance/per_symbol_fixture_tests.v1.json", "per-symbol fixture tests", "coverage_accounting_drift"),
        "per-symbol fixture tests",
        "coverage_accounting_drift",
    )
    prioritizer = as_object(
        load_json(ROOT / "tests/conformance/fixture_coverage_prioritizer.v1.json", "fixture coverage prioritizer", "coverage_accounting_drift"),
        "fixture coverage prioritizer",
        "coverage_accounting_drift",
    )

    coverage_summary = as_object(coverage.get("summary"), "symbol_fixture_coverage.summary", "coverage_accounting_drift")
    if coverage_summary.get("target_covered_symbols") != expected.get("total_target_covered"):
        add_error("coverage_accounting_drift", "total target covered symbols drifted")
    if coverage_summary.get("target_uncovered_symbols") != expected.get("total_target_uncovered"):
        add_error("coverage_accounting_drift", "total target uncovered symbols drifted")
    unistd_family = None
    for row in as_array(coverage.get("families"), "symbol_fixture_coverage.families", "coverage_accounting_drift"):
        obj = as_object(row, "symbol_fixture_coverage.families[]", "coverage_accounting_drift")
        if obj.get("module") == "unistd_abi":
            unistd_family = obj
            break
    if not unistd_family:
        add_error("coverage_accounting_drift", "missing unistd_abi coverage family row")
        unistd_family = {}
    if unistd_family.get("target_covered") != expected.get("unistd_target_covered"):
        add_error("coverage_accounting_drift", "unistd target_covered drifted")
    if unistd_family.get("target_uncovered") != expected.get("unistd_target_uncovered"):
        add_error("coverage_accounting_drift", "unistd target_uncovered drifted")
    if unistd_family.get("target_coverage_pct") != expected.get("unistd_current_coverage_pct"):
        add_error("coverage_accounting_drift", "unistd target_coverage_pct drifted")

    coverage_rows = {
        obj.get("symbol"): obj
        for obj in (
            as_object(row, "symbol_fixture_coverage.symbols[]", "coverage_accounting_drift")
            for row in as_array(coverage.get("symbols"), "symbol_fixture_coverage.symbols", "coverage_accounting_drift")
        )
        if isinstance(obj.get("symbol"), str)
    }
    for symbol in required_symbols:
        row = coverage_rows.get(symbol, {})
        if row.get("covered") is not True or FIXTURE_FILE not in row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} missing fixture coverage row for {FIXTURE_FILE}")
        if set(row.get("fixture_modes", [])) != required_modes:
            add_error("coverage_accounting_drift", f"{symbol} fixture modes drifted in symbol coverage")

    per_summary = as_object(per_symbol.get("summary"), "per_symbol.summary", "coverage_accounting_drift")
    if per_summary.get("symbols_with_fixtures") != expected.get("per_symbol_symbols_with_fixtures"):
        add_error("coverage_accounting_drift", "per-symbol symbols_with_fixtures drifted")
    if per_summary.get("total_cases") != expected.get("per_symbol_total_cases"):
        add_error("coverage_accounting_drift", "per-symbol total_cases drifted")
    fixture_analysis = None
    for row in as_array(per_symbol.get("fixture_file_analyses"), "per_symbol.fixture_file_analyses", "coverage_accounting_drift"):
        obj = as_object(row, "per_symbol.fixture_file_analyses[]", "coverage_accounting_drift")
        if obj.get("file") == FIXTURE_FILE:
            fixture_analysis = obj
            break
    if not fixture_analysis:
        add_error("coverage_accounting_drift", f"missing fixture analysis for {FIXTURE_FILE}")
        fixture_analysis = {}
    if fixture_analysis.get("total_cases") != completion.get("expected_fixture_case_count"):
        add_error("coverage_accounting_drift", "fixture analysis total_cases drifted")
    if fixture_analysis.get("unique_symbols") != len(required_symbols):
        add_error("coverage_accounting_drift", "fixture analysis unique_symbols drifted")
    per_rows = {
        obj.get("symbol"): obj
        for obj in (
            as_object(row, "per_symbol.per_symbol_report[]", "coverage_accounting_drift")
            for row in as_array(per_symbol.get("per_symbol_report"), "per_symbol.per_symbol_report", "coverage_accounting_drift")
        )
        if isinstance(obj.get("symbol"), str)
    }
    for symbol in required_symbols:
        row = per_rows.get(symbol, {})
        if row.get("has_fixtures") is not True or FIXTURE_FILE not in row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} missing per-symbol fixture row")
        if row.get("case_count") != len(required_modes):
            add_error("coverage_accounting_drift", f"{symbol} per-symbol case count drifted")
        if set(row.get("modes_tested", [])) != required_modes:
            add_error("coverage_accounting_drift", f"{symbol} per-symbol modes drifted")

    campaign = None
    for row in as_array(prioritizer.get("campaigns"), "prioritizer.campaigns", "coverage_accounting_drift"):
        obj = as_object(row, "prioritizer.campaigns[]", "coverage_accounting_drift")
        if obj.get("campaign_id") == CAMPAIGN_ID:
            campaign = obj
            break
    if not campaign:
        add_error("coverage_accounting_drift", "missing prioritizer unistd campaign")
        campaign = {}
    if campaign.get("target_covered") != expected.get("unistd_target_covered"):
        add_error("coverage_accounting_drift", "prioritizer unistd target_covered drifted")
    if campaign.get("target_uncovered") != expected.get("unistd_target_uncovered"):
        add_error("coverage_accounting_drift", "prioritizer unistd target_uncovered drifted")
    if campaign.get("current_coverage_pct") != expected.get("unistd_current_coverage_pct"):
        add_error("coverage_accounting_drift", "prioritizer unistd current_coverage_pct drifted")
    still_claimed = sorted(required_symbols & set(campaign.get("first_wave_symbols", [])))
    if still_claimed:
        add_error("completed_symbol_still_claimed", f"completed wave-05 symbols still in next wave: {still_claimed}")
    mark_check(
        start_errors,
        "coverage_accounting_validated",
        "coverage_accounting_drift",
        total_target_covered=coverage_summary.get("target_covered_symbols"),
        unistd_target_covered=unistd_family.get("target_covered"),
        per_symbol_total_cases=per_summary.get("total_cases"),
    )


def validate_commands(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    commands = [row for row in as_array(completion.get("required_validation_commands"), "required_validation_commands") if isinstance(row, str)]
    if len(commands) != 4:
        add_error("missing_validation_command", "expected exactly four required validation commands")
    required_substrings = [
        "cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave05_completion_contract_test",
        "cargo check -p frankenlibc-harness --test unistd_process_filesystem_wave05_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test unistd_process_filesystem_wave05_completion_contract_test -- -D warnings",
        "cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave05_conformance_test",
    ]
    for command in commands:
        before_rch = command.split("rch exec", 1)[0]
        if (
            "RCH_FORCE_REMOTE=true" not in command
            or "rch exec --" not in command
            or "CARGO_TARGET_DIR=" not in command
            or "[RCH] local" in command
            or "cargo " in before_rch
        ):
            add_error("non_rch_validation_command", f"validation command is not remote-rch-only: {command}")
    for required in required_substrings:
        if not any(required in command for command in commands):
            add_error("missing_validation_command", f"missing validation command containing {required}")
    mark_check(start_errors, "validation_commands_validated", "non_rch_validation_command", command_count=len(commands))


def validate_test_surfaces(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    checker_text = read_text(ROOT / CHECKER_PATH, "completion checker", "missing_test_binding")
    test_text = read_text(ROOT / COMPLETION_TEST, "completion harness test", "missing_test_binding")
    fixture_test_text = read_text(ROOT / HARNESS_TEST, "wave-05 harness test", "missing_test_binding")
    required_positive = string_set(completion.get("required_positive_tests"), "required_positive_tests", "malformed_contract")
    required_negative = string_set(completion.get("required_negative_tests"), "required_negative_tests", "malformed_contract")
    for needle in [
        SCHEMA,
        BEAD_ID,
        FIXTURE_FILE,
        "coverage_accounting_drift",
        "non_rch_validation_command",
        "missing_telemetry_event",
    ]:
        if needle not in checker_text:
            add_error("missing_test_binding", f"checker missing binding {needle}")
    for test_name in required_positive | required_negative:
        if test_name not in test_text:
            add_error("missing_test_binding", f"completion harness missing test {test_name}")
    for needle in ["FIRST_WAVE_SYMBOLS", AMBIENT_POLICY, "conformance-matrix-case"]:
        if needle not in fixture_test_text:
            add_error("missing_test_binding", f"wave-05 harness test missing binding {needle}")
    mark_check(start_errors, "test_surfaces_validated", "missing_test_binding", test_count=len(required_positive | required_negative))


def validate_telemetry(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    declared = string_set(completion.get("required_telemetry_events"), "required_telemetry_events", "malformed_contract")
    missing = sorted(REQUIRED_EVENTS - declared)
    if missing:
        add_error("missing_telemetry_event", f"missing required telemetry events: {missing}")
    mark_check(start_errors, "telemetry_contract_validated", "missing_telemetry_event", required_event_count=len(declared))


contract = as_object(load_json(CONTRACT, "completion contract"), "completion contract")
artifact_map(contract)
completion = validate_top_level(contract)
validate_fixture(completion)
validate_coverage(completion)
validate_commands(completion)
validate_test_surfaces(completion)
validate_telemetry(completion)

status = "pass" if not errors else "fail"
events.append(
    event(
        "unistd_wave05_completion_contract_validated",
        status,
        "none" if status == "pass" else primary_signature(),
        error_count=len(errors),
    )
)

report = {
    "schema_version": REPORT_SCHEMA,
    "bead_id": BEAD_ID,
    "trace_id": TRACE_ID,
    "status": status,
    "source_commit": SOURCE_COMMIT,
    "target_dir": rel(OUT_DIR),
    "artifact_refs": sorted(artifact_refs),
    "summary": summary,
    "errors": errors,
    "events": events,
}
write_json(REPORT, report)
write_jsonl(LOG, events)
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if status == "pass" else 1)
PY
