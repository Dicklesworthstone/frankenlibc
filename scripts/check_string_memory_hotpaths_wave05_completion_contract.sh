#!/usr/bin/env bash
# check_string_memory_hotpaths_wave05_completion_contract.sh -- bd-0y1w6.2 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STRING_WAVE05_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/string_memory_hotpaths_wave05_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRING_WAVE05_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/string_memory_hotpaths_wave05_completion}"
REPORT="${FRANKENLIBC_STRING_WAVE05_COMPLETION_REPORT:-${OUT_DIR}/string_memory_hotpaths_wave05_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRING_WAVE05_COMPLETION_LOG:-${OUT_DIR}/string_memory_hotpaths_wave05_completion_contract.events.jsonl}"
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

SCHEMA = "string_memory_hotpaths_wave05_completion_contract.v1"
REPORT_SCHEMA = "string_memory_hotpaths_wave05_completion_contract.report.v1"
BEAD_ID = "bd-0y1w6.2"
EPIC_ID = "bd-0y1w6"
TRACE_ID = "bd-0y1w6.2::string-memory-hotpaths-wave05::completion::v1"
CAMPAIGN_ID = "fcq-string-memory-hotpaths"
WAVE_ID = "wave-05-string-memory-hotpaths"
FIXTURE_FILE = "string_memory_hotpaths_wave05.json"
FIXTURE_PATH = "tests/conformance/fixtures/string_memory_hotpaths_wave05.json"

REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "fixture_coverage_prioritizer",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "string_wave05_fixture",
    "fixture_executor",
    "string_wave05_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_PROOFS = {
    "string-wave05-code-proof": {"commit": "ba933b3a"},
    "bd-0y1w6.1": {"commit": "0cfb12e8", "tracker_close_commit": "9d6686a2"},
}
REQUIRED_TELEMETRY_EVENTS = {
    "source_artifacts_validated",
    "dependency_proofs_validated",
    "string_wave05_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "string_wave05_completion_contract_validated",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_string_wave05_sources",
    "checker_accepts_string_wave05_completion_contract",
    "checker_emits_structured_string_wave05_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_string_wave05_fixture_symbol",
    "checker_rejects_stale_string_wave05_coverage_accounting",
    "checker_rejects_non_remote_rch_cargo_validation_command",
    "checker_rejects_missing_required_telemetry_event",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "dependency_proof_missing",
    "dependency_commit_missing",
    "string_wave05_fixture_symbol_coverage",
    "string_wave05_fixture_mode_coverage",
    "string_wave05_fixture_schema",
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
    "string_wave05_symbol_count": 0,
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
    return "string_wave05_completion_contract_failed"


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


def artifact_path(artifacts: dict[str, dict[str, Any]], artifact_id: str, fallback: str) -> pathlib.Path:
    row = artifacts.get(artifact_id, {})
    path = row.get("path", fallback)
    return resolve(path if isinstance(path, str) else fallback)


def mark_check(name: str, start_errors: int, event_name: str, signature: str, **fields: Any) -> None:
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
        if not resolve(path).exists():
            add_error("missing_source_artifact", f"source artifact {artifact_id} missing path {path}")
    missing = sorted(REQUIRED_ARTIFACT_IDS - set(result))
    if missing:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing}")
    mark_check("source_artifacts", start_errors, "source_artifacts_validated", "missing_source_artifact", artifact_count=len(result))
    return result


def validate_top_level(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", "schema_version mismatch")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", "bead_id mismatch")
    if contract.get("epic_id") != EPIC_ID:
        add_error("malformed_contract", "epic_id mismatch")
    if contract.get("trace_id") != TRACE_ID:
        add_error("malformed_contract", "trace_id mismatch")
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    missing_items = string_set(
        completion.get("missing_item_ids"),
        "completion_contract.missing_item_ids",
        "malformed_contract",
    )
    missing_required = sorted(REQUIRED_MISSING_ITEMS - missing_items)
    if missing_required:
        add_error("malformed_contract", f"missing completion items: {missing_required}")
    if completion.get("campaign_id") != CAMPAIGN_ID:
        add_error("malformed_contract", "campaign_id mismatch")
    if completion.get("wave_id") != WAVE_ID:
        add_error("malformed_contract", "wave_id mismatch")
    return completion


def validate_dependency_proofs(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    proofs = {}
    for row in as_array(completion.get("required_dependency_proofs"), "required_dependency_proofs"):
        obj = as_object(row, "required_dependency_proofs[]")
        proof_id = obj.get("proof_id") or obj.get("bead_id")
        if isinstance(proof_id, str):
            proofs[proof_id] = obj
    for proof_id, required in REQUIRED_PROOFS.items():
        proof = proofs.get(proof_id)
        if proof is None:
            add_error("dependency_proof_missing", f"missing dependency proof {proof_id}")
            continue
        for key, expected in required.items():
            if proof.get(key) != expected:
                add_error("dependency_commit_missing", f"{proof_id}.{key} expected {expected}, got {proof.get(key)}")
        for evidence_path in as_array(proof.get("evidence_paths"), f"{proof_id}.evidence_paths", "dependency_proof_missing"):
            if not isinstance(evidence_path, str) or not resolve(evidence_path).exists():
                add_error("dependency_proof_missing", f"{proof_id} evidence path missing: {evidence_path}")
    mark_check(
        "dependency_proofs",
        start_errors,
        "dependency_proofs_validated",
        "dependency_proof_missing",
        proof_count=len(proofs),
    )


def validate_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> tuple[set[str], set[str]]:
    start_errors = len(errors)
    required_symbols = string_set(
        completion.get("required_first_wave_symbols"),
        "completion_contract.required_first_wave_symbols",
        "string_wave05_fixture_symbol_coverage",
    )
    required_modes = string_set(
        completion.get("required_modes"),
        "completion_contract.required_modes",
        "string_wave05_fixture_mode_coverage",
    )
    summary["string_wave05_symbol_count"] = len(required_symbols)
    summary["required_mode_count"] = len(required_modes)
    if completion.get("fixture_file") != FIXTURE_PATH:
        add_error("string_wave05_fixture_schema", "fixture_file mismatch")
    fixture = load_json(artifact_path(artifacts, "string_wave05_fixture", FIXTURE_PATH), "string wave05 fixture", "string_wave05_fixture_schema")
    campaign = as_object(fixture.get("campaign"), "fixture.campaign", "string_wave05_fixture_schema")
    if fixture.get("version") != "v1" or fixture.get("family") != "string_memory_hotpaths_wave05":
        add_error("string_wave05_fixture_schema", "fixture version/family mismatch")
    if campaign.get("campaign_id") != CAMPAIGN_ID or campaign.get("wave_id") != WAVE_ID:
        add_error("string_wave05_fixture_schema", "fixture campaign mismatch")
    if campaign.get("ambient_state_policy") != "forbid_pointer_locale_or_process_buffer_capture":
        add_error("string_wave05_fixture_schema", "fixture ambient-state policy mismatch")
    declared = string_set(campaign.get("first_wave_symbols"), "fixture.campaign.first_wave_symbols", "string_wave05_fixture_symbol_coverage")
    if declared != required_symbols:
        add_error("string_wave05_fixture_symbol_coverage", f"fixture first-wave symbols drifted: missing={sorted(required_symbols - declared)} extra={sorted(declared - required_symbols)}")
    if as_array(campaign.get("residual_symbols"), "fixture.campaign.residual_symbols", "string_wave05_fixture_schema"):
        add_error("string_wave05_fixture_schema", "fixture residual_symbols must be empty")
    structured = string_set(fixture.get("structured_log_fields"), "fixture.structured_log_fields", "string_wave05_fixture_schema")
    required_fields = string_set(
        completion.get("required_structured_log_fields"),
        "completion_contract.required_structured_log_fields",
        "string_wave05_fixture_schema",
    )
    if not required_fields <= structured:
        add_error("string_wave05_fixture_schema", f"fixture structured fields missing {sorted(required_fields - structured)}")
    modes_by_symbol: dict[str, set[str]] = {}
    forbidden_tokens = string_set(
        completion.get("forbidden_ambient_output_tokens"),
        "completion_contract.forbidden_ambient_output_tokens",
        "string_wave05_fixture_schema",
    )
    cases = as_array(fixture.get("cases"), "fixture.cases", "string_wave05_fixture_schema")
    summary["fixture_case_count"] = len(cases)
    for case in cases:
        obj = as_object(case, "fixture.cases[]", "string_wave05_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        expected_output = obj.get("expected_output")
        if isinstance(symbol, str) and isinstance(mode, str):
            modes_by_symbol.setdefault(symbol, set()).add(mode)
        if mode not in required_modes:
            add_error("string_wave05_fixture_mode_coverage", f"unsupported fixture mode {mode} for {symbol}")
        if obj.get("expected_errno") != 0:
            add_error("string_wave05_fixture_schema", f"case {obj.get('name')} exposes errno")
        inputs = as_object(obj.get("inputs"), "fixture.cases[].inputs", "string_wave05_fixture_schema")
        if inputs.get("symbol") != symbol:
            add_error("string_wave05_fixture_schema", f"case {obj.get('name')} inputs.symbol mismatch")
        if inputs.get("ambient_state_policy") != "forbid_pointer_locale_or_process_buffer_capture":
            add_error("string_wave05_fixture_schema", f"case {obj.get('name')} ambient policy mismatch")
        if isinstance(expected_output, str):
            for field in required_fields:
                if f"{field}=" not in expected_output:
                    add_error("string_wave05_fixture_schema", f"case {obj.get('name')} expected_output missing {field}")
            for token in forbidden_tokens:
                if token in expected_output:
                    add_error("string_wave05_fixture_schema", f"case {obj.get('name')} leaks ambient token {token}")
        else:
            add_error("string_wave05_fixture_schema", f"case {obj.get('name')} expected_output must be a string")
    for symbol in required_symbols:
        modes = modes_by_symbol.get(symbol, set())
        if modes != required_modes:
            add_error("string_wave05_fixture_mode_coverage", f"{symbol} modes {sorted(modes)} != {sorted(required_modes)}")
    mark_check(
        "string_wave05_fixture",
        start_errors,
        "string_wave05_fixture_validated",
        "string_wave05_fixture_symbol_coverage",
        symbol_count=len(required_symbols),
        case_count=len(cases),
    )
    return required_symbols, required_modes


def find_by_key(rows: Any, key: str, expected: str) -> dict[str, Any] | None:
    for row in as_array(rows, f"rows[{key}]", "coverage_accounting_drift"):
        obj = as_object(row, "coverage row", "coverage_accounting_drift")
        if obj.get(key) == expected:
            return obj
    return None


def json_has_str(value: Any, expected: str) -> bool:
    return isinstance(value, list) and expected in {row for row in value if isinstance(row, str)}


def validate_coverage(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]], required_symbols: set[str], required_modes: set[str]) -> None:
    start_errors = len(errors)
    accounting = as_object(completion.get("coverage_accounting"), "coverage_accounting", "coverage_accounting_drift")
    prioritizer = load_json(artifact_path(artifacts, "fixture_coverage_prioritizer", "tests/conformance/fixture_coverage_prioritizer.v1.json"), "fixture coverage prioritizer", "coverage_accounting_drift")
    coverage = load_json(artifact_path(artifacts, "symbol_fixture_coverage", "tests/conformance/symbol_fixture_coverage.v1.json"), "symbol fixture coverage", "coverage_accounting_drift")
    per_symbol = load_json(artifact_path(artifacts, "per_symbol_fixture_tests", "tests/conformance/per_symbol_fixture_tests.v1.json"), "per-symbol fixture tests", "coverage_accounting_drift")
    campaign = find_by_key(prioritizer.get("campaigns"), "campaign_id", CAMPAIGN_ID)
    if campaign is None:
        add_error("coverage_accounting_drift", f"missing campaign {CAMPAIGN_ID}")
    else:
        if float(campaign.get("current_coverage_pct", 0.0)) < float(accounting.get("campaign_current_coverage_pct_min", 0.0)):
            add_error("coverage_accounting_drift", "string coverage percent below wave-05 floor")
        if int(campaign.get("target_covered", 0)) < int(accounting.get("campaign_target_covered_min", 0)):
            add_error("coverage_accounting_drift", "string target_covered below wave-05 floor")
        if int(campaign.get("target_uncovered", 999999)) > int(accounting.get("campaign_target_uncovered_max", 999999)):
            add_error("coverage_accounting_drift", "string target_uncovered above wave-05 ceiling")
        if float(campaign.get("expected_coverage_after_first_wave_pct", 0.0)) < float(accounting.get("campaign_expected_after_first_wave_pct_min", 0.0)):
            add_error("coverage_accounting_drift", "next-wave expected coverage below floor")
        next_wave = string_set(campaign.get("first_wave_symbols"), "campaign.first_wave_symbols", "coverage_accounting_drift")
        if accounting.get("completed_symbols_must_not_be_next_wave") is True:
            still_claimed = sorted(required_symbols & next_wave)
            if still_claimed:
                add_error("completed_symbol_still_claimed", f"completed symbols still in next wave: {still_claimed}")
    cov_summary = as_object(coverage.get("summary"), "symbol coverage summary", "coverage_accounting_drift")
    per_summary = as_object(per_symbol.get("summary"), "per-symbol summary", "coverage_accounting_drift")
    if int(cov_summary.get("target_covered_symbols", 0)) < int(accounting.get("symbol_fixture_covered_min", 0)):
        add_error("coverage_accounting_drift", "symbol fixture coverage total below floor")
    if int(per_summary.get("symbols_with_fixtures", 0)) < int(accounting.get("per_symbol_fixture_linked_min", 0)):
        add_error("coverage_accounting_drift", "per-symbol linked total below floor")
    if int(per_summary.get("total_fixture_files", 0)) < int(accounting.get("per_symbol_total_fixture_files_min", 0)):
        add_error("coverage_accounting_drift", "per-symbol fixture file total below floor")
    if int(per_summary.get("total_cases", 0)) < int(accounting.get("per_symbol_total_cases_min", 0)):
        add_error("coverage_accounting_drift", "per-symbol case total below floor")
    for symbol in required_symbols:
        row = find_by_key(coverage.get("symbols"), "symbol", symbol)
        if row is None:
            add_error("coverage_accounting_drift", f"missing symbol coverage row for {symbol}")
            continue
        if row.get("covered") is not True or int(row.get("fixture_case_count", 0)) < len(required_modes):
            add_error("coverage_accounting_drift", f"{symbol} coverage row does not show strict+hardened coverage")
        if not json_has_str(row.get("fixture_files"), FIXTURE_FILE):
            add_error("coverage_accounting_drift", f"{symbol} symbol coverage missing {FIXTURE_FILE}")
        for mode in required_modes:
            if not json_has_str(row.get("fixture_modes"), mode):
                add_error("coverage_accounting_drift", f"{symbol} symbol coverage missing mode {mode}")
        per_row = find_by_key(per_symbol.get("per_symbol_report"), "symbol", symbol)
        if per_row is None:
            add_error("coverage_accounting_drift", f"missing per-symbol row for {symbol}")
            continue
        if per_row.get("has_fixtures") is not True or int(per_row.get("case_count", 0)) < len(required_modes):
            add_error("coverage_accounting_drift", f"{symbol} per-symbol row does not show strict+hardened coverage")
        if not json_has_str(per_row.get("fixture_files"), FIXTURE_FILE):
            add_error("coverage_accounting_drift", f"{symbol} per-symbol coverage missing {FIXTURE_FILE}")
        for mode in required_modes:
            if not json_has_str(per_row.get("modes_tested"), mode):
                add_error("coverage_accounting_drift", f"{symbol} per-symbol coverage missing mode {mode}")
    mark_check(
        "coverage_accounting",
        start_errors,
        "coverage_accounting_validated",
        "coverage_accounting_drift",
        campaign_id=CAMPAIGN_ID,
    )


def validate_validation_commands(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    commands = as_array(completion.get("runtime_validation"), "runtime_validation", "missing_validation_command")
    command_texts = [row for row in commands if isinstance(row, str)]
    if len(command_texts) != len(commands):
        add_error("missing_validation_command", "runtime_validation must contain only strings")
    for command in command_texts:
        if "cargo " in command and ("RCH_FORCE_REMOTE=true" not in command or "rch exec --" not in command):
            add_error("non_rch_validation_command", f"cargo command is not remote-only: {command}")
    required_needles = [
        "jq empty tests/conformance/string_memory_hotpaths_wave05_completion_contract.v1.json",
        "bash -n scripts/check_string_memory_hotpaths_wave05_completion_contract.sh",
        "bash scripts/check_string_memory_hotpaths_wave05_completion_contract.sh",
        "bash scripts/check_fixture_coverage_prioritizer.sh --validate-only",
        "AGENT_NAME=BrownTern br --no-db dep cycles --json",
        " cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave05_completion_contract_test ",
        " cargo check -p frankenlibc-harness --test string_memory_hotpaths_wave05_completion_contract_test",
        " cargo clippy -p frankenlibc-harness --test string_memory_hotpaths_wave05_completion_contract_test ",
        " cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave05_conformance_test ",
    ]
    joined = "\n".join(command_texts)
    for needle in required_needles:
        if needle not in joined:
            add_error("missing_validation_command", f"missing validation command containing: {needle}")
    mark_check(
        "validation_commands",
        start_errors,
        "validation_commands_validated",
        "non_rch_validation_command",
        command_count=len(command_texts),
    )


def validate_test_surfaces(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    start_errors = len(errors)
    harness_text = read_text(
        artifact_path(artifacts, "string_wave05_harness_test", "crates/frankenlibc-harness/tests/string_memory_hotpaths_wave05_conformance_test.rs"),
        "string wave05 harness test",
        "missing_test_binding",
    )
    completion_text = read_text(
        artifact_path(artifacts, "completion_harness_test", "crates/frankenlibc-harness/tests/string_memory_hotpaths_wave05_completion_contract_test.rs"),
        "completion harness test",
        "missing_test_binding",
    )
    for needle in string_set(
        completion.get("required_fixture_harness_needles"),
        "required_fixture_harness_needles",
        "missing_test_binding",
    ):
        if needle not in harness_text:
            add_error("missing_test_binding", f"missing fixture harness test needle {needle}")
    for needle in sorted(REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS):
        if needle not in completion_text:
            add_error("missing_test_binding", f"missing completion harness test {needle}")
    bindings = {}
    for row in as_array(contract.get("missing_item_bindings"), "missing_item_bindings", "missing_test_binding"):
        obj = as_object(row, "missing_item_bindings[]", "missing_test_binding")
        item_id = obj.get("missing_item_id")
        if isinstance(item_id, str):
            bindings[item_id] = obj
    missing_bindings = sorted(REQUIRED_MISSING_ITEMS - set(bindings))
    if missing_bindings:
        add_error("missing_test_binding", f"missing item bindings: {missing_bindings}")
    mark_check(
        "test_surfaces",
        start_errors,
        "test_surfaces_validated",
        "missing_test_binding",
        positive_tests=len(REQUIRED_POSITIVE_TESTS),
        negative_tests=len(REQUIRED_NEGATIVE_TESTS),
    )


def validate_telemetry_contract(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    declared = string_set(
        completion.get("required_telemetry_events"),
        "required_telemetry_events",
        "missing_telemetry_event",
    )
    missing = sorted(REQUIRED_TELEMETRY_EVENTS - declared)
    if missing:
        add_error("missing_telemetry_event", f"missing telemetry events: {missing}")
    mark_check(
        "telemetry",
        start_errors,
        "telemetry_contract_validated",
        "missing_telemetry_event",
        declared_event_count=len(declared),
    )


contract_raw = load_json(CONTRACT, "completion contract")
contract = as_object(contract_raw, "completion contract")
completion = validate_top_level(contract)
artifacts = artifact_map(contract)
validate_dependency_proofs(completion)
symbols, modes = validate_fixture(completion, artifacts)
validate_coverage(completion, artifacts, symbols, modes)
validate_validation_commands(completion)
validate_test_surfaces(completion, artifacts)
validate_telemetry_contract(completion)

status = "pass" if not errors else "fail"
events.append(
    event(
        "string_wave05_completion_contract_validated",
        status,
        "none" if status == "pass" else primary_signature(),
        error_count=len(errors),
        symbol_count=len(symbols),
    )
)

checks = {
    "source_artifacts": "pass",
    "dependency_proofs": "pass",
    "string_wave05_fixture": "pass",
    "coverage_accounting": "pass",
    "validation_commands": "pass",
    "test_surfaces": "pass",
    "telemetry": "pass",
}
for row in events:
    if row["status"] == "fail":
        event_name = row["event"]
        if event_name == "source_artifacts_validated":
            checks["source_artifacts"] = "fail"
        elif event_name == "dependency_proofs_validated":
            checks["dependency_proofs"] = "fail"
        elif event_name == "string_wave05_fixture_validated":
            checks["string_wave05_fixture"] = "fail"
        elif event_name == "coverage_accounting_validated":
            checks["coverage_accounting"] = "fail"
        elif event_name == "validation_commands_validated":
            checks["validation_commands"] = "fail"
        elif event_name == "test_surfaces_validated":
            checks["test_surfaces"] = "fail"
        elif event_name == "telemetry_contract_validated":
            checks["telemetry"] = "fail"

report = {
    "schema_version": REPORT_SCHEMA,
    "status": status,
    "bead_id": BEAD_ID,
    "epic_id": EPIC_ID,
    "trace_id": TRACE_ID,
    "source_commit": SOURCE_COMMIT,
    "artifact_refs": sorted(artifact_refs),
    "checks": checks,
    "summary": {**summary, "error_count": len(errors)},
    "errors": errors,
    "events": events,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if status == "pass":
    print(
        "check_string_memory_hotpaths_wave05_completion_contract: PASS "
        f"symbols={summary['string_wave05_symbol_count']} cases={summary['fixture_case_count']} "
        f"events={len(events)} report={rel(REPORT)}"
    )
else:
    print(
        "check_string_memory_hotpaths_wave05_completion_contract: FAIL "
        f"errors={len(errors)} signature={primary_signature()} report={rel(REPORT)}",
        file=sys.stderr,
    )
    sys.exit(1)
PY
