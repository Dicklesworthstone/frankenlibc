#!/usr/bin/env bash
# check_string_memory_hotpath_fixture_wave_completion_contract.sh -- bd-yy970.3 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/string_memory_hotpath_fixture_wave_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/string_memory_hotpath_fixture_wave_completion}"
REPORT="${FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_REPORT:-${OUT_DIR}/string_memory_hotpath_fixture_wave_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRING_MEMORY_HOTPATH_COMPLETION_LOG:-${OUT_DIR}/string_memory_hotpath_fixture_wave_completion_contract.events.jsonl}"
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

SCHEMA = "string_memory_hotpath_fixture_wave_completion_contract.v1"
REPORT_SCHEMA = "string_memory_hotpath_fixture_wave_completion_contract.report.v1"
BEAD_ID = "bd-yy970.3"
EPIC_ID = "bd-yy970"
TRACE_ID = "bd-yy970.3::string-memory-hotpath-fixture-wave::completion::v1"
CAMPAIGN_ID = "fcq-string-memory-hotpaths"
WAVE_ID = "wave-04-string-memory-hotpaths"
FIXTURE_FILE = "string_memory_hotpaths.json"
FIXTURE_PATH = "tests/conformance/fixtures/string_memory_hotpaths.json"

REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "fixture_coverage_prioritizer",
    "symbol_fixture_coverage",
    "string_memory_fixture",
    "fixture_executor",
    "string_memory_fixture_harness_test",
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
REQUIRED_EVENTS = {
    "source_artifacts_validated",
    "dependency_proofs_validated",
    "string_memory_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "string_memory_hotpath_fixture_wave_completion_contract_validated",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "dependency_proof_missing",
    "dependency_commit_missing",
    "string_memory_fixture_symbol_coverage",
    "string_memory_fixture_mode_coverage",
    "string_memory_fixture_schema",
    "coverage_accounting_drift",
    "completed_symbol_still_claimed",
    "non_rch_validation_command",
    "missing_test_binding",
    "missing_telemetry_event",
]

events: list[dict[str, Any]] = []
errors: list[dict[str, str]] = []
artifact_refs: set[str] = {str(CONTRACT)}


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
    return "string_memory_hotpath_fixture_wave_completion_contract_failed"


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


def string_set(value: Any, context: str, signature: str = "malformed_contract") -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
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
    events.append(
        event(
            "source_artifacts_validated",
            "pass" if not missing else "fail",
            "none" if not missing else "missing_source_artifact",
            artifact_count=len(result),
        )
    )
    return result


def validate_top_level(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", "schema_version mismatch")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", "bead_id mismatch")
    if contract.get("epic_id") != EPIC_ID:
        add_error("malformed_contract", "epic_id mismatch")
    completion = as_object(contract.get("completion_contract"), "completion_contract")
    missing_items = string_set(completion.get("missing_item_ids"), "completion_contract.missing_item_ids")
    missing_required = sorted(REQUIRED_MISSING_ITEMS - missing_items)
    if missing_required:
        add_error("malformed_contract", f"missing completion items: {missing_required}")
    if completion.get("campaign_id") != CAMPAIGN_ID:
        add_error("malformed_contract", "campaign_id mismatch")
    if completion.get("wave_id") != WAVE_ID:
        add_error("malformed_contract", "wave_id mismatch")
    return completion


def validate_dependency_proofs(completion: dict[str, Any]) -> None:
    proofs = [as_object(row, "required_dependency_proofs[]") for row in as_array(completion.get("required_dependency_proofs"), "completion_contract.required_dependency_proofs")]
    by_id = {proof.get("bead_id"): proof for proof in proofs if isinstance(proof.get("bead_id"), str)}
    for bead_id in ["bd-yy970.1", "bd-yy970.2"]:
        proof = by_id.get(bead_id)
        if proof is None:
            add_error("dependency_proof_missing", f"missing dependency proof for {bead_id}")
            continue
        if proof.get("proof_state") != "tracker_closed":
            add_error("dependency_proof_missing", f"{bead_id} proof_state must be tracker_closed")
        commit = proof.get("commit")
        if not isinstance(commit, str) or len(commit) < 8:
            add_error("dependency_commit_missing", f"{bead_id} commit must be recorded")
        for path_text in as_array(proof.get("evidence_paths"), f"{bead_id}.evidence_paths"):
            if not isinstance(path_text, str) or not resolve(path_text).exists():
                add_error("dependency_proof_missing", f"{bead_id} evidence path missing: {path_text}")
    events.append(
        event(
            "dependency_proofs_validated",
            "pass" if not any(error["failure_signature"].startswith("dependency_") for error in errors) else "fail",
            "none" if not any(error["failure_signature"].startswith("dependency_") for error in errors) else primary_signature(),
            proof_count=len(proofs),
        )
    )


def validate_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> set[str]:
    required_symbols = string_set(completion.get("required_first_wave_symbols"), "completion_contract.required_first_wave_symbols")
    required_modes = string_set(completion.get("required_modes"), "completion_contract.required_modes")
    required_fields = string_set(completion.get("required_structured_log_fields"), "completion_contract.required_structured_log_fields")
    forbidden = string_set(completion.get("forbidden_ambient_output_tokens"), "completion_contract.forbidden_ambient_output_tokens")
    fixture_path = resolve(str(artifacts.get("string_memory_fixture", {}).get("path", FIXTURE_PATH)))
    fixture = as_object(load_json(fixture_path, "string/memory fixture", "string_memory_fixture_schema"), "string_memory_fixture")
    campaign = as_object(fixture.get("campaign"), "string_memory_fixture.campaign", "string_memory_fixture_schema")
    if campaign.get("campaign_id") != CAMPAIGN_ID or campaign.get("wave_id") != WAVE_ID:
        add_error("string_memory_fixture_schema", "fixture campaign id or wave id mismatch")
    if string_set(campaign.get("first_wave_symbols"), "string_memory_fixture.campaign.first_wave_symbols", "string_memory_fixture_schema") != required_symbols:
        add_error("string_memory_fixture_symbol_coverage", "fixture first_wave_symbols must match contract symbols")
    if string_set(campaign.get("residual_symbols"), "string_memory_fixture.campaign.residual_symbols", "string_memory_fixture_schema"):
        add_error("string_memory_fixture_symbol_coverage", "fixture residual_symbols must be empty")
    if string_set(fixture.get("structured_log_fields"), "string_memory_fixture.structured_log_fields", "string_memory_fixture_schema") != required_fields:
        add_error("string_memory_fixture_schema", "fixture structured_log_fields mismatch")

    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    for case in as_array(fixture.get("cases"), "string_memory_fixture.cases", "string_memory_fixture_schema"):
        obj = as_object(case, "string_memory_fixture.cases[]", "string_memory_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str) and symbol in modes_by_symbol:
            modes_by_symbol[symbol].add(mode)
        expected = obj.get("expected_output")
        if isinstance(expected, str):
            for field in required_fields:
                if f"{field}=" not in expected:
                    add_error("string_memory_fixture_schema", f"{symbol} expected_output missing {field}")
            for token in forbidden:
                if token in expected:
                    add_error("string_memory_fixture_schema", f"{symbol} expected_output leaks {token}")
    for symbol, modes in sorted(modes_by_symbol.items()):
        if not required_modes.issubset(modes):
            add_error("string_memory_fixture_mode_coverage", f"{symbol} modes={sorted(modes)} missing {sorted(required_modes)}")
    fixture_errors = {error["failure_signature"] for error in errors}
    fixture_ok = not any(sig.startswith("string_memory_fixture") for sig in fixture_errors)
    events.append(
        event(
            "string_memory_fixture_validated",
            "pass" if fixture_ok else "fail",
            "none" if fixture_ok else primary_signature(),
            symbol_count=len(required_symbols),
            required_modes=sorted(required_modes),
        )
    )
    return required_symbols


def validate_coverage(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]], required_symbols: set[str]) -> None:
    coverage = as_object(load_json(resolve(str(artifacts.get("symbol_fixture_coverage", {}).get("path", ""))), "symbol fixture coverage", "coverage_accounting_drift"), "symbol_fixture_coverage")
    prioritizer = as_object(load_json(resolve(str(artifacts.get("fixture_coverage_prioritizer", {}).get("path", ""))), "fixture coverage prioritizer", "coverage_accounting_drift"), "fixture_coverage_prioritizer")
    rows = {row.get("symbol"): row for row in as_array(coverage.get("symbols"), "symbol_fixture_coverage.symbols", "coverage_accounting_drift") if isinstance(row, dict)}
    for symbol in sorted(required_symbols):
        row = as_object(rows.get(symbol), f"symbol_fixture_coverage[{symbol}]", "coverage_accounting_drift")
        if row.get("covered") is not True:
            add_error("coverage_accounting_drift", f"{symbol} must be covered")
        if row.get("fixture_case_count") != 2:
            add_error("coverage_accounting_drift", f"{symbol} fixture_case_count must be 2")
        files = string_set(row.get("fixture_files"), f"{symbol}.fixture_files", "coverage_accounting_drift")
        modes = string_set(row.get("fixture_modes"), f"{symbol}.fixture_modes", "coverage_accounting_drift")
        if FIXTURE_FILE not in files:
            add_error("coverage_accounting_drift", f"{symbol} must cite {FIXTURE_FILE}")
        if not {"strict", "hardened"}.issubset(modes):
            add_error("coverage_accounting_drift", f"{symbol} must cite strict and hardened modes")

    campaign = None
    for row in as_array(prioritizer.get("campaigns"), "fixture_coverage_prioritizer.campaigns", "coverage_accounting_drift"):
        if isinstance(row, dict) and row.get("campaign_id") == CAMPAIGN_ID:
            campaign = row
            break
    if not isinstance(campaign, dict):
        add_error("coverage_accounting_drift", f"missing campaign {CAMPAIGN_ID}")
        campaign = {}
    accounting = as_object(completion.get("coverage_accounting"), "coverage_accounting", "coverage_accounting_drift")
    if float(campaign.get("current_coverage_pct", 0.0)) < float(accounting.get("campaign_current_coverage_pct_min", 0.0)):
        add_error("coverage_accounting_drift", "campaign coverage percent is stale")
    if int(campaign.get("target_covered", 0)) < int(accounting.get("campaign_target_covered_min", 0)):
        add_error("coverage_accounting_drift", "campaign target_covered is stale")
    if int(campaign.get("target_uncovered", 10**9)) > int(accounting.get("campaign_target_uncovered_max", 10**9)):
        add_error("coverage_accounting_drift", "campaign target_uncovered is stale")
    summary = as_object(coverage.get("summary"), "symbol_fixture_coverage.summary", "coverage_accounting_drift")
    if int(summary.get("target_covered_symbols", 0)) < int(accounting.get("symbol_fixture_covered_min", 0)):
        add_error("coverage_accounting_drift", "overall symbol fixture covered count is stale")
    next_wave = string_set(campaign.get("first_wave_symbols"), "campaign.first_wave_symbols", "coverage_accounting_drift")
    if accounting.get("completed_symbols_must_not_be_next_wave") is True:
        repeated = sorted(required_symbols & next_wave)
        if repeated:
            add_error("completed_symbol_still_claimed", f"completed symbols still in next wave: {repeated}")
    coverage_ok = not any(error["failure_signature"] in {"coverage_accounting_drift", "completed_symbol_still_claimed"} for error in errors)
    events.append(
        event(
            "coverage_accounting_validated",
            "pass" if coverage_ok else "fail",
            "none" if coverage_ok else primary_signature(),
            campaign_id=CAMPAIGN_ID,
            target_covered=campaign.get("target_covered"),
            target_uncovered=campaign.get("target_uncovered"),
        )
    )


def validate_validation_commands(completion: dict[str, Any]) -> None:
    commands = string_set(completion.get("runtime_validation"), "completion_contract.runtime_validation")
    cargo_commands = [command for command in commands if "cargo " in command]
    for command in cargo_commands:
        if "rch exec" not in command or "RCH_FORCE_REMOTE=true" not in command:
            add_error("non_rch_validation_command", f"cargo validation must be remote-only rch: {command}")
    required_needles = [
        "jq empty tests/conformance/string_memory_hotpath_fixture_wave_completion_contract.v1.json",
        "bash scripts/check_string_memory_hotpath_fixture_wave_completion_contract.sh",
        "bash scripts/check_symbol_fixture_coverage.sh",
        "bash scripts/check_fixture_coverage_prioritizer.sh",
        "br dep cycles --no-db --json",
        "cargo test -p frankenlibc-harness --test string_memory_hotpath_fixture_wave_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test string_memory_hotpath_fixture_wave_completion_contract_test",
    ]
    for needle in required_needles:
        if not any(needle in command for command in commands):
            add_error("non_rch_validation_command", f"missing validation command containing {needle}")
    command_ok = not any(error["failure_signature"] == "non_rch_validation_command" for error in errors)
    events.append(
        event(
            "validation_commands_validated",
            "pass" if command_ok else "fail",
            "none" if command_ok else "non_rch_validation_command",
            command_count=len(commands),
            cargo_command_count=len(cargo_commands),
        )
    )


def validate_tests(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    harness_path = resolve(str(artifacts.get("completion_harness_test", {}).get("path", "")))
    text = read_text(harness_path, "completion harness test", "missing_test_binding")
    required_names = string_set(completion.get("required_positive_tests"), "required_positive_tests") | string_set(completion.get("required_negative_tests"), "required_negative_tests")
    missing = sorted(name for name in required_names if f"fn {name}" not in text)
    if missing:
        add_error("missing_test_binding", f"completion harness missing tests: {missing}")
    fixture_test_path = resolve(str(artifacts.get("string_memory_fixture_harness_test", {}).get("path", "")))
    fixture_text = read_text(fixture_test_path, "string/memory fixture harness test", "missing_test_binding")
    for needle in [
        "string_memory_hotpaths_coverage_artifacts_bind_first_wave",
        "string_memory_hotpaths_fixture_executes_via_isolated_harness",
    ]:
        if needle not in fixture_text:
            add_error("missing_test_binding", f"fixture harness missing {needle}")
    test_ok = not any(error["failure_signature"] == "missing_test_binding" for error in errors)
    events.append(
        event(
            "test_surfaces_validated",
            "pass" if test_ok else "fail",
            "none" if test_ok else "missing_test_binding",
            required_test_count=len(required_names),
        )
    )


def validate_telemetry(completion: dict[str, Any]) -> None:
    required = string_set(completion.get("required_telemetry_events"), "required_telemetry_events")
    missing = sorted(REQUIRED_EVENTS - required)
    if missing:
        add_error("missing_telemetry_event", f"missing telemetry events: {missing}")
    telemetry_ok = not any(error["failure_signature"] == "missing_telemetry_event" for error in errors)
    events.append(
        event(
            "telemetry_contract_validated",
            "pass" if telemetry_ok else "fail",
            "none" if telemetry_ok else "missing_telemetry_event",
            required_event_count=len(required),
        )
    )


contract = as_object(load_json(CONTRACT, "completion contract"), "completion_contract_root")
completion = validate_top_level(contract)
artifacts = artifact_map(contract)
validate_dependency_proofs(completion)
required_symbols = validate_fixture(completion, artifacts)
validate_coverage(completion, artifacts, required_symbols)
validate_validation_commands(completion)
validate_tests(completion, artifacts)
validate_telemetry(completion)

status = "pass" if not errors else "fail"
events.append(
    event(
        "string_memory_hotpath_fixture_wave_completion_contract_validated",
        status,
        "none" if status == "pass" else primary_signature(),
        error_count=len(errors),
    )
)

checks = {
    "source_artifacts": "fail" if any(error["failure_signature"] == "missing_source_artifact" for error in errors) else "pass",
    "dependency_proofs": "fail" if any(error["failure_signature"].startswith("dependency_") for error in errors) else "pass",
    "string_memory_fixture": "fail" if any(error["failure_signature"].startswith("string_memory_fixture") for error in errors) else "pass",
    "coverage_accounting": "fail" if any(error["failure_signature"] in {"coverage_accounting_drift", "completed_symbol_still_claimed"} for error in errors) else "pass",
    "validation_commands": "fail" if any(error["failure_signature"] == "non_rch_validation_command" for error in errors) else "pass",
    "test_surfaces": "fail" if any(error["failure_signature"] == "missing_test_binding" for error in errors) else "pass",
    "telemetry": "fail" if any(error["failure_signature"] == "missing_telemetry_event" for error in errors) else "pass",
}

report = {
    "schema_version": REPORT_SCHEMA,
    "status": status,
    "bead_id": BEAD_ID,
    "epic_id": EPIC_ID,
    "campaign_id": CAMPAIGN_ID,
    "wave_id": WAVE_ID,
    "source_commit": SOURCE_COMMIT,
    "checks": checks,
    "summary": {
        "string_memory_first_wave_symbol_count": len(required_symbols),
        "required_mode_count": len(string_set(completion.get("required_modes"), "completion_contract.required_modes")),
        "telemetry_event_count": len(events),
        "artifact_ref_count": len(artifact_refs),
    },
    "artifact_refs": sorted(artifact_refs),
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)
if status != "pass":
    print(f"check_string_memory_hotpath_fixture_wave_completion_contract: FAIL {primary_signature()}", file=sys.stderr)
    raise SystemExit(1)
print(f"check_string_memory_hotpath_fixture_wave_completion_contract: PASS ({len(required_symbols)} symbols)")
PY
