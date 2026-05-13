#!/usr/bin/env bash
# check_unistd_process_filesystem_wave3_completion_contract.sh -- bd-ph6um.3 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_UNISTD_WAVE3_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/unistd_process_filesystem_wave3_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_UNISTD_WAVE3_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/unistd_process_filesystem_wave3_completion}"
REPORT="${FRANKENLIBC_UNISTD_WAVE3_COMPLETION_REPORT:-${OUT_DIR}/unistd_process_filesystem_wave3_completion_contract.report.json}"
LOG="${FRANKENLIBC_UNISTD_WAVE3_COMPLETION_LOG:-${OUT_DIR}/unistd_process_filesystem_wave3_completion_contract.events.jsonl}"
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

SCHEMA = "unistd_process_filesystem_wave3_completion_contract.v1"
REPORT_SCHEMA = "unistd_process_filesystem_wave3_completion_contract.report.v1"
BEAD_ID = "bd-ph6um.3"
EPIC_ID = "bd-ph6um"
TRACE_ID = "bd-ph6um.3::unistd-process-filesystem-wave3::completion::v1"
CAMPAIGN_ID = "fcq-unistd-process-filesystem"
WAVE_ID = "wave-03-unistd-process-filesystem-aio-time"
FIXTURE_FILE = "unistd_process_filesystem_wave03.json"
FIXTURE_PATH = "tests/conformance/fixtures/unistd_process_filesystem_wave03.json"
UNISTD_MODULE = "unistd_abi"
AMBIENT_POLICY = "forbid_ambient_aio_time_fd_or_scheduler_metadata"

REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "fixture_coverage_prioritizer",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "unistd_wave3_fixture",
    "fixture_executor",
    "unistd_wave3_harness_test",
    "prioritizer_gate",
    "prioritizer_guard_test",
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
REQUIRED_DEPENDENCIES = {"bd-ph6um.1", "bd-ph6um.2"}
REQUIRED_TELEMETRY_EVENTS = {
    "source_artifacts_validated",
    "dependency_proofs_validated",
    "unistd_wave3_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "unistd_wave3_completion_contract_validated",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_unistd_wave3_sources",
    "checker_accepts_unistd_wave3_completion_contract",
    "checker_emits_structured_unistd_wave3_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_unistd_wave3_fixture_symbol",
    "checker_rejects_stale_unistd_wave3_coverage_accounting",
    "checker_rejects_non_remote_rch_cargo_validation_command",
    "checker_rejects_missing_required_telemetry_event",
    "checker_rejects_stale_dependency_proof_commit",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "dependency_proof_missing",
    "dependency_commit_missing",
    "unistd_wave3_fixture_symbol_coverage",
    "unistd_wave3_fixture_mode_coverage",
    "unistd_wave3_fixture_schema",
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
    return "unistd_wave3_completion_contract_failed"


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
    failed = len(errors) > start_errors
    events.append(
        event(
            "source_artifacts_validated",
            "fail" if failed else "pass",
            "missing_source_artifact" if failed else "none",
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


def validate_bindings(contract: dict[str, Any]) -> None:
    by_id: dict[str, dict[str, Any]] = {}
    for row in as_array(contract.get("missing_item_bindings"), "missing_item_bindings"):
        obj = as_object(row, "missing_item_bindings[]")
        item_id = obj.get("missing_item_id")
        if isinstance(item_id, str):
            by_id[item_id] = obj
    for item_id in sorted(REQUIRED_MISSING_ITEMS):
        binding = by_id.get(item_id)
        if not binding:
            add_error("malformed_contract", f"missing binding for {item_id}")
            continue
        for field in ["implementation_refs", "test_refs", "runtime_validation"]:
            values = string_set(binding.get(field), f"{item_id}.{field}", "malformed_contract")
            if not values:
                add_error("malformed_contract", f"{item_id}.{field} must not be empty")


def load_ledger(artifacts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    ledger_path = artifact_path(artifacts, "beads_ledger", ".beads/issues.jsonl")
    rows: dict[str, dict[str, Any]] = {}
    for line in read_text(ledger_path, "beads ledger", "missing_source_artifact").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            rows[row["id"]] = row
    return rows


def commit_binding_valid(commit: Any) -> bool:
    return isinstance(commit, str) and len(commit) >= 7 and all(
        ch in "0123456789abcdefABCDEF" for ch in commit
    )


def validate_dependency_proofs(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    start_errors = len(errors)
    proofs = as_array(
        completion.get("required_dependency_proofs"),
        "completion_contract.required_dependency_proofs",
        "dependency_proof_missing",
    )
    by_id: dict[str, dict[str, Any]] = {}
    for row in proofs:
        obj = as_object(row, "completion_contract.required_dependency_proofs[]", "dependency_proof_missing")
        bead_id = obj.get("bead_id")
        if isinstance(bead_id, str):
            by_id[bead_id] = obj

    ledger = load_ledger(artifacts)
    missing: list[str] = []
    missing_commits: list[str] = []
    for bead_id in sorted(REQUIRED_DEPENDENCIES):
        proof = by_id.get(bead_id)
        if not proof:
            missing.append(bead_id)
            continue
        ledger_closed = ledger.get(bead_id, {}).get("status") == "closed"
        proof_state = proof.get("proof_state")
        proof_committed = proof_state in {"tracker_closed", "proof_committed"}
        if not ledger_closed and not proof_committed:
            missing.append(bead_id)
        if not commit_binding_valid(proof.get("commit")):
            missing_commits.append(bead_id)
        if proof.get("tracker_close_commit") is not None and not commit_binding_valid(proof.get("tracker_close_commit")):
            missing_commits.append(f"{bead_id}:tracker_close_commit")
        paths = proof.get("evidence_paths")
        if not isinstance(paths, list) or not paths:
            add_error("dependency_proof_missing", f"{bead_id} missing evidence_paths")
        else:
            for path in paths:
                if not isinstance(path, str) or not resolve(path).exists():
                    add_error("dependency_proof_missing", f"{bead_id} evidence path missing: {path}")

    if missing:
        add_error("dependency_proof_missing", f"dependency proof missing for: {missing}")
    if missing_commits:
        add_error("dependency_commit_missing", f"dependency proof commits malformed: {missing_commits}")
    failed = len(errors) > start_errors
    events.append(
        event(
            "dependency_proofs_validated",
            "fail" if failed else "pass",
            "dependency_proof_missing" if missing else ("dependency_commit_missing" if missing_commits else "none"),
            dependency_count=len(by_id),
        )
    )


def validate_unistd_wave3_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    start_errors = len(errors)
    fixture = load_json(
        artifact_path(artifacts, "unistd_wave3_fixture", FIXTURE_PATH),
        "unistd wave-03 fixture",
        "unistd_wave3_fixture_schema",
    )
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
    required_fields = string_set(
        completion.get("required_structured_log_fields"),
        "completion_contract.required_structured_log_fields",
        "malformed_contract",
    )
    forbidden_tokens = string_set(
        completion.get("forbidden_ambient_output_tokens"),
        "completion_contract.forbidden_ambient_output_tokens",
        "malformed_contract",
    )

    if fixture.get("family") != "unistd/process-filesystem":
        add_error("unistd_wave3_fixture_schema", "unistd wave-03 fixture family mismatch")
    campaign = as_object(fixture.get("campaign"), "unistd_wave3_fixture.campaign", "unistd_wave3_fixture_schema")
    if campaign.get("bead") != "bd-ph6um.1":
        add_error("unistd_wave3_fixture_schema", "unistd wave-03 fixture bead binding mismatch")
    if campaign.get("campaign_id") != CAMPAIGN_ID or campaign.get("wave_id") != WAVE_ID:
        add_error("unistd_wave3_fixture_schema", "unistd wave-03 fixture campaign/wave binding mismatch")
    if campaign.get("ambient_state_policy") != AMBIENT_POLICY:
        add_error("unistd_wave3_fixture_schema", "unistd wave-03 ambient_state_policy mismatch")
    declared = set(campaign.get("first_wave_symbols", []))
    if declared != required_symbols:
        add_error(
            "unistd_wave3_fixture_symbol_coverage",
            f"campaign first_wave_symbols mismatch missing={sorted(required_symbols - declared)} extra={sorted(declared - required_symbols)}",
        )
    if campaign.get("residual_symbols") not in ([], None):
        add_error("unistd_wave3_fixture_symbol_coverage", "fixture must not leave residual wave-03 symbols")
    if set(fixture.get("structured_log_fields", [])) != required_fields:
        add_error("unistd_wave3_fixture_schema", "structured_log_fields mismatch")

    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    case_count = 0
    for case in as_array(fixture.get("cases"), "unistd_wave3_fixture.cases", "unistd_wave3_fixture_schema"):
        obj = as_object(case, "unistd_wave3_fixture.cases[]", "unistd_wave3_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str):
            case_count += 1
            modes_by_symbol.setdefault(symbol, set()).add(mode)
        inputs = as_object(obj.get("inputs"), f"unistd_wave3_fixture.case[{symbol}].inputs", "unistd_wave3_fixture_schema")
        for field in ["symbol", "expected", "ambient_state_policy", "oracle_source"]:
            if not isinstance(inputs.get(field), str) or not inputs.get(field):
                add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} missing inputs.{field}")
        if isinstance(symbol, str) and inputs.get("symbol") != symbol:
            add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} inputs.symbol mismatch")
        if inputs.get("ambient_state_policy") != AMBIENT_POLICY:
            add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} ambient-state policy mismatch")
        expected_output = obj.get("expected_output")
        if not isinstance(expected_output, str):
            add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} missing expected_output")
            expected_output = ""
        for field in sorted(required_fields):
            if f"{field}=" not in expected_output:
                add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} expected_output missing {field} token")
        for token in forbidden_tokens:
            if token in expected_output:
                add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} leaks ambient token {token}")
        if obj.get("expected_errno") != 0:
            add_error("unistd_wave3_fixture_schema", f"case {obj.get('name')} expected_errno must be 0")

    mode_failures = [
        symbol
        for symbol, modes in sorted(modes_by_symbol.items())
        if symbol in required_symbols and modes != required_modes
    ]
    if mode_failures:
        add_error("unistd_wave3_fixture_mode_coverage", f"symbols missing required modes: {mode_failures}")

    failed = len(errors) > start_errors
    signature = "none"
    if failed:
        signature = "unistd_wave3_fixture_mode_coverage" if mode_failures else "unistd_wave3_fixture_schema"
    events.append(
        event(
            "unistd_wave3_fixture_validated",
            "fail" if failed else "pass",
            signature,
            symbol_count=len(required_symbols),
            case_count=case_count,
        )
    )


def campaign_row(prioritizer: dict[str, Any]) -> dict[str, Any]:
    for row in as_array(prioritizer.get("campaigns"), "prioritizer.campaigns", "coverage_accounting_drift"):
        obj = as_object(row, "prioritizer.campaigns[]", "coverage_accounting_drift")
        if obj.get("campaign_id") == CAMPAIGN_ID:
            return obj
    add_error("coverage_accounting_drift", f"{CAMPAIGN_ID} missing from fixture coverage prioritizer")
    return {}


def validate_coverage_accounting(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    start_errors = len(errors)
    coverage_contract = as_object(
        completion.get("coverage_accounting"),
        "completion_contract.coverage_accounting",
        "malformed_contract",
    )
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

    prioritizer = load_json(
        artifact_path(artifacts, "fixture_coverage_prioritizer", "tests/conformance/fixture_coverage_prioritizer.v1.json"),
        "fixture coverage prioritizer",
        "coverage_accounting_drift",
    )
    symbol_coverage = load_json(
        artifact_path(artifacts, "symbol_fixture_coverage", "tests/conformance/symbol_fixture_coverage.v1.json"),
        "symbol fixture coverage",
        "coverage_accounting_drift",
    )
    per_symbol = load_json(
        artifact_path(artifacts, "per_symbol_fixture_tests", "tests/conformance/per_symbol_fixture_tests.v1.json"),
        "per-symbol fixture tests",
        "coverage_accounting_drift",
    )

    campaign = campaign_row(as_object(prioritizer, "fixture coverage prioritizer", "coverage_accounting_drift"))
    if campaign.get("target_covered", 0) < coverage_contract.get("campaign_target_covered_min", 0):
        add_error("coverage_accounting_drift", "campaign target_covered below contract")
    if campaign.get("target_uncovered", 10**12) > coverage_contract.get("campaign_target_uncovered_max", 0):
        add_error("coverage_accounting_drift", "campaign target_uncovered above contract")
    if float(campaign.get("current_coverage_pct", 0.0)) < float(coverage_contract.get("campaign_current_coverage_pct_min", 0)):
        add_error("coverage_accounting_drift", "campaign current_coverage_pct below contract")
    if float(campaign.get("expected_coverage_after_first_wave_pct", 0.0)) < float(coverage_contract.get("campaign_expected_after_first_wave_pct_min", 0)):
        add_error("coverage_accounting_drift", "campaign expected_coverage_after_first_wave_pct below contract")
    stale_symbols = sorted(required_symbols & set(campaign.get("first_wave_symbols", [])))
    if stale_symbols:
        add_error("completed_symbol_still_claimed", f"completed symbols still appear in next first-wave claim: {stale_symbols}")

    per_symbol_rows = {
        row.get("symbol"): row
        for row in as_array(per_symbol.get("per_symbol_report"), "per_symbol.per_symbol_report", "coverage_accounting_drift")
        if isinstance(row, dict) and row.get("module") == UNISTD_MODULE
    }
    coverage_rows = {
        row.get("symbol"): row
        for row in as_array(symbol_coverage.get("symbols"), "symbol_fixture_coverage.symbols", "coverage_accounting_drift")
        if isinstance(row, dict) and row.get("module") == UNISTD_MODULE
    }
    for symbol in sorted(required_symbols):
        per_row = per_symbol_rows.get(symbol)
        cov_row = coverage_rows.get(symbol)
        if not per_row:
            add_error("coverage_accounting_drift", f"{symbol} missing from per-symbol fixture report")
            continue
        if per_row.get("has_fixtures") is not True or per_row.get("case_count", 0) < 2:
            add_error("coverage_accounting_drift", f"{symbol} lacks strict/hardened fixture accounting")
        if FIXTURE_FILE not in per_row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} lacks {FIXTURE_FILE} backlink in per-symbol report")
        if set(per_row.get("modes_tested", [])) != required_modes:
            add_error("coverage_accounting_drift", f"{symbol} lacks strict/hardened mode accounting")
        if not cov_row or cov_row.get("covered") is not True:
            add_error("coverage_accounting_drift", f"{symbol} missing covered symbol-fixture row")
        elif FIXTURE_FILE not in cov_row.get("fixture_files", []):
            add_error("coverage_accounting_drift", f"{symbol} lacks {FIXTURE_FILE} backlink in symbol coverage")

    symbol_summary = as_object(symbol_coverage.get("summary"), "symbol_coverage.summary", "coverage_accounting_drift")
    per_summary = as_object(per_symbol.get("summary"), "per_symbol.summary", "coverage_accounting_drift")
    if symbol_summary.get("covered_exported_symbols", 0) < coverage_contract.get("symbol_fixture_covered_min", 0):
        add_error("coverage_accounting_drift", "symbol fixture covered count drifted below contract")
    if per_summary.get("symbols_with_fixtures", 0) < coverage_contract.get("per_symbol_fixture_linked_min", 0):
        add_error("coverage_accounting_drift", "per-symbol linked fixture count drifted below contract")
    if per_summary.get("total_fixture_files", 0) < coverage_contract.get("per_symbol_total_fixture_files_min", 0):
        add_error("coverage_accounting_drift", "per-symbol fixture file total drifted below contract")
    if per_summary.get("total_cases", 0) < coverage_contract.get("per_symbol_total_cases_min", 0):
        add_error("coverage_accounting_drift", "per-symbol case total drifted below contract")

    required_needles = string_set(
        completion.get("required_coverage_guard_needles"),
        "completion_contract.required_coverage_guard_needles",
        "malformed_contract",
    )
    gate_text = read_text(
        artifact_path(artifacts, "prioritizer_gate", "scripts/check_fixture_coverage_prioritizer.sh"),
        "prioritizer gate",
        "coverage_accounting_drift",
    )
    test_text = read_text(
        artifact_path(artifacts, "prioritizer_guard_test", "crates/frankenlibc-harness/tests/fixture_coverage_prioritizer_test.rs"),
        "prioritizer guard test",
        "coverage_accounting_drift",
    )
    for needle in sorted(required_needles):
        if needle not in gate_text and needle not in test_text:
            add_error("coverage_accounting_drift", f"coverage guard surfaces missing needle {needle}")

    failed = len(errors) > start_errors
    events.append(
        event(
            "coverage_accounting_validated",
            "fail" if failed else "pass",
            "coverage_accounting_drift" if failed else "none",
            target_covered=campaign.get("target_covered"),
            target_uncovered=campaign.get("target_uncovered"),
            current_coverage_pct=campaign.get("current_coverage_pct"),
        )
    )


def validate_validation_commands(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    commands = string_set(
        completion.get("runtime_validation"),
        "completion_contract.runtime_validation",
        "malformed_contract",
    )
    required_fragments = [
        "cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave3_completion_contract_test",
        "cargo check -p frankenlibc-harness --test unistd_process_filesystem_wave3_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test unistd_process_filesystem_wave3_completion_contract_test --no-deps -- -D warnings",
    ]
    for fragment in required_fragments:
        matches = [command for command in commands if fragment in command]
        if not matches:
            add_error("non_rch_validation_command", f"missing validation command fragment: {fragment}")
            continue
        for command in matches:
            if "RCH_FORCE_REMOTE=true" not in command or "rch exec --" not in command or "CARGO_TARGET_DIR=" not in command:
                add_error("non_rch_validation_command", f"cargo validation is not remote rch-scoped: {command}")
    if not any("br --no-db dep cycles --json" in command for command in commands):
        add_error("non_rch_validation_command", "missing br --no-db dep cycles validation command")
    failed = len(errors) > start_errors
    events.append(
        event(
            "validation_commands_validated",
            "fail" if failed else "pass",
            "non_rch_validation_command" if failed else "none",
            validation_command_count=len(commands),
        )
    )


def validate_test_surfaces(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    start_errors = len(errors)
    text = read_text(
        artifact_path(artifacts, "completion_harness_test", "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave3_completion_contract_test.rs"),
        "completion harness test",
        "missing_test_binding",
    )
    missing_positive = sorted(test for test in REQUIRED_POSITIVE_TESTS if test not in text)
    missing_negative = sorted(test for test in REQUIRED_NEGATIVE_TESTS if test not in text)
    if missing_positive or missing_negative:
        add_error(
            "missing_test_binding",
            f"missing positive tests={missing_positive} negative tests={missing_negative}",
        )

    fixture_test = read_text(
        artifact_path(artifacts, "unistd_wave3_harness_test", "crates/frankenlibc-harness/tests/unistd_process_filesystem_wave03_conformance_test.rs"),
        "unistd wave-03 fixture harness test",
        "missing_test_binding",
    )
    required_needles = string_set(
        completion.get("required_fixture_harness_needles"),
        "completion_contract.required_fixture_harness_needles",
        "malformed_contract",
    )
    for needle in sorted(required_needles):
        if needle not in fixture_test:
            add_error("missing_test_binding", f"unistd wave-03 fixture harness missing {needle}")

    failed = len(errors) > start_errors
    events.append(
        event(
            "test_surfaces_validated",
            "fail" if failed else "pass",
            "missing_test_binding" if failed else "none",
            positive_test_count=len(REQUIRED_POSITIVE_TESTS),
            negative_test_count=len(REQUIRED_NEGATIVE_TESTS),
        )
    )


def validate_telemetry_contract(completion: dict[str, Any]) -> None:
    start_errors = len(errors)
    required = string_set(
        completion.get("required_telemetry_events"),
        "completion_contract.required_telemetry_events",
        "missing_telemetry_event",
    )
    missing_events = sorted(REQUIRED_TELEMETRY_EVENTS - required)
    if missing_events:
        add_error("missing_telemetry_event", f"required telemetry events missing: {missing_events}")
    failed = len(errors) > start_errors
    events.append(
        event(
            "telemetry_contract_validated",
            "fail" if failed else "pass",
            "missing_telemetry_event" if failed else "none",
            required_event_count=len(required),
        )
    )


def build_report(completion: dict[str, Any]) -> dict[str, Any]:
    status = "pass" if not errors else "fail"
    checks = {
        "source_artifacts": "pass",
        "dependency_proofs": "pass",
        "unistd_wave3_fixture": "pass",
        "coverage_accounting": "pass",
        "validation_commands": "pass",
        "test_surfaces": "pass",
        "telemetry": "pass",
    }
    for error in errors:
        signature = error["failure_signature"]
        if signature == "missing_source_artifact":
            checks["source_artifacts"] = "fail"
        elif signature in {"dependency_proof_missing", "dependency_commit_missing"}:
            checks["dependency_proofs"] = "fail"
        elif signature.startswith("unistd_wave3_fixture"):
            checks["unistd_wave3_fixture"] = "fail"
        elif signature in {"coverage_accounting_drift", "completed_symbol_still_claimed"}:
            checks["coverage_accounting"] = "fail"
        elif signature == "non_rch_validation_command":
            checks["validation_commands"] = "fail"
        elif signature == "missing_test_binding":
            checks["test_surfaces"] = "fail"
        elif signature == "missing_telemetry_event":
            checks["telemetry"] = "fail"
        else:
            for key in checks:
                checks[key] = "fail"
    return {
        "schema_version": REPORT_SCHEMA,
        "status": status,
        "bead_id": BEAD_ID,
        "epic_id": EPIC_ID,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "generated_at": utc_now(),
        "contract": rel(CONTRACT),
        "checks": checks,
        "summary": {
            "campaign_id": CAMPAIGN_ID,
            "wave_id": WAVE_ID,
            "fixture_file": FIXTURE_PATH,
            "unistd_wave3_symbol_count": len(completion.get("required_first_wave_symbols", [])),
            "required_mode_count": len(completion.get("required_modes", [])),
            "telemetry_event_count": len(completion.get("required_telemetry_events", [])),
            "error_count": len(errors),
        },
        "errors": errors,
        "artifact_refs": sorted(artifact_refs),
    }


def main() -> int:
    contract = as_object(load_json(CONTRACT, "completion contract"), "completion contract")
    completion = validate_top_level(contract)
    artifacts = artifact_map(contract)
    validate_bindings(contract)
    validate_dependency_proofs(completion, artifacts)
    validate_unistd_wave3_fixture(completion, artifacts)
    validate_coverage_accounting(completion, artifacts)
    validate_validation_commands(completion)
    validate_test_surfaces(completion, artifacts)
    validate_telemetry_contract(completion)

    status = "pass" if not errors else "fail"
    events.append(
        event(
            "unistd_wave3_completion_contract_validated",
            status,
            "none" if status == "pass" else primary_signature(),
            error_count=len(errors),
        )
    )
    report = build_report(completion)
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if errors:
        print(f"FAIL unistd process/filesystem wave-03 completion contract errors={len(errors)} report={rel(REPORT)}", file=sys.stderr)
        return 1
    print(
        "PASS unistd process/filesystem wave-03 completion contract "
        f"symbols={report['summary']['unistd_wave3_symbol_count']} "
        f"events={len(events)} report={rel(REPORT)} log={rel(LOG)}"
    )
    return 0


raise SystemExit(main())
PY
