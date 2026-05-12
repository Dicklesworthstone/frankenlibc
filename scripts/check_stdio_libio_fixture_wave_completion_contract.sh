#!/usr/bin/env bash
# check_stdio_libio_fixture_wave_completion_contract.sh -- bd-6cly1.3 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STDIO_LIBIO_FIXTURE_WAVE_CONTRACT:-${ROOT}/tests/conformance/stdio_libio_fixture_wave_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STDIO_LIBIO_FIXTURE_WAVE_OUT_DIR:-${ROOT}/target/conformance/stdio_libio_fixture_wave_completion}"
REPORT="${FRANKENLIBC_STDIO_LIBIO_FIXTURE_WAVE_REPORT:-${OUT_DIR}/stdio_libio_fixture_wave_completion_contract.report.json}"
LOG="${FRANKENLIBC_STDIO_LIBIO_FIXTURE_WAVE_LOG:-${OUT_DIR}/stdio_libio_fixture_wave_completion_contract.events.jsonl}"
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

SCHEMA = "stdio_libio_fixture_wave_completion_contract.v1"
REPORT_SCHEMA = "stdio_libio_fixture_wave_completion_contract.report.v1"
BEAD_ID = "bd-6cly1.3"
EPIC_ID = "bd-6cly1"
TRACE_ID = "bd-6cly1.3::stdio-libio-fixture-wave::completion::v1"
CAMPAIGN_ID = "fcq-stdio-libio"
WAVE_ID = "wave-03-stdio-libio"
FIXTURE_FILE = "stdio_libio_symbols.json"
FIXTURE_PATH = "tests/conformance/fixtures/stdio_libio_symbols.json"
STDIO_MODULE = "stdio_abi"

REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "fixture_coverage_prioritizer",
    "top_blocker_wave_plan",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "conformance_coverage_snapshot",
    "stdio_libio_fixture",
    "fixture_executor",
    "stdio_libio_fixture_harness_test",
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
REQUIRED_TELEMETRY_EVENTS = {
    "source_artifacts_validated",
    "dependency_proofs_validated",
    "stdio_libio_fixture_validated",
    "coverage_accounting_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "stdio_libio_fixture_wave_completion_contract_validated",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_stdio_libio_fixture_wave_sources",
    "checker_accepts_stdio_libio_fixture_wave_completion_contract",
    "checker_emits_structured_stdio_libio_completion_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_stdio_libio_fixture_symbol",
    "checker_rejects_stale_stdio_libio_coverage_accounting",
    "checker_rejects_non_rch_cargo_validation_command",
    "checker_rejects_missing_required_telemetry_event",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "dependency_proof_missing",
    "dependency_commit_missing",
    "stdio_libio_fixture_symbol_coverage",
    "stdio_libio_fixture_mode_coverage",
    "stdio_libio_fixture_schema",
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
    return "stdio_libio_fixture_wave_completion_contract_failed"


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
        if not resolve(path).exists() and artifact_id != "beads_ledger":
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
    ledger_path = resolve(artifacts.get("beads_ledger", {}).get("path", ".beads/issues.jsonl"))
    if not ledger_path.exists():
        artifact_refs.add(rel(ledger_path))
        return {}
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
    for bead_id in ["bd-6cly1.1", "bd-6cly1.2"]:
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
    events.append(
        event(
            "dependency_proofs_validated",
            "pass" if not missing and not missing_commits else "fail",
            "none" if not missing and not missing_commits else "dependency_proof_missing",
            dependency_count=len(by_id),
        )
    )


def validate_stdio_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    fixture = load_json(
        resolve(artifacts.get("stdio_libio_fixture", {}).get("path", FIXTURE_PATH)),
        "stdio/libio fixture",
        "stdio_libio_fixture_schema",
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

    if fixture.get("family") != "stdio_libio_symbols":
        add_error("stdio_libio_fixture_schema", "stdio/libio fixture family mismatch")
    campaign = as_object(fixture.get("campaign"), "stdio_fixture.campaign", "stdio_libio_fixture_schema")
    if campaign.get("bead") != "bd-6cly1.1":
        add_error("stdio_libio_fixture_schema", "stdio fixture bead binding mismatch")
    if campaign.get("campaign_id") != CAMPAIGN_ID or campaign.get("wave_id") != WAVE_ID:
        add_error("stdio_libio_fixture_schema", "stdio fixture campaign/wave binding mismatch")
    if campaign.get("ambient_state_policy") != "forbid_file_address_fd_or_path_capture":
        add_error("stdio_libio_fixture_schema", "stdio fixture ambient_state_policy mismatch")
    if set(campaign.get("first_wave_symbols", [])) != required_symbols:
        declared = set(campaign.get("first_wave_symbols", []))
        add_error(
            "stdio_libio_fixture_symbol_coverage",
            f"campaign first_wave_symbols mismatch missing={sorted(required_symbols - declared)} extra={sorted(declared - required_symbols)}",
        )
    if campaign.get("residual_symbols") not in ([], None):
        add_error("stdio_libio_fixture_symbol_coverage", "stdio/libio fixture must not leave residual first-wave symbols")
    if set(fixture.get("structured_log_fields", [])) != required_fields:
        add_error("stdio_libio_fixture_schema", "structured_log_fields mismatch")

    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    case_count = 0
    for case in as_array(fixture.get("cases"), "stdio_fixture.cases", "stdio_libio_fixture_schema"):
        obj = as_object(case, "stdio_fixture.cases[]", "stdio_libio_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str):
            case_count += 1
            modes_by_symbol.setdefault(symbol, set()).add(mode)
        inputs = as_object(obj.get("inputs"), f"stdio_fixture.case[{symbol}].inputs", "stdio_libio_fixture_schema")
        for field in ["symbol", "expected", "ambient_state_policy", "oracle_source"]:
            if not isinstance(inputs.get(field), str) or not inputs.get(field):
                add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} missing inputs.{field}")
        if isinstance(symbol, str) and inputs.get("symbol") != symbol:
            add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} inputs.symbol mismatch")
        if inputs.get("ambient_state_policy") != "forbid_file_address_fd_or_path_capture":
            add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} ambient-state policy mismatch")
        expected_output = obj.get("expected_output")
        if not isinstance(expected_output, str):
            add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} missing expected_output")
            expected_output = ""
        for field in sorted(required_fields):
            if f"{field}=" not in expected_output:
                add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} expected_output missing {field} token")
        for token in forbidden_tokens:
            if token in expected_output:
                add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} leaks ambient token {token}")
        if obj.get("expected_errno") != 0:
            add_error("stdio_libio_fixture_schema", f"case {obj.get('name')} expected_errno must be 0")

    mode_failures = [
        symbol
        for symbol, modes in sorted(modes_by_symbol.items())
        if symbol in required_symbols and modes != required_modes
    ]
    if mode_failures:
        add_error("stdio_libio_fixture_mode_coverage", f"symbols missing required modes: {mode_failures}")

    events.append(
        event(
            "stdio_libio_fixture_validated",
            "pass" if not mode_failures else "fail",
            "none" if not mode_failures else "stdio_libio_fixture_mode_coverage",
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


def wave_row(wave_plan: dict[str, Any]) -> dict[str, Any]:
    for row in as_array(wave_plan.get("coverage_waves"), "top_blocker.coverage_waves", "coverage_accounting_drift"):
        obj = as_object(row, "top_blocker.coverage_waves[]", "coverage_accounting_drift")
        if obj.get("campaign_id") == CAMPAIGN_ID:
            return obj
    add_error("coverage_accounting_drift", f"{CAMPAIGN_ID} missing from top blocker wave plan")
    return {}


def validate_coverage_accounting(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
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

    prioritizer = load_json(resolve(artifacts["fixture_coverage_prioritizer"]["path"]), "fixture coverage prioritizer", "coverage_accounting_drift")
    wave_plan = load_json(resolve(artifacts["top_blocker_wave_plan"]["path"]), "top blocker wave plan", "coverage_accounting_drift")
    symbol_coverage = load_json(resolve(artifacts["symbol_fixture_coverage"]["path"]), "symbol fixture coverage", "coverage_accounting_drift")
    per_symbol = load_json(resolve(artifacts["per_symbol_fixture_tests"]["path"]), "per-symbol fixture tests", "coverage_accounting_drift")
    snapshot = load_json(resolve(artifacts["conformance_coverage_snapshot"]["path"]), "conformance coverage snapshot", "coverage_accounting_drift")

    campaign = campaign_row(as_object(prioritizer, "fixture coverage prioritizer", "coverage_accounting_drift"))
    top_wave = wave_row(as_object(wave_plan, "top blocker wave plan", "coverage_accounting_drift"))
    target_covered_min = coverage_contract.get("campaign_target_covered_min", 0)
    target_uncovered_max = coverage_contract.get("campaign_target_uncovered_max", 0)
    coverage_pct_min = coverage_contract.get("campaign_current_coverage_pct_min", 0)
    expected_after_min = coverage_contract.get("campaign_expected_after_first_wave_pct_min", 0)

    for source_name, row in [("prioritizer", campaign), ("top_blocker", top_wave)]:
        if row.get("target_covered", 0) < target_covered_min:
            add_error("coverage_accounting_drift", f"{source_name} target_covered below {target_covered_min}")
        if row.get("target_uncovered", 0) > target_uncovered_max:
            add_error("coverage_accounting_drift", f"{source_name} target_uncovered above {target_uncovered_max}")
        if float(row.get("current_coverage_pct", 0.0)) < float(coverage_pct_min):
            add_error("coverage_accounting_drift", f"{source_name} current_coverage_pct below {coverage_pct_min}")
        if float(row.get("expected_coverage_after_first_wave_pct", 0.0)) < float(expected_after_min):
            add_error("coverage_accounting_drift", f"{source_name} expected_coverage_after_first_wave_pct below {expected_after_min}")
        stale_symbols = sorted(required_symbols & set(row.get("first_wave_symbols", [])))
        if stale_symbols:
            add_error("completed_symbol_still_claimed", f"{source_name} still claims completed first-wave symbols: {stale_symbols}")

    if FIXTURE_PATH not in top_wave.get("fixture_files", []):
        add_error("coverage_accounting_drift", "top blocker wave plan missing stdio/libio fixture file")

    per_symbol_rows = {
        row.get("symbol"): row
        for row in as_array(per_symbol.get("per_symbol_report"), "per_symbol.per_symbol_report", "coverage_accounting_drift")
        if isinstance(row, dict) and row.get("module") == STDIO_MODULE
    }
    coverage_rows = {
        row.get("symbol"): row
        for row in as_array(symbol_coverage.get("symbols"), "symbol_fixture_coverage.symbols", "coverage_accounting_drift")
        if isinstance(row, dict) and row.get("module") == STDIO_MODULE
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
    snapshot_summary = as_object(snapshot.get("summary"), "snapshot.summary", "coverage_accounting_drift")
    if symbol_summary.get("covered_exported_symbols", 0) < coverage_contract.get("symbol_fixture_covered_min", 0):
        add_error("coverage_accounting_drift", "symbol fixture covered count drifted below contract")
    if per_summary.get("symbols_with_fixtures", 0) < coverage_contract.get("per_symbol_fixture_linked_min", 0):
        add_error("coverage_accounting_drift", "per-symbol linked fixture count drifted below contract")
    if snapshot_summary.get("total_fixture_files", 0) < coverage_contract.get("conformance_total_fixture_files_min", 0):
        add_error("coverage_accounting_drift", "conformance fixture file count drifted below contract")
    if snapshot_summary.get("total_fixture_cases", 0) < coverage_contract.get("conformance_total_fixture_cases_min", 0):
        add_error("coverage_accounting_drift", "conformance fixture case count drifted below contract")

    required_needles = string_set(
        completion.get("required_coverage_guard_needles"),
        "completion_contract.required_coverage_guard_needles",
        "malformed_contract",
    )
    gate_text = read_text(resolve(artifacts["prioritizer_gate"]["path"]), "prioritizer gate", "coverage_accounting_drift")
    test_text = read_text(resolve(artifacts["prioritizer_guard_test"]["path"]), "prioritizer guard test", "coverage_accounting_drift")
    for needle in sorted(required_needles):
        if needle not in gate_text and needle not in test_text:
            add_error("coverage_accounting_drift", f"coverage guard surfaces missing needle {needle}")

    coverage_failed = any(
        error["failure_signature"] in {"coverage_accounting_drift", "completed_symbol_still_claimed"}
        for error in errors
    )
    events.append(
        event(
            "coverage_accounting_validated",
            "pass" if not coverage_failed else "fail",
            "none" if not coverage_failed else "coverage_accounting_drift",
            target_covered=campaign.get("target_covered"),
            target_uncovered=campaign.get("target_uncovered"),
            current_coverage_pct=campaign.get("current_coverage_pct"),
        )
    )


def validate_validation_commands(completion: dict[str, Any]) -> None:
    commands = string_set(
        completion.get("runtime_validation"),
        "completion_contract.runtime_validation",
        "malformed_contract",
    )
    required_fragments = [
        "cargo test -p frankenlibc-harness --test stdio_libio_fixture_wave_completion_contract_test",
        "cargo check -p frankenlibc-harness --test stdio_libio_fixture_wave_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test stdio_libio_fixture_wave_completion_contract_test -- -D warnings",
    ]
    for fragment in required_fragments:
        matches = [command for command in commands if fragment in command]
        if not matches:
            add_error("non_rch_validation_command", f"missing validation command fragment: {fragment}")
            continue
        for command in matches:
            if "rch exec --" not in command or "CARGO_TARGET_DIR=" not in command or "RCH_FORCE_REMOTE=true" not in command:
                add_error("non_rch_validation_command", f"cargo validation is not remote rch-scoped: {command}")
    if not any("br --no-db dep cycles --json" in command for command in commands):
        add_error("non_rch_validation_command", "missing br --no-db dep cycles validation command")
    events.append(
        event(
            "validation_commands_validated",
            "pass",
            "none",
            validation_command_count=len(commands),
        )
    )


def validate_test_surfaces(artifacts: dict[str, dict[str, Any]]) -> None:
    text = read_text(
        resolve(artifacts.get("completion_harness_test", {}).get("path", "crates/frankenlibc-harness/tests/stdio_libio_fixture_wave_completion_contract_test.rs")),
        "completion harness test",
        "missing_test_binding",
    )
    missing_positive = sorted(test for test in REQUIRED_POSITIVE_TESTS if test not in text)
    missing_negative = sorted(test for test in REQUIRED_NEGATIVE_TESTS if test not in text)
    fixture_test = read_text(
        resolve(artifacts.get("stdio_libio_fixture_harness_test", {}).get("path", "crates/frankenlibc-harness/tests/stdio_libio_symbols_conformance_test.rs")),
        "stdio/libio fixture harness test",
        "missing_test_binding",
    )
    for needle in [
        "stdio_libio_symbols_cover_first_wave_in_both_modes",
        "stdio_libio_symbols_bind_logs_without_ambient_stream_leaks",
        "stdio_libio_symbols_fixture_executes_via_isolated_harness",
    ]:
        if needle not in fixture_test:
            add_error("missing_test_binding", f"stdio/libio fixture harness missing {needle}")
    if missing_positive or missing_negative:
        add_error(
            "missing_test_binding",
            f"missing positive tests={missing_positive} negative tests={missing_negative}",
        )
    events.append(
        event(
            "test_surfaces_validated",
            "pass" if not missing_positive and not missing_negative else "fail",
            "none" if not missing_positive and not missing_negative else "missing_test_binding",
            positive_test_count=len(REQUIRED_POSITIVE_TESTS),
            negative_test_count=len(REQUIRED_NEGATIVE_TESTS),
        )
    )


def validate_telemetry_contract(completion: dict[str, Any]) -> None:
    required = string_set(
        completion.get("required_telemetry_events"),
        "completion_contract.required_telemetry_events",
        "missing_telemetry_event",
    )
    missing_events = sorted(REQUIRED_TELEMETRY_EVENTS - required)
    if missing_events:
        add_error("missing_telemetry_event", f"missing required telemetry events: {missing_events}")
    events.append(
        event(
            "telemetry_contract_validated",
            "pass" if not missing_events else "fail",
            "none" if not missing_events else "missing_telemetry_event",
            required_event_count=len(required),
        )
    )


contract = load_json(CONTRACT, "contract")
contract_obj = as_object(contract, "contract")
completion = validate_top_level(contract_obj)
artifacts = artifact_map(contract_obj)
validate_bindings(contract_obj)
validate_dependency_proofs(completion, artifacts)
validate_stdio_fixture(completion, artifacts)
validate_coverage_accounting(completion, artifacts)
validate_validation_commands(completion)
validate_test_surfaces(artifacts)
validate_telemetry_contract(completion)

status = "pass" if not errors else "fail"
events.append(
    event(
        "stdio_libio_fixture_wave_completion_contract_validated",
        status,
        "none" if status == "pass" else primary_signature(),
    )
)

checks = {
    "source_artifacts": "pass" if not any(e["failure_signature"] == "missing_source_artifact" for e in errors) else "fail",
    "dependency_proofs": "pass" if not any(e["failure_signature"] in {"dependency_proof_missing", "dependency_commit_missing"} for e in errors) else "fail",
    "stdio_libio_fixture": "pass" if not any(e["failure_signature"].startswith("stdio_libio_fixture") for e in errors) else "fail",
    "coverage_accounting": "pass" if not any(e["failure_signature"] in {"coverage_accounting_drift", "completed_symbol_still_claimed"} for e in errors) else "fail",
    "validation_commands": "pass" if not any(e["failure_signature"] == "non_rch_validation_command" for e in errors) else "fail",
    "test_surfaces": "pass" if not any(e["failure_signature"] == "missing_test_binding" for e in errors) else "fail",
    "telemetry": "pass" if not any(e["failure_signature"] == "missing_telemetry_event" for e in errors) else "fail",
}
report = {
    "schema_version": REPORT_SCHEMA,
    "bead_id": BEAD_ID,
    "epic_id": EPIC_ID,
    "status": status,
    "checks": checks,
    "summary": {
        "source_artifact_count": len(artifacts),
        "required_dependency_proof_count": len(completion.get("required_dependency_proofs", [])),
        "stdio_libio_first_wave_symbol_count": len(completion.get("required_first_wave_symbols", [])),
        "required_mode_count": len(completion.get("required_modes", [])),
        "required_telemetry_event_count": len(completion.get("required_telemetry_events", [])),
    },
    "errors": errors,
    "events": events,
    "artifact_refs": sorted(artifact_refs),
    "source_commit": SOURCE_COMMIT,
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    for error in errors:
        print(f"ERROR[{error['failure_signature']}]: {error['message']}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: stdio/libio fixture wave completion contract "
    f"symbols={report['summary']['stdio_libio_first_wave_symbol_count']} "
    f"events={len(events)} report={rel(REPORT)} log={rel(LOG)}"
)
PY
