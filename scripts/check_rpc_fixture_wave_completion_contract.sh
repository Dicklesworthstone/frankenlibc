#!/usr/bin/env bash
# check_rpc_fixture_wave_completion_contract.sh -- bd-mu4lw.3 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RPC_FIXTURE_WAVE_CONTRACT:-${ROOT}/tests/conformance/rpc_fixture_wave_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RPC_FIXTURE_WAVE_OUT_DIR:-${ROOT}/target/conformance/rpc_fixture_wave_completion}"
REPORT="${FRANKENLIBC_RPC_FIXTURE_WAVE_REPORT:-${OUT_DIR}/rpc_fixture_wave_completion_contract.report.json}"
LOG="${FRANKENLIBC_RPC_FIXTURE_WAVE_LOG:-${OUT_DIR}/rpc_fixture_wave_completion_contract.events.jsonl}"
README_OVERRIDE="${FRANKENLIBC_RPC_FIXTURE_WAVE_README:-}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" "${README_OVERRIDE}" <<'PY'
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
README_OVERRIDE = sys.argv[7]

SCHEMA = "rpc_fixture_wave_completion_contract.v1"
REPORT_SCHEMA = "rpc_fixture_wave_completion_contract.report.v1"
BEAD_ID = "bd-mu4lw.3"
EPIC_ID = "bd-mu4lw"
TRACE_ID = "bd-mu4lw.3::rpc-fixture-wave::completion::v1"

REQUIRED_ARTIFACT_IDS = {
    "beads_ledger",
    "fixture_coverage_prioritizer",
    "rpc_fixture",
    "fixture_executor",
    "rpc_fixture_harness_test",
    "readme_claim_surface",
    "support_matrix",
    "artifact_precedence_manifest",
    "artifact_precedence_gate",
    "artifact_precedence_test",
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
    "child_beads_validated",
    "rpc_fixture_validated",
    "claim_realism_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "rpc_fixture_wave_completion_contract_validated",
}
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_rpc_fixture_wave_sources",
    "checker_accepts_rpc_fixture_wave_completion_contract",
    "checker_emits_structured_rpc_completion_telemetry",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_rpc_fixture_symbol",
    "checker_rejects_stale_rpc_readme_stub_wording",
    "checker_rejects_non_rch_cargo_validation_command",
    "checker_rejects_missing_required_telemetry_event",
}

FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "child_bead_not_closed",
    "rpc_fixture_symbol_coverage",
    "rpc_fixture_mode_coverage",
    "rpc_fixture_schema",
    "readme_rpc_stub_claim",
    "support_matrix_stub_count",
    "artifact_precedence_drift",
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
    return "rpc_fixture_wave_completion_contract_failed"


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
    rows = as_array(contract.get("source_artifacts"), "source_artifacts")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
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
    missing_items = string_set(
        completion.get("missing_item_ids"),
        "completion_contract.missing_item_ids",
        "malformed_contract",
    )
    missing_required = sorted(REQUIRED_MISSING_ITEMS - missing_items)
    if missing_required:
        add_error("malformed_contract", f"missing completion items: {missing_required}")
    return completion


def validate_bindings(contract: dict[str, Any]) -> None:
    rows = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
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


def validate_child_beads(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    required = string_set(
        completion.get("closed_child_beads"),
        "completion_contract.closed_child_beads",
        "malformed_contract",
    )
    evidence_rows = as_array(
        completion.get("child_closure_evidence"),
        "completion_contract.child_closure_evidence",
        "child_bead_not_closed",
    )
    evidence: dict[str, dict[str, Any]] = {}
    for row in evidence_rows:
        obj = as_object(row, "completion_contract.child_closure_evidence[]", "child_bead_not_closed")
        bead_id = obj.get("bead_id")
        if isinstance(bead_id, str):
            evidence[bead_id] = obj
    ledger_path = resolve(artifacts.get("beads_ledger", {}).get("path", ".beads/issues.jsonl"))
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
    open_children: list[str] = []
    for bead in sorted(required):
        ledger_closed = rows.get(bead, {}).get("status") == "closed"
        evidence_row = evidence.get(bead, {})
        evidence_closed = (
            evidence_row.get("status") == "closed"
            and isinstance(evidence_row.get("commit"), str)
            and bool(evidence_row.get("commit"))
            and isinstance(evidence_row.get("evidence"), str)
            and bool(evidence_row.get("evidence"))
        )
        if not ledger_closed and not evidence_closed:
            open_children.append(bead)
    if open_children:
        add_error("child_bead_not_closed", f"child beads not closed: {open_children}")
    events.append(
        event(
            "child_beads_validated",
            "pass" if not open_children else "fail",
            "none" if not open_children else "child_bead_not_closed",
            child_beads=sorted(required),
        )
    )


def validate_rpc_fixture(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    fixture = load_json(
        resolve(artifacts.get("rpc_fixture", {}).get("path", "tests/conformance/fixtures/rpc_legacy_network.json")),
        "rpc fixture",
        "rpc_fixture_schema",
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

    if fixture.get("family") != "rpc/legacy-network":
        add_error("rpc_fixture_schema", "rpc fixture family mismatch")
    campaign = as_object(fixture.get("campaign"), "rpc_fixture.campaign", "rpc_fixture_schema")
    declared_symbols = set(campaign.get("first_wave_symbols", []))
    if declared_symbols != required_symbols:
        add_error(
            "rpc_fixture_symbol_coverage",
            f"campaign first_wave_symbols mismatch missing={sorted(required_symbols - declared_symbols)} extra={sorted(declared_symbols - required_symbols)}",
        )
    if campaign.get("network_access") != "forbidden":
        add_error("rpc_fixture_schema", "rpc fixture must forbid network access")
    log_fields = set(fixture.get("structured_log_fields", []))
    if log_fields != required_fields:
        add_error("rpc_fixture_schema", "structured_log_fields mismatch")

    modes_by_symbol: dict[str, set[str]] = {symbol: set() for symbol in required_symbols}
    case_count = 0
    for case in as_array(fixture.get("cases"), "rpc_fixture.cases", "rpc_fixture_schema"):
        obj = as_object(case, "rpc_fixture.cases[]", "rpc_fixture_schema")
        symbol = obj.get("function")
        mode = obj.get("mode")
        if isinstance(symbol, str) and isinstance(mode, str):
            case_count += 1
            modes_by_symbol.setdefault(symbol, set()).add(mode)
        inputs = as_object(obj.get("inputs"), f"rpc_fixture.case[{symbol}].inputs", "rpc_fixture_schema")
        for field in [
            "symbol",
            "expected_class",
            "strict_behavior",
            "hardened_behavior",
            "safe_default_rationale",
            "oracle_source",
        ]:
            if not isinstance(inputs.get(field), str) or not inputs.get(field):
                add_error("rpc_fixture_schema", f"case {obj.get('name')} missing inputs.{field}")
        expected_output = obj.get("expected_output")
        if not isinstance(expected_output, str):
            add_error("rpc_fixture_schema", f"case {obj.get('name')} missing expected_output")
            expected_output = ""
        for field in sorted(required_fields):
            if f"{field}=" not in expected_output:
                add_error("rpc_fixture_schema", f"case {obj.get('name')} expected_output missing {field} token")

    mode_failures = [
        symbol
        for symbol, modes in sorted(modes_by_symbol.items())
        if symbol in required_symbols and modes != required_modes
    ]
    if mode_failures:
        add_error("rpc_fixture_mode_coverage", f"symbols missing required modes: {mode_failures}")

    events.append(
        event(
            "rpc_fixture_validated",
            "pass" if not mode_failures else "fail",
            "none" if not mode_failures else "rpc_fixture_mode_coverage",
            symbol_count=len(required_symbols),
            case_count=case_count,
        )
    )


def validate_claim_realism(completion: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    readme_path = pathlib.Path(README_OVERRIDE) if README_OVERRIDE else resolve(artifacts.get("readme_claim_surface", {}).get("path", "README.md"))
    readme = read_text(readme_path, "README claim surface", "readme_rpc_stub_claim")
    required_text = completion.get("readme_rpc_abi_text")
    if isinstance(required_text, str) and required_text not in readme:
        add_error("readme_rpc_stub_claim", "README missing required rpc_abi safe-default wording")

    support = load_json(resolve(artifacts.get("support_matrix", {}).get("path", "support_matrix.json")), "support matrix", "support_matrix_stub_count")
    stub_count = support.get("counts", {}).get("stub") if isinstance(support, dict) else None
    if stub_count != completion.get("support_matrix_stub_count"):
        add_error("support_matrix_stub_count", f"support_matrix counts.stub={stub_count}")
    if stub_count == 0:
        for line_no, line in enumerate(readme.splitlines(), start=1):
            if "rpc_abi.rs" in line and "stub" in line.lower():
                add_error("readme_rpc_stub_claim", f"README {rel(readme_path)}:{line_no} has rpc_abi stub wording while Stub count is 0")

    precedence = load_json(
        resolve(artifacts.get("artifact_precedence_manifest", {}).get("path", "tests/conformance/artifact_precedence.v1.json")),
        "artifact precedence manifest",
        "artifact_precedence_drift",
    )
    expected_count = completion.get("artifact_precedence_summary", {}).get("readme_rpc_stub_claim_count")
    actual_count = precedence.get("expected_current_summary", {}).get("readme_rpc_stub_claim_count")
    if actual_count != expected_count:
        add_error("artifact_precedence_drift", f"artifact precedence readme_rpc_stub_claim_count={actual_count}")

    gate_text = read_text(
        resolve(artifacts.get("artifact_precedence_gate", {}).get("path", "scripts/check_artifact_precedence.sh")),
        "artifact precedence gate",
        "artifact_precedence_drift",
    )
    for needle in ["readme_rpc_stub_claim", "FLC_ARTIFACT_PRECEDENCE_README"]:
        if needle not in gate_text:
            add_error("artifact_precedence_drift", f"artifact precedence gate missing {needle}")

    events.append(
        event(
            "claim_realism_validated",
            "pass",
            "none",
            support_matrix_stub_count=stub_count,
            readme_rpc_stub_claim_count=actual_count,
        )
    )


def validate_validation_commands(completion: dict[str, Any]) -> None:
    commands = string_set(
        completion.get("runtime_validation"),
        "completion_contract.runtime_validation",
        "malformed_contract",
    )
    required_fragments = [
        "cargo test -p frankenlibc-harness --test rpc_fixture_wave_completion_contract_test",
        "cargo check -p frankenlibc-harness --test rpc_fixture_wave_completion_contract_test",
        "cargo clippy -p frankenlibc-harness --test rpc_fixture_wave_completion_contract_test -- -D warnings",
    ]
    for fragment in required_fragments:
        matches = [command for command in commands if fragment in command]
        if not matches:
            add_error("non_rch_validation_command", f"missing validation command fragment: {fragment}")
            continue
        for command in matches:
            if "rch exec --" not in command or "CARGO_TARGET_DIR=" not in command:
                add_error("non_rch_validation_command", f"cargo validation is not rch-scoped: {command}")
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
        resolve(artifacts.get("completion_harness_test", {}).get("path", "crates/frankenlibc-harness/tests/rpc_fixture_wave_completion_contract_test.rs")),
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
validate_child_beads(completion, artifacts)
validate_rpc_fixture(completion, artifacts)
validate_claim_realism(completion, artifacts)
validate_validation_commands(completion)
validate_test_surfaces(artifacts)
validate_telemetry_contract(completion)

status = "pass" if not errors else "fail"
events.append(
    event(
        "rpc_fixture_wave_completion_contract_validated",
        status,
        "none" if status == "pass" else primary_signature(),
    )
)

checks = {
    "source_artifacts": "pass" if not any(e["failure_signature"] == "missing_source_artifact" for e in errors) else "fail",
    "child_beads": "pass" if not any(e["failure_signature"] == "child_bead_not_closed" for e in errors) else "fail",
    "rpc_fixture": "pass" if not any(e["failure_signature"].startswith("rpc_fixture") for e in errors) else "fail",
    "claim_realism": "pass" if not any(e["failure_signature"] in {"readme_rpc_stub_claim", "support_matrix_stub_count", "artifact_precedence_drift"} for e in errors) else "fail",
    "validation_commands": "pass" if not any(e["failure_signature"] == "non_rch_validation_command" for e in errors) else "fail",
    "test_surfaces": "pass" if not any(e["failure_signature"] == "missing_test_binding" for e in errors) else "fail",
    "telemetry": "pass" if not any(e["failure_signature"] == "missing_telemetry_event" for e in errors) else "fail",
}
report = {
    "schema_version": REPORT_SCHEMA,
    "bead_id": BEAD_ID,
    "status": status,
    "checks": checks,
    "summary": {
        "source_artifact_count": len(artifacts),
        "required_child_bead_count": len(completion.get("closed_child_beads", [])),
        "rpc_first_wave_symbol_count": len(completion.get("required_first_wave_symbols", [])),
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
    "PASS: rpc fixture wave completion contract "
    f"symbols={report['summary']['rpc_first_wave_symbol_count']} "
    f"events={len(events)} report={rel(REPORT)} log={rel(LOG)}"
)
PY
