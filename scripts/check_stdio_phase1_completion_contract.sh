#!/usr/bin/env bash
# Validate bd-2vv.3.1.1 stdio Phase 1 completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STDIO_PHASE1_CONTRACT:-${1:-${ROOT}/tests/conformance/stdio_phase1_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_STDIO_PHASE1_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_STDIO_PHASE1_REPORT:-${OUT_DIR}/stdio_phase1_completion_contract.report.json}"
LOG="${FRANKENLIBC_STDIO_PHASE1_LOG:-${OUT_DIR}/stdio_phase1_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(sys.argv[1]).resolve()
CONTRACT = Path(sys.argv[2]).resolve()
REPORT = Path(sys.argv[3]).resolve()
LOG = Path(sys.argv[4]).resolve()
SOURCE_COMMIT = sys.argv[5]

SCHEMA = "stdio_phase1_completion_contract.v1"
BEAD = "bd-2vv.3.1"
COMPLETION_BEAD = "bd-2vv.3.1.1"
MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
TARGET_SYMBOLS = {
    "fopen",
    "fclose",
    "fflush",
    "fread",
    "fwrite",
    "fgetc",
    "fputc",
    "fgets",
    "fputs",
    "ungetc",
    "fileno",
    "setvbuf",
    "setbuf",
}
SOURCE_KEYS = {
    "abi_stdio",
    "abi_stdio_test",
    "c_fixture_spec",
    "e2e_runner",
    "e2e_stdio_fixture",
    "support_matrix",
    "completion_checker",
    "completion_test",
}
UNIT_REFS = {
    ("abi_stdio_test", "fopen_fputs_fflush_fclose_round_trip"),
    ("abi_stdio_test", "fputc_fgetc_and_ungetc_behave_consistently"),
    ("abi_stdio_test", "fwrite_then_fread_round_trip_matches_bytes"),
    ("abi_stdio_test", "fgets_reads_a_line_and_nul_terminates"),
    ("abi_stdio_test", "fileno_and_setvbuf_contracts_hold"),
    ("abi_stdio_test", "rejects_invalid_open_mode_and_null_stream_handles"),
    ("abi_stdio_test", "null_and_zero_length_io_paths_are_safe_defaults"),
    ("abi_stdio_test", "fgets_rejects_invalid_destination_or_size"),
    ("completion_test", "checker_accepts_contract_and_emits_report_log"),
}
E2E_ARTIFACTS = {"c_fixture_spec", "e2e_runner", "e2e_stdio_fixture"}
COMPLETION_EVENTS = {
    "stdio_phase1_completion.source_artifacts",
    "stdio_phase1_completion.unit_bindings",
    "stdio_phase1_completion.e2e_binding",
    "stdio_phase1_completion.telemetry_contract",
    "stdio_phase1_completion.completion_contract_validated",
}
FIXTURE_EVENTS = {"fixture_result", "run_summary"}
LOG_FIELDS = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}
REPORT_FIELDS = {
    "schema_version",
    "status",
    "bead",
    "source_bead",
    "missing_items_closed",
    "target_symbols",
    "unit_bindings",
    "e2e_bindings",
    "telemetry_events",
    "source_summary",
    "errors",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} JSON load failed: {rel(path)}: {exc}")
        return {}


def read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        error(f"{label} read failed: {rel(path)}: {exc}")
        return ""


def strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        error(f"{label} must be a non-empty list of strings")
        return []
    return list(value)


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": "stdio_phase1_completion_contract.log.v1",
            "timestamp": utc_now(),
            "event": event,
            "status": status,
            "bead": COMPLETION_BEAD,
            "bead_id": COMPLETION_BEAD,
            "source_bead": BEAD,
            "source_commit": SOURCE_COMMIT,
            "trace_id": f"{COMPLETION_BEAD}::{event}",
            "mode": "strict+hardened",
            "api_family": "stdio",
            "symbol": "stdio-phase1",
            "decision_path": "completion_contract>source_artifact_validation",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": 0,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def workspace_path(path_text: str) -> Path:
    return (ROOT / path_text).resolve()


def validate_top_level(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == SCHEMA, "schema_version mismatch")
    require(manifest.get("bead") == BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")
    require(set(strings(manifest.get("target_symbols"), "target_symbols")) == TARGET_SYMBOLS, "target_symbols drift")
    debt = manifest.get("completion_debt_evidence")
    if not isinstance(debt, dict):
        error("completion_debt_evidence must be an object")
        return
    require(debt.get("original_bead") == BEAD, "completion_debt_evidence.original_bead mismatch")
    require(debt.get("next_audit_score_threshold", 0) >= 800, "next audit threshold must be at least 800")
    missing = set(strings(debt.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
    require(missing == MISSING_ITEMS, f"missing_items_closed drift: {sorted(missing)}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        error("source_artifacts must be an object")
        return {}
    missing = SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")
    paths: dict[str, Path] = {}
    for key in sorted(SOURCE_KEYS):
        value = source_artifacts.get(key)
        if not isinstance(value, str) or not value:
            error(f"source_artifacts.{key} must be a non-empty path")
            continue
        path = workspace_path(value)
        if ROOT not in path.parents and path != ROOT:
            error(f"source_artifacts.{key} escapes workspace: {value}")
            continue
        if not path.is_file():
            error(f"source_artifacts.{key} missing file: {value}")
            continue
        paths[key] = path
    append_event(
        "stdio_phase1_completion.source_artifacts",
        "fail" if errors else "pass",
        {"source_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_rch_commands(commands: Any, label: str) -> None:
    for command in strings(commands, label):
        if "cargo " in command or "bash scripts/c_fixture_suite.sh" in command:
            require(command.startswith("rch exec --"), f"{label} must use rch: {command}")


def validate_unit_primary(manifest: dict[str, Any], paths: dict[str, Path]) -> list[str]:
    unit = manifest.get("unit_primary")
    if not isinstance(unit, dict):
        error("unit_primary must be an object")
        return []
    refs = unit.get("required_test_refs")
    if not isinstance(refs, list):
        error("unit_primary.required_test_refs must be an array")
        refs = []
    actual: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            error(f"unit_primary.required_test_refs[{index}] must be an object")
            continue
        artifact = ref.get("artifact")
        name = ref.get("name")
        if not isinstance(artifact, str) or not isinstance(name, str):
            error(f"unit_primary.required_test_refs[{index}] must contain artifact and name")
            continue
        actual.add((artifact, name))
        if artifact not in paths:
            error(f"unit ref references unknown artifact: {artifact}")
            continue
        text = read_text(paths[artifact], artifact)
        require(f"fn {name}" in text, f"{artifact} missing Rust test ref: {name}")
    require(actual == UNIT_REFS, f"unit refs mismatch: {sorted(actual)}")
    validate_rch_commands(unit.get("required_commands"), "unit_primary.required_commands")
    append_event(
        "stdio_phase1_completion.unit_bindings",
        "fail" if errors else "pass",
        {"unit_ref_count": len(actual), "unit_refs": sorted(name for _, name in actual)},
    )
    return [name for _, name in sorted(actual)]


def validate_support_matrix(path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    support = load_json(path, "support_matrix")
    rows = support.get("symbols") if isinstance(support, dict) else []
    if not isinstance(rows, list):
        error("support_matrix.symbols must be an array")
        rows = []
    by_symbol = {
        row.get("symbol"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("symbol"), str)
    }
    expected_status = contract.get("expected_status")
    expected_module = contract.get("expected_module")
    found: dict[str, Any] = {}
    for symbol in sorted(TARGET_SYMBOLS):
        row = by_symbol.get(symbol)
        if not isinstance(row, dict):
            error(f"support_matrix missing symbol: {symbol}")
            continue
        require(row.get("status") == expected_status, f"support_matrix {symbol} status drift")
        require(row.get("module") == expected_module, f"support_matrix {symbol} module drift")
        found[symbol] = {"status": row.get("status"), "module": row.get("module")}
    return found


def validate_fixture_spec(path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    spec = load_json(path, "c_fixture_spec")
    fixtures = spec.get("fixtures") if isinstance(spec, dict) else []
    if not isinstance(fixtures, list):
        error("c_fixture_spec.fixtures must be an array")
        fixtures = []
    expected_id = contract.get("expected_fixture_id")
    fixture = next((item for item in fixtures if isinstance(item, dict) and item.get("id") == expected_id), None)
    if not isinstance(fixture, dict):
        error(f"c_fixture_spec missing fixture id: {expected_id}")
        return {}
    require(fixture.get("source") == contract.get("expected_source"), "fixture_stdio source drift")
    covered = set(strings(fixture.get("covered_symbols"), "fixture_stdio.covered_symbols"))
    require(TARGET_SYMBOLS.issubset(covered), "fixture_stdio covered_symbols missing target symbols")
    modes = fixture.get("mode_expectations")
    if not isinstance(modes, dict):
        error("fixture_stdio mode_expectations must be an object")
        modes = {}
    for mode in ("strict", "hardened"):
        mode_contract = modes.get(mode)
        if not isinstance(mode_contract, dict):
            error(f"fixture_stdio missing mode: {mode}")
            continue
        require(mode_contract.get("expected_exit") == 0, f"fixture_stdio {mode} expected_exit drift")
        require(
            mode_contract.get("expected_stdout_contains") == contract.get("expected_stdout_contains"),
            f"fixture_stdio {mode} stdout expectation drift",
        )
    return {"fixture_id": fixture.get("id"), "covered_symbols": sorted(covered), "modes": sorted(modes)}


def validate_source_markers(manifest: dict[str, Any], paths: dict[str, Path]) -> None:
    source_contract = manifest.get("required_source_contract")
    if not isinstance(source_contract, dict):
        error("required_source_contract must be an object")
        return
    markers = source_contract.get("source_markers")
    if not isinstance(markers, dict):
        error("required_source_contract.source_markers must be an object")
        return
    for artifact, values in markers.items():
        if artifact not in paths:
            error(f"source_markers references unknown artifact: {artifact}")
            continue
        text = read_text(paths[artifact], artifact)
        for marker in strings(values, f"source_markers.{artifact}"):
            require(marker in text, f"{artifact} missing source marker: {marker}")


def validate_e2e_primary(manifest: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    e2e = manifest.get("e2e_primary")
    if not isinstance(e2e, dict):
        error("e2e_primary must be an object")
        return {}
    require(e2e.get("fixture_id") == "fixture_stdio", "e2e fixture_id drift")
    require(set(strings(e2e.get("required_modes"), "e2e_primary.required_modes")) == {"strict", "hardened"}, "e2e required modes drift")
    artifacts = set(strings(e2e.get("required_artifacts"), "e2e_primary.required_artifacts"))
    require(artifacts == E2E_ARTIFACTS, f"e2e artifact refs mismatch: {sorted(artifacts)}")
    for artifact in artifacts:
        require(artifact in paths, f"e2e artifact missing in source_artifacts: {artifact}")
    validate_rch_commands(e2e.get("required_commands"), "e2e_primary.required_commands")
    source_contract = manifest.get("required_source_contract", {})
    fixture_summary = {}
    if isinstance(source_contract, dict):
        fixture_spec = source_contract.get("c_fixture_spec", {})
        if isinstance(fixture_spec, dict) and "c_fixture_spec" in paths:
            fixture_summary = validate_fixture_spec(paths["c_fixture_spec"], fixture_spec)
    append_event(
        "stdio_phase1_completion.e2e_binding",
        "fail" if errors else "pass",
        {"fixture_id": e2e.get("fixture_id"), "artifacts": sorted(artifacts), "fixture_summary": fixture_summary},
    )
    return {"fixture": fixture_summary, "artifacts": sorted(artifacts)}


def validate_telemetry_primary(manifest: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        error("telemetry_primary must be an object")
        return {}
    completion_events = set(strings(telemetry.get("required_completion_events"), "telemetry_primary.required_completion_events"))
    fixture_events = set(strings(telemetry.get("required_fixture_events"), "telemetry_primary.required_fixture_events"))
    log_fields = set(strings(telemetry.get("required_log_fields"), "telemetry_primary.required_log_fields"))
    report_fields = set(strings(telemetry.get("required_report_fields"), "telemetry_primary.required_report_fields"))
    require(completion_events == COMPLETION_EVENTS, "completion events drift")
    require(fixture_events == FIXTURE_EVENTS, "fixture events drift")
    require(log_fields == LOG_FIELDS, "required log fields drift")
    require(report_fields == REPORT_FIELDS, "required report fields drift")
    if "e2e_runner" in paths:
        runner = read_text(paths["e2e_runner"], "e2e_runner")
        for event in fixture_events:
            require(event in runner, f"e2e runner missing fixture event marker: {event}")
        for field in log_fields:
            require(field in runner, f"e2e runner missing telemetry field: {field}")
    append_event(
        "stdio_phase1_completion.telemetry_contract",
        "fail" if errors else "pass",
        {
            "completion_events": sorted(completion_events),
            "fixture_events": sorted(fixture_events),
            "log_fields": sorted(log_fields),
        },
    )
    return {
        "completion_events": sorted(completion_events),
        "fixture_events": sorted(fixture_events),
        "log_fields": sorted(log_fields),
        "report_fields": sorted(report_fields),
    }


manifest_raw = load_json(CONTRACT, "contract")
manifest = manifest_raw if isinstance(manifest_raw, dict) else {}
validate_top_level(manifest)
paths = validate_source_artifacts(manifest)
unit_refs = validate_unit_primary(manifest, paths) if paths else []
e2e_summary = validate_e2e_primary(manifest, paths) if paths else {}
source_contract = manifest.get("required_source_contract", {})
support_summary = {}
if isinstance(source_contract, dict) and "support_matrix" in paths:
    support_contract = source_contract.get("support_matrix", {})
    if isinstance(support_contract, dict):
        support_summary = validate_support_matrix(paths["support_matrix"], support_contract)
validate_source_markers(manifest, paths)
telemetry_summary = validate_telemetry_primary(manifest, paths) if paths else {}

status = "fail" if errors else "pass"
append_event(
    "stdio_phase1_completion.completion_contract_validated",
    status,
    {
        "unit_ref_count": len(unit_refs),
        "target_symbol_count": len(TARGET_SYMBOLS),
        "error_count": len(errors),
    },
)

missing_items = sorted(MISSING_ITEMS)
report = {
    "schema_version": "stdio_phase1_completion_contract.report.v1",
    "status": status,
    "bead": COMPLETION_BEAD,
    "source_bead": BEAD,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(CONTRACT),
    "missing_items_closed": missing_items,
    "target_symbols": sorted(TARGET_SYMBOLS),
    "unit_bindings": unit_refs,
    "e2e_bindings": e2e_summary,
    "telemetry_events": telemetry_summary,
    "source_summary": {
        "source_count": len(paths),
        "support_matrix": support_summary,
    },
    "events": events,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print("FAIL stdio phase1 completion contract: " + "; ".join(errors[:8]), file=sys.stderr)
    sys.exit(1)

print(
    "PASS stdio phase1 completion contract "
    f"symbols={len(TARGET_SYMBOLS)} unit={len(unit_refs)} "
    f"events={len(events)}"
)
PY
