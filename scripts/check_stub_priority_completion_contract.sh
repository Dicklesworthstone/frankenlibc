#!/usr/bin/env bash
# Validate bd-4ia.1 stub priority completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/stub_priority_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/stub_priority_completion_contract}"
REPORT="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_REPORT:-${OUT_DIR}/report.json}"
LOG="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_LOG:-${OUT_DIR}/events.jsonl}"
GATE_STDOUT="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_GATE_STDOUT:-${OUT_DIR}/gate_stdout.txt}"
GATE_STDERR="${FRANKENLIBC_STUB_PRIORITY_COMPLETION_GATE_STDERR:-${OUT_DIR}/gate_stderr.txt}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "$(dirname "${GATE_STDOUT}")" "$(dirname "${GATE_STDERR}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${GATE_STDOUT}" "${GATE_STDERR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(sys.argv[1]).resolve()
CONTRACT = Path(sys.argv[2]).resolve()
REPORT = Path(sys.argv[3]).resolve()
LOG = Path(sys.argv[4]).resolve()
GATE_STDOUT = Path(sys.argv[5]).resolve()
GATE_STDERR = Path(sys.argv[6]).resolve()
SOURCE_COMMIT = sys.argv[7]
START_NS = time.time_ns()

SCHEMA = "stub_priority_completion_contract.v1"
REPORT_SCHEMA = "stub_priority_completion_contract.report.v1"
BEAD_ID = "bd-4ia.1"
ORIGINAL_BEAD = "bd-4ia"
TRACE_ID = "bd-4ia.1::stub-priority::v1"
MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
SOURCE_IDS = {
    "stub_priority_ranking",
    "stub_priority_generator",
    "stub_priority_gate",
    "stub_priority_harness",
    "support_matrix",
    "workload_matrix",
    "verification_matrix",
    "ld_preload_smoke_summary",
    "ld_preload_smoke_e2e_index",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
UNIT_TESTS = {
    "ranking_exists_and_valid",
    "ranked_symbols_match_support_matrix",
    "scores_match_formula",
    "tier_assignments_consistent",
    "burn_down_consistent",
    "summary_consistent",
    "gate_script_exists_and_executable",
    "gate_script_passes",
}
COMPLETION_EVENTS = {
    "stub_priority_completion.source_artifacts",
    "stub_priority_completion.unit_bindings",
    "stub_priority_completion.e2e_gate_replayed",
    "stub_priority_completion.telemetry_contract",
    "stub_priority_completion.completion_contract_validated",
    "stub_priority_completion.completion_contract_failed",
}
REPORT_FIELDS = {
    "schema_version",
    "bead_id",
    "original_bead",
    "trace_id",
    "source_commit",
    "status",
    "failure_signature",
    "missing_items_closed",
    "source_count",
    "unit_test_count",
    "gate_stdout",
    "ranking_summary",
    "artifact_refs",
    "errors",
}
LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "bead_id",
    "original_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "outcome",
    "errno",
    "latency_ns",
    "artifact_refs",
    "failure_signature",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_e2e_binding",
    "base_gate_failed",
    "missing_telemetry_binding",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
artifact_refs: set[str] = set()


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "stub_priority_completion_contract_failed"


def read_text(path: Path, context: str, signature: str = "missing_source_artifact") -> str:
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"{context}: cannot read {rel(path)}: {exc}")
        return ""


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def strings(value: Any, context: str, signature: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        add_error(signature, f"{context} must be a non-empty string array")
        return []
    return list(value)


def string_set(value: Any, context: str, signature: str) -> set[str]:
    return set(strings(value, context, signature))


def append_event(event: str, status: str, details: dict[str, Any] | None = None) -> None:
    failure_signature = "none" if status == "pass" else primary_signature()
    events.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{TRACE_ID}::{event}",
            "level": "info" if status == "pass" else "error",
            "bead_id": BEAD_ID,
            "original_bead": ORIGINAL_BEAD,
            "stream": "conformance",
            "gate": "stub_priority_completion_contract",
            "scenario_id": event,
            "event": event,
            "status": status,
            "mode": "strict",
            "runtime_mode": "strict",
            "replacement_level": "L0",
            "api_family": "stub_priority",
            "symbol": "stub_priority_ranking",
            "oracle_kind": "completion_contract",
            "expected": {"status": "pass"},
            "actual": {"status": status},
            "decision_path": "completion_contract>stub_priority_gate",
            "healing_action": "None",
            "outcome": "pass" if status == "pass" else "fail",
            "errno": 0 if status == "pass" else 22,
            "latency_ns": time.time_ns() - START_NS,
            "source_commit": SOURCE_COMMIT,
            "target_dir": "target/conformance",
            "failure_signature": failure_signature,
            "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG), rel(GATE_STDOUT)}),
            "details": details or {},
        }
    )


def require_commands_use_rch(commands: Any, context: str, signature: str) -> None:
    for command in strings(commands, context, signature):
        if "cargo " in command and not command.startswith("rch exec --"):
            add_error(signature, f"{context} must use rch for cargo command: {command}")


def validate_top_level(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", f"schema_version must be {SCHEMA}")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
    if contract.get("trace_id") != TRACE_ID:
        add_error("malformed_contract", f"trace_id must be {TRACE_ID}")
    completion = contract.get("completion_debt_evidence")
    if not isinstance(completion, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        return
    missing = string_set(
        completion.get("missing_items_closed"),
        "completion_debt_evidence.missing_items_closed",
        "malformed_contract",
    )
    if missing != MISSING_ITEMS:
        add_error("malformed_contract", f"missing_items_closed drifted: {sorted(missing)}")
    threshold = completion.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 700:
        add_error("malformed_contract", "next_audit_score_threshold must be at least 700")


def validate_sources(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = contract.get("source_artifacts")
    if not isinstance(rows, list):
        add_error("malformed_contract", "source_artifacts must be an array")
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = row.get("id")
        path_text = row.get("path")
        if not isinstance(artifact_id, str) or not isinstance(path_text, str):
            add_error("malformed_contract", f"source_artifacts[{index}] must have id/path")
            continue
        by_id[artifact_id] = row
        text = read_text(resolve(path_text), f"source_artifacts.{artifact_id}")
        for needle in strings(row.get("required_needles"), f"source_artifacts.{artifact_id}.required_needles", "malformed_contract"):
            if needle not in text:
                add_error("missing_source_artifact", f"{path_text} missing required needle: {needle}")
    ids = set(by_id)
    if ids != SOURCE_IDS:
        add_error("malformed_contract", f"source artifact ids drifted: {sorted(ids)}")
    append_event(
        "stub_priority_completion.source_artifacts",
        "pass" if not any(error["failure_signature"] in {"malformed_contract", "missing_source_artifact"} for error in errors) else "fail",
        {"source_count": len(ids), "source_ids": sorted(ids)},
    )
    return by_id


def source_path(sources: dict[str, dict[str, Any]], source_id: str) -> Path:
    path_text = sources.get(source_id, {}).get("path")
    return resolve(path_text) if isinstance(path_text, str) else ROOT / "__missing__"


def validate_ranking_summary(
    ranking: dict[str, Any],
    support_matrix: dict[str, Any],
    expected_summary: dict[str, Any],
) -> dict[str, int]:
    if ranking.get("bead") != ORIGINAL_BEAD:
        add_error("missing_unit_binding", "ranking bead must be bd-4ia")
    symbols = support_matrix.get("symbols")
    if not isinstance(symbols, list):
        add_error("missing_unit_binding", "support_matrix symbols must be an array")
        symbols = []
    stubs = [row for row in symbols if isinstance(row, dict) and row.get("status") == "Stub"]
    callthroughs = [
        row for row in symbols if isinstance(row, dict) and row.get("status") == "GlibcCallThrough"
    ]
    expected_total = len(stubs) + len(callthroughs)
    tiers = ranking.get("symbol_ranking", {}).get("tiers", [])
    if not isinstance(tiers, list):
        add_error("missing_unit_binding", "ranking tiers must be an array")
        tiers = []
    ranked_symbols: list[str] = []
    for tier in tiers:
        if not isinstance(tier, dict):
            add_error("missing_unit_binding", "ranking tier must be an object")
            continue
        tier_symbols = tier.get("symbols")
        if not isinstance(tier_symbols, list):
            add_error("missing_unit_binding", "ranking tier symbols must be an array")
            continue
        if tier.get("count") != len(tier_symbols):
            add_error("missing_unit_binding", f"ranking tier {tier.get('tier')} count mismatch")
        ranked_symbols.extend(str(row.get("symbol", "")) for row in tier_symbols if isinstance(row, dict))
    if len(set(ranked_symbols)) != len(ranked_symbols):
        add_error("missing_unit_binding", "ranking contains duplicate symbols")
    ranked_set = set(ranked_symbols)
    support_set = {str(row.get("symbol", "")) for row in stubs + callthroughs if isinstance(row, dict)}
    if ranked_set != support_set:
        add_error("missing_unit_binding", "ranked symbols do not match support_matrix Stub/GlibcCallThrough rows")
    summary = ranking.get("summary", {})
    burn = ranking.get("burn_down", {})
    if not isinstance(summary, dict) or not isinstance(burn, dict):
        add_error("missing_unit_binding", "ranking summary and burn_down must be objects")
        summary = {}
        burn = {}
    actual = {
        "total_non_implemented": int(summary.get("total_non_implemented", -1)),
        "stubs": int(summary.get("stubs", -1)),
        "callthroughs": int(summary.get("callthroughs", -1)),
        "modules_affected": int(summary.get("modules_affected", -1)),
        "symbols_unscheduled": int(burn.get("symbols_unscheduled", -1)),
    }
    derived = {
        "total_non_implemented": expected_total,
        "stubs": len(stubs),
        "callthroughs": len(callthroughs),
    }
    for key, value in derived.items():
        if actual[key] != value:
            add_error("missing_unit_binding", f"ranking {key}={actual[key]} does not match derived {value}")
    for key, value in expected_summary.items():
        if actual.get(key) != value:
            add_error("missing_unit_binding", f"required_summary {key}={value} but ranking has {actual.get(key)}")
    return actual


def validate_unit(contract: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, int]:
    before = len(errors)
    section = contract.get("unit_primary")
    if not isinstance(section, dict):
        add_error("missing_unit_binding", "unit_primary must be an object")
        section = {}
    if section.get("missing_item_id") != "tests.unit.primary":
        add_error("missing_unit_binding", "unit_primary missing_item_id drifted")
    tests = string_set(section.get("required_harness_tests"), "unit_primary.required_harness_tests", "missing_unit_binding")
    if tests != UNIT_TESTS:
        add_error("missing_unit_binding", f"required_harness_tests drifted: {sorted(tests)}")
    require_commands_use_rch(section.get("required_commands"), "unit_primary.required_commands", "missing_unit_binding")
    harness_text = read_text(source_path(sources, "stub_priority_harness"), "stub priority harness")
    for name in sorted(UNIT_TESTS):
        if f"fn {name}(" not in harness_text:
            add_error("missing_unit_binding", f"stub_priority_test missing fn {name}(")
    ranking = load_json(source_path(sources, "stub_priority_ranking"), "stub priority ranking", "missing_unit_binding")
    support = load_json(source_path(sources, "support_matrix"), "support matrix", "missing_unit_binding")
    expected_summary = section.get("required_summary")
    if not isinstance(expected_summary, dict):
        add_error("missing_unit_binding", "unit_primary.required_summary must be an object")
        expected_summary = {}
    summary = validate_ranking_summary(ranking if isinstance(ranking, dict) else {}, support if isinstance(support, dict) else {}, expected_summary)
    append_event(
        "stub_priority_completion.unit_bindings",
        "pass" if len(errors) == before else "fail",
        {"unit_test_count": len(tests), "ranking_summary": summary},
    )
    return summary


def validate_e2e(contract: dict[str, Any]) -> None:
    before = len(errors)
    section = contract.get("e2e_primary")
    if not isinstance(section, dict):
        add_error("missing_e2e_binding", "e2e_primary must be an object")
        section = {}
    if section.get("missing_item_id") != "tests.e2e.primary":
        add_error("missing_e2e_binding", "e2e_primary missing_item_id drifted")
    gate_text = section.get("gate_script")
    if not isinstance(gate_text, str):
        add_error("missing_e2e_binding", "e2e_primary.gate_script must be a path")
        gate_path = ROOT / "__missing__"
    else:
        gate_path = resolve(gate_text)
    require_commands_use_rch(section.get("required_commands"), "e2e_primary.required_commands", "missing_e2e_binding")
    result = subprocess.run(["bash", str(gate_path)], cwd=ROOT, capture_output=True, text=True)
    GATE_STDOUT.write_text(result.stdout, encoding="utf-8")
    GATE_STDERR.write_text(result.stderr, encoding="utf-8")
    artifact_refs.update({rel(GATE_STDOUT), rel(GATE_STDERR)})
    if result.returncode != 0:
        add_error("base_gate_failed", f"stub priority gate failed with exit {result.returncode}")
    for needle in strings(section.get("required_gate_stdout"), "e2e_primary.required_gate_stdout", "missing_e2e_binding"):
        if needle not in result.stdout:
            add_error("missing_e2e_binding", f"gate stdout missing required marker: {needle}")
    append_event(
        "stub_priority_completion.e2e_gate_replayed",
        "pass" if len(errors) == before else "fail",
        {"exit_code": result.returncode, "gate_stdout": rel(GATE_STDOUT), "gate_stderr": rel(GATE_STDERR)},
    )


def validate_telemetry(contract: dict[str, Any]) -> None:
    before = len(errors)
    section = contract.get("telemetry_primary")
    if not isinstance(section, dict):
        add_error("missing_telemetry_binding", "telemetry_primary must be an object")
        section = {}
    if section.get("missing_item_id") != "telemetry.primary":
        add_error("missing_telemetry_binding", "telemetry_primary missing_item_id drifted")
    events_required = string_set(section.get("required_completion_events"), "telemetry_primary.required_completion_events", "missing_telemetry_binding")
    if events_required != COMPLETION_EVENTS:
        add_error("missing_telemetry_binding", f"required_completion_events drifted: {sorted(events_required)}")
    report_fields = string_set(section.get("required_report_fields"), "telemetry_primary.required_report_fields", "missing_telemetry_binding")
    if not REPORT_FIELDS <= report_fields:
        add_error("missing_telemetry_binding", f"required_report_fields missing {sorted(REPORT_FIELDS - report_fields)}")
    log_fields = string_set(section.get("required_log_fields"), "telemetry_primary.required_log_fields", "missing_telemetry_binding")
    if not LOG_FIELDS <= log_fields:
        add_error("missing_telemetry_binding", f"required_log_fields missing {sorted(LOG_FIELDS - log_fields)}")
    append_event(
        "stub_priority_completion.telemetry_contract",
        "pass" if len(errors) == before else "fail",
        {"telemetry_event_count": len(events_required), "log_field_count": len(log_fields)},
    )


def write_outputs(contract: dict[str, Any], ranking_summary: dict[str, int]) -> None:
    ok = not errors
    status = "pass" if ok else "fail"
    append_event(
        "stub_priority_completion.completion_contract_validated" if ok else "stub_priority_completion.completion_contract_failed",
        status,
        {"error_count": len(errors), "ranking_summary": ranking_summary},
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "failure_signature": "none" if ok else primary_signature(),
        "missing_items_closed": sorted(MISSING_ITEMS),
        "source_count": len(contract.get("source_artifacts", [])) if isinstance(contract.get("source_artifacts"), list) else 0,
        "unit_test_count": len(UNIT_TESTS),
        "gate_stdout": rel(GATE_STDOUT),
        "ranking_summary": ranking_summary,
        "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG), rel(GATE_STDOUT)}),
        "errors": errors,
    }
    missing_report_fields = REPORT_FIELDS - set(report)
    if missing_report_fields:
        report["errors"].append(
            {
                "failure_signature": "missing_telemetry_binding",
                "message": f"report missing fields: {sorted(missing_report_fields)}",
            }
        )
        report["status"] = "fail"
        report["failure_signature"] = "missing_telemetry_binding"
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if report["status"] == "pass":
        print(
            f"PASS stub priority completion contract sources={report['source_count']} "
            f"unit_refs={report['unit_test_count']} events={len(events)}"
        )
    else:
        print(f"FAIL stub priority completion contract errors={len(report['errors'])}", file=sys.stderr)
        for error in report["errors"]:
            print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
        raise SystemExit(1)


def main() -> None:
    contract = load_json(CONTRACT, "completion contract")
    if not isinstance(contract, dict):
        add_error("malformed_contract", "completion contract must be a JSON object")
        contract = {}
    validate_top_level(contract)
    sources = validate_sources(contract)
    ranking_summary = validate_unit(contract, sources)
    validate_e2e(contract)
    validate_telemetry(contract)
    write_outputs(contract, ranking_summary)


main()
PY
