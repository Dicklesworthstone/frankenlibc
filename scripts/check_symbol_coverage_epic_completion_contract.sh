#!/usr/bin/env bash
# Validate bd-ldj.9 symbol coverage epic completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/symbol_coverage_epic_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/symbol_coverage_epic_completion}"
REPORT="${FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_REPORT:-${OUT_DIR}/symbol_coverage_epic_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_COVERAGE_EPIC_COMPLETION_LOG:-${OUT_DIR}/symbol_coverage_epic_completion_contract.events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

SCHEMA = "symbol_coverage_epic_completion_contract.v1"
REPORT_SCHEMA = "symbol_coverage_epic_completion_contract.report.v1"
LOG_SCHEMA = "symbol_coverage_epic_completion_contract.event.v1"
ORIGINAL_BEAD = "bd-ldj"
COMPLETION_BEAD = "bd-ldj.9"
TRACE_ID = "bd-ldj-9-symbol-coverage-epic-completion-v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "symbol_universe",
    "support_matrix_maintenance_report",
    "conformance_matrix",
    "symbol_fixture_coverage",
    "symbol_universe_checker",
    "support_matrix_checker",
    "conformance_matrix_checker",
    "symbol_fixture_coverage_checker",
    "completion_checker",
    "completion_harness",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def string_array(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": LOG_SCHEMA,
            "timestamp": utc_now(),
            "trace_id": f"{TRACE_ID}:{event}",
            "event": event,
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        error(f"{label} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        error(f"{label} must be file:line")
        return
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} references missing file: {value}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        error(f"{label} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        error(f"{label} references blank line: {value}")


def validate_contract_shape(contract: dict[str, Any]) -> None:
    require(contract.get("schema_version") == SCHEMA, "schema_version drifted")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead drifted")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drifted")
    require(contract.get("trace_id") == TRACE_ID, "trace_id drifted")

    audit = contract.get("audit_reference")
    require(isinstance(audit, dict), "audit_reference must be an object")
    if isinstance(audit, dict):
        require(audit.get("score_before") == 685, "audit_reference.score_before drifted")
        require(
            isinstance(audit.get("score_threshold"), int) and audit.get("score_threshold") >= 800,
            "audit_reference.score_threshold must be at least 800",
        )

    evidence = contract.get("completion_debt_evidence")
    require(isinstance(evidence, dict), "completion_debt_evidence must be an object")
    if isinstance(evidence, dict):
        missing_items = set(
            string_array(
                evidence.get("missing_items_closed"),
                "completion_debt_evidence.missing_items_closed",
            )
        )
        require(
            missing_items == EXPECTED_MISSING_ITEMS,
            f"missing_items_closed drifted: {sorted(missing_items)}",
        )
        for key in ("unit_binding", "e2e_binding", "conformance_binding", "telemetry_binding"):
            string_array(evidence.get(key), f"completion_debt_evidence.{key}")

    for index, value in enumerate(contract.get("implementation_refs", [])):
        validate_file_line_ref(value, f"implementation_refs[{index}]")


def validate_source_artifacts(contract: dict[str, Any]) -> None:
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        error("source_artifacts must be an array")
        return
    ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        ids.add(source_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source_artifacts[{source_id}].path must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            error(f"source_artifacts[{source_id}] missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in string_array(
            source.get("required_needles"),
            f"source_artifacts[{source_id}].required_needles",
        ):
            if needle not in text:
                error(f"source_artifacts[{source_id}] missing required needle: {needle}")
    require(ids == REQUIRED_SOURCE_IDS, f"source artifact ids drifted: {sorted(ids)}")
    append_event(
        "symbol_coverage_epic.source_artifacts_validated",
        "pass" if ids == REQUIRED_SOURCE_IDS else "fail",
        {"source_count": len(ids)},
    )


def validate_symbol_universe(contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract["artifact_invariants"]["symbol_universe"]
    doc = load_json(ROOT / spec["path"], "symbol_universe")
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    require(summary.get("total_symbols", 0) >= spec["min_total_symbols"], "symbol_universe total_symbols below contract")
    require(summary.get("unique_symbols") == spec["required_unique_symbols"], "symbol_universe unique_symbols drifted")
    require(summary.get("duplicates") == spec["expected_duplicates"], "symbol_universe duplicates drifted")
    require(
        summary.get("unknown_action_count") == spec["expected_unknown_action_count"],
        "symbol_universe unknown_action_count drifted",
    )
    classifications = summary.get("classifications", {})
    for key, expected in spec["required_classifications"].items():
        require(classifications.get(key) == expected, f"symbol_universe classification {key} drifted")
    confidence = summary.get("confidence_levels", {})
    for key, expected in spec["required_confidence_levels"].items():
        require(confidence.get(key) == expected, f"symbol_universe confidence {key} drifted")
    normalized = doc.get("normalized_symbols", [])
    require(isinstance(normalized, list) and len(normalized) == summary.get("total_symbols"), "normalized symbol count mismatch")
    append_event(
        "symbol_coverage_epic.symbol_universe_validated",
        "pass",
        {
            "total_symbols": summary.get("total_symbols"),
            "classifications": classifications,
            "unknown_action_count": summary.get("unknown_action_count"),
        },
    )
    return summary


def validate_support_matrix(contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract["artifact_invariants"]["support_matrix_maintenance"]
    doc = load_json(ROOT / spec["path"], "support_matrix_maintenance")
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    checks = {
        "total_symbols": "expected_total_symbols",
        "status_validated": "expected_status_validated",
        "status_invalid": "expected_status_invalid",
        "status_skipped": "expected_status_skipped",
        "status_valid_pct": "expected_status_valid_pct",
    }
    for field, expected_key in checks.items():
        require(summary.get(field) == spec[expected_key], f"support matrix {field} drifted")
    require(summary.get("fixture_linked", 0) >= spec["min_fixture_linked"], "support matrix fixture_linked below contract")
    append_event(
        "symbol_coverage_epic.support_matrix_validated",
        "pass",
        {
            "status_validated": summary.get("status_validated"),
            "status_invalid": summary.get("status_invalid"),
            "fixture_linked": summary.get("fixture_linked"),
        },
    )
    return summary


def validate_conformance_matrix(contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract["artifact_invariants"]["conformance_matrix"]
    doc = load_json(ROOT / spec["path"], "conformance_matrix")
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    require(summary.get("total_cases", 0) >= spec["min_total_cases"], "conformance matrix total_cases below contract")
    require(summary.get("failed") == spec["expected_failed"], "conformance matrix failed count drifted")
    require(summary.get("errors") == spec["expected_errors"], "conformance matrix error count drifted")
    require(
        summary.get("pass_rate_percent") == spec["expected_pass_rate_percent"],
        "conformance matrix pass_rate_percent drifted",
    )
    cases = doc.get("cases", [])
    require(isinstance(cases, list) and len(cases) == summary.get("total_cases"), "conformance case count mismatch")
    append_event(
        "symbol_coverage_epic.conformance_matrix_validated",
        "pass",
        {
            "total_cases": summary.get("total_cases"),
            "failed": summary.get("failed"),
            "errors": summary.get("errors"),
        },
    )
    return summary


def validate_fixture_coverage(contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract["artifact_invariants"]["symbol_fixture_coverage"]
    doc = load_json(ROOT / spec["path"], "symbol_fixture_coverage")
    summary = doc.get("summary", {}) if isinstance(doc, dict) else {}
    require(
        summary.get("target_total_symbols") == spec["expected_target_total_symbols"],
        "symbol fixture coverage target_total_symbols drifted",
    )
    require(
        summary.get("covered_exported_symbols", 0) >= spec["min_covered_exported_symbols"],
        "symbol fixture coverage covered_exported_symbols below contract",
    )
    require(
        summary.get("coverage_pct", 0.0) >= spec["min_coverage_pct"],
        "symbol fixture coverage coverage_pct below contract",
    )
    require(
        set(summary.get("target_statuses", [])) == set(spec["required_target_statuses"]),
        "symbol fixture coverage target_statuses drifted",
    )
    append_event(
        "symbol_coverage_epic.fixture_coverage_validated",
        "pass",
        {
            "covered_exported_symbols": summary.get("covered_exported_symbols"),
            "target_total_symbols": summary.get("target_total_symbols"),
            "coverage_pct": summary.get("coverage_pct"),
        },
    )
    return summary


def validate_telemetry_contract(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        error("telemetry_contract must be an object")
        return
    required_events = set(string_array(telemetry.get("required_events"), "telemetry_contract.required_events"))
    emitted = {row["event"] for row in events}
    missing = sorted(required_events - emitted - {"symbol_coverage_epic.telemetry_validated", "symbol_coverage_epic.completion_contract_validated"})
    require(not missing, f"telemetry preflight events missing: {missing}")
    required_fields = string_array(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
    for event_row in events:
        for field in required_fields:
            require(field in event_row, f"event {event_row['event']} missing required log field {field}")
    append_event(
        "symbol_coverage_epic.telemetry_validated",
        "pass",
        {"validated_event_count": len(events), "required_event_count": len(required_events)},
    )


def write_outputs(status: str, summaries: dict[str, Any]) -> None:
    if status == "pass":
        append_event("symbol_coverage_epic.completion_contract_validated", "pass", summaries)
    else:
        append_event(
            "symbol_coverage_epic.completion_contract_failed",
            "fail",
            {"error_count": len(errors), "errors": errors},
        )

    report = {
        "schema_version": REPORT_SCHEMA,
        "generated_utc": utc_now(),
        "status": status,
        "failure_signature": "none" if status == "pass" else "symbol_coverage_epic_completion_contract_failed",
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "error_count": len(errors),
        "errors": errors,
        "summaries": summaries,
        "event_count": len(events),
        "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
        encoding="utf-8",
    )


contract = load_json(CONTRACT, "completion contract")
summaries: dict[str, Any] = {}
if isinstance(contract, dict):
    validate_contract_shape(contract)
    validate_source_artifacts(contract)
    invariants = contract.get("artifact_invariants")
    if isinstance(invariants, dict):
        summaries["symbol_universe"] = validate_symbol_universe(contract)
        summaries["support_matrix_maintenance"] = validate_support_matrix(contract)
        summaries["conformance_matrix"] = validate_conformance_matrix(contract)
        summaries["symbol_fixture_coverage"] = validate_fixture_coverage(contract)
    else:
        error("artifact_invariants must be an object")
    validate_telemetry_contract(contract)

status = "pass" if not errors else "fail"
write_outputs(status, summaries)

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS symbol coverage epic completion contract "
    f"symbols={summaries['symbol_universe']['total_symbols']} "
    f"cases={summaries['conformance_matrix']['total_cases']} "
    f"fixture_symbols={summaries['symbol_fixture_coverage']['covered_exported_symbols']}"
)
PY
