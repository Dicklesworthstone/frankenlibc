#!/usr/bin/env bash
# Validate bd-3tp.1 math value proof completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/math_value_proof_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/math_value_proof_completion_contract}"
REPORT="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_REPORT:-${OUT_DIR}/report.json}"
LOG="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_LOG:-${OUT_DIR}/events.jsonl}"
GATE_STDOUT="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_GATE_STDOUT:-${OUT_DIR}/gate_stdout.txt}"
GATE_STDERR="${FRANKENLIBC_MATH_VALUE_PROOF_COMPLETION_GATE_STDERR:-${OUT_DIR}/gate_stderr.txt}"
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

SCHEMA = "math_value_proof_completion_contract.v1"
REPORT_SCHEMA = "math_value_proof_completion_contract.report.v1"
BEAD_ID = "bd-3tp.1"
ORIGINAL_BEAD = "bd-3tp"
TRACE_ID = "bd-3tp.1::math-value-proof::v1"
MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
SOURCE_IDS = {
    "math_value_proof",
    "math_governance",
    "math_retirement_policy",
    "value_gate",
    "value_harness",
    "verification_matrix",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
UNIT_TESTS = {
    "spec_exists_and_valid",
    "core_modules_match_governance",
    "monitor_modules_match_governance",
    "retained_modules_meet_threshold",
    "score_formula_consistent",
    "assessments_have_required_fields",
    "summary_consistent",
    "gate_script_exists_and_executable",
}
EXPECTED_SUMMARY = {
    "total_modules_assessed": 25,
    "core_assessments": 12,
    "monitor_assessments": 13,
    "all_retained": True,
    "min_score": 3.0,
    "retention_threshold": 2.0,
    "research_modules_excluded": 44,
}
COMPLETION_EVENTS = {
    "math_value_proof_completion.source_artifacts",
    "math_value_proof_completion.unit_bindings",
    "math_value_proof_completion.e2e_gate_replayed",
    "math_value_proof_completion.telemetry_contract",
    "math_value_proof_completion.completion_contract_validated",
    "math_value_proof_completion.completion_contract_failed",
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
    "policy_summary",
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
    return "math_value_proof_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def read_text(path: Path, context: str, signature: str = "missing_source_artifact") -> str:
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error(signature, f"{context}: cannot read {rel(path)}: {exc}")
        return ""


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
            "bead_id": BEAD_ID,
            "original_bead": ORIGINAL_BEAD,
            "event": event,
            "status": status,
            "mode": "strict+hardened",
            "api_family": "runtime_math",
            "symbol": "math_value_proof",
            "decision_path": "completion_contract>math_value_proof_gate",
            "outcome": status,
            "errno": 0 if status == "pass" else 22,
            "latency_ns": time.time_ns() - START_NS,
            "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG), rel(GATE_STDOUT)}),
            "failure_signature": failure_signature,
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
    if not isinstance(threshold, int) or threshold < 800:
        add_error("malformed_contract", "next_audit_score_threshold must be at least 800")


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
        source_id = row.get("id")
        path_text = row.get("path")
        if not isinstance(source_id, str) or not source_id:
            add_error("malformed_contract", f"source_artifacts[{index}].id must be non-empty")
            continue
        if not isinstance(path_text, str) or not path_text:
            add_error("malformed_contract", f"source_artifacts.{source_id}.path must be non-empty")
            continue
        by_id[source_id] = row
        path = resolve(path_text)
        if ROOT not in path.resolve().parents and path.resolve() != ROOT:
            add_error("missing_source_artifact", f"source artifact escapes workspace: {path_text}")
            continue
        if not path.is_file():
            add_error("missing_source_artifact", f"source artifact missing: {path_text}")
            continue
        text = read_text(path, path_text)
        for needle in strings(row.get("required_needles"), f"source_artifacts.{source_id}.required_needles", "missing_source_artifact"):
            if needle not in text:
                add_error("missing_source_artifact", f"{path_text} missing required needle: {needle}")
    declared = set(by_id)
    if declared != SOURCE_IDS:
        add_error("missing_source_artifact", f"source artifact ids drifted: declared={sorted(declared)} expected={sorted(SOURCE_IDS)}")
    if not any(error["failure_signature"] in {"malformed_contract", "missing_source_artifact"} for error in errors):
        append_event("math_value_proof_completion.source_artifacts", "pass", {"source_count": len(by_id)})
    return by_id


def validate_unit(contract: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict):
        add_error("missing_unit_binding", "unit_primary must be an object")
        return 0, {}
    if unit.get("missing_item_id") != "tests.unit.primary":
        add_error("missing_unit_binding", "unit_primary.missing_item_id must be tests.unit.primary")
    actual_tests = string_set(unit.get("required_harness_tests"), "unit_primary.required_harness_tests", "missing_unit_binding")
    if actual_tests != UNIT_TESTS:
        add_error("missing_unit_binding", f"required harness tests drifted: {sorted(actual_tests)}")
    harness_text = read_text(ROOT / "crates/frankenlibc-harness/tests/math_value_proof_test.rs", "math_value_proof_test", "missing_unit_binding")
    for test_name in sorted(actual_tests):
        if f"fn {test_name}(" not in harness_text:
            add_error("missing_unit_binding", f"math_value_proof_test.rs missing fn {test_name}")
    require_commands_use_rch(unit.get("required_commands"), "unit_primary.required_commands", "missing_unit_binding")

    value_proof = load_json(ROOT / "tests/conformance/math_value_proof.json", "math_value_proof", "missing_unit_binding")
    summary = value_proof.get("summary", {}) if isinstance(value_proof.get("summary"), dict) else {}
    required_summary = unit.get("required_summary")
    if not isinstance(required_summary, dict):
        add_error("missing_unit_binding", "unit_primary.required_summary must be an object")
    else:
        for key, expected in EXPECTED_SUMMARY.items():
            if required_summary.get(key) != expected:
                add_error("missing_unit_binding", f"unit_primary.required_summary.{key} must be {expected}")
            if summary.get(key) != expected:
                add_error("missing_unit_binding", f"math_value_proof.summary.{key} drifted: {summary.get(key)} != {expected}")
    if not any(error["failure_signature"] == "missing_unit_binding" for error in errors):
        append_event(
            "math_value_proof_completion.unit_bindings",
            "pass",
            {"unit_test_count": len(actual_tests), "policy_summary": summary},
        )
    return len(actual_tests), summary


def validate_e2e(contract: dict[str, Any]) -> None:
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        add_error("missing_e2e_binding", "e2e_primary must be an object")
        return
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        add_error("missing_e2e_binding", "e2e_primary.missing_item_id must be tests.e2e.primary")
    if e2e.get("gate_script") != "scripts/check_math_value_proof.sh":
        add_error("missing_e2e_binding", "e2e_primary.gate_script must be scripts/check_math_value_proof.sh")
    if e2e.get("value_proof") != "tests/conformance/math_value_proof.json":
        add_error("missing_e2e_binding", "e2e_primary.value_proof must be tests/conformance/math_value_proof.json")
    require_commands_use_rch(e2e.get("required_commands"), "e2e_primary.required_commands", "missing_e2e_binding")

    result = subprocess.run(
        ["bash", "scripts/check_math_value_proof.sh"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    GATE_STDOUT.write_text(result.stdout, encoding="utf-8")
    GATE_STDERR.write_text(result.stderr, encoding="utf-8")
    artifact_refs.add(rel(GATE_STDOUT))
    artifact_refs.add(rel(GATE_STDERR))
    if result.returncode != 0:
        add_error("base_gate_failed", f"check_math_value_proof.sh failed with status {result.returncode}: {result.stderr[-2000:]}")
        return
    for needle in strings(e2e.get("required_gate_stdout"), "e2e_primary.required_gate_stdout", "missing_e2e_binding"):
        if needle not in result.stdout:
            add_error("missing_e2e_binding", f"gate stdout missing required text: {needle}")
    if not any(error["failure_signature"] in {"missing_e2e_binding", "base_gate_failed"} for error in errors):
        append_event(
            "math_value_proof_completion.e2e_gate_replayed",
            "pass",
            {"gate_stdout": rel(GATE_STDOUT), "gate_stderr": rel(GATE_STDERR)},
        )


def validate_telemetry(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        add_error("missing_telemetry_binding", "telemetry_primary must be an object")
        return
    if telemetry.get("missing_item_id") != "telemetry.primary":
        add_error("missing_telemetry_binding", "telemetry_primary.missing_item_id must be telemetry.primary")
    completion_events = string_set(
        telemetry.get("required_completion_events"),
        "telemetry_primary.required_completion_events",
        "missing_telemetry_binding",
    )
    if not COMPLETION_EVENTS.issubset(completion_events):
        add_error("missing_telemetry_binding", f"completion events missing {sorted(COMPLETION_EVENTS - completion_events)}")
    report_fields = string_set(
        telemetry.get("required_report_fields"),
        "telemetry_primary.required_report_fields",
        "missing_telemetry_binding",
    )
    if not REPORT_FIELDS.issubset(report_fields):
        add_error("missing_telemetry_binding", f"report fields missing {sorted(REPORT_FIELDS - report_fields)}")
    log_fields = string_set(
        telemetry.get("required_log_fields"),
        "telemetry_primary.required_log_fields",
        "missing_telemetry_binding",
    )
    if not LOG_FIELDS.issubset(log_fields):
        add_error("missing_telemetry_binding", f"log fields missing {sorted(LOG_FIELDS - log_fields)}")
    if not any(error["failure_signature"] == "missing_telemetry_binding" for error in errors):
        append_event(
            "math_value_proof_completion.telemetry_contract",
            "pass",
            {"completion_event_count": len(completion_events), "report_field_count": len(report_fields), "log_field_count": len(log_fields)},
        )


def finish(source_count: int, unit_count: int, policy_summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        append_event("math_value_proof_completion.completion_contract_validated", "pass")
    else:
        append_event("math_value_proof_completion.completion_contract_failed", "fail")
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "failure_signature": "none" if status == "pass" else primary_signature(),
        "missing_items_closed": sorted(MISSING_ITEMS),
        "source_count": source_count,
        "unit_test_count": unit_count,
        "gate_stdout": rel(GATE_STDOUT),
        "policy_summary": policy_summary,
        "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if errors:
        print(f"FAIL math value proof completion contract errors={len(errors)}", file=sys.stderr)
        for error in errors[:16]:
            print(f"- {error['failure_signature']}: {error['message']}", file=sys.stderr)
        sys.exit(1)
    print(
        "PASS math value proof completion contract "
        f"sources={source_count} unit_refs={unit_count} events={len(events)}"
    )


contract_data = load_json(CONTRACT, "completion contract")
if not isinstance(contract_data, dict):
    add_error("malformed_contract", "completion contract must be a JSON object")
    contract_data = {}
validate_top_level(contract_data)
sources = validate_sources(contract_data)
unit_count, policy_summary = validate_unit(contract_data)
validate_e2e(contract_data)
validate_telemetry(contract_data)
finish(len(sources), unit_count, policy_summary)
PY
