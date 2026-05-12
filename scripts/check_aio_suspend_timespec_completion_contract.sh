#!/usr/bin/env bash
# Validate bd-4rdz8.1 aio_suspend timespec completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_AIO_SUSPEND_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/aio_suspend_timespec_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_AIO_SUSPEND_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/aio_suspend_timespec_completion_contract}"
REPORT="${FRANKENLIBC_AIO_SUSPEND_COMPLETION_REPORT:-${OUT_DIR}/report.json}"
LOG="${FRANKENLIBC_AIO_SUSPEND_COMPLETION_LOG:-${OUT_DIR}/events.jsonl}"
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
START_NS = time.time_ns()

SCHEMA = "aio_suspend_timespec_completion_contract.v1"
REPORT_SCHEMA = "aio_suspend_timespec_completion_contract.report.v1"
BEAD_ID = "bd-4rdz8.1"
ORIGINAL_BEAD = "bd-4rdz8"
TRACE_ID = "bd-4rdz8.1::aio-suspend-timespec::v1"
MISSING_ITEMS = {"tests.unit.primary", "tests.golden.primary"}
SOURCE_IDS = {
    "implementation",
    "unit_harness",
    "golden",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
UNIT_TESTS = {
    "aio_suspend_rejects_negative_tv_sec_without_panic",
    "aio_suspend_rejects_negative_tv_nsec",
    "aio_suspend_rejects_oversize_tv_nsec",
    "aio_suspend_rejects_empty_list_before_timeout",
}
GOLDEN_CASES = {
    "negative_tv_sec",
    "negative_tv_nsec",
    "oversize_tv_nsec",
    "empty_list_precedes_timeout",
}
EVENTS = {
    "aio_suspend_timespec_completion.source_artifacts",
    "aio_suspend_timespec_completion.unit_bindings",
    "aio_suspend_timespec_completion.golden_bindings",
    "aio_suspend_timespec_completion.validated",
    "aio_suspend_timespec_completion.failed",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_unit_binding",
    "missing_golden_binding",
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
    return "aio_suspend_timespec_completion_failed"


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
            "gate": "aio_suspend_timespec_completion_contract",
            "scenario_id": event,
            "event": event,
            "status": status,
            "mode": "strict",
            "runtime_mode": "strict",
            "replacement_level": "L0",
            "api_family": "unistd",
            "symbol": "aio_suspend",
            "oracle_kind": "golden",
            "expected": {"return_value": -1, "errno": "EINVAL", "no_panic": True},
            "actual": {"status": status},
            "decision_path": "completion_contract>golden>unit_harness",
            "healing_action": "None",
            "outcome": "pass" if status == "pass" else "fail",
            "errno": 0 if status == "pass" else 22,
            "latency_ns": time.time_ns() - START_NS,
            "source_commit": SOURCE_COMMIT,
            "target_dir": "target/conformance",
            "failure_signature": failure_signature,
            "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
            "details": details or {},
        }
    )


def require_rch(commands: Any, context: str, signature: str) -> None:
    for command in strings(commands, context, signature):
        if "cargo " in command and not command.startswith("rch exec --"):
            add_error(signature, f"{context} cargo command must use rch: {command}")


def validate_top_level(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != SCHEMA:
        add_error("malformed_contract", f"schema_version must be {SCHEMA}")
    if contract.get("bead_id") != BEAD_ID:
        add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
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
        "aio_suspend_timespec_completion.source_artifacts",
        "pass" if not any(error["failure_signature"] in {"malformed_contract", "missing_source_artifact"} for error in errors) else "fail",
        {"source_ids": sorted(ids), "source_count": len(ids)},
    )
    return by_id


def source_path(sources: dict[str, dict[str, Any]], source_id: str) -> Path:
    path_text = sources.get(source_id, {}).get("path")
    return resolve(path_text) if isinstance(path_text, str) else ROOT / "__missing__"


def validate_unit(contract: dict[str, Any], sources: dict[str, dict[str, Any]]) -> None:
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
    if section.get("required_errno") != "EINVAL" or section.get("required_errno_value") != 22:
        add_error("missing_unit_binding", "unit_primary must require EINVAL/22")
    require_rch(section.get("required_commands"), "unit_primary.required_commands", "missing_unit_binding")
    harness_text = read_text(source_path(sources, "unit_harness"), "unit harness")
    for name in sorted(UNIT_TESTS):
        if f"fn {name}(" not in harness_text:
            add_error("missing_unit_binding", f"unit harness missing fn {name}(")
    if harness_text.count("assert_eq!(errno_value(), libc::EINVAL);") < len(UNIT_TESTS):
        add_error("missing_unit_binding", "unit harness must assert EINVAL for every aio_suspend case")
    append_event(
        "aio_suspend_timespec_completion.unit_bindings",
        "pass" if len(errors) == before else "fail",
        {"unit_test_count": len(tests), "required_errno": "EINVAL"},
    )


def validate_golden(contract: dict[str, Any], sources: dict[str, dict[str, Any]]) -> None:
    before = len(errors)
    section = contract.get("golden_primary")
    if not isinstance(section, dict):
        add_error("missing_golden_binding", "golden_primary must be an object")
        section = {}
    if section.get("missing_item_id") != "tests.golden.primary":
        add_error("missing_golden_binding", "golden_primary missing_item_id drifted")
    required_cases = string_set(section.get("required_case_ids"), "golden_primary.required_case_ids", "missing_golden_binding")
    if required_cases != GOLDEN_CASES:
        add_error("missing_golden_binding", f"required_case_ids drifted: {sorted(required_cases)}")
    require_rch(section.get("required_commands"), "golden_primary.required_commands", "missing_golden_binding")
    golden = load_json(source_path(sources, "golden"), "golden artifact", "missing_golden_binding")
    if not isinstance(golden, dict):
        golden = {}
    if golden.get("schema_version") != "aio_suspend_timespec_invalid_inputs.golden.v1":
        add_error("missing_golden_binding", "golden schema_version drifted")
    cases = golden.get("cases")
    if not isinstance(cases, list):
        add_error("missing_golden_binding", "golden cases must be an array")
        cases = []
    actual_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            add_error("missing_golden_binding", "golden case must be an object")
            continue
        case_id = case.get("id")
        if isinstance(case_id, str):
            actual_ids.add(case_id)
        expected = case.get("expected")
        if not isinstance(expected, dict):
            add_error("missing_golden_binding", f"golden case {case_id} expected must be an object")
            continue
        if expected.get("return_value") != -1:
            add_error("missing_golden_binding", f"golden case {case_id} must return -1")
        if expected.get("errno") != "EINVAL" or expected.get("errno_value") != 22:
            add_error("missing_golden_binding", f"golden case {case_id} must pin EINVAL/22")
        if expected.get("no_panic") is not True:
            add_error("missing_golden_binding", f"golden case {case_id} must pin no_panic=true")
    if actual_ids != GOLDEN_CASES:
        add_error("missing_golden_binding", f"golden cases drifted: {sorted(actual_ids)}")
    invariants = set(strings(golden.get("invariants"), "golden.invariants", "missing_golden_binding"))
    required_invariants = string_set(section.get("required_invariants"), "golden_primary.required_invariants", "missing_golden_binding")
    if not required_invariants <= invariants:
        add_error("missing_golden_binding", f"golden invariants missing {sorted(required_invariants - invariants)}")
    append_event(
        "aio_suspend_timespec_completion.golden_bindings",
        "pass" if len(errors) == before else "fail",
        {"case_count": len(actual_ids), "invariant_count": len(invariants)},
    )


def write_outputs(contract: dict[str, Any]) -> None:
    ok = not errors
    status = "pass" if ok else "fail"
    append_event(
        "aio_suspend_timespec_completion.validated" if ok else "aio_suspend_timespec_completion.failed",
        status,
        {"error_count": len(errors)},
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
        "golden_case_count": len(GOLDEN_CASES),
        "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if ok:
        print(
            f"PASS aio_suspend timespec completion contract sources={report['source_count']} "
            f"unit_refs={report['unit_test_count']} golden_cases={report['golden_case_count']}"
        )
    else:
        print(f"FAIL aio_suspend timespec completion contract errors={len(errors)}", file=sys.stderr)
        for error in errors:
            print(f"{error['failure_signature']}: {error['message']}", file=sys.stderr)
        raise SystemExit(1)


def main() -> None:
    contract = load_json(CONTRACT, "completion contract")
    if not isinstance(contract, dict):
        add_error("malformed_contract", "completion contract must be a JSON object")
        contract = {}
    validate_top_level(contract)
    sources = validate_sources(contract)
    validate_unit(contract, sources)
    validate_golden(contract, sources)
    write_outputs(contract)


main()
PY
