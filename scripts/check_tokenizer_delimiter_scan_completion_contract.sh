#!/usr/bin/env bash
# Validate bd-5if6f.1 tokenizer delimiter scan conformance completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_TOKENIZER_DELIMITER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/tokenizer_delimiter_scan_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_TOKENIZER_DELIMITER_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/tokenizer_delimiter_scan_completion}"
REPORT="${FRANKENLIBC_TOKENIZER_DELIMITER_COMPLETION_REPORT:-${OUT_DIR}/tokenizer_delimiter_scan_completion.report.json}"
LOG="${FRANKENLIBC_TOKENIZER_DELIMITER_COMPLETION_LOG:-${OUT_DIR}/tokenizer_delimiter_scan_completion.events.jsonl}"
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

SCHEMA = "tokenizer_delimiter_scan_completion_contract.v1"
REPORT_SCHEMA = "tokenizer_delimiter_scan_completion_contract.report.v1"
BEAD_ID = "bd-5if6f.1"
ORIGINAL_BEAD = "bd-5if6f"
TRACE_ID = "bd-5if6f.1::tokenizer-delimiter-scan::v1"
REQUIRED_OBLIGATIONS = {"tests.conformance.primary"}
REQUIRED_SOURCE_KEYS = {
    "implementation",
    "conformance_diff",
    "unit_regressions",
    "fixture",
    "golden_fixture_table",
    "completion_gate",
    "completion_harness",
}
REQUIRED_EVENTS = [
    "tokenizer_delimiter_completion.source_binding",
    "tokenizer_delimiter_completion.conformance_binding",
    "tokenizer_delimiter_completion.fixture_golden_binding",
    "tokenizer_delimiter_completion.summary",
]
REQUIRED_FIXTURE_CASES = {
    "strtok_all_delims",
    "strtok_basic_first",
    "strtok_comma_delim",
    "strtok_leading_delims",
    "strtok_no_delim_found",
    "strtok_r_basic_first",
    "strtok_r_comma_delim",
    "strtok_r_empty",
}
REQUIRED_FIXTURE_FUNCTIONS = {"strtok", "strtok_r"}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_source_artifact_marker",
    "missing_tokenizer_conformance_function",
    "tokenizer_fixture_case_drift",
    "tokenizer_golden_trace_drift",
]

failures: list[dict[str, Any]] = []
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


def add_failure(signature: str, message: str, **details: Any) -> None:
    failures.append({"failure_signature": signature, "message": message, **details})


def primary_signature() -> str:
    present = {failure["failure_signature"] for failure in failures}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "tokenizer_delimiter_completion_failed"


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        add_failure("malformed_contract", f"unsafe artifact path: {path_text}")
        return ROOT / "__unsafe_path__"
    return ROOT / path


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_failure(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def read_text(path: Path, context: str) -> str:
    try:
        artifact_refs.add(rel(path))
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        add_failure("missing_source_artifact", f"{context}: cannot read {rel(path)}: {exc}")
        return ""


def string_list(value: Any, context: str, signature: str = "malformed_contract") -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        add_failure(signature, f"{context} must be a non-empty string array")
        return []
    return list(value)


def optional_string_list(value: Any, context: str, signature: str = "malformed_contract") -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        add_failure(signature, f"{context} must be a string array when present")
        return []
    return list(value)


def append_event(event: str, outcome: str, **details: Any) -> None:
    events.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{TRACE_ID}::{event}",
            "bead_id": BEAD_ID,
            "original_bead": ORIGINAL_BEAD,
            "event": event,
            "outcome": outcome,
            "mode": details.pop("mode", "strict"),
            "api_family": "string",
            "symbol": details.pop("symbol", "strtok/strtok_r/strsep"),
            "decision_path": details.pop(
                "decision_path",
                "completion_contract>conformance_diff>fixture_golden",
            ),
            "healing_action": details.pop("healing_action", "None"),
            "errno": details.pop("errno", 0),
            "latency_ns": time.time_ns() - START_NS,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
            **details,
        }
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def source_path(sources: dict[str, Any], key: str) -> Path:
    row = sources.get(key)
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        add_failure("malformed_contract", f"source_artifacts.{key}.path must be present")
        return ROOT / "__missing__"
    return resolve(row["path"])


def validate_top_level(contract: dict[str, Any]) -> None:
    if contract.get("schema_version") != SCHEMA:
        add_failure("malformed_contract", f"schema_version must be {SCHEMA}")
    if contract.get("bead_id") != BEAD_ID:
        add_failure("malformed_contract", f"bead_id must be {BEAD_ID}")
    if contract.get("original_bead") != ORIGINAL_BEAD:
        add_failure("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
    completion = contract.get("completion_debt_evidence")
    if not isinstance(completion, dict):
        add_failure("malformed_contract", "completion_debt_evidence must be an object")
    else:
        missing_items = set(string_list(completion.get("missing_items_closed"), "missing_items_closed"))
        if missing_items != REQUIRED_OBLIGATIONS:
            add_failure("malformed_contract", f"missing_items_closed drifted: {sorted(missing_items)}")
        threshold = completion.get("next_audit_score_threshold")
        if not isinstance(threshold, int) or threshold < 700:
            add_failure("malformed_contract", "next_audit_score_threshold must be at least 700")
    obligations = contract.get("completion_obligations")
    if not isinstance(obligations, list):
        add_failure("malformed_contract", "completion_obligations must be an array")
    else:
        ids = {row.get("id") for row in obligations if isinstance(row, dict)}
        if ids != REQUIRED_OBLIGATIONS:
            add_failure("malformed_contract", f"completion obligations drifted: {sorted(ids)}")


def validate_sources(contract: dict[str, Any]) -> dict[str, Any]:
    before = len(failures)
    sources = contract.get("source_artifacts")
    if not isinstance(sources, dict):
        add_failure("malformed_contract", "source_artifacts must be an object")
        sources = {}
    keys = set(sources)
    if keys != REQUIRED_SOURCE_KEYS:
        add_failure("malformed_contract", f"source artifact keys drifted: {sorted(keys)}")
    for key, row in sources.items():
        if not isinstance(row, dict):
            add_failure("malformed_contract", f"source_artifacts.{key} must be an object")
            continue
        path_text = row.get("path")
        if not isinstance(path_text, str):
            add_failure("malformed_contract", f"source_artifacts.{key}.path must be a string")
            continue
        text = read_text(resolve(path_text), f"source_artifacts.{key}")
        for marker in optional_string_list(row.get("required_markers"), f"source_artifacts.{key}.required_markers"):
            if marker not in text:
                add_failure(
                    "missing_source_artifact_marker",
                    f"{path_text} missing required marker: {marker}",
                )
    append_event(
        "tokenizer_delimiter_completion.source_binding",
        "pass" if len(failures) == before else "fail",
        source_count=len(keys),
    )
    return sources


def validate_conformance_diff(sources: dict[str, Any]) -> None:
    before = len(failures)
    row = sources.get("conformance_diff", {})
    text = read_text(source_path(sources, "conformance_diff"), "conformance_diff")
    for function_name in string_list(
        row.get("required_functions"),
        "conformance_diff.required_functions",
        "missing_tokenizer_conformance_function",
    ):
        if f"fn {function_name}(" not in text:
            add_failure(
                "missing_tokenizer_conformance_function",
                f"conformance diff missing fn {function_name}",
            )
    for marker in string_list(
        row.get("required_case_markers"),
        "conformance_diff.required_case_markers",
        "missing_tokenizer_conformance_function",
    ):
        if marker not in text:
            add_failure(
                "missing_tokenizer_conformance_function",
                f"conformance diff missing case marker {marker}",
            )
    unit_row = sources.get("unit_regressions", {})
    unit_text = read_text(source_path(sources, "unit_regressions"), "unit_regressions")
    for function_name in string_list(
        unit_row.get("required_functions"),
        "unit_regressions.required_functions",
        "missing_tokenizer_conformance_function",
    ):
        if f"fn {function_name}(" not in unit_text:
            add_failure(
                "missing_tokenizer_conformance_function",
                f"unit regression missing fn {function_name}",
            )
    append_event(
        "tokenizer_delimiter_completion.conformance_binding",
        "pass" if len(failures) == before else "fail",
        differential_tests=len(row.get("required_functions", [])) if isinstance(row, dict) else 0,
    )


def validate_fixture_and_golden(sources: dict[str, Any]) -> None:
    before = len(failures)
    fixture_row = sources.get("fixture", {})
    fixture = load_json(source_path(sources, "fixture"), "fixture", "tokenizer_fixture_case_drift")
    if not isinstance(fixture, dict):
        fixture = {}
    if fixture.get("family") != fixture_row.get("required_family"):
        add_failure("tokenizer_fixture_case_drift", "fixture family drifted")
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        add_failure("tokenizer_fixture_case_drift", "fixture cases must be an array")
        cases = []
    actual_cases = {case.get("name") for case in cases if isinstance(case, dict)}
    required_cases = set(
        string_list(
            fixture_row.get("required_case_ids"),
            "fixture.required_case_ids",
            "tokenizer_fixture_case_drift",
        )
    )
    if required_cases != REQUIRED_FIXTURE_CASES:
        add_failure("tokenizer_fixture_case_drift", f"required fixture cases drifted: {sorted(required_cases)}")
    if not required_cases <= actual_cases:
        add_failure(
            "tokenizer_fixture_case_drift",
            f"fixture missing cases: {sorted(required_cases - actual_cases)}",
        )
    actual_functions = {case.get("function") for case in cases if isinstance(case, dict)}
    required_functions = set(
        string_list(
            fixture_row.get("required_functions"),
            "fixture.required_functions",
            "tokenizer_fixture_case_drift",
        )
    )
    if required_functions != REQUIRED_FIXTURE_FUNCTIONS or not required_functions <= actual_functions:
        add_failure("tokenizer_fixture_case_drift", f"fixture functions drifted: {sorted(actual_functions)}")

    golden_row = sources.get("golden_fixture_table", {})
    golden_text = read_text(source_path(sources, "golden_fixture_table"), "golden_fixture_table")
    status = golden_row.get("required_status")
    for trace_id in string_list(
        golden_row.get("required_trace_ids"),
        "golden_fixture_table.required_trace_ids",
        "tokenizer_golden_trace_drift",
    ):
        if trace_id not in golden_text:
            add_failure("tokenizer_golden_trace_drift", f"golden table missing trace id: {trace_id}")
        elif isinstance(status, str) and f"`{trace_id}`" in golden_text:
            line = next((line for line in golden_text.splitlines() if trace_id in line), "")
            if status not in line:
                add_failure("tokenizer_golden_trace_drift", f"golden trace {trace_id} missing status {status}")
    append_event(
        "tokenizer_delimiter_completion.fixture_golden_binding",
        "pass" if len(failures) == before else "fail",
        fixture_cases=len(actual_cases),
        golden_traces=len(golden_row.get("required_trace_ids", [])) if isinstance(golden_row, dict) else 0,
    )


def validate_log_contract(contract: dict[str, Any]) -> None:
    log_contract = contract.get("completion_log_contract")
    if not isinstance(log_contract, dict):
        add_failure("malformed_contract", "completion_log_contract must be an object")
        return
    events = string_list(log_contract.get("required_events"), "completion_log_contract.required_events")
    if events != REQUIRED_EVENTS:
        add_failure("malformed_contract", f"completion log events drifted: {events}")
    fields = set(string_list(log_contract.get("required_fields"), "completion_log_contract.required_fields"))
    missing = {
        "timestamp",
        "trace_id",
        "bead_id",
        "original_bead",
        "event",
        "outcome",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    } - fields
    if missing:
        add_failure("malformed_contract", f"completion log required fields missing: {sorted(missing)}")


def write_outputs(contract: dict[str, Any]) -> None:
    ok = not failures
    append_event(
        "tokenizer_delimiter_completion.summary",
        "pass" if ok else "fail",
        failure_signature="none" if ok else primary_signature(),
        error_count=len(failures),
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "outcome": "pass" if ok else "fail",
        "failure_signature": "none" if ok else primary_signature(),
        "missing_items_closed": sorted(REQUIRED_OBLIGATIONS),
        "summary": {
            "source_count": len(contract.get("source_artifacts", {}))
            if isinstance(contract.get("source_artifacts"), dict)
            else 0,
            "fixture_case_count": len(REQUIRED_FIXTURE_CASES),
            "fixture_function_count": len(REQUIRED_FIXTURE_FUNCTIONS),
            "required_event_count": len(REQUIRED_EVENTS),
        },
        "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
        "failures": failures,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if ok:
        print(
            "PASS tokenizer delimiter scan completion contract "
            f"sources={report['summary']['source_count']} "
            f"fixture_cases={report['summary']['fixture_case_count']} "
            f"events={report['summary']['required_event_count']}"
        )
    else:
        print(f"FAIL tokenizer delimiter scan completion contract errors={len(failures)}", file=sys.stderr)
        for failure in failures:
            print(f"{failure['failure_signature']}: {failure['message']}", file=sys.stderr)
        raise SystemExit(1)


def main() -> None:
    contract = load_json(CONTRACT, "completion contract")
    if not isinstance(contract, dict):
        add_failure("malformed_contract", "completion contract must be a JSON object")
        contract = {}
    validate_top_level(contract)
    sources = validate_sources(contract)
    validate_conformance_diff(sources)
    validate_fixture_and_golden(sources)
    validate_log_contract(contract)
    write_outputs(contract)


main()
PY
