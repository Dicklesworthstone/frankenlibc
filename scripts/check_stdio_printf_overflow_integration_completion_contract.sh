#!/usr/bin/env bash
# Validate bd-5t6zo.1 stdio printf overflow integration completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/stdio_printf_overflow_integration_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/stdio_printf_overflow_integration_completion}"
REPORT="${FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_REPORT:-${OUT_DIR}/stdio_printf_overflow_integration_completion.report.json}"
LOG="${FRANKENLIBC_STDIO_PRINTF_OVERFLOW_COMPLETION_LOG:-${OUT_DIR}/stdio_printf_overflow_integration_completion.events.jsonl}"
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

SCHEMA = "stdio_printf_overflow_integration_completion_contract.v1"
REPORT_SCHEMA = "stdio_printf_overflow_integration_completion_contract.report.v1"
BEAD_ID = "bd-5t6zo.1"
ORIGINAL_BEAD = "bd-5t6zo"
TRACE_ID = "bd-5t6zo.1::stdio-printf-overflow-integration::v1"
REQUIRED_OBLIGATIONS = {"tests.integration.primary"}
REQUIRED_SOURCE_KEYS = {
    "implementation",
    "fixture_spec",
    "integration_fixture",
    "integration_gate",
    "fixture_suite_harness",
    "completion_gate",
    "completion_harness",
}
REQUIRED_EVENTS = [
    "stdio_printf_overflow_completion.source_binding",
    "stdio_printf_overflow_completion.integration_binding",
    "stdio_printf_overflow_completion.summary",
]
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_printf_overflow_guard_marker",
    "printf_overflow_helper_use_count_drift",
    "fixture_stdio_printf_spec_drift",
    "stdio_printf_integration_fixture_drift",
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
    return "stdio_printf_overflow_completion_failed"


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
            "mode": details.pop("mode", "strict+hardened"),
            "api_family": "stdio",
            "symbol": details.pop("symbol", "snprintf/sprintf/vsnprintf/vsprintf"),
            "decision_path": details.pop(
                "decision_path",
                "completion_contract>integration_fixture>printf_overflow_guard",
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
                    "missing_source_artifact",
                    f"{path_text} missing required marker: {marker}",
                )
    append_event(
        "stdio_printf_overflow_completion.source_binding",
        "pass" if len(failures) == before else "fail",
        source_count=len(keys),
    )
    return sources


def validate_implementation(sources: dict[str, Any]) -> None:
    row = sources.get("implementation", {})
    text = read_text(source_path(sources, "implementation"), "implementation")
    helper_uses = text.count("printf_result_to_c_int(total_len)")
    minimum = row.get("minimum_helper_uses")
    if not isinstance(minimum, int) or minimum <= 0:
        add_failure("malformed_contract", "implementation.minimum_helper_uses must be positive")
        minimum = 20
    if helper_uses < minimum:
        add_failure(
            "printf_overflow_helper_use_count_drift",
            f"printf_result_to_c_int(total_len) count {helper_uses} < {minimum}",
        )


def validate_integration(sources: dict[str, Any]) -> None:
    before = len(failures)
    validate_implementation(sources)

    spec_row = sources.get("fixture_spec", {})
    spec = load_json(source_path(sources, "fixture_spec"), "fixture_spec", "fixture_stdio_printf_spec_drift")
    fixtures = spec.get("fixtures") if isinstance(spec, dict) else None
    if not isinstance(fixtures, list):
        add_failure("fixture_stdio_printf_spec_drift", "fixtures must be an array")
        fixtures = []
    fixture_id = spec_row.get("required_fixture_id")
    fixture = next((row for row in fixtures if isinstance(row, dict) and row.get("id") == fixture_id), None)
    if not isinstance(fixture, dict):
        add_failure("fixture_stdio_printf_spec_drift", f"missing fixture {fixture_id}")
        fixture = {}
    covered_symbols = set(fixture.get("covered_symbols", [])) if isinstance(fixture.get("covered_symbols"), list) else set()
    required_symbols = set(
        string_list(spec_row.get("required_symbols"), "fixture_spec.required_symbols", "fixture_stdio_printf_spec_drift")
    )
    missing_symbols = sorted(required_symbols - covered_symbols)
    if missing_symbols:
        add_failure("fixture_stdio_printf_spec_drift", f"fixture_stdio_printf missing symbols: {missing_symbols}")
    minimum_tests = spec_row.get("minimum_tests")
    if not isinstance(minimum_tests, int) or int(fixture.get("tests", 0)) < minimum_tests:
        add_failure("fixture_stdio_printf_spec_drift", "fixture_stdio_printf tests below minimum")
    mode_expectations = fixture.get("mode_expectations")
    if not isinstance(mode_expectations, dict):
        add_failure("fixture_stdio_printf_spec_drift", "fixture_stdio_printf missing mode_expectations")
        mode_expectations = {}
    for mode in string_list(spec_row.get("required_modes"), "fixture_spec.required_modes", "fixture_stdio_printf_spec_drift"):
        mode_obj = mode_expectations.get(mode)
        if not isinstance(mode_obj, dict):
            add_failure("fixture_stdio_printf_spec_drift", f"missing mode expectation {mode}")
        elif mode_obj.get("expected_exit") != 0 or "fixture_stdio_printf: PASS" not in str(mode_obj.get("expected_stdout_contains", "")):
            add_failure("fixture_stdio_printf_spec_drift", f"invalid mode expectation {mode}")

    fixture_row = sources.get("integration_fixture", {})
    fixture_text = read_text(source_path(sources, "integration_fixture"), "integration_fixture")
    for function_name in string_list(
        fixture_row.get("required_functions"),
        "integration_fixture.required_functions",
        "stdio_printf_integration_fixture_drift",
    ):
        if f"static int {function_name}(void)" not in fixture_text:
            add_failure("stdio_printf_integration_fixture_drift", f"missing integration function {function_name}")

    harness_row = sources.get("fixture_suite_harness", {})
    harness_text = read_text(source_path(sources, "fixture_suite_harness"), "fixture_suite_harness")
    for function_name in string_list(
        harness_row.get("required_functions"),
        "fixture_suite_harness.required_functions",
        "stdio_printf_integration_fixture_drift",
    ):
        if f"fn {function_name}(" not in harness_text:
            add_failure("stdio_printf_integration_fixture_drift", f"missing fixture suite test {function_name}")

    append_event(
        "stdio_printf_overflow_completion.integration_binding",
        "pass" if len(failures) == before else "fail",
        helper_uses=read_text(source_path(sources, "implementation"), "implementation").count("printf_result_to_c_int(total_len)"),
        integration_functions=len(fixture_row.get("required_functions", [])) if isinstance(fixture_row, dict) else 0,
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
        "stdio_printf_overflow_completion.summary",
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
            "required_event_count": len(REQUIRED_EVENTS),
        },
        "artifact_refs": sorted(artifact_refs | {rel(REPORT), rel(LOG)}),
        "failures": failures,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    if ok:
        print(
            "PASS stdio printf overflow integration completion contract "
            f"sources={report['summary']['source_count']} "
            f"events={report['summary']['required_event_count']}"
        )
    else:
        print(f"FAIL stdio printf overflow integration completion contract errors={len(failures)}", file=sys.stderr)
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
    validate_integration(sources)
    validate_log_contract(contract)
    write_outputs(contract)


main()
PY
