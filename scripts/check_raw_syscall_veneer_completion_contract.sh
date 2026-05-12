#!/usr/bin/env bash
# Validate bd-cj0.1 raw syscall veneer completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/raw_syscall_veneer_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/raw_syscall_veneer_completion}"
REPORT="${FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_REPORT:-${OUT_DIR}/raw_syscall_veneer_completion_contract.report.json}"
LOG="${FRANKENLIBC_RAW_SYSCALL_VENEER_COMPLETION_LOG:-${OUT_DIR}/raw_syscall_veneer_completion_contract.events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

BEAD_ID = "bd-cj0"
COMPLETION_BEAD_ID = "bd-cj0.1"
MANIFEST_ID = "raw-syscall-veneer-completion-contract"
REPORT_SCHEMA = "raw_syscall_veneer_completion_contract.report.v1"
LOG_SCHEMA = "raw_syscall_veneer_completion_contract.log.v1"
REQUIRED_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
REQUIRED_SOURCE_IDS = {
    "raw_syscall_primitives",
    "typed_syscall_wrappers",
    "core_syscall_unit_tests",
    "raw_syscall_unit_tests",
    "core_syscall_integration_tests",
    "verification_matrix_record",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
SUCCESS_EVENTS = {
    "raw_syscall_veneer.source_artifacts_validated",
    "raw_syscall_veneer.expectations_validated",
    "raw_syscall_veneer.implementation_refs_validated",
    "raw_syscall_veneer.unit_binding_validated",
    "raw_syscall_veneer.e2e_binding_validated",
    "raw_syscall_veneer.telemetry_binding_validated",
    "raw_syscall_veneer.completion_contract_validated",
}
FAILURE_EVENT = "raw_syscall_veneer.completion_contract_failed"
REQUIRED_LOG_FIELDS = {
    "schema_version",
    "timestamp",
    "trace_id",
    "event",
    "level",
    "status",
    "bead_id",
    "completion_debt_bead",
    "source_commit",
    "artifact_refs",
    "details",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_paths: dict[str, str] = {}
source_count = 0
raw_syscall_primitive_count = 0
typed_wrapper_count = 0
core_unit_test_count = 0
raw_unit_test_count = 0
integration_test_count = 0
test_ref_count = 0


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


def read_text(path_text: str, label: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        error(f"{label} unreadable: {path_text}: {exc}")
        return ""


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        error(f"{label} must be a JSON object")
        return {}
    return value


def strings(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def append_event(event: str, status: str, details: dict[str, Any], artifact_refs: list[str] | None = None) -> None:
    events.append(
        {
            "schema_version": LOG_SCHEMA,
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD_ID}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "status": status,
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_BEAD_ID,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": artifact_refs or [rel(CONTRACT), rel(REPORT)],
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


def validate_sources(contract: dict[str, Any]) -> None:
    global source_count
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list):
        error("source_artifacts must be an array")
        return
    seen: set[str] = set()
    source_errors_before = len(errors)
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            error(f"source_artifacts[{index}].artifact_id missing")
            continue
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"{artifact_id}.path missing")
            continue
        source_paths[artifact_id] = path_text
        text = read_text(path_text, artifact_id)
        missing_needles: list[str] = []
        for needle in strings(artifact.get("required_needles"), f"{artifact_id}.required_needles"):
            if needle not in text:
                missing_needles.append(needle)
                error(f"{artifact_id} missing required needle {needle!r}")
        forbidden_hits: list[str] = []
        for needle in artifact.get("forbidden_needles", []):
            if not isinstance(needle, str):
                error(f"{artifact_id}.forbidden_needles entries must be strings")
            elif needle in text:
                forbidden_hits.append(needle)
                error(f"{artifact_id} contains forbidden needle {needle!r}")
    if seen != REQUIRED_SOURCE_IDS:
        error(f"source_artifacts must be exactly {sorted(REQUIRED_SOURCE_IDS)}, got {sorted(seen)}")
    source_count = len(seen)
    append_event(
        "raw_syscall_veneer.source_artifacts_validated",
        "pass" if len(errors) == source_errors_before else "fail",
        {"source_count": source_count, "source_ids": sorted(seen)},
    )


def validate_expectations(contract: dict[str, Any]) -> None:
    global raw_syscall_primitive_count, typed_wrapper_count, core_unit_test_count, raw_unit_test_count, integration_test_count
    before = len(errors)
    expectations = contract.get("raw_veneer_expectations")
    if not isinstance(expectations, dict):
        error("raw_veneer_expectations must be an object")
        return
    require(set(strings(expectations.get("expected_architectures"), "raw_veneer_expectations.expected_architectures")) == {"x86_64", "aarch64"}, "expected_architectures must be x86_64 and aarch64")

    raw_text = read_text(source_paths.get("raw_syscall_primitives", ""), "raw_syscall_primitives")
    wrapper_text = read_text(source_paths.get("typed_syscall_wrappers", ""), "typed_syscall_wrappers")
    core_tests_text = read_text(source_paths.get("core_syscall_unit_tests", ""), "core_syscall_unit_tests")
    raw_tests_text = read_text(source_paths.get("raw_syscall_unit_tests", ""), "raw_syscall_unit_tests")
    integration_text = read_text(source_paths.get("core_syscall_integration_tests", ""), "core_syscall_integration_tests")

    raw_syscall_primitive_count = len(re.findall(r"pub unsafe fn syscall[0-6]\(", raw_text))
    typed_wrapper_count = len(re.findall(r"pub (?:unsafe )?fn sys_[a-z0-9_]+\(", wrapper_text))
    core_unit_test_count = core_tests_text.count("#[test]")
    raw_unit_test_count = raw_tests_text.count("#[test]")
    integration_test_count = integration_text.count("#[test]")

    require(raw_syscall_primitive_count >= int(expectations.get("minimum_raw_syscall_primitives", 0)), "raw syscall primitive count below expectation")
    require(typed_wrapper_count >= int(expectations.get("minimum_typed_wrappers", 0)), "typed syscall wrapper count below expectation")
    require(core_unit_test_count >= int(expectations.get("minimum_core_unit_tests", 0)), "core unit test count below expectation")
    require(raw_unit_test_count >= int(expectations.get("minimum_raw_unit_tests", 0)), "raw unit test count below expectation")
    require(integration_test_count >= int(expectations.get("minimum_integration_tests", 0)), "integration test count below expectation")

    errno = expectations.get("errno_contract")
    if not isinstance(errno, dict):
        error("raw_veneer_expectations.errno_contract must be an object")
    else:
        require(errno.get("linux_max_errno") == 4095, "linux_max_errno must be 4095")
        require(errno.get("error_return_range") == "[-4095, -1]", "error_return_range drifted")
    registers = expectations.get("x86_64_register_contract")
    if not isinstance(registers, dict):
        error("x86_64_register_contract must be an object")
    else:
        require(registers.get("syscall_number") == "rax", "x86_64 syscall number register drifted")
        require(registers.get("return_register") == "rax", "x86_64 return register drifted")
        require(strings(registers.get("arguments"), "x86_64_register_contract.arguments") == ["rdi", "rsi", "rdx", "r10", "r8", "r9"], "x86_64 argument register order drifted")
        require(set(strings(registers.get("clobbers"), "x86_64_register_contract.clobbers")) == {"rcx", "r11"}, "x86_64 clobber register set drifted")

    append_event(
        "raw_syscall_veneer.expectations_validated",
        "pass" if len(errors) == before else "fail",
        {
            "raw_syscall_primitive_count": raw_syscall_primitive_count,
            "typed_wrapper_count": typed_wrapper_count,
            "core_unit_test_count": core_unit_test_count,
            "raw_unit_test_count": raw_unit_test_count,
            "integration_test_count": integration_test_count,
        },
    )


def validate_implementation_refs(contract: dict[str, Any]) -> None:
    refs = contract.get("implementation_refs")
    before = len(errors)
    for index, value in enumerate(strings(refs, "implementation_refs")):
        validate_file_line_ref(value, f"implementation_refs[{index}]")
    append_event(
        "raw_syscall_veneer.implementation_refs_validated",
        "pass" if len(errors) == before else "fail",
        {"implementation_ref_count": len(refs) if isinstance(refs, list) else 0},
    )


def validate_test_ref(source: str, name: str, context: str) -> None:
    if source == "completion_harness":
        source_path = source_paths.get("completion_harness")
    else:
        source_path = source_paths.get(source)
    if not source_path:
        error(f"{context} references unknown source {source}")
        return
    text = read_text(source_path, f"{context}.{source}")
    if f"fn {name}" not in text:
        error(f"{context} references missing test {source}::{name}")


def validate_binding(section: dict[str, Any], section_name: str, event_name: str) -> None:
    global test_ref_count
    before = len(errors)
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        error(f"{section_name}.required_test_refs must be a non-empty array")
        refs = []
    for index, test_ref in enumerate(refs):
        if not isinstance(test_ref, dict):
            error(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = test_ref.get("source")
        name = test_ref.get("name")
        if not isinstance(source, str) or not source or not isinstance(name, str) or not name:
            error(f"{section_name}.required_test_refs[{index}] must contain source and name")
            continue
        validate_test_ref(source, name, section_name)
        test_ref_count += 1
    commands = strings(section.get("required_commands"), f"{section_name}.required_commands")
    for command in commands:
        if not command.startswith("rch exec -- cargo "):
            error(f"{section_name}.required_commands must use rch cargo: {command}")
    required_events = set(strings(section.get("required_completion_events"), f"{section_name}.required_completion_events"))
    require(event_name in required_events, f"{section_name}.required_completion_events missing {event_name}")
    append_event(
        event_name,
        "pass" if len(errors) == before else "fail",
        {"test_ref_count": len(refs), "command_count": len(commands)},
    )


def validate_completion_evidence(contract: dict[str, Any]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        error("completion_debt_evidence must be an object")
        return
    require(evidence.get("bead") == COMPLETION_BEAD_ID, f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    require(evidence.get("original_bead") == BEAD_ID, f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    require(isinstance(threshold, int) and threshold >= 800, "next_audit_score_threshold must be >= 800")
    missing = set(strings(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
    require(missing == REQUIRED_ITEMS, f"missing_items_closed must be {sorted(REQUIRED_ITEMS)}")
    for section_name, event_name in [
        ("unit_primary", "raw_syscall_veneer.unit_binding_validated"),
        ("e2e_primary", "raw_syscall_veneer.e2e_binding_validated"),
        ("telemetry_primary", "raw_syscall_veneer.telemetry_binding_validated"),
    ]:
        section = evidence.get(section_name)
        if not isinstance(section, dict):
            error(f"completion_debt_evidence.{section_name} must be an object")
            continue
        validate_binding(section, section_name, event_name)


def validate_telemetry_contract(contract: dict[str, Any]) -> None:
    before = len(errors)
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        error("telemetry_contract must be an object")
        return
    success_events = set(strings(telemetry.get("required_success_events"), "telemetry_contract.required_success_events"))
    require(success_events == SUCCESS_EVENTS, "telemetry_contract.required_success_events drifted")
    require(telemetry.get("required_failure_event") == FAILURE_EVENT, "telemetry_contract.required_failure_event drifted")
    required_log_fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    require(required_log_fields == REQUIRED_LOG_FIELDS, "telemetry_contract.required_log_fields drifted")
    required_report_fields = set(strings(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"))
    report_fields = {
        "schema_version",
        "timestamp",
        "status",
        "bead_id",
        "completion_debt_bead",
        "source_count",
        "raw_syscall_primitive_count",
        "typed_wrapper_count",
        "core_unit_test_count",
        "raw_unit_test_count",
        "integration_test_count",
        "missing_items_closed",
        "events",
        "errors",
    }
    require(required_report_fields == report_fields, "telemetry_contract.required_report_fields drifted")
    for row in events:
        missing = REQUIRED_LOG_FIELDS - row.keys()
        if missing:
            error(f"telemetry row {row.get('event')} missing fields {sorted(missing)}")
    append_event(
        "raw_syscall_veneer.telemetry_binding_validated",
        "pass" if len(errors) == before else "fail",
        {"required_success_events": sorted(success_events), "required_log_fields": sorted(required_log_fields)},
    )


contract = load_json(CONTRACT, "contract")
require(contract.get("schema_version") == "v1", "schema_version must be v1")
require(contract.get("manifest_id") == MANIFEST_ID, f"manifest_id must be {MANIFEST_ID}")
require(contract.get("bead") == BEAD_ID, f"bead must be {BEAD_ID}")
require(contract.get("completion_debt_bead") == COMPLETION_BEAD_ID, f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
validate_sources(contract)
validate_expectations(contract)
validate_implementation_refs(contract)
validate_completion_evidence(contract)
validate_telemetry_contract(contract)

if errors:
    append_event(FAILURE_EVENT, "fail", {"errors": errors})
else:
    append_event(
        "raw_syscall_veneer.completion_contract_validated",
        "pass",
        {"source_count": source_count, "test_ref_count": test_ref_count},
    )

report = {
    "schema_version": REPORT_SCHEMA,
    "timestamp": utc_now(),
    "status": "fail" if errors else "pass",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "source_commit": SOURCE_COMMIT,
    "source_count": source_count,
    "raw_syscall_primitive_count": raw_syscall_primitive_count,
    "typed_wrapper_count": typed_wrapper_count,
    "core_unit_test_count": core_unit_test_count,
    "raw_unit_test_count": raw_unit_test_count,
    "integration_test_count": integration_test_count,
    "missing_items_closed": sorted(REQUIRED_ITEMS),
    "events": [row["event"] for row in events],
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL raw syscall veneer completion contract", file=sys.stderr)
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS raw syscall veneer completion contract "
    f"sources={source_count} raw_primitives={raw_syscall_primitive_count} "
    f"wrappers={typed_wrapper_count} integration_tests={integration_test_count} "
    f"events={len(events)}"
)
PY
