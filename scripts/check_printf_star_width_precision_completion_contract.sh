#!/usr/bin/env bash
# Validate bd-wv5ym.1 printf star width/precision completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PRINTF_STAR_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/printf_star_width_precision_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PRINTF_STAR_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/printf_star_width_precision_completion}"
REPORT="${FRANKENLIBC_PRINTF_STAR_COMPLETION_REPORT:-${OUT_DIR}/printf_star_width_precision_completion_contract.report.json}"
LOG="${FRANKENLIBC_PRINTF_STAR_COMPLETION_LOG:-${OUT_DIR}/printf_star_width_precision_completion_contract.events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

SCHEMA = "printf_star_width_precision_completion_contract.v1"
REPORT_SCHEMA = "printf_star_width_precision_completion_contract.report.v1"
LOG_SCHEMA = "printf_star_width_precision_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-wv5ym"
COMPLETION_BEAD = "bd-wv5ym.1"
EXPECTED_MISSING = {"tests.conformance.primary"}
REQUIRED_SOURCE_IDS = {
    "printf_abi_implementation",
    "stdio_abi_regressions",
    "glibc_differential_conformance",
    "discrepancy_record",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_EVENTS = {
    "printf_star_width_precision.source_artifacts_validated",
    "printf_star_width_precision.conformance_binding_validated",
    "printf_star_width_precision.completion_contract_validated",
    "printf_star_width_precision.completion_contract_failed",
}
REQUIRED_TESTS = {
    "snprintf_normalizes_positional_negative_star_width",
    "snprintf_normalizes_positional_negative_star_precision",
    "vsprintf_normalizes_negative_star_width_from_va_list",
    "diff_snprintf_negative_star_width_precision",
    "checker_accepts_contract_and_emits_telemetry",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_count = 0
implementation_ref_count = 0
test_binding_count = 0


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
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
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


def validate_sources(contract: dict[str, Any]) -> None:
    global source_count
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
            error(f"source artifact {source_id} path must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            error(f"source artifact {source_id} missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in string_array(source.get("required_needles"), f"{source_id}.required_needles"):
            if needle not in text:
                error(f"source artifact {source_id} missing required needle: {needle}")
    missing = REQUIRED_SOURCE_IDS - ids
    extra = ids - REQUIRED_SOURCE_IDS
    if missing:
        error(f"source_artifacts missing required ids: {sorted(missing)}")
    if extra:
        error(f"source_artifacts contains unexpected ids: {sorted(extra)}")
    source_count = len(ids)
    append_event(
        "printf_star_width_precision.source_artifacts_validated",
        "pass" if not errors else "fail",
        {"source_count": source_count},
    )


def validate_contract(contract: dict[str, Any]) -> None:
    global implementation_ref_count, test_binding_count
    require(contract.get("schema_version") == SCHEMA, "schema_version drifted")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead drifted")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drifted")
    audit = contract.get("audit_reference", {})
    require(isinstance(audit, dict), "audit_reference must be object")
    require(audit.get("score_before") == 470, "audit_reference.score_before drifted")
    require(audit.get("score_threshold") == 800, "audit_reference.score_threshold must be 800")
    evidence = contract.get("completion_debt_evidence", {})
    require(isinstance(evidence, dict), "completion_debt_evidence must be object")
    missing_items = set(string_array(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
    if "tests.conformance.primary" not in missing_items:
        error("missing_items_closed must bind tests.conformance.primary")
    if missing_items != EXPECTED_MISSING:
        error(f"missing_items_closed drifted: {sorted(missing_items)}")
    refs = string_array(contract.get("implementation_refs"), "implementation_refs")
    implementation_ref_count = len(refs)
    for index, reference in enumerate(refs):
        validate_file_line_ref(reference, f"implementation_refs[{index}]")
    conformance = contract.get("conformance_primary", {})
    require(isinstance(conformance, dict), "conformance_primary must be object")
    require(conformance.get("missing_item_id") == "tests.conformance.primary", "conformance_primary.missing_item_id drifted")
    tests = {
        row.get("name")
        for row in conformance.get("required_test_refs", [])
        if isinstance(row, dict)
    }
    test_binding_count = len(tests)
    if not REQUIRED_TESTS.issubset(tests):
        error(f"conformance_primary.required_test_refs missing {sorted(REQUIRED_TESTS - tests)}")
    completion_events = set(string_array(conformance.get("required_completion_events"), "conformance_primary.required_completion_events"))
    if not REQUIRED_EVENTS.issubset(completion_events):
        error(f"conformance_primary.required_completion_events missing {sorted(REQUIRED_EVENTS - completion_events)}")
    commands = set(string_array(conformance.get("required_commands"), "conformance_primary.required_commands"))
    required_commands = {
        "bash scripts/check_printf_star_width_precision_completion_contract.sh",
        "rch exec -- cargo test -p frankenlibc-abi --test stdio_abi_test negative_star -- --nocapture",
        "rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_stdio_printf diff_snprintf_negative_star_width_precision -- --nocapture",
        "rch exec -- cargo test -p frankenlibc-harness --test printf_star_width_precision_completion_contract_test -- --nocapture",
    }
    if not required_commands.issubset(commands):
        error(f"conformance_primary.required_commands missing {sorted(required_commands - commands)}")
    append_event(
        "printf_star_width_precision.conformance_binding_validated",
        "pass" if not errors else "fail",
        {"test_binding_count": test_binding_count},
    )


def write_outputs(contract: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    event = (
        "printf_star_width_precision.completion_contract_failed"
        if errors
        else "printf_star_width_precision.completion_contract_validated"
    )
    append_event(event, status, {"error_count": len(errors)})
    evidence = contract.get("completion_debt_evidence", {}) if isinstance(contract, dict) else {}
    missing = []
    if isinstance(evidence, dict):
        missing = string_array(evidence.get("missing_items_closed", []), "completion_debt_evidence.missing_items_closed", allow_empty=True)
    report = {
        "schema_version": REPORT_SCHEMA,
        "timestamp": utc_now(),
        "event": event,
        "status": status,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "missing_items_bound": sorted(missing),
        "source_count": source_count,
        "implementation_ref_count": implementation_ref_count,
        "test_binding_count": test_binding_count,
        "artifact_refs": [
            rel(CONTRACT),
            "crates/frankenlibc-abi/src/stdio_abi.rs",
            "crates/frankenlibc-abi/tests/stdio_abi_test.rs",
            "crates/frankenlibc-abi/tests/conformance_diff_stdio_printf.rs",
            "tests/conformance/DISCREPANCIES.md",
        ],
        "failure_signature": "none" if not errors else "printf_star_width_precision_completion_contract_failed",
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with LOG.open("w", encoding="utf-8") as handle:
        for row in events:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


contract_value = load_json(CONTRACT, "completion contract")
if not isinstance(contract_value, dict):
    error("completion contract root must be object")
    contract_value = {}

validate_contract(contract_value)
validate_sources(contract_value)

script = ROOT / "scripts/check_printf_star_width_precision_completion_contract.sh"
if not script.is_file() or not (script.stat().st_mode & stat.S_IXUSR):
    error("completion checker must be executable")

write_outputs(contract_value)

if errors:
    print("FAIL printf star width precision completion contract", file=sys.stderr)
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS printf star width precision completion contract "
    f"sources={source_count} tests={test_binding_count} events={len(events)}"
)
PY
