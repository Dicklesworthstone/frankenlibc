#!/usr/bin/env bash
# Validate bd-ef2.1 I/O raw veneer migration completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/io_raw_veneer_migration_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/io_raw_veneer_migration_completion}"
REPORT="${FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_REPORT:-${OUT_DIR}/io_raw_veneer_migration_completion_contract.report.json}"
LOG="${FRANKENLIBC_IO_RAW_VENEER_MIGRATION_COMPLETION_LOG:-${OUT_DIR}/io_raw_veneer_migration_completion_contract.events.jsonl}"

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

BEAD_ID = "bd-ef2"
COMPLETION_BEAD_ID = "bd-ef2.1"
MANIFEST_ID = "io-raw-veneer-migration-completion-contract"
REPORT_SCHEMA = "io_raw_veneer_migration_completion_contract.report.v1"
LOG_SCHEMA = "io_raw_veneer_migration_completion_contract.log.v1"
REQUIRED_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "migrations.primary", "telemetry.primary"}
REQUIRED_SOURCE_IDS = {
    "abi_unistd_raw_routes",
    "abi_io_raw_routes",
    "abi_mmap_raw_routes",
    "abi_io_tests",
    "abi_mmap_tests",
    "abi_unistd_tests",
    "verification_matrix_record",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
SUCCESS_EVENTS = {
    "io_raw_veneer_migration.source_artifacts_validated",
    "io_raw_veneer_migration.expectations_validated",
    "io_raw_veneer_migration.implementation_refs_validated",
    "io_raw_veneer_migration.unit_binding_validated",
    "io_raw_veneer_migration.e2e_binding_validated",
    "io_raw_veneer_migration.migration_binding_validated",
    "io_raw_veneer_migration.telemetry_binding_validated",
    "io_raw_veneer_migration.completion_contract_validated",
}
FAILURE_EVENT = "io_raw_veneer_migration.completion_contract_failed"
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
raw_route_call_site_count = 0
io_abi_test_count = 0
mmap_abi_test_count = 0
unistd_abi_test_count = 0


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


def strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        error(f"{label} must be a non-empty array")
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


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
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
    before = len(errors)
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list):
        error("source_artifacts must be an array")
        return
    seen: set[str] = set()
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
        for needle in strings(artifact.get("required_needles"), f"{artifact_id}.required_needles"):
            if needle not in text:
                error(f"{artifact_id} missing required needle {needle!r}")
        for needle in artifact.get("forbidden_needles", []):
            if not isinstance(needle, str):
                error(f"{artifact_id}.forbidden_needles entries must be strings")
            elif needle in text:
                error(f"{artifact_id} contains forbidden migration route {needle!r}")
    if seen != REQUIRED_SOURCE_IDS:
        error(f"source_artifacts must be exactly {sorted(REQUIRED_SOURCE_IDS)}, got {sorted(seen)}")
    source_count = len(seen)
    append_event(
        "io_raw_veneer_migration.source_artifacts_validated",
        "pass" if len(errors) == before else "fail",
        {"source_count": source_count, "source_ids": sorted(seen)},
    )


def validate_expectations(contract: dict[str, Any]) -> None:
    global raw_route_call_site_count, io_abi_test_count, mmap_abi_test_count, unistd_abi_test_count
    before = len(errors)
    expectations = contract.get("migration_expectations")
    if not isinstance(expectations, dict):
        error("migration_expectations must be an object")
        return
    route_paths = strings(expectations.get("required_route_modules"), "migration_expectations.required_route_modules")
    require(set(route_paths) == {source_paths.get("abi_unistd_raw_routes"), source_paths.get("abi_io_raw_routes"), source_paths.get("abi_mmap_raw_routes")}, "required_route_modules drifted")
    forbidden = expectations.get("forbidden_runtime_route")
    require(forbidden == "libc::syscall(", "forbidden_runtime_route drifted")

    route_text = "\n".join(read_text(path, path) for path in route_paths)
    raw_route_call_site_count = len(re.findall(r"(?:syscall|raw_syscall)::sys_[a-z0-9_]+|crate::(?:io_abi|mmap_abi)::[a-z0-9_]+", route_text))
    require(raw_route_call_site_count >= int(expectations.get("minimum_raw_route_call_sites", 0)), "raw route call-site count below expectation")
    if forbidden and forbidden in route_text:
        error("direct libc::syscall route found in migration route modules")

    io_abi_test_count = read_text(source_paths.get("abi_io_tests", ""), "abi_io_tests").count("#[test]")
    mmap_abi_test_count = read_text(source_paths.get("abi_mmap_tests", ""), "abi_mmap_tests").count("#[test]")
    unistd_abi_test_count = read_text(source_paths.get("abi_unistd_tests", ""), "abi_unistd_tests").count("#[test]")
    require(io_abi_test_count >= int(expectations.get("minimum_io_abi_tests", 0)), "io ABI test count below expectation")
    require(mmap_abi_test_count >= int(expectations.get("minimum_mmap_abi_tests", 0)), "mmap ABI test count below expectation")
    require(unistd_abi_test_count >= int(expectations.get("minimum_unistd_abi_tests", 0)), "unistd ABI test count below expectation")
    append_event(
        "io_raw_veneer_migration.expectations_validated",
        "pass" if len(errors) == before else "fail",
        {
            "raw_route_call_site_count": raw_route_call_site_count,
            "io_abi_test_count": io_abi_test_count,
            "mmap_abi_test_count": mmap_abi_test_count,
            "unistd_abi_test_count": unistd_abi_test_count,
        },
    )


def validate_implementation_refs(contract: dict[str, Any]) -> None:
    before = len(errors)
    refs = contract.get("implementation_refs")
    for index, value in enumerate(strings(refs, "implementation_refs")):
        validate_file_line_ref(value, f"implementation_refs[{index}]")
    append_event(
        "io_raw_veneer_migration.implementation_refs_validated",
        "pass" if len(errors) == before else "fail",
        {"implementation_ref_count": len(refs) if isinstance(refs, list) else 0},
    )


def validate_test_ref(source: str, name: str, context: str) -> None:
    source_path = source_paths.get(source)
    if not source_path:
        error(f"{context} references unknown source {source}")
        return
    text = read_text(source_path, f"{context}.{source}")
    if f"fn {name}" not in text:
        error(f"{context} references missing test {source}::{name}")


def validate_test_binding(section: dict[str, Any], section_name: str, event_name: str) -> None:
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


def validate_migration_binding(section: dict[str, Any]) -> None:
    before = len(errors)
    required_sources = set(strings(section.get("required_sources"), "migrations_primary.required_sources"))
    require(required_sources == {"abi_unistd_raw_routes", "abi_io_raw_routes", "abi_mmap_raw_routes", "verification_matrix_record"}, "migrations_primary.required_sources drifted")
    forbidden_needles = strings(section.get("forbidden_needles"), "migrations_primary.forbidden_needles")
    require(forbidden_needles == ["libc::syscall("], "migrations_primary.forbidden_needles drifted")
    route_sources = {"abi_unistd_raw_routes", "abi_io_raw_routes", "abi_mmap_raw_routes"}
    for source in sorted(required_sources & route_sources):
        text = read_text(source_paths.get(source, ""), source)
        for needle in forbidden_needles:
            if needle in text:
                error(f"{source} contains forbidden migration route {needle!r}")
    commands = strings(section.get("required_commands"), "migrations_primary.required_commands")
    require("bash scripts/check_io_raw_veneer_migration_completion_contract.sh" in commands, "migrations_primary command missing checker")
    required_events = set(strings(section.get("required_completion_events"), "migrations_primary.required_completion_events"))
    require("io_raw_veneer_migration.migration_binding_validated" in required_events, "migrations_primary required event missing")
    append_event(
        "io_raw_veneer_migration.migration_binding_validated",
        "pass" if len(errors) == before else "fail",
        {"source_count": len(required_sources), "forbidden_needles": forbidden_needles},
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
        ("unit_primary", "io_raw_veneer_migration.unit_binding_validated"),
        ("e2e_primary", "io_raw_veneer_migration.e2e_binding_validated"),
        ("telemetry_primary", "io_raw_veneer_migration.telemetry_binding_validated"),
    ]:
        section = evidence.get(section_name)
        if not isinstance(section, dict):
            error(f"completion_debt_evidence.{section_name} must be an object")
            continue
        validate_test_binding(section, section_name, event_name)
    migration = evidence.get("migrations_primary")
    if not isinstance(migration, dict):
        error("completion_debt_evidence.migrations_primary must be an object")
    else:
        validate_migration_binding(migration)


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
    for row in events:
        missing = REQUIRED_LOG_FIELDS - row.keys()
        if missing:
            error(f"telemetry row {row.get('event')} missing fields {sorted(missing)}")
    append_event(
        "io_raw_veneer_migration.telemetry_binding_validated",
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
        "io_raw_veneer_migration.completion_contract_validated",
        "pass",
        {"source_count": source_count, "raw_route_call_site_count": raw_route_call_site_count},
    )

report = {
    "schema_version": REPORT_SCHEMA,
    "timestamp": utc_now(),
    "status": "fail" if errors else "pass",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "source_commit": SOURCE_COMMIT,
    "source_count": source_count,
    "raw_route_call_site_count": raw_route_call_site_count,
    "io_abi_test_count": io_abi_test_count,
    "mmap_abi_test_count": mmap_abi_test_count,
    "unistd_abi_test_count": unistd_abi_test_count,
    "missing_items_closed": sorted(REQUIRED_ITEMS),
    "events": [row["event"] for row in events],
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL io raw veneer migration completion contract", file=sys.stderr)
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS io raw veneer migration completion contract "
    f"sources={source_count} routes={raw_route_call_site_count} "
    f"io_tests={io_abi_test_count} mmap_tests={mmap_abi_test_count} "
    f"unistd_tests={unistd_abi_test_count} events={len(events)}"
)
PY
