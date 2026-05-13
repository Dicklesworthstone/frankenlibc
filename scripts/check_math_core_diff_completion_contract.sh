#!/usr/bin/env bash
# Validate bd-xrmnr.1 math core diff completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/math_core_diff_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/math_core_diff_completion}"
REPORT="${FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_REPORT:-${OUT_DIR}/math_core_diff_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_LOG:-${OUT_DIR}/math_core_diff_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import shlex
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

SCHEMA = "math_core_diff_completion_contract.v1"
REPORT_SCHEMA = "math_core_diff_completion_contract.report.v1"
LOG_SCHEMA = "math_core_diff_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-xrmnr"
COMPLETION_BEAD = "bd-xrmnr.1"
EXPECTED_MISSING = {
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "math_abi",
    "core_math_exports",
    "math_diff_harness",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_TESTS = {
    "diff_sqrt_exact",
    "diff_fabs_exact",
    "diff_floor_ceil_exact",
    "diff_fmod_exact",
    "diff_sin_cos_tan_within_4_ulps",
    "diff_atan2_within_4_ulps",
    "diff_exp_log_pow_within_4_ulps",
    "diff_hyperbolic_within_4_ulps",
    "math_diff_coverage_report",
}
REQUIRED_COMMANDS = {
    "bash scripts/check_math_core_diff_completion_contract.sh",
    "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_abi cargo test -p frankenlibc-abi --test conformance_diff_math -- --nocapture",
    "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_harness cargo test -p frankenlibc-harness --test math_core_diff_completion_contract_test -- --nocapture",
    "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_clippy cargo clippy -p frankenlibc-harness --test math_core_diff_completion_contract_test -- -D warnings",
}
REQUIRED_EVENTS = {
    "math_core_diff.source_artifacts_validated",
    "math_core_diff.conformance_binding_validated",
    "math_core_diff.telemetry_binding_validated",
    "math_core_diff.completion_contract_validated",
    "math_core_diff.completion_contract_failed",
}
REQUIRED_LOG_FIELDS = {
    "schema_version",
    "timestamp",
    "trace_id",
    "event",
    "level",
    "status",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "artifact_refs",
    "details",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_count = 0
implementation_ref_count = 0
test_count = 0
command_count = 0


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


def string_set(value: Any, label: str, allow_empty: bool = False) -> set[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.add(item)
    return result


def split_command(command: str, label: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError as exc:
        error(f"{label} must be shell-parseable: {exc}: {command}")
        return []


def validate_remote_cargo_command(command: str, label: str) -> None:
    if "[RCH] local" in command or "remote execution failed" in command:
        error(f"{label} must not include local rch fallback evidence: {command}")

    tokens = split_command(command, label)
    shell_wrapped = "bash" in tokens or "sh" in tokens or "-c" in tokens
    if "cargo" in command and "cargo" not in tokens and shell_wrapped:
        error(f"{label} must not shell-wrap cargo: {command}")
        return

    if "cargo" not in tokens:
        return

    cargo_index = tokens.index("cargo")
    if shell_wrapped and (
        "bash" in tokens[:cargo_index] or "sh" in tokens[:cargo_index] or "-c" in tokens[:cargo_index]
    ):
        error(f"{label} must not shell-wrap cargo: {command}")
        return

    if "RCH_FORCE_REMOTE=true" not in tokens:
        error(f"{label} must set RCH_FORCE_REMOTE=true: {command}")

    try:
        rch_index = tokens.index("rch")
    except ValueError:
        error(f"{label} must run cargo through rch exec: {command}")
        return

    if rch_index + 1 >= len(tokens) or tokens[rch_index + 1] != "exec":
        error(f"{label} must use rch exec: {command}")
        return

    try:
        dashdash_index = tokens.index("--", rch_index + 2)
    except ValueError:
        error(f"{label} must use rch exec -- env: {command}")
        return

    if dashdash_index >= cargo_index:
        error(f"{label} must place cargo after rch exec -- env: {command}")
        return

    if dashdash_index + 1 >= len(tokens) or tokens[dashdash_index + 1] != "env":
        error(f"{label} must use env after rch exec --: {command}")

    env_tokens = tokens[dashdash_index + 1 : cargo_index]
    if not any(token.startswith("CARGO_TARGET_DIR=") and token != "CARGO_TARGET_DIR=" for token in env_tokens):
        error(f"{label} must set isolated CARGO_TARGET_DIR before cargo: {command}")


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
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
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
        for needle in string_set(source.get("required_needles"), f"{source_id}.required_needles"):
            if needle not in text:
                error(f"source artifact {source_id} missing required needle: {needle}")
        if source_id == "completion_checker" and not (path.stat().st_mode & stat.S_IXUSR):
            error("scripts/check_math_core_diff_completion_contract.sh must be executable")
    missing = REQUIRED_SOURCE_IDS - ids
    extra = ids - REQUIRED_SOURCE_IDS
    require(not missing, f"source_artifacts missing ids: {sorted(missing)}")
    require(not extra, f"source_artifacts has unexpected ids: {sorted(extra)}")
    source_count = len(ids)


def validate_refs(contract: dict[str, Any]) -> None:
    global implementation_ref_count
    refs = contract.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        error("implementation_refs must be a non-empty array")
        return
    for index, value in enumerate(refs):
        validate_file_line_ref(value, f"implementation_refs[{index}]")
    implementation_ref_count = len(refs)


def validate_conformance(contract: dict[str, Any]) -> None:
    global test_count, command_count
    binding = contract.get("conformance_binding")
    if not isinstance(binding, dict):
        error("conformance_binding must be an object")
        return
    tests = string_set(binding.get("required_test_names"), "conformance_binding.required_test_names")
    commands = string_set(binding.get("required_commands"), "conformance_binding.required_commands")
    outputs = string_set(binding.get("expected_output_needles"), "conformance_binding.expected_output_needles")
    failures = string_set(binding.get("failure_signatures"), "conformance_binding.failure_signatures")
    missing_tests = REQUIRED_TESTS - tests
    missing_commands = REQUIRED_COMMANDS - commands
    require(not missing_tests, f"conformance binding missing tests: {sorted(missing_tests)}")
    require(not missing_commands, f"conformance binding missing commands: {sorted(missing_commands)}")
    require('"divergences":0' in outputs, "expected outputs must include zero divergence telemetry")
    require('"ulp_tolerance":4' in outputs, "expected outputs must include ULP tolerance telemetry")
    require("sqrt divergences" in failures, "failure signatures must name sqrt divergence output")
    require("hyperbolic divergences" in failures, "failure signatures must name hyperbolic divergence output")
    for command in commands:
        validate_remote_cargo_command(command, "conformance_binding.required_commands")
    test_count = len(tests)
    command_count = len(commands)


def validate_telemetry(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_binding")
    if not isinstance(telemetry, dict):
        error("telemetry_binding must be an object")
        return
    require(telemetry.get("report_schema") == REPORT_SCHEMA, "telemetry report schema mismatch")
    require(telemetry.get("log_schema") == LOG_SCHEMA, "telemetry log schema mismatch")
    declared_events = string_set(telemetry.get("required_events"), "telemetry_binding.required_events")
    declared_fields = string_set(telemetry.get("required_fields"), "telemetry_binding.required_fields")
    missing_events = REQUIRED_EVENTS - declared_events
    missing_fields = REQUIRED_LOG_FIELDS - declared_fields
    require(not missing_events, f"telemetry missing events: {sorted(missing_events)}")
    require(not missing_fields, f"telemetry missing log fields: {sorted(missing_fields)}")


contract = load_json(CONTRACT, "contract")
if isinstance(contract, dict):
    require(contract.get("schema_version") == SCHEMA, "schema_version mismatch")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        error("completion_debt_evidence must be an object")
    else:
        missing_items = string_set(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed")
        require(missing_items == EXPECTED_MISSING, f"missing_items_closed mismatch: {sorted(missing_items)}")
    validate_sources(contract)
    validate_refs(contract)
    validate_conformance(contract)
    validate_telemetry(contract)

passed = not errors
if passed:
    append_event(
        "math_core_diff.source_artifacts_validated",
        "pass",
        {"source_artifacts": source_count, "implementation_refs": implementation_ref_count},
    )
    append_event(
        "math_core_diff.conformance_binding_validated",
        "pass",
        {"tests": test_count, "commands": command_count},
    )
    append_event(
        "math_core_diff.telemetry_binding_validated",
        "pass",
        {"required_events": sorted(REQUIRED_EVENTS), "required_fields": sorted(REQUIRED_LOG_FIELDS)},
    )
    append_event(
        "math_core_diff.completion_contract_validated",
        "pass",
        {"contract": rel(CONTRACT), "report": rel(REPORT), "log": rel(LOG)},
    )
else:
    append_event(
        "math_core_diff.completion_contract_failed",
        "fail",
        {"errors": errors},
    )

report = {
    "schema_version": REPORT_SCHEMA,
    "generated_at": utc_now(),
    "passed": passed,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(CONTRACT),
    "source_artifacts": source_count,
    "implementation_refs": implementation_ref_count,
    "conformance_tests": test_count,
    "validation_commands": command_count,
    "events": [event["event"] for event in events],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if passed:
    print(
        "math_core_diff_completion_contract: PASS "
        f"sources={source_count} refs={implementation_ref_count} tests={test_count} events={len(events)}"
    )
    sys.exit(0)

print(
    "math_core_diff_completion_contract: FAIL "
    f"errors={len(errors)} report={rel(REPORT)} log={rel(LOG)}",
    file=sys.stderr,
)
for message in errors:
    print(f"- {message}", file=sys.stderr)
sys.exit(1)
PY
