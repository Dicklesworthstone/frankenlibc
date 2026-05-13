#!/usr/bin/env bash
# check_unistd_process_filesystem_wave2_completion_contract.sh -- bd-pz1g1.3 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_UNISTD_WAVE2_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/unistd_process_filesystem_wave2_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_UNISTD_WAVE2_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/unistd_process_filesystem_wave2_completion_contract}"
REPORT="${FRANKENLIBC_UNISTD_WAVE2_COMPLETION_REPORT:-${OUT_DIR}/unistd_process_filesystem_wave2_completion_contract.report.json}"
LOG="${FRANKENLIBC_UNISTD_WAVE2_COMPLETION_LOG:-${OUT_DIR}/unistd_process_filesystem_wave2_completion_contract.events.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
REPORT = pathlib.Path(sys.argv[3])
LOG = pathlib.Path(sys.argv[4])
OUT_DIR = pathlib.Path(sys.argv[5])
SOURCE_COMMIT = sys.argv[6]

SCHEMA = "unistd_process_filesystem_wave2_completion_contract.v1"
REPORT_SCHEMA = "unistd_process_filesystem_wave2_completion_contract.report.v1"
BEAD_ID = "bd-pz1g1.3"
PARENT_BEAD = "bd-pz1g1"
FIXTURE_BEAD = "bd-pz1g1.1"
COVERAGE_BEAD = "bd-pz1g1.2"
CAMPAIGN_ID = "fcq-unistd-process-filesystem"
WAVE_ID = "wave-02-unistd-process-filesystem"
TRACE_ID = "bd-pz1g1.3::unistd-process-filesystem-wave2::completion::v1"

REQUIRED_SYMBOLS = [
    "__sched_cpualloc",
    "__sched_cpucount",
    "__sched_cpufree",
    "__sched_rr_get_interval",
    "__sched_setparam",
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__xpg_basename",
    "__xstat",
    "__xstat64",
    "add_key",
    "addmntent",
]
REQUIRED_ARTIFACT_IDS = {
    "wave_fixture",
    "wave_harness",
    "conformance_executor",
    "symbol_fixture_coverage",
    "fixture_coverage_prioritizer",
    "symbol_fixture_coverage_checker",
    "fixture_coverage_prioritizer_checker",
    "completion_contract",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_EVENTS = [
    "unistd_wave2_completion_contract_validated",
    "fixture_wave_bound",
    "coverage_truth_bound",
    "validation_commands_bound",
    "dependency_proof_bound",
]
REQUIRED_EVENT_FIELDS = [
    "timestamp",
    "trace_id",
    "bead_id",
    "parent_bead",
    "campaign_id",
    "wave_id",
    "event",
    "status",
    "source_commit",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_VALIDATION_PREFIXES = [
    "jq empty tests/conformance/unistd_process_filesystem_wave2_completion_contract.v1.json",
    "bash -n scripts/check_unistd_process_filesystem_wave2_completion_contract.sh",
    "bash scripts/check_unistd_process_filesystem_wave2_completion_contract.sh",
    "bash scripts/check_symbol_fixture_coverage.sh",
    "bash scripts/check_fixture_coverage_prioritizer.sh",
    "rustfmt --edition 2024 --check crates/frankenlibc-harness/tests/unistd_process_filesystem_wave2_completion_contract_test.rs",
    "git diff --check -- tests/conformance/unistd_process_filesystem_wave2_completion_contract.v1.json",
    "AGENT_NAME=BrownTern br --no-db dep cycles --json",
    "rch exec -- cargo test -p frankenlibc-harness --test unistd_process_filesystem_wave2_completion_contract_test",
    "rch exec -- cargo check -p frankenlibc-harness --test unistd_process_filesystem_wave2_completion_contract_test",
    "rch exec -- cargo clippy -p frankenlibc-harness --test unistd_process_filesystem_wave2_completion_contract_test",
]
EXPECTED_SOURCE_COMMITS = {
    "fixture_wave": "696cba3a136443a4412db159da1bdde5037ccc64",
    "coverage_truth": "f07bce6b3fc1ff4718ed6ae59642bbf0cec03fab",
    "tracker_closeout": "7271f47e5f03af8c952a7de6faff19b4575f606f",
}
FORBIDDEN_OUTPUT_NEEDLES = [
    "0x",
    "ptr=",
    "address",
    "pid=",
    "inode",
    "st_dev",
    "dev=",
    "key_serial",
    "/tmp",
    "/dev",
    "timestamp",
    "tv_sec",
    "mount path",
]
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_wave_symbol",
    "fixture_wave_drift",
    "ambient_state_leak",
    "stale_coverage_count",
    "missing_coverage_row",
    "non_rch_cargo_validation",
    "missing_validation_command",
    "missing_telemetry_event",
    "missing_telemetry_field",
    "stale_source_commit",
    "dependency_proof_drift",
    "dependency_cycle_detected",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
artifact_refs: set[str] = {str(CONTRACT)}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else ROOT / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "unistd_wave2_completion_contract_failed"


def load_json(path: pathlib.Path, context: str) -> Any:
    artifact_refs.add(rel(path))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "parent_bead": PARENT_BEAD,
        "campaign_id": CAMPAIGN_ID,
        "wave_id": WAVE_ID,
        "event": name,
        "status": status,
        "source_commit": SOURCE_COMMIT,
        "artifact_refs": sorted(artifact_refs),
        "failure_signature": failure_signature,
        **fields,
    }


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def string_array(value: Any, context: str, signature: str) -> list[str]:
    rows = as_array(value, context, signature)
    result: list[str] = []
    for row in rows:
        if isinstance(row, str):
            result.append(row)
        else:
            add_error(signature, f"{context} must contain only strings")
    return result


def artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = as_array(contract.get("source_artifacts"), "source_artifacts")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        obj = as_object(row, "source_artifacts[]")
        artifact_id = obj.get("id")
        path = obj.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", "source artifact id must be a non-empty string")
            continue
        if not isinstance(path, str) or not path:
            add_error("malformed_contract", f"source artifact {artifact_id} path must be non-empty")
            continue
        result[artifact_id] = obj
        if not resolve(path).exists():
            add_error("missing_source_artifact", f"missing source artifact {artifact_id}: {path}")
    missing = sorted(REQUIRED_ARTIFACT_IDS - set(result))
    if missing:
        add_error("missing_source_artifact", f"missing source artifact ids: {missing}")
    return result


def require_contract_shape(contract: dict[str, Any]) -> None:
    expected = {
        "schema_version": SCHEMA,
        "bead_id": BEAD_ID,
        "parent_bead": PARENT_BEAD,
        "fixture_bead": FIXTURE_BEAD,
        "coverage_bead": COVERAGE_BEAD,
        "campaign_id": CAMPAIGN_ID,
        "wave_id": WAVE_ID,
    }
    for key, expected_value in expected.items():
        if contract.get(key) != expected_value:
            add_error("malformed_contract", f"{key} must be {expected_value}")
    symbols = string_array(contract.get("first_wave_symbols"), "first_wave_symbols", "missing_wave_symbol")
    if symbols != REQUIRED_SYMBOLS:
        add_error(
            "missing_wave_symbol",
            f"first_wave_symbols must exactly match refreshed wave-02 symbols: {REQUIRED_SYMBOLS}",
        )


def require_source_commits(contract: dict[str, Any]) -> None:
    commits = as_object(contract.get("source_commits"), "source_commits")
    for key, expected in EXPECTED_SOURCE_COMMITS.items():
        value = commits.get(key)
        if value != expected:
            add_error(
                "stale_source_commit",
                f"source_commits.{key} must bind expected proof commit {expected}",
            )


def require_fixture(contract: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    fixture_artifact = artifacts.get("wave_fixture", {})
    fixture_path = resolve(str(fixture_artifact.get("path", "")))
    fixture = as_object(load_json(fixture_path, "wave fixture"), "wave fixture", "fixture_wave_drift")
    campaign = as_object(fixture.get("campaign"), "wave fixture campaign", "fixture_wave_drift")
    coverage = as_object(contract.get("coverage_requirements"), "coverage_requirements")

    if fixture.get("family") != coverage.get("fixture_family"):
        add_error("fixture_wave_drift", "fixture family does not match coverage requirement")
    if campaign.get("campaign_id") != CAMPAIGN_ID or campaign.get("wave_id") != WAVE_ID:
        add_error("fixture_wave_drift", "fixture campaign id or wave id drifted")
    if campaign.get("ambient_state_policy") != coverage.get("ambient_state_policy"):
        add_error("fixture_wave_drift", "fixture ambient-state policy drifted")
    if string_array(campaign.get("first_wave_symbols"), "fixture campaign first_wave_symbols", "missing_wave_symbol") != REQUIRED_SYMBOLS:
        add_error("missing_wave_symbol", "fixture campaign first_wave_symbols drifted")
    if as_array(campaign.get("residual_symbols"), "fixture campaign residual_symbols", "fixture_wave_drift") != []:
        add_error("fixture_wave_drift", "wave-02 fixture must have no residual symbols")
    if string_array(fixture.get("structured_log_fields"), "fixture structured_log_fields", "fixture_wave_drift") != coverage.get("structured_log_fields"):
        add_error("fixture_wave_drift", "fixture structured_log_fields drifted")

    cases = as_array(fixture.get("cases"), "fixture cases", "fixture_wave_drift")
    if len(cases) < int(coverage.get("required_case_count", 0)):
        add_error("fixture_wave_drift", "fixture case count is below required strict+hardened rows")

    modes_by_symbol: dict[str, set[str]] = {}
    for index, raw_case in enumerate(cases):
        case = as_object(raw_case, f"fixture cases[{index}]", "fixture_wave_drift")
        function = case.get("function")
        mode = case.get("mode")
        if isinstance(function, str) and isinstance(mode, str):
            modes_by_symbol.setdefault(function, set()).add(mode)
        output = case.get("expected_output")
        if not isinstance(output, str):
            add_error("fixture_wave_drift", f"case {index} expected_output must be a string")
            continue
        for field in coverage.get("structured_log_fields", []):
            if f"{field}=" not in output:
                add_error("fixture_wave_drift", f"case {index} output missing structured field {field}")
        for needle in FORBIDDEN_OUTPUT_NEEDLES:
            if needle in output:
                add_error("ambient_state_leak", f"case {index} output leaks ambient detail {needle}")

    required_modes = set(string_array(coverage.get("required_modes"), "coverage_requirements.required_modes", "fixture_wave_drift"))
    for symbol in REQUIRED_SYMBOLS:
        modes = modes_by_symbol.get(symbol, set())
        missing_modes = sorted(required_modes - modes)
        if missing_modes:
            add_error("missing_wave_symbol", f"{symbol} missing modes {missing_modes}")

    events.append(
        event(
            "fixture_wave_bound",
            "pass" if not any(err["failure_signature"] in {"fixture_wave_drift", "missing_wave_symbol", "ambient_state_leak"} for err in errors) else "fail",
            "none" if not any(err["failure_signature"] in {"fixture_wave_drift", "missing_wave_symbol", "ambient_state_leak"} for err in errors) else primary_signature(),
            case_count=len(cases),
            symbol_count=len(modes_by_symbol),
        )
    )


def row_has_string(row: dict[str, Any], key: str, expected: str) -> bool:
    value = row.get(key)
    return isinstance(value, list) and expected in value


def require_coverage(contract: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    requirements = as_object(contract.get("coverage_requirements"), "coverage_requirements")
    coverage_path = resolve(str(artifacts.get("symbol_fixture_coverage", {}).get("path", "")))
    prioritizer_path = resolve(str(artifacts.get("fixture_coverage_prioritizer", {}).get("path", "")))
    coverage = as_object(load_json(coverage_path, "symbol fixture coverage"), "symbol fixture coverage", "stale_coverage_count")
    prioritizer = as_object(load_json(prioritizer_path, "fixture coverage prioritizer"), "fixture coverage prioritizer", "stale_coverage_count")
    symbol_rows = {
        row.get("symbol"): row
        for row in as_array(coverage.get("symbols"), "coverage.symbols", "stale_coverage_count")
        if isinstance(row, dict)
    }

    required_modes = set(string_array(requirements.get("required_modes"), "coverage_requirements.required_modes", "stale_coverage_count"))
    fixture_file = str(requirements.get("fixture_file"))
    for symbol in REQUIRED_SYMBOLS:
        row = symbol_rows.get(symbol)
        if not isinstance(row, dict):
            add_error("missing_coverage_row", f"missing coverage row for {symbol}")
            continue
        if row.get("covered") is not True:
            add_error("stale_coverage_count", f"{symbol} is not marked covered")
        if int(row.get("fixture_case_count", 0)) < len(required_modes):
            add_error("stale_coverage_count", f"{symbol} fixture_case_count does not cover both modes")
        if not row_has_string(row, "fixture_files", fixture_file):
            add_error("stale_coverage_count", f"{symbol} coverage row does not cite {fixture_file}")
        modes = set(row.get("fixture_modes", [])) if isinstance(row.get("fixture_modes"), list) else set()
        if not required_modes.issubset(modes):
            add_error("stale_coverage_count", f"{symbol} coverage row missing fixture modes {sorted(required_modes - modes)}")

    campaigns = [
        row
        for row in as_array(prioritizer.get("campaigns"), "prioritizer.campaigns", "stale_coverage_count")
        if isinstance(row, dict) and row.get("campaign_id") == CAMPAIGN_ID
    ]
    if len(campaigns) != 1:
        add_error("stale_coverage_count", f"expected one prioritizer campaign row for {CAMPAIGN_ID}")
    else:
        campaign = campaigns[0]
        if int(campaign.get("target_covered", 0)) < int(requirements.get("min_target_covered", 0)):
            add_error("stale_coverage_count", "prioritizer target_covered is stale")
        if int(campaign.get("target_uncovered", 10**9)) > int(requirements.get("max_target_uncovered", 10**9)):
            add_error("stale_coverage_count", "prioritizer target_uncovered is stale")
        if float(campaign.get("current_coverage_pct", 0.0)) < float(requirements.get("min_current_coverage_pct", 0.0)):
            add_error("stale_coverage_count", "prioritizer current_coverage_pct is stale")
        if requirements.get("next_wave_must_exclude_completed_symbols") is not True:
            add_error("stale_coverage_count", "next_wave_must_exclude_completed_symbols must be true")
        next_wave = set(campaign.get("first_wave_symbols", [])) if isinstance(campaign.get("first_wave_symbols"), list) else set()
        leaked = sorted(set(REQUIRED_SYMBOLS) & next_wave)
        if leaked:
            add_error("stale_coverage_count", f"covered symbols remain in next prioritizer wave: {leaked}")

    events.append(
        event(
            "coverage_truth_bound",
            "pass" if not any(err["failure_signature"] in {"stale_coverage_count", "missing_coverage_row"} for err in errors) else "fail",
            "none" if not any(err["failure_signature"] in {"stale_coverage_count", "missing_coverage_row"} for err in errors) else primary_signature(),
            required_symbol_count=len(REQUIRED_SYMBOLS),
        )
    )


def require_validation_commands(contract: dict[str, Any]) -> None:
    commands = string_array(contract.get("validation_commands"), "validation_commands", "missing_validation_command")
    for prefix in REQUIRED_VALIDATION_PREFIXES:
        if not any(command.startswith(prefix) for command in commands):
            add_error("missing_validation_command", f"validation_commands missing prefix: {prefix}")
    for command in commands:
        if "cargo " in command and not command.startswith("rch exec -- "):
            add_error("non_rch_cargo_validation", f"cargo validation must be rch-backed: {command}")
    events.append(
        event(
            "validation_commands_bound",
            "pass" if not any(err["failure_signature"] in {"missing_validation_command", "non_rch_cargo_validation"} for err in errors) else "fail",
            "none" if not any(err["failure_signature"] in {"missing_validation_command", "non_rch_cargo_validation"} for err in errors) else primary_signature(),
            validation_command_count=len(commands),
        )
    )


def require_telemetry_contract(contract: dict[str, Any]) -> None:
    telemetry = as_object(contract.get("telemetry_contract"), "telemetry_contract")
    events_declared = string_array(telemetry.get("required_events"), "telemetry_contract.required_events", "missing_telemetry_event")
    fields_declared = string_array(telemetry.get("required_fields"), "telemetry_contract.required_fields", "missing_telemetry_field")
    missing_events = sorted(set(REQUIRED_EVENTS) - set(events_declared))
    missing_fields = sorted(set(REQUIRED_EVENT_FIELDS) - set(fields_declared))
    if missing_events:
        add_error("missing_telemetry_event", f"telemetry contract missing events {missing_events}")
    if missing_fields:
        add_error("missing_telemetry_field", f"telemetry contract missing fields {missing_fields}")


def require_dependency_proof(contract: dict[str, Any]) -> None:
    proof = as_object(contract.get("dependency_proof"), "dependency_proof")
    if proof.get("command") != "AGENT_NAME=BrownTern br --no-db dep cycles --json":
        add_error("dependency_proof_drift", "dependency_proof.command drifted")
    if proof.get("expected_empty") is not True:
        add_error("dependency_proof_drift", "dependency_proof.expected_empty must be true")
    if set(string_array(proof.get("prerequisite_beads"), "dependency_proof.prerequisite_beads", "dependency_proof_drift")) != {FIXTURE_BEAD, COVERAGE_BEAD}:
        add_error("dependency_proof_drift", "dependency_proof prerequisites drifted")
    commits = as_object(contract.get("source_commits"), "source_commits")
    if proof.get("tracker_closeout_commit") != commits.get("tracker_closeout"):
        add_error("dependency_proof_drift", "dependency_proof tracker closeout commit must match source_commits")

    result = subprocess.run(
        ["br", "--no-db", "dep", "cycles", "--json"],
        cwd=ROOT,
        env={"AGENT_NAME": "BrownTern", **dict(__import__("os").environ)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        add_error("dependency_cycle_detected", f"br dep cycles failed: {result.stderr.strip()}")
    else:
        try:
            cycles = json.loads(result.stdout)
        except Exception as exc:
            add_error("dependency_cycle_detected", f"br dep cycles emitted non-json output: {exc}")
        else:
            has_cycles = True
            if cycles == []:
                has_cycles = False
            elif isinstance(cycles, dict):
                has_cycles = bool(cycles.get("count", 0) or cycles.get("cycles", []))
            if has_cycles:
                add_error("dependency_cycle_detected", f"dependency cycles present: {cycles}")

    events.append(
        event(
            "dependency_proof_bound",
            "pass" if not any(err["failure_signature"] in {"dependency_proof_drift", "dependency_cycle_detected"} for err in errors) else "fail",
            "none" if not any(err["failure_signature"] in {"dependency_proof_drift", "dependency_cycle_detected"} for err in errors) else primary_signature(),
            command=proof.get("command"),
        )
    )


contract = as_object(load_json(CONTRACT, "completion contract"), "completion contract")
require_contract_shape(contract)
artifacts = artifact_map(contract)
require_source_commits(contract)
require_telemetry_contract(contract)
require_fixture(contract, artifacts)
require_coverage(contract, artifacts)
require_validation_commands(contract)
require_dependency_proof(contract)

status = "pass" if not errors else "fail"
events.insert(
    0,
    event(
        "unistd_wave2_completion_contract_validated",
        status,
        "none" if not errors else primary_signature(),
        error_count=len(errors),
    ),
)
for row in events:
    row["artifact_refs"] = sorted(artifact_refs)
    for field in REQUIRED_EVENT_FIELDS:
        if field not in row:
            row[field] = ""

report = {
    "schema_version": REPORT_SCHEMA,
    "status": status,
    "bead_id": BEAD_ID,
    "parent_bead": PARENT_BEAD,
    "campaign_id": CAMPAIGN_ID,
    "wave_id": WAVE_ID,
    "source_commit": SOURCE_COMMIT,
    "summary": {
        "error_count": len(errors),
        "source_artifact_count": len(artifacts),
        "required_symbol_count": len(REQUIRED_SYMBOLS),
        "event_count": len(events),
    },
    "errors": errors,
    "artifact_refs": sorted(artifact_refs),
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)

print(f"check_unistd_process_filesystem_wave2_completion_contract: PASS ({len(REQUIRED_SYMBOLS)} symbols)")
PY
