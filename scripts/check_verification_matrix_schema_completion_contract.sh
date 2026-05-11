#!/usr/bin/env bash
# check_verification_matrix_schema_completion_contract.sh - bd-1s7.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_CONTRACT:-$ROOT/tests/conformance/verification_matrix_schema_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_REPORT:-$OUT_DIR/verification_matrix_schema_completion_contract.report.json}"
LOG="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_LOG:-$OUT_DIR/verification_matrix_schema_completion_contract.log.jsonl}"
GATE_TRANSCRIPT="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_GATE_TRANSCRIPT:-$OUT_DIR/verification_matrix_schema_completion_contract.gate.txt}"
BEADS="${FRANKENLIBC_VERIFY_MATRIX_SCHEMA_BEADS:-${FRANKENLIBC_VERIFICATION_MATRIX_BEADS:-$ROOT/.beads/issues.jsonl}}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GATE_TRANSCRIPT")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
GATE_TRANSCRIPT="$GATE_TRANSCRIPT" \
BEADS="$BEADS" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GATE_TRANSCRIPT = pathlib.Path(os.environ["GATE_TRANSCRIPT"])
BEADS = pathlib.Path(os.environ["BEADS"])
if not BEADS.is_absolute():
    BEADS = ROOT / BEADS

EXPECTED_SCHEMA = "verification_matrix_schema_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "verification_matrix_schema_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-1s7.1-verification-matrix-schema-completion-contract"
ORIGINAL_BEAD = "bd-1s7"
COMPLETION_BEAD = "bd-1s7.1"
REQUIRED_MISSING_ITEMS = {"tests.e2e.primary", "tests.conformance.primary"}
PASS_EVENTS = {
    "verification_matrix_schema_e2e_bindings_verified",
    "verification_matrix_schema_conformance_bindings_verified",
    "verification_matrix_schema_gate_replayed",
    "verification_matrix_schema_contract_verified",
    "verification_matrix_schema_completion_contract_pass",
}
FAIL_EVENT = "verification_matrix_schema_completion_contract_fail"
REQUIRED_E2E_TEST_NAMES = {
    "schema_has_row_contract_and_stream_examples",
    "all_critique_beads_have_rows",
    "entry_coverage_counts_consistent",
    "dashboard_stats_consistent_with_entries",
    "entries_have_non_empty_backfill_rows",
    "checker_replays_verification_matrix_schema_gate",
    "checker_rejects_local_cargo_command",
}
REQUIRED_CONFORMANCE_TEST_NAMES = {
    "matrix_exists_and_valid_json",
    "schema_defines_required_types",
    "schema_has_row_contract_and_stream_examples",
    "entries_have_valid_coverage_statuses",
    "no_empty_bead_ids",
    "manifest_binds_verification_matrix_schema_evidence",
    "checker_validates_schema_contract_and_emits_report_log",
    "checker_rejects_missing_stream_example",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = git_head()


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def artifact_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text or f"def {name}(" in text


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "source_commit": SOURCE_COMMIT,
            "status": status,
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "verification_matrix_schema_completion_contract_failed",
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(section: dict[str, Any], section_name: str, sources: dict[str, str], required_names: set[str]) -> list[str]:
    found: list[str] = []
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{section_name}.required_test_refs must be a non-empty array")
        return found
    source_cache = {source_id: source_text(path, f"test_source.{source_id}") for source_id, path in sources.items()}
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in source_cache:
            err(f"{section_name}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"{section_name}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.split("::", 1)[1] for item in found if "::" in item}
    missing_required = sorted(required_names - found_names)
    if missing_required:
        err(f"{section_name}.required_test_refs missing required bindings {missing_required}")
    for command in section.get("required_commands", []):
        if not isinstance(command, str):
            err(f"{section_name}.required_commands entries must be strings")
            continue
        if "cargo " in command and "rch exec --" not in command:
            err(f"{section_name} cargo command must be rch-backed: {command}")
    return found


def run_gate(artifacts: dict[str, str]) -> dict[str, Any]:
    gate_env = os.environ.copy()
    gate_env["FRANKENLIBC_VERIFICATION_MATRIX_BEADS"] = str(BEADS)
    proc = subprocess.run(
        ["bash", artifacts.get("verification_matrix_gate", "scripts/check_verification_matrix.sh")],
        cwd=ROOT,
        env=gate_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    transcript = proc.stdout
    if proc.stderr:
        transcript += "\n[stderr]\n" + proc.stderr
    GATE_TRANSCRIPT.write_text(transcript, encoding="utf-8")
    if proc.returncode != 0:
        err(f"verification_matrix gate failed with exit {proc.returncode}")
    if "check_verification_matrix: PASS" not in transcript:
        err("verification_matrix gate transcript missing PASS sentinel")
    return {
        "label": "verification_matrix",
        "exit_code": proc.returncode,
        "pass_sentinel": "check_verification_matrix: PASS",
        "transcript": rel(GATE_TRANSCRIPT),
    }


def validate_required_source_text(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    required_text = contract.get("required_source_text", {})
    if not isinstance(required_text, dict) or not required_text:
        err("required_schema_contract.required_source_text must be a non-empty object")
        return {"checked_artifacts": 0, "checked_tokens": 0}
    checked_tokens = 0
    for artifact_id, needles in required_text.items():
        text = source_text(artifacts.get(str(artifact_id)), f"required_source_text.{artifact_id}")
        for needle in as_string_list(needles, f"required_source_text.{artifact_id}"):
            checked_tokens += 1
            require(needle in text, f"{artifact_id} missing required text {needle!r}")
    return {"checked_artifacts": len(required_text), "checked_tokens": checked_tokens}


def validate_schema_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_schema_contract", {})
    if not isinstance(contract, dict):
        err("required_schema_contract must be an object")
        contract = {}
    matrix = load_json(ROOT / artifacts.get("verification_matrix", ""), "verification matrix")
    schema = matrix.get("schema", {})
    if not isinstance(schema, dict):
        err("verification_matrix.schema must be an object")
        schema = {}

    require(matrix.get("matrix_version") == contract.get("matrix_version"), "matrix_version mismatch")
    require(schema.get("row_schema_version") == contract.get("row_schema_version"), "row_schema_version mismatch")
    for key in ["coverage_statuses", "obligation_types", "row_status_states", "row_status_transitions", "row_template", "stream_examples"]:
        require(key in schema, f"schema missing required key {key}")

    coverage_statuses = schema.get("coverage_statuses", {})
    obligation_types = schema.get("obligation_types", {})
    row_status_states = schema.get("row_status_states", {})
    row_template = schema.get("row_template", {})
    transitions = schema.get("row_status_transitions", [])
    stream_examples = schema.get("stream_examples", [])

    if not isinstance(coverage_statuses, dict):
        err("schema.coverage_statuses must be an object")
        coverage_statuses = {}
    if not isinstance(obligation_types, dict):
        err("schema.obligation_types must be an object")
        obligation_types = {}
    if not isinstance(row_status_states, dict):
        err("schema.row_status_states must be an object")
        row_status_states = {}
    if not isinstance(row_template, dict):
        err("schema.row_template must be an object")
        row_template = {}
    if not isinstance(transitions, list):
        err("schema.row_status_transitions must be an array")
        transitions = []
    if not isinstance(stream_examples, list):
        err("schema.stream_examples must be an array")
        stream_examples = []

    for status in as_string_list(contract.get("required_coverage_statuses"), "required_schema_contract.required_coverage_statuses"):
        require(status in coverage_statuses, f"coverage_statuses missing {status}")
    for obligation in as_string_list(contract.get("required_obligation_types"), "required_schema_contract.required_obligation_types"):
        require(obligation in obligation_types, f"obligation_types missing {obligation}")
    for state in as_string_list(contract.get("required_row_status_states"), "required_schema_contract.required_row_status_states"):
        require(state in row_status_states, f"row_status_states missing {state}")
    for key in as_string_list(contract.get("required_row_template_keys"), "required_schema_contract.required_row_template_keys"):
        require(key in row_template, f"row_template missing {key}")

    transition_targets = {
        transition.get("to")
        for transition in transitions
        if isinstance(transition, dict) and isinstance(transition.get("to"), str)
    }
    expected_targets = set(as_string_list(contract.get("required_transition_targets"), "required_schema_contract.required_transition_targets"))
    require(transition_targets == expected_targets, f"row_status_transitions targets mismatch: {sorted(transition_targets)}")
    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            err(f"row_status_transitions[{index}] must be an object")
            continue
        require(bool(transition.get("when")), f"row_status_transitions[{index}] missing non-empty when clause")

    required_streams = set(as_string_list(contract.get("required_stream_examples"), "required_schema_contract.required_stream_examples"))
    seen_streams: set[str] = set()
    required_row_keys = as_string_list(contract.get("required_row_template_keys"), "required_schema_contract.required_row_template_keys")
    list_keys = {"unit_cmds", "e2e_cmds", "expected_assertions", "log_schema_refs", "artifact_paths", "perf_proof_refs", "close_blockers"}
    for index, row in enumerate(stream_examples):
        if not isinstance(row, dict):
            err(f"stream_examples[{index}] must be an object")
            continue
        stream = row.get("stream")
        if isinstance(stream, str):
            seen_streams.add(stream)
        else:
            err(f"stream_examples[{index}].stream must be a string")
        require(row.get("status") in expected_targets, f"stream_examples[{index}].status must be a valid row state")
        for key in required_row_keys:
            require(key in row, f"stream_examples[{index}] missing key {key}")
        for key in list_keys:
            require(isinstance(row.get(key), list), f"stream_examples[{index}].{key} must be an array")
        for key in ["unit_cmds", "expected_assertions", "log_schema_refs", "artifact_paths"]:
            require(bool(row.get(key)), f"stream_examples[{index}].{key} must be non-empty")
    require(required_streams <= seen_streams, f"stream_examples missing required streams {sorted(required_streams - seen_streams)}")

    source_text_summary = validate_required_source_text(contract, artifacts)
    return {
        "matrix_version": matrix.get("matrix_version"),
        "row_schema_version": schema.get("row_schema_version"),
        "coverage_statuses": sorted(coverage_statuses.keys()),
        "obligation_types": sorted(obligation_types.keys()),
        "transition_targets": sorted(transition_targets),
        "stream_examples": sorted(seen_streams),
        "source_text": source_text_summary,
    }


def write_outputs(manifest: dict[str, Any], status: str, summary: dict[str, Any], gate_results: list[dict[str, Any]], e2e_refs: list[str], conformance_refs: list[str]) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "schema_summary": summary,
        "gate_results": gate_results,
        "e2e_bindings": e2e_refs,
        "conformance_bindings": conformance_refs,
        "events": events,
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")


started = time.time_ns()
manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, f"manifest_id must be {EXPECTED_MANIFEST}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
artifacts = validate_source_artifacts(manifest)

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
require(set(as_string_list(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed")) == REQUIRED_MISSING_ITEMS, "missing_items_closed must be exactly e2e and conformance primary")

e2e_section = evidence.get("e2e_primary", {})
if not isinstance(e2e_section, dict):
    err("e2e_primary must be an object")
    e2e_section = {}
conformance_section = evidence.get("conformance_primary", {})
if not isinstance(conformance_section, dict):
    err("conformance_primary must be an object")
    conformance_section = {}
require(e2e_section.get("missing_item_id") == "tests.e2e.primary", "e2e_primary missing_item_id mismatch")
require(conformance_section.get("missing_item_id") == "tests.conformance.primary", "conformance_primary missing_item_id mismatch")

sources = {
    "verification_matrix_harness": artifacts.get("verification_matrix_harness", ""),
    "completion_harness": artifacts.get("completion_harness", ""),
}
e2e_refs = validate_test_refs(e2e_section, "e2e_primary", sources, REQUIRED_E2E_TEST_NAMES)
conformance_refs = validate_test_refs(conformance_section, "conformance_primary", sources, REQUIRED_CONFORMANCE_TEST_NAMES)
for script in as_string_list(e2e_section.get("required_scripts"), "e2e_primary.required_scripts"):
    require(script in artifacts.values(), f"e2e required script {script} must be listed in source_artifacts")
for artifact in as_string_list(conformance_section.get("required_artifacts"), "conformance_primary.required_artifacts"):
    require(artifact in artifacts.values(), f"conformance artifact {artifact} must be listed in source_artifacts")

gate_results = [run_gate(artifacts)]
summary = validate_schema_contract(manifest, artifacts)

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
required_report_fields = as_string_list(telemetry.get("required_report_fields"), "telemetry.required_report_fields")
required_log_fields = as_string_list(telemetry.get("required_log_fields"), "telemetry.required_log_fields")
require(set(as_string_list(telemetry.get("required_events"), "telemetry.required_events")) == PASS_EVENTS, "telemetry.required_events must match pass event set")
require(FAIL_EVENT in as_string_list(telemetry.get("forbidden_pass_events"), "telemetry.forbidden_pass_events"), "telemetry.forbidden_pass_events must include fail event")

elapsed_ns = time.time_ns() - started
if not errors:
    append_event("verification_matrix_schema_e2e_bindings_verified", "pass", [artifacts.get("verification_matrix_gate", ""), artifacts.get("verification_matrix_harness", "")], {"e2e_test_refs": e2e_refs})
    append_event("verification_matrix_schema_conformance_bindings_verified", "pass", [artifacts.get("verification_matrix", "")], {"conformance_test_refs": conformance_refs})
    append_event("verification_matrix_schema_gate_replayed", "pass", [rel(GATE_TRANSCRIPT)], {"gate_results": gate_results})
    append_event("verification_matrix_schema_contract_verified", "pass", [artifacts.get("verification_matrix", "")], summary)
    append_event("verification_matrix_schema_completion_contract_pass", "pass", [rel(CONTRACT), rel(REPORT), rel(LOG)], {"elapsed_ns": elapsed_ns})
    status = "pass"
else:
    append_event(FAIL_EVENT, "fail", [rel(CONTRACT), rel(REPORT), rel(LOG)], {"errors": errors[:16], "elapsed_ns": elapsed_ns})
    status = "fail"

sample_report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "schema_summary": summary,
    "gate_results": gate_results,
    "e2e_bindings": e2e_refs,
    "conformance_bindings": conformance_refs,
    "events": events,
    "errors": errors,
}
for field in required_report_fields:
    require(field in sample_report, f"report missing required telemetry field {field}")
for event in events:
    for field in required_log_fields:
        require(field in event, f"log event {event.get('event')} missing required field {field}")
if status == "pass" and errors:
    status = "fail"

write_outputs(manifest, status, summary, gate_results, e2e_refs, conformance_refs)

if status == "pass":
    print(
        "PASS: verification matrix schema completion contract "
        f"streams={len(summary.get('stream_examples', []))} "
        f"e2e_refs={len(e2e_refs)} conformance_refs={len(conformance_refs)}"
    )
else:
    print("FAIL: verification matrix schema completion contract", file=os.sys.stderr)
    for message in errors:
        print(f" - {message}", file=os.sys.stderr)
    raise SystemExit(1)
PY
