#!/usr/bin/env bash
# check_verification_matrix_maintenance_completion_contract.sh - bd-1o4k.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_VERIFY_MATRIX_MAINT_CONTRACT:-$ROOT/tests/conformance/verification_matrix_maintenance_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_VERIFY_MATRIX_MAINT_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_VERIFY_MATRIX_MAINT_REPORT:-$OUT_DIR/verification_matrix_maintenance_completion_contract.report.json}"
LOG="${FRANKENLIBC_VERIFY_MATRIX_MAINT_LOG:-$OUT_DIR/verification_matrix_maintenance_completion_contract.log.jsonl}"
SYNC_TRANSCRIPT="${FRANKENLIBC_VERIFY_MATRIX_MAINT_SYNC_TRANSCRIPT:-$OUT_DIR/verification_matrix_maintenance_completion_contract.sync.txt}"
MATRIX_TRANSCRIPT="${FRANKENLIBC_VERIFY_MATRIX_MAINT_MATRIX_TRANSCRIPT:-$OUT_DIR/verification_matrix_maintenance_completion_contract.matrix.txt}"
DRIFT_TRANSCRIPT="${FRANKENLIBC_VERIFY_MATRIX_MAINT_DRIFT_TRANSCRIPT:-$OUT_DIR/verification_matrix_maintenance_completion_contract.drift.txt}"
BEADS="${FRANKENLIBC_VERIFY_MATRIX_MAINT_BEADS:-${FRANKENLIBC_VERIFICATION_MATRIX_BEADS:-$ROOT/.beads/issues.jsonl}}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SYNC_TRANSCRIPT")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
SYNC_TRANSCRIPT="$SYNC_TRANSCRIPT" \
MATRIX_TRANSCRIPT="$MATRIX_TRANSCRIPT" \
DRIFT_TRANSCRIPT="$DRIFT_TRANSCRIPT" \
BEADS="$BEADS" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SYNC_TRANSCRIPT = pathlib.Path(os.environ["SYNC_TRANSCRIPT"])
MATRIX_TRANSCRIPT = pathlib.Path(os.environ["MATRIX_TRANSCRIPT"])
DRIFT_TRANSCRIPT = pathlib.Path(os.environ["DRIFT_TRANSCRIPT"])
BEADS = pathlib.Path(os.environ["BEADS"])
if not BEADS.is_absolute():
    BEADS = ROOT / BEADS

EXPECTED_SCHEMA = "verification_matrix_maintenance_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "verification_matrix_maintenance_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-1o4k.1-verification-matrix-maintenance-completion-contract"
ORIGINAL_BEAD = "bd-1o4k"
COMPLETION_BEAD = "bd-1o4k.1"
REQUIRED_MISSING_ITEMS = {"tests.integration.primary", "tests.conformance.primary"}
PASS_EVENTS = {
    "verification_matrix_maintenance_integration_bindings_verified",
    "verification_matrix_maintenance_conformance_bindings_verified",
    "verification_matrix_maintenance_gates_replayed",
    "verification_matrix_maintenance_contract_verified",
    "verification_matrix_maintenance_completion_contract_pass",
}
FAIL_EVENT = "verification_matrix_maintenance_completion_contract_fail"
REQUIRED_INTEGRATION_TEST_NAMES = {
    "all_critique_beads_have_rows",
    "entry_coverage_counts_consistent",
    "dashboard_stats_consistent_with_entries",
    "entries_have_non_empty_backfill_rows",
    "drift_guard_script_exists_and_executable",
    "all_open_critique_beads_have_matrix_rows",
    "dashboard_total_matches_entries",
    "dashboard_coverage_stats_consistent",
    "no_duplicate_bead_entries",
    "checker_replays_sync_and_matrix_gates",
    "checker_rejects_local_cargo_command",
}
REQUIRED_CONFORMANCE_TEST_NAMES = {
    "matrix_exists_and_valid_json",
    "schema_defines_required_types",
    "schema_has_row_contract_and_stream_examples",
    "entries_have_valid_coverage_statuses",
    "no_empty_bead_ids",
    "verification_matrix_artifact_is_present_and_well_formed",
    "primary_e2e_test_file_carries_named_functions",
    "manifest_binds_verification_matrix_maintenance_evidence",
    "checker_validates_matrix_maintenance_contract_and_emits_report_log",
    "checker_rejects_matrix_count_drift",
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


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return rows
    for line_no, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            err(f"{label}:{line_no} is not valid JSON: {exc}")
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            err(f"{label}:{line_no} must be a JSON object")
    return rows


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
            "failure_signature": "none" if status == "pass" else "verification_matrix_maintenance_completion_contract_failed",
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


def run_gate(label: str, command: list[str], transcript_path: pathlib.Path, pass_sentinel: str) -> dict[str, Any]:
    gate_env = os.environ.copy()
    gate_env["FRANKENLIBC_VERIFICATION_MATRIX_BEADS"] = str(BEADS)
    proc = subprocess.run(
        command,
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
    transcript_path.write_text(transcript, encoding="utf-8")
    if proc.returncode != 0:
        err(f"{label} gate failed with exit {proc.returncode}")
    if pass_sentinel and pass_sentinel not in transcript:
        err(f"{label} gate transcript missing sentinel {pass_sentinel!r}")
    return {
        "label": label,
        "exit_code": proc.returncode,
        "pass_sentinel": pass_sentinel,
        "transcript": rel(transcript_path),
    }


def validate_required_source_text(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    required_text = contract.get("required_source_text", {})
    if not isinstance(required_text, dict) or not required_text:
        err("required_matrix_contract.required_source_text must be a non-empty object")
        return {"checked_artifacts": 0, "checked_tokens": 0}
    checked_tokens = 0
    for artifact_id, needles in required_text.items():
        text = source_text(artifacts.get(str(artifact_id)), f"required_source_text.{artifact_id}")
        for needle in as_string_list(needles, f"required_source_text.{artifact_id}"):
            checked_tokens += 1
            require(needle in text, f"{artifact_id} missing required text {needle!r}")
    return {"checked_artifacts": len(required_text), "checked_tokens": checked_tokens}


def validate_backfill_index(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    index = load_json(ROOT / artifacts.get("backfill_index", ""), "backfill index")
    required = contract.get("backfill_index", {})
    if not isinstance(required, dict):
        err("required_matrix_contract.backfill_index must be an object")
        return {}
    for field in ["manifest_id", "verification_matrix_artifact", "primary_e2e_test_file"]:
        require(index.get(field) == required.get(field), f"backfill_index.{field} mismatch")
    test_file = source_text(required.get("primary_e2e_test_file"), "backfill_index.primary_e2e_test_file")
    for name in as_string_list(index.get("primary_e2e_test_functions"), "backfill_index.primary_e2e_test_functions"):
        require(function_exists(test_file, name), f"backfill index primary test function missing: {name}")
    return {
        "manifest_id": index.get("manifest_id"),
        "primary_e2e_tests": len(index.get("primary_e2e_test_functions", [])),
    }


def validate_matrix_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_matrix_contract", {})
    if not isinstance(contract, dict):
        err("required_matrix_contract must be an object")
        contract = {}
    matrix = load_json(ROOT / artifacts.get("verification_matrix", ""), "verification matrix")
    beads = load_jsonl(BEADS, "beads")
    entries = matrix.get("entries", [])
    dashboard = matrix.get("dashboard", {})
    schema = matrix.get("schema", {})
    if not isinstance(entries, list):
        err("verification_matrix.entries must be an array")
        entries = []
    if not isinstance(dashboard, dict):
        err("verification_matrix.dashboard must be an object")
        dashboard = {}
    if not isinstance(schema, dict):
        err("verification_matrix.schema must be an object")
        schema = {}

    require(matrix.get("matrix_version") == contract.get("matrix_version"), "matrix_version mismatch")
    require(schema.get("row_schema_version") == contract.get("row_schema_version"), "row_schema_version mismatch")
    require(len(entries) == contract.get("entry_count"), "verification matrix entry_count drift")
    require(dashboard.get("total_critique_beads") == contract.get("total_critique_beads"), "dashboard total_critique_beads drift")
    for key in as_string_list(contract.get("required_dashboard_keys"), "required_matrix_contract.required_dashboard_keys"):
        require(key in dashboard, f"dashboard missing required key {key}")

    actual_counts = Counter()
    missing_backfill = []
    duplicate_ids = []
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            err("verification matrix entry must be an object")
            continue
        bead_id = str(entry.get("bead_id", ""))
        if not bead_id or bead_id in seen_ids:
            duplicate_ids.append(bead_id)
        seen_ids.add(bead_id)
        actual_counts[str(entry.get("coverage_summary", {}).get("overall", "missing"))] += 1
        row = entry.get("row", {})
        if not isinstance(row, dict) or not row.get("unit_cmds") or not row.get("expected_assertions") or not row.get("artifact_paths"):
            missing_backfill.append(bead_id)
    require(not duplicate_ids, f"verification matrix duplicate bead entries {duplicate_ids}")
    require(not missing_backfill, f"verification matrix entries missing backfill row data {missing_backfill[:8]}")

    for key, expected in (contract.get("coverage_counts") or {}).items():
        require(actual_counts.get(str(key), 0) == expected, f"coverage count {key} drift")
        require(dashboard.get("by_coverage_status", {}).get(str(key), 0) == expected, f"dashboard by_coverage_status.{key} drift")
    for key, expected in (contract.get("priority_counts") or {}).items():
        require(dashboard.get("by_priority", {}).get(str(key), {}).get("total") == expected, f"dashboard by_priority.{key}.total drift")

    matrix_ids = {str(entry.get("bead_id", "")) for entry in entries if isinstance(entry, dict)}
    missing_critique = []
    for bead in beads:
        labels = bead.get("labels", [])
        if bead.get("status") in {"open", "in_progress"} and isinstance(labels, list) and "critique" in labels:
            bead_id = str(bead.get("id", ""))
            if bead_id not in matrix_ids:
                missing_critique.append(bead_id)
    require(not missing_critique, f"open/in_progress critique beads missing matrix rows {missing_critique}")

    source_text_summary = validate_required_source_text(contract, artifacts)
    backfill_summary = validate_backfill_index(contract, artifacts)
    return {
        "entry_count": len(entries),
        "total_critique_beads": dashboard.get("total_critique_beads"),
        "coverage_counts": dict(actual_counts),
        "missing_open_critique_rows": missing_critique,
        "source_text": source_text_summary,
        "backfill_index": backfill_summary,
    }


def write_outputs(manifest: dict[str, Any], status: str, summary: dict[str, Any], gate_results: list[dict[str, Any]], integration_refs: list[str], conformance_refs: list[str]) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "matrix_summary": summary,
        "gate_results": gate_results,
        "integration_bindings": integration_refs,
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
require(set(as_string_list(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed")) == REQUIRED_MISSING_ITEMS, "missing_items_closed must be exactly integration and conformance primary")

integration_section = evidence.get("integration_primary", {})
if not isinstance(integration_section, dict):
    err("integration_primary must be an object")
    integration_section = {}
conformance_section = evidence.get("conformance_primary", {})
if not isinstance(conformance_section, dict):
    err("conformance_primary must be an object")
    conformance_section = {}
require(integration_section.get("missing_item_id") == "tests.integration.primary", "integration_primary missing_item_id mismatch")
require(conformance_section.get("missing_item_id") == "tests.conformance.primary", "conformance_primary missing_item_id mismatch")

integration_sources = {
    "verification_matrix_harness": artifacts.get("verification_matrix_harness", ""),
    "matrix_drift_harness": artifacts.get("matrix_drift_harness", ""),
    "completion_harness": artifacts.get("completion_harness", ""),
}
conformance_sources = {
    "verification_matrix_harness": artifacts.get("verification_matrix_harness", ""),
    "backfill_index_harness": artifacts.get("backfill_index_harness", ""),
    "completion_harness": artifacts.get("completion_harness", ""),
}
integration_refs = validate_test_refs(integration_section, "integration_primary", integration_sources, REQUIRED_INTEGRATION_TEST_NAMES)
conformance_refs = validate_test_refs(conformance_section, "conformance_primary", conformance_sources, REQUIRED_CONFORMANCE_TEST_NAMES)
for script in as_string_list(integration_section.get("required_scripts"), "integration_primary.required_scripts"):
    require(script in artifacts.values(), f"integration required script {script} must be listed in source_artifacts")
for artifact in as_string_list(conformance_section.get("required_artifacts"), "conformance_primary.required_artifacts"):
    require(artifact in artifacts.values(), f"conformance artifact {artifact} must be listed in source_artifacts")

gate_results = [
    run_gate("sync_helper", ["python3", "scripts/sync_verification_matrix.py", "--check"], SYNC_TRANSCRIPT, ""),
    run_gate("verification_matrix", ["bash", "scripts/check_verification_matrix.sh"], MATRIX_TRANSCRIPT, "check_verification_matrix: PASS"),
    run_gate("matrix_drift", ["bash", "scripts/check_matrix_drift.sh"], DRIFT_TRANSCRIPT, "check_matrix_drift: PASS"),
]
summary = validate_matrix_contract(manifest, artifacts)

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
    append_event("verification_matrix_maintenance_integration_bindings_verified", "pass", [artifacts.get("verification_matrix_harness", ""), artifacts.get("matrix_drift_harness", "")], {"integration_test_refs": integration_refs})
    append_event("verification_matrix_maintenance_conformance_bindings_verified", "pass", [artifacts.get("verification_matrix", ""), artifacts.get("backfill_index", "")], {"conformance_test_refs": conformance_refs})
    append_event("verification_matrix_maintenance_gates_replayed", "pass", [rel(SYNC_TRANSCRIPT), rel(MATRIX_TRANSCRIPT), rel(DRIFT_TRANSCRIPT)], {"gate_results": gate_results})
    append_event("verification_matrix_maintenance_contract_verified", "pass", [artifacts.get("verification_matrix", ""), artifacts.get("sync_helper", "")], summary)
    append_event("verification_matrix_maintenance_completion_contract_pass", "pass", [rel(CONTRACT), rel(REPORT), rel(LOG)], {"elapsed_ns": elapsed_ns})
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
    "matrix_summary": summary,
    "gate_results": gate_results,
    "integration_bindings": integration_refs,
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

write_outputs(manifest, status, summary, gate_results, integration_refs, conformance_refs)

if status == "pass":
    print(
        "PASS: verification matrix maintenance completion contract "
        f"entries={summary.get('entry_count')} "
        f"integration_refs={len(integration_refs)} conformance_refs={len(conformance_refs)}"
    )
else:
    print("FAIL: verification matrix maintenance completion contract", file=os.sys.stderr)
    for message in errors:
        print(f" - {message}", file=os.sys.stderr)
    raise SystemExit(1)
PY
