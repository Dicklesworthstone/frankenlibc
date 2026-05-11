#!/usr/bin/env bash
# check_runtime_math_determinism_completion_contract.sh - bd-1fk1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_DETERMINISM_CONTRACT:-$ROOT/tests/conformance/runtime_math_determinism_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_DETERMINISM_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_DETERMINISM_REPORT:-$OUT_DIR/runtime_math_determinism_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_DETERMINISM_LOG:-$OUT_DIR/runtime_math_determinism_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
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

EXPECTED_SCHEMA = "runtime_math_determinism_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_determinism_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-1fk1.1-runtime-math-determinism-completion-contract"
ORIGINAL_BEAD = "bd-1fk1"
COMPLETION_BEAD = "bd-1fk1.1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.integration.primary"}
PASS_EVENTS = {
    "runtime_math_determinism_unit_bindings_verified",
    "runtime_math_determinism_integration_bindings_verified",
    "runtime_math_determinism_contract_verified",
    "runtime_math_determinism_completion_contract_pass",
}
FAIL_EVENT = "runtime_math_determinism_completion_contract_fail"
REQUIRED_UNIT_TEST_NAMES = {
    "runtime_kernel_snapshot_schema_doc_matches_constant",
    "snapshot_contract_ranges_are_sane_for_fresh_kernel",
    "snapshot_decision_and_evidence_counters_are_monotone",
    "deterministic_replay_produces_identical_decisions_and_evidence",
}
REQUIRED_INTEGRATION_TEST_NAMES = {
    "runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
    "gate_script_exists_and_executable",
    "gate_script_emits_logs_and_report",
    "manifest_binds_runtime_math_determinism_unit_and_integration_items",
    "checker_validates_runtime_math_determinism_contract_and_emits_report_log",
    "checker_rejects_missing_observe_binding",
    "checker_rejects_missing_unit_test_binding",
    "checker_rejects_local_cargo_command",
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
    return f"fn {name}(" in text or f"fn {name}<" in text


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
            "failure_signature": "none" if status == "pass" else "runtime_math_determinism_completion_contract_failed",
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


def validate_test_refs(
    section: dict[str, Any],
    section_name: str,
    sources: dict[str, str],
    required_names: set[str],
) -> list[str]:
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
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"{section_name} cargo command must be rch-backed: {command}")
    return found


def validate_required_source_text(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    required_text = contract.get("required_source_text", {})
    if not isinstance(required_text, dict) or not required_text:
        err("required_determinism_contract.required_source_text must be a non-empty object")
        return {"checked_artifacts": 0, "checked_tokens": 0}
    checked_tokens = 0
    for artifact_id, needles in required_text.items():
        path_text = artifacts.get(str(artifact_id))
        text = source_text(path_text, f"required_source_text.{artifact_id}")
        for needle in as_string_list(needles, f"required_source_text.{artifact_id}"):
            checked_tokens += 1
            require(needle in text, f"{artifact_id} missing required text {needle!r}")
    return {"checked_artifacts": len(required_text), "checked_tokens": checked_tokens}


def validate_verification_matrix(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    matrix_path = artifact_path(artifacts.get("verification_matrix"), "source_artifacts.verification_matrix")
    if matrix_path is None:
        return {}
    matrix = load_json(matrix_path, "verification matrix")
    required = contract.get("required_verification_matrix", {})
    if not isinstance(required, dict):
        err("required_determinism_contract.required_verification_matrix must be an object")
        return {}
    rows = matrix.get("entries")
    if not isinstance(rows, list):
        err("verification_matrix.entries must be an array")
        return {}
    bead_id = required.get("bead_id")
    entry = next((item for item in rows if isinstance(item, dict) and item.get("bead_id") == bead_id), None)
    if not isinstance(entry, dict):
        err(f"verification matrix missing row for {bead_id}")
        return {}
    row = entry.get("row")
    if not isinstance(row, dict):
        err(f"verification matrix entry for {bead_id} must include row object")
        return {}
    require(row.get("status") == required.get("status"), "verification matrix status mismatch")
    coverage_summary = entry.get("coverage_summary", {})
    if isinstance(coverage_summary, dict):
        require(coverage_summary.get("overall") == "complete", "verification matrix coverage_summary.overall must be complete")
    else:
        err("verification matrix coverage_summary must be an object")
    for field in ["unit_cmds", "e2e_cmds", "expected_assertions"]:
        have = row.get(field)
        want = required.get(field)
        if not isinstance(have, list) or not isinstance(want, list):
            err(f"verification matrix {field} must be arrays")
            continue
        missing = [item for item in want if item not in have]
        if missing:
            err(f"verification matrix {field} missing required entries {missing}")
    artifact_paths = row.get("artifact_paths")
    if isinstance(artifact_paths, list):
        for artifact_id in [
            "runtime_math_mod",
            "determinism_proof_source",
            "determinism_gate_script",
            "harness_cli",
            "snapshot_schema_doc",
        ]:
            require(
                artifacts.get(artifact_id) in artifact_paths,
                f"verification matrix artifact_paths missing {artifacts.get(artifact_id)}",
            )
    else:
        err("verification matrix artifact_paths must be an array")
    return {"bead_id": bead_id, "unit_cmds": len(row.get("unit_cmds", [])), "e2e_cmds": len(row.get("e2e_cmds", []))}


def validate_proof_obligation(contract: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    proof_path = artifact_path(artifacts.get("proof_binder_validation"), "source_artifacts.proof_binder_validation")
    if proof_path is None:
        return {}
    proof_doc = load_json(proof_path, "proof binder validation")
    required = contract.get("proof_obligation", {})
    if not isinstance(required, dict):
        err("required_determinism_contract.proof_obligation must be an object")
        return {}
    obligations = proof_doc.get("obligations")
    if not isinstance(obligations, list):
        err("proof_binder_validation.obligations must be an array")
        return {}
    obligation_id = required.get("obligation_id")
    row = next((item for item in obligations if isinstance(item, dict) and item.get("obligation_id") == obligation_id), None)
    if not isinstance(row, dict):
        err(f"proof binder validation missing obligation {obligation_id}")
        return {}
    require(row.get("statement") == required.get("statement"), "proof obligation statement mismatch")
    require(row.get("verification_command") == required.get("verification_command"), "proof obligation verification command mismatch")
    require(isinstance(row.get("verification_command"), str) and row["verification_command"].startswith("rch exec -- cargo test"), "proof obligation command must be rch-backed cargo test")
    require(row.get("valid") is True, "proof obligation row must be valid")
    return {"obligation_id": obligation_id, "verification_command": row.get("verification_command")}


def validate_determinism_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_determinism_contract", {})
    if not isinstance(contract, dict):
        err("required_determinism_contract must be an object")
        contract = {}
    require(contract.get("seed") == 3735928559, "determinism seed must be 0xDEAD_BEEF")
    require(contract.get("seed_literal") == "0xDEAD_BEEF", "determinism seed_literal mismatch")
    require(contract.get("steps") == 512, "determinism steps must remain 512")
    require(as_string_list(contract.get("modes"), "required_determinism_contract.modes") == ["strict", "hardened"], "determinism modes must be strict+hardened")
    proof_text = source_text(artifacts.get("determinism_proof_source"), "source_artifacts.determinism_proof_source")
    for family in as_string_list(contract.get("scenario_families"), "required_determinism_contract.scenario_families"):
        require(f"ApiFamily::{family}" in proof_text, f"determinism proof missing scenario family {family}")
    source_text_summary = validate_required_source_text(contract, artifacts)
    matrix_summary = validate_verification_matrix(contract, artifacts)
    proof_summary = validate_proof_obligation(contract, artifacts)
    return {
        "seed": contract.get("seed"),
        "steps": contract.get("steps"),
        "modes": contract.get("modes"),
        "families": contract.get("scenario_families"),
        "source_text": source_text_summary,
        "verification_matrix": matrix_summary,
        "proof_obligation": proof_summary,
    }


def write_outputs(manifest: dict[str, Any], status: str, summary: dict[str, Any], unit_refs: list[str], integration_refs: list[str]) -> None:
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "determinism_contract": summary,
        "unit_bindings": unit_refs,
        "integration_bindings": integration_refs,
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
missing_items = evidence.get("missing_items_closed")
require(set(as_string_list(missing_items, "completion_debt_evidence.missing_items_closed")) == REQUIRED_MISSING_ITEMS, "missing_items_closed must be exactly unit and integration primary")

unit_section = evidence.get("unit_primary", {})
if not isinstance(unit_section, dict):
    err("unit_primary must be an object")
    unit_section = {}
integration_section = evidence.get("integration_primary", {})
if not isinstance(integration_section, dict):
    err("integration_primary must be an object")
    integration_section = {}
require(unit_section.get("missing_item_id") == "tests.unit.primary", "unit_primary missing_item_id mismatch")
require(integration_section.get("missing_item_id") == "tests.integration.primary", "integration_primary missing_item_id mismatch")

unit_sources = {"runtime_math_mod": artifacts.get("runtime_math_mod", "")}
integration_sources = {
    "determinism_harness_test": artifacts.get("determinism_harness_test", ""),
    "completion_harness_test": artifacts.get("completion_harness_test", ""),
}
unit_refs = validate_test_refs(unit_section, "unit_primary", unit_sources, REQUIRED_UNIT_TEST_NAMES)
integration_refs = validate_test_refs(
    integration_section,
    "integration_primary",
    integration_sources,
    REQUIRED_INTEGRATION_TEST_NAMES,
)
for script in as_string_list(integration_section.get("required_scripts"), "integration_primary.required_scripts"):
    require(script in artifacts.values(), f"integration required script {script} must be listed in source_artifacts")

summary = validate_determinism_contract(manifest, artifacts)

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
    append_event(
        "runtime_math_determinism_unit_bindings_verified",
        "pass",
        [artifacts.get("runtime_math_mod", "")],
        {"unit_test_refs": unit_refs, "unit_test_ref_count": len(unit_refs)},
    )
    append_event(
        "runtime_math_determinism_integration_bindings_verified",
        "pass",
        [artifacts.get("determinism_gate_script", ""), artifacts.get("determinism_harness_test", ""), artifacts.get("completion_harness_test", "")],
        {"integration_test_refs": integration_refs, "integration_test_ref_count": len(integration_refs)},
    )
    append_event(
        "runtime_math_determinism_contract_verified",
        "pass",
        [artifacts.get("determinism_proof_source", ""), artifacts.get("verification_matrix", ""), artifacts.get("proof_binder_validation", "")],
        summary,
    )
    append_event(
        "runtime_math_determinism_completion_contract_pass",
        "pass",
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {"elapsed_ns": elapsed_ns},
    )
    status = "pass"
else:
    append_event(
        FAIL_EVENT,
        "fail",
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        {"errors": errors[:16], "elapsed_ns": elapsed_ns},
    )
    status = "fail"

sample_report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id") if isinstance(manifest, dict) else None,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "determinism_contract": summary,
    "unit_bindings": unit_refs,
    "integration_bindings": integration_refs,
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

write_outputs(manifest, status, summary, unit_refs, integration_refs)

if status == "pass":
    print(
        "PASS: runtime_math determinism completion contract "
        f"unit_refs={len(unit_refs)} integration_refs={len(integration_refs)} "
        f"tokens={summary.get('source_text', {}).get('checked_tokens')}"
    )
else:
    print("FAIL: runtime_math determinism completion contract", file=os.sys.stderr)
    for message in errors:
        print(f" - {message}", file=os.sys.stderr)
    raise SystemExit(1)
PY
