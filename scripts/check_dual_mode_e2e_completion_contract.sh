#!/usr/bin/env bash
# check_dual_mode_e2e_completion_contract.sh - bd-oai.5.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_CONTRACT:-$ROOT/tests/conformance/dual_mode_e2e_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_REPORT:-$OUT_DIR/dual_mode_e2e_completion_contract.report.json}"
LOG="${FRANKENLIBC_DUAL_MODE_E2E_COMPLETION_LOG:-$OUT_DIR/dual_mode_e2e_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "dual_mode_e2e_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "dual_mode_e2e_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-oai.5.1-dual-mode-e2e-completion-contract"
ORIGINAL_BEAD = "bd-oai.5"
COMPLETION_BEAD = "bd-oai.5.1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_UNIT_TEST_NAMES = {
    "manifest_binds_dual_mode_e2e_completion_items",
    "checker_validates_dual_mode_e2e_contract_and_emits_report_log",
    "checker_rejects_missing_structured_field_binding",
    "checker_rejects_missing_required_e2e_test_binding",
    "checker_rejects_non_rch_cargo_command",
}
REQUIRED_E2E_TEST_NAMES = {
    "e2e_deterministic_replay_emits_identical_decisions_and_logs",
    "e2e_mode_behavioral_divergence_is_stable_and_structured",
    "e2e_hardened_repair_evidence_chain_is_complete_and_gapless",
    "e2e_hash_linked_repair_chain_verifies_record_integrity",
    "e2e_snapshot_deterministic_replay_produces_identical_snapshots",
    "e2e_snapshot_golden_replay_field_stability",
    "e2e_independent_kernels_produce_consistent_results_under_concurrent_scenario",
    "e2e_kernel_isolation_divergent_inputs_produce_independent_state",
}
REQUIRED_STRUCTURED_FIELDS = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "decision_action",
    "evidence_seqno",
}
PASS_EVENTS = {
    "dual_mode_e2e_unit_bindings_verified",
    "dual_mode_e2e_source_contract_verified",
    "dual_mode_e2e_bindings_verified",
    "dual_mode_e2e_completion_contract_pass",
}
FAIL_EVENT = "dual_mode_e2e_completion_contract_fail"

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
            "failure_signature": "none" if status == "pass" else "dual_mode_e2e_completion_contract_failed",
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


def validate_dual_mode_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_dual_mode_e2e_contract", {})
    if not isinstance(contract, dict):
        err("required_dual_mode_e2e_contract must be an object")
        contract = {}

    e2e_text = source_text(artifacts.get("dual_mode_e2e_test"), "source_artifacts.dual_mode_e2e_test")
    evidence_text = source_text(artifacts.get("runtime_math_evidence"), "source_artifacts.runtime_math_evidence")
    runtime_text = source_text(artifacts.get("runtime_math_mod"), "source_artifacts.runtime_math_mod")

    require(contract.get("scenario_id") == "bd-oai.5-dual-mode-runtime-math-e2e", "scenario_id mismatch")
    modes = set(as_string_list(contract.get("required_modes"), "required_dual_mode_e2e_contract.required_modes"))
    require(modes == {"strict", "hardened"}, "required_modes must be exactly strict+hardened")
    require(int(contract.get("deterministic_replay_steps", 0)) >= 96, "deterministic_replay_steps must preserve 96-step replay proof")
    require(int(contract.get("strict_divergence_rows", 0)) >= 64, "strict_divergence_rows must preserve 64-row proof")
    require(int(contract.get("hardened_divergence_rows", 0)) >= 64, "hardened_divergence_rows must preserve 64-row proof")
    require(int(contract.get("gapless_repair_rows", 0)) >= 96, "gapless_repair_rows must preserve 96-row proof")
    require(int(contract.get("hash_linked_records", 0)) >= 64, "hash_linked_records must preserve 64-record chain proof")
    require(contract.get("strict_expected_action") == "Deny", "strict_expected_action must be Deny")
    require(contract.get("hardened_expected_action") == "Repair", "hardened_expected_action must be Repair")
    require(contract.get("hardened_expected_healing_action") == "ReturnSafeDefault", "hardened_expected_healing_action must be ReturnSafeDefault")

    fields = set(as_string_list(contract.get("required_structured_fields"), "required_dual_mode_e2e_contract.required_structured_fields"))
    missing_fields = sorted(REQUIRED_STRUCTURED_FIELDS - fields)
    if missing_fields:
        err(f"required_structured_fields missing required bindings {missing_fields}")
    for field in sorted(REQUIRED_STRUCTURED_FIELDS):
        require(f'"{field}"' in e2e_text or field in e2e_text, f"dual-mode e2e source does not assert structured field {field}")

    for token in as_string_list(contract.get("required_source_tokens"), "required_dual_mode_e2e_contract.required_source_tokens"):
        require(token in e2e_text, f"dual-mode e2e source missing token {token!r}")
    for token in [
        "MembraneAction::Deny",
        "MembraneAction::Repair(HealingAction::ReturnSafeDefault)",
        "evidence_contract_snapshot",
        "export_runtime_math_log_jsonl",
    ]:
        require(token in e2e_text, f"dual-mode e2e source missing invariant token {token!r}")
    for token in ["verify_payload_hash_v1", "verify_chain_hash_v1"]:
        require(token in evidence_text or token in e2e_text, f"evidence chain verifier token missing: {token}")
    require("RuntimeKernelSnapshot" in runtime_text, "runtime_math_mod must define RuntimeKernelSnapshot")

    return {
        "scenario_id": contract.get("scenario_id"),
        "required_modes": sorted(modes),
        "structured_fields": sorted(fields),
        "e2e_required_tests": sorted(REQUIRED_E2E_TEST_NAMES),
        "strict_expected_action": contract.get("strict_expected_action"),
        "hardened_expected_action": contract.get("hardened_expected_action"),
        "hardened_expected_healing_action": contract.get("hardened_expected_healing_action"),
    }


def write_outputs(
    manifest: dict[str, Any],
    status: str,
    dual_mode_summary: dict[str, Any],
    unit_refs: list[str],
    e2e_refs: list[str],
) -> None:
    telemetry = manifest.get("telemetry_contract", {}) if isinstance(manifest, dict) else {}
    required_events = set(as_string_list(telemetry.get("required_events", []), "telemetry_contract.required_events", allow_empty=True))
    forbidden_pass_events = set(as_string_list(telemetry.get("forbidden_pass_events", []), "telemetry_contract.forbidden_pass_events", allow_empty=True))
    observed_events = {event["event"] for event in events}
    if status == "pass":
        missing_events = sorted(required_events - observed_events)
        if missing_events:
            err(f"required telemetry events missing {missing_events}")
            status = "fail"
        forbidden = sorted(forbidden_pass_events & observed_events)
        if forbidden:
            err(f"forbidden pass telemetry events observed {forbidden}")
            status = "fail"
    if status == "fail" and FAIL_EVENT not in observed_events:
        append_event(
            FAIL_EVENT,
            "fail",
            [rel(CONTRACT)],
            {"errors": errors.copy()},
        )

    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": manifest.get("original_bead"),
        "completion_debt_bead": manifest.get("completion_debt_bead"),
        "status": status,
        "unit_bindings": unit_refs,
        "e2e_bindings": e2e_refs,
        "dual_mode_contract": dual_mode_summary,
        "events": [event["event"] for event in events],
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

    required_report_fields = set(as_string_list(telemetry.get("required_report_fields", []), "telemetry_contract.required_report_fields", allow_empty=True))
    missing_report_fields = sorted(field for field in required_report_fields if field not in report)
    if missing_report_fields:
        errors.append(f"report missing required fields {missing_report_fields}")
        report["status"] = "fail"
        report["errors"] = errors
        REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
missing_items = set(as_string_list(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
require(missing_items == REQUIRED_MISSING_ITEMS, "missing_items_closed must close exactly tests.unit.primary and tests.e2e.primary")

unit_section = evidence.get("unit_primary", {})
if not isinstance(unit_section, dict):
    err("completion_debt_evidence.unit_primary must be an object")
    unit_section = {}
e2e_section = evidence.get("e2e_primary", {})
if not isinstance(e2e_section, dict):
    err("completion_debt_evidence.e2e_primary must be an object")
    e2e_section = {}

unit_refs = validate_test_refs(unit_section, "unit_primary", artifacts, REQUIRED_UNIT_TEST_NAMES)
append_event(
    "dual_mode_e2e_unit_bindings_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("completion_harness_test", ""))],
    {"unit_refs": unit_refs},
)

e2e_refs = validate_test_refs(e2e_section, "e2e_primary", artifacts, REQUIRED_E2E_TEST_NAMES)
dual_mode_summary = validate_dual_mode_contract(manifest, artifacts)
append_event(
    "dual_mode_e2e_source_contract_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("dual_mode_e2e_test", "")), rel(artifacts.get("runtime_math_evidence", ""))],
    {"structured_fields": dual_mode_summary.get("structured_fields", [])},
)
append_event(
    "dual_mode_e2e_bindings_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("dual_mode_e2e_test", ""))],
    {"e2e_refs": e2e_refs},
)

status = "pass" if not errors else "fail"
if status == "pass":
    append_event(
        "dual_mode_e2e_completion_contract_pass",
        "pass",
        [rel(CONTRACT), rel(artifacts.get("completion_checker", ""))],
        {"unit_ref_count": len(unit_refs), "e2e_ref_count": len(e2e_refs)},
    )
write_outputs(manifest, status, dual_mode_summary, unit_refs, e2e_refs)

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=os.sys.stderr)
    raise SystemExit(1)

print(f"PASS: dual-mode E2E completion contract validated e2e_tests={len(e2e_refs)} fields={len(REQUIRED_STRUCTURED_FIELDS)}")
PY
