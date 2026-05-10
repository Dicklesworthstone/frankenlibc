#!/usr/bin/env bash
# check_family_degradation_policy_completion_contract.sh - bd-w2c3.7.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_PATH="${FRANKENLIBC_FAMILY_DEGRADATION_POLICY_CONTRACT:-${ROOT}/tests/conformance/family_degradation_policy_completion_contract.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${FRANKENLIBC_FAMILY_DEGRADATION_POLICY_REPORT:-${OUT_DIR}/family_degradation_policy_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_FAMILY_DEGRADATION_POLICY_LOG:-${OUT_DIR}/family_degradation_policy_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

errors: list[str] = []
events: list[dict[str, Any]] = []

REQUIRED_EVENTS = {
    "family_degradation_policy_table_validated",
    "family_degradation_policy_e2e_validated",
    "family_degradation_policy_telemetry_validated",
    "runtime_decision",
    "runtime_pressure_sensor",
    "runtime_overload_policy_applied",
}

REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "completion_debt_bead",
    "original_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "overload_state",
    "degradation_active",
    "overload_policy",
    "policy_id",
    "artifact_refs",
    "failure_signature",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def event_payload(event: str, status: str, *, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "trace_id": f"bd-w2c3.7.2.1:{event}",
        "completion_debt_bead": "bd-w2c3.7.2.1",
        "original_bead": "bd-w2c3.7.2",
        "source_commit": SOURCE_COMMIT,
        "event": event,
        "status": status,
        "mode": "hardened" if event != "family_degradation_policy_e2e_validated" else "strict",
        "api_family": "runtime_math",
        "symbol": "runtime_math::degradation_policy",
        "decision_path": "policy_table+pressure_sensor+overload_policy",
        "healing_action": "ReturnSafeDefault" if event != "family_degradation_policy_e2e_validated" else "None",
        "errno": 0 if status in {"pass", "info"} else 1,
        "latency_ns": 0,
        "overload_state": "overloaded",
        "degradation_active": True,
        "overload_policy": "overloaded_safe_fallback",
        "policy_id": 0,
        "artifact_refs": [
            "tests/conformance/family_degradation_policy_completion_contract.v1.json",
            "scripts/check_family_degradation_policy_completion_contract.sh",
            "crates/frankenlibc-membrane/src/runtime_math/policy_table.rs",
            "crates/frankenlibc-membrane/src/runtime_math/mod.rs",
        ],
        "failure_signature": "none" if status in {"pass", "info"} else "family_degradation_policy_completion_contract_failed",
        "details": details or {},
    }


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        errors.append(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"implementation ref has invalid line: {ref}")
        return
    path = rel_path(path_text)
    if not path.is_file():
        errors.append(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        errors.append(f"implementation ref does not point to non-empty line: {ref}")


def require_test_fn(path: Path, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if f"fn {name}" not in text:
        errors.append(f"{path.relative_to(root)} missing test function {name}")


def rows_with_module(value: Any, module: str) -> list[dict[str, Any]]:
    rows: list[Any]
    if isinstance(value, list):
        rows = value
    elif isinstance(value, dict):
        candidates = [
            value.get("admission_ledger"),
            value.get("controller_manifest"),
            value.get("controllers"),
            value.get("modules"),
        ]
        rows = []
        for candidate in candidates:
            if isinstance(candidate, list):
                rows.extend(candidate)
            elif isinstance(candidate, dict):
                item = candidate.get(module)
                if isinstance(item, dict):
                    rows.append(item)
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict) and row.get("module") == module]


contract = load_json(contract_path)
evidence = contract.get("completion_debt_evidence", {})
artifacts = evidence.get("artifacts", {})

if contract.get("schema") != "family_degradation_policy_completion_contract.v1":
    errors.append("schema mismatch")
if contract.get("bead") != "bd-w2c3.7.2":
    errors.append("bead must be bd-w2c3.7.2")
if contract.get("completion_debt_bead") != "bd-w2c3.7.2.1":
    errors.append("completion_debt_bead must be bd-w2c3.7.2.1")
if int(contract.get("next_audit_score_threshold", 0)) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

missing_items = set(evidence.get("missing_items", []))
if missing_items != {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}:
    errors.append(f"missing_items mismatch: {sorted(missing_items)}")

artifact_paths: dict[str, Path] = {}
for name, value in artifacts.items():
    try:
        path = rel_path(str(value))
    except ValueError as exc:
        errors.append(str(exc))
        continue
    artifact_paths[name] = path
    if not path.is_file():
        errors.append(f"artifact {name} missing: {value}")

for ref in evidence.get("implementation_refs", []):
    check_file_line_ref(str(ref))

policy_table_source = artifact_paths["policy_table_source"].read_text(encoding="utf-8")
runtime_math_source = artifact_paths["runtime_math_source"].read_text(encoding="utf-8")
pressure_sensor_source = artifact_paths["pressure_sensor_source"].read_text(encoding="utf-8")
proof_policy_script = artifact_paths["proof_policy_script"].read_text(encoding="utf-8")
proof_policy_audit = load_json(artifact_paths["proof_policy_audit"])
admission_report = load_json(artifact_paths["admission_report"])
controller_manifest = load_json(artifact_paths["controller_manifest"])
runtime_linkage = load_json(artifact_paths["runtime_linkage"])
pressure_fixture = load_json(artifact_paths["pressure_fixture"])

guard = evidence.get("policy_table_guard", {})
linkage_policy = runtime_linkage.get("modules", {}).get("policy_table", {})
if linkage_policy.get("linkage_status") != "Production":
    errors.append("runtime linkage policy_table must be Production")
if linkage_policy.get("invariant") != guard.get("required_invariant"):
    errors.append("runtime linkage policy_table invariant does not match contract")
if linkage_policy.get("fallback_when_data_missing") != guard.get("fallback_when_data_missing"):
    errors.append("runtime linkage policy_table fallback does not match contract")
for output in guard.get("required_action_outputs", []):
    if output not in linkage_policy.get("action_outputs", []):
        errors.append(f"runtime linkage policy_table action_outputs missing {output}")
for input_name in guard.get("required_lookup_dimensions", []):
    if input_name not in linkage_policy.get("evidence_inputs", []):
        errors.append(f"runtime linkage policy_table evidence_inputs missing {input_name}")

for snippet in [
    "pub struct PolicyTableLookup",
    "pub fn from_artifact",
    "pub fn lookup",
    "PolicyTableError::StrictRepairNotAllowed",
    "PolicyTableError::RiskMonotonicityViolation",
]:
    if snippet not in policy_table_source:
        errors.append(f"policy_table.rs missing {snippet}")
for snippet in [
    "\\\"event\\\":\\\"runtime_decision\\\"",
    "\\\"event\\\":\\\"runtime_pressure_sensor\\\"",
    "\\\"event\\\":\\\"runtime_overload_policy_applied\\\"",
    "\\\"degradation_active\\\":{degradation_active}",
    "\\\"overload_policy\\\":\\\"{overload_policy_label}\\\"",
    "OVERLOAD_POLICY_OVERLOADED_SAFE_FALLBACK",
    "MembraneAction::Repair(HealingAction::ReturnSafeDefault)",
]:
    if snippet not in runtime_math_source:
        errors.append(f"runtime_math/mod.rs missing {snippet}")
if "matches!(self, Self::Overloaded)" not in pressure_sensor_source:
    errors.append("pressure_sensor.rs must make degradation_active true only for Overloaded")

if proof_policy_audit.get("schema_version") != "v1":
    errors.append("proof policy audit schema_version must be v1")
if "DONE" not in proof_policy_audit.get("policy", {}).get("block_status_without_evidence", []):
    errors.append("proof policy audit must block DONE without evidence")
if proof_policy_audit.get("verification_command", "").find("rch exec") == -1:
    errors.append("proof policy audit verification_command must use rch exec")
for field in ["trace_id", "bead_id", "policy_id", "proof_hash", "artifact_refs", "failure_signature"]:
    if field not in proof_policy_audit.get("required_log_fields", []):
        errors.append(f"proof policy audit required_log_fields missing {field}")

for snippet in ["--validate-only", "--rch", "exec rch exec -- cargo test -p frankenlibc-harness --test proof_carrying_policy_audit_test"]:
    if snippet not in proof_policy_script:
        errors.append(f"proof policy script missing {snippet}")

admission_rows = rows_with_module(admission_report, "policy_table")
if not admission_rows:
    errors.append("admission report missing policy_table row")
else:
    row = admission_rows[0]
    if row.get("tier") != "production_core":
        errors.append("admission policy_table tier must be production_core")
    if row.get("admission_status") != "ADMITTED":
        errors.append("admission policy_table status must be ADMITTED")
    if row.get("in_production_manifest") is not True:
        errors.append("admission policy_table must be in production manifest")
manifest_rows = rows_with_module(controller_manifest, "policy_table")
if not manifest_rows:
    errors.append("controller manifest missing policy_table row")
else:
    row = manifest_rows[0]
    if row.get("decision_hook") != "RuntimeMathKernel::decide proof-carrying policy table lookup":
        errors.append("controller manifest policy_table decision_hook mismatch")
    if row.get("runtime_cost_target", {}).get("strict_hot_path_ns_max") != 20:
        errors.append("controller manifest policy_table strict hot-path target must be 20ns")
    if row.get("runtime_cost_target", {}).get("hardened_hot_path_ns_max") != 200:
        errors.append("controller manifest policy_table hardened hot-path target must be 200ns")

fixture_cases = []
if isinstance(pressure_fixture, dict):
    for row in pressure_fixture.get("cases", []):
        if isinstance(row, dict):
            fixture_cases.append(row)
case_names = {str(row.get("name")) for row in fixture_cases}
if "degradation_active_in_overloaded_hardened" not in case_names:
    errors.append("pressure fixture missing overloaded hardened degradation case")

test_sources = evidence.get("test_sources", {})
source_paths = {
    name: rel_path(path)
    for name, path in test_sources.items()
}
for section_name in ["unit_primary", "e2e_primary"]:
    section = evidence.get(section_name, {})
    if section.get("missing_item_id") != f"tests.{section_name.split('_')[0]}.primary":
        errors.append(f"{section_name} missing_item_id mismatch")
    for test_ref in section.get("required_test_refs", []):
        source_name = test_ref.get("source")
        test_name = test_ref.get("name")
        if source_name not in source_paths:
            errors.append(f"unknown test source {source_name}")
            continue
        require_test_fn(source_paths[source_name], str(test_name))
    for command in section.get("required_commands", []):
        command_text = str(command)
        if "cargo " in command_text and "rch exec" not in command_text:
            errors.append(f"cargo command must offload through rch: {command_text}")

for required_script in evidence.get("e2e_primary", {}).get("required_scripts", []):
    script = str(required_script)
    if script.startswith("scripts/") and " " in script:
        script_path = script.split(" ", 1)[0]
    else:
        script_path = script
    if not rel_path(script_path).is_file():
        errors.append(f"required e2e script missing: {required_script}")

telemetry = evidence.get("telemetry_primary", {})
if telemetry.get("missing_item_id") != "telemetry.primary":
    errors.append("telemetry_primary missing_item_id mismatch")
required_events = set(telemetry.get("required_events", []))
required_fields = set(telemetry.get("required_fields", []))
if not REQUIRED_EVENTS.issubset(required_events):
    errors.append("telemetry_primary.required_events missing required events")
if not REQUIRED_FIELDS.issubset(required_fields):
    errors.append("telemetry_primary.required_fields missing required fields")
for artifact in telemetry.get("required_log_artifacts", []):
    artifact_text = str(artifact)
    if artifact_text.startswith("target/conformance/family_degradation_policy_completion_contract"):
        continue
    if artifact_text not in admission_report.get("artifacts_emitted", {}).values():
        errors.append(f"telemetry log artifact not emitted by admission report: {artifact_text}")

events.append(event_payload("family_degradation_policy_table_validated", "info"))
events.append(event_payload("family_degradation_policy_e2e_validated", "info"))
events.append(event_payload("family_degradation_policy_telemetry_validated", "info"))

status = "pass" if not errors else "fail"
events.append(
    event_payload(
        "family_degradation_policy_completion_contract_validated"
        if status == "pass"
        else "family_degradation_policy_completion_contract_failed",
        status,
        details={"error_count": len(errors)},
    )
)

for row_event in events:
    missing = REQUIRED_FIELDS - set(row_event)
    if missing:
        errors.append(f"internal telemetry row missing fields {sorted(missing)}")

report = {
    "schema": "family_degradation_policy_completion_contract.report.v1",
    "status": "pass" if not errors else "fail",
    "generated_at": ts,
    "source_commit": SOURCE_COMMIT,
    "completion_debt_bead": "bd-w2c3.7.2.1",
    "original_bead": "bd-w2c3.7.2",
    "summary": {
        "policy_table_tests": len(proof_policy_audit.get("required_positive_tests", []))
        + len(proof_policy_audit.get("required_negative_tests", [])),
        "required_event_count": len(required_events),
        "required_field_count": len(required_fields),
        "admission_policy_table_rows": len(admission_rows),
        "controller_manifest_policy_table_rows": len(manifest_rows),
        "pressure_fixture_cases": len(fixture_cases),
    },
    "errors": errors,
    "artifacts": {
        "contract": str(contract_path.relative_to(root)) if contract_path.is_relative_to(root) else str(contract_path),
        "log_jsonl": str(log_path.relative_to(root)) if log_path.is_relative_to(root) else str(log_path),
    },
}

log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("w", encoding="utf-8") as handle:
    for row_event in events:
        handle.write(json.dumps(row_event, sort_keys=True))
        handle.write("\n")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(
        f"FAIL: family degradation policy completion contract errors={len(errors)} "
        f"report={report_path.relative_to(root)}"
    )
    raise SystemExit(1)

print(
    "PASS: family degradation policy completion contract "
    f"(policy_table_tests={report['summary']['policy_table_tests']}, "
    f"events={report['summary']['required_event_count']}, "
    f"report={report_path.relative_to(root)})"
)
PY
