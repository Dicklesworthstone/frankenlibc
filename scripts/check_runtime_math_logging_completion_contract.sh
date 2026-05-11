#!/usr/bin/env bash
# check_runtime_math_logging_completion_contract.sh - bd-5vr.8.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_LOGGING_CONTRACT:-${ROOT}/tests/conformance/runtime_math_logging_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_LOGGING_REPORT:-${ROOT}/target/conformance/runtime_math_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_LOGGING_LOG:-${ROOT}/target/conformance/runtime_math_logging_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-5vr.8.1"
ORIGINAL_BEAD = "bd-5vr.8"
PASS_EVENT = "runtime_math_logging_completion_contract_validated"
FAIL_EVENT = "runtime_math_logging_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
}
REQUIRED_JSONL_EVENTS = {
    "runtime_mode_dispatch",
    "runtime_decision",
    "runtime_evidence_emitted",
    "runtime_pressure_sensor",
    "runtime_overload_policy_applied",
    "runtime_reverse_round_math_selection",
    "runtime_reverse_round_coverage_milestone",
    "runtime_reverse_round_diversity_violation",
    "runtime_calibration",
    "runtime_snapshot",
    "runtime_certificate_loaded",
    "runtime_certificate_verification_failed",
    "runtime_regret_alert",
    "runtime_drift_alert",
}
REQUIRED_JSONL_FIELDS = {
    "timestamp",
    "trace_id",
    "bead_id",
    "scenario_id",
    "decision_id",
    "schema_version",
    "level",
    "event",
    "controller_id",
    "decision",
    "decision_action",
    "decision_path",
    "validation_profile",
    "mode",
    "api_family",
    "symbol",
    "healing_action",
    "errno",
    "latency_ns",
    "evidence_seqno",
    "artifact_refs",
    "risk_inputs",
    "snapshot_capture_latency_ns",
    "snapshot_validated_field_count",
    "full_validation_trigger_ppm",
    "repair_trigger_ppm",
    "design_selected_probes",
    "design_budget_ns",
    "sampled_risk_bonus_ppm",
    "policy_hash_prefix",
    "quarantine_depth",
    "arena_utilization_ppm",
    "pareto_cap_enforcements",
    "pareto_exhausted_families",
    "padic_drift_count",
    "equivariant_drift_count",
    "doob_max_drift",
    "wasserstein_aggregate_distance",
    "verification",
}
REQUIRED_DECISION_PATHS = {
    "mode->runtime_math_kernel->decision",
    "risk->bandit->control->barrier->allow",
    "evidence->record_decision",
    "pressure_sensor::observe",
    "pressure_sensor::degradation_policy",
    "reverse_round::math_family_selection",
    "reverse_round::coverage_milestone",
    "reverse_round::diversity_constraints",
    "snapshot::calibration",
    "snapshot::state",
    "certificate::verify",
    "pareto::regret",
    "drift::monitor",
}
REQUIRED_OBSERVABILITY_EXPORTS = {
    "build_runtime_export",
    "capture_bundle",
    "kernel.export_runtime_math_log_jsonl",
    "runtime_math.decision_total",
    "runtime_math.snapshot_decisions",
}
REQUIRED_TELEMETRY_EVENTS = {
    "runtime_math_logging_source_bound",
    "runtime_math_logging_unit_bound",
    "runtime_math_logging_e2e_bound",
    "runtime_math_logging_telemetry_bound",
    PASS_EVENT,
    FAIL_EVENT,
}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "gate",
    "missing_item_id",
    "jsonl_event_count",
    "jsonl_field_count",
    "unit_test_count",
    "e2e_test_count",
    "telemetry_event_count",
    "observability_anchor_count",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path, errors, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def read_source(path_text, source_name, errors):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"test_sources.{source_name} missing")
        return ""
    path = root / path_text
    if not path.is_file():
        errors.append(f"test_sources.{source_name} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"test_sources.{source_name} unreadable: {path_text}: {exc}")
        return ""


def string_set(values, label, errors):
    if not isinstance(values, list):
        errors.append(f"{label} must be an array")
        return set()
    actual = {value for value in values if isinstance(value, str)}
    if len(actual) != len(values):
        errors.append(f"{label} must contain only strings")
    return actual


def require_set(values, required, label, errors):
    actual = string_set(values, label, errors)
    missing = sorted(required - actual)
    if missing:
        errors.append(f"{label} missing {','.join(missing)}")
    return actual


def file_line_ref_exists(ref, errors):
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"invalid file-line ref line: {ref}")
        return
    path = root / path_text
    if line_no <= 0 or not path.is_file():
        errors.append(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        errors.append(f"file-line ref outside file: {ref}")


def function_exists(source_text, name):
    return f"fn {name}" in source_text


def emit(status, errors, summary, test_refs, artifact_refs):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    failure_signature = "" if status == "pass" else ";".join(errors[:8])
    report = {
        "schema_version": "runtime_math_logging_completion_contract.report.v1",
        "status": status,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "summary": summary,
        "errors": errors,
        "artifacts": {
            "contract": rel(contract_path),
            "report": rel(report_path),
            "log": rel(log_path),
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    common = {
        "timestamp": now,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "gate": "runtime_math_logging_completion_contract",
        "jsonl_event_count": summary.get("jsonl_event_count", 0),
        "jsonl_field_count": summary.get("jsonl_field_count", 0),
        "unit_test_count": summary.get("unit_test_count", 0),
        "e2e_test_count": summary.get("e2e_test_count", 0),
        "telemetry_event_count": summary.get("telemetry_event_count", 0),
        "observability_anchor_count": summary.get("observability_anchor_count", 0),
        "test_refs": sorted(test_refs),
        "artifact_refs": sorted(artifact_refs),
        "failure_signature": failure_signature,
    }
    rows = [
        {
            **common,
            "trace_id": f"{COMPLETION_DEBT_BEAD}::runtime_math_logging::source::{status}",
            "event": "runtime_math_logging_source_bound",
            "missing_item_id": "implementation.primary",
        },
        {
            **common,
            "trace_id": f"{COMPLETION_DEBT_BEAD}::runtime_math_logging::unit::{status}",
            "event": "runtime_math_logging_unit_bound",
            "missing_item_id": "tests.unit.primary",
        },
        {
            **common,
            "trace_id": f"{COMPLETION_DEBT_BEAD}::runtime_math_logging::e2e::{status}",
            "event": "runtime_math_logging_e2e_bound",
            "missing_item_id": "tests.e2e.primary",
        },
        {
            **common,
            "trace_id": f"{COMPLETION_DEBT_BEAD}::runtime_math_logging::telemetry::{status}",
            "event": "runtime_math_logging_telemetry_bound",
            "missing_item_id": "telemetry.primary",
        },
        {
            **common,
            "trace_id": f"{COMPLETION_DEBT_BEAD}::runtime_math_logging::summary::{status}",
            "event": PASS_EVENT if status == "pass" else FAIL_EVENT,
            "missing_item_id": "completion_debt.summary",
        },
    ]
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


errors = []
test_refs = set()
artifact_refs = set()
contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "runtime_math_logging_completion_contract.v1":
    errors.append("schema_version drifted")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

for ref in evidence.get("implementation_refs", []):
    file_line_ref_exists(ref, errors)

artifacts = evidence.get("artifacts", {})
if not isinstance(artifacts, dict):
    errors.append("artifacts must be an object")
    artifacts = {}
for name, rel_path in artifacts.items():
    if not isinstance(rel_path, str) or not rel_path:
        errors.append(f"artifacts.{name} missing path")
        continue
    path = root / rel_path
    if not path.is_file():
        errors.append(f"artifacts.{name} path missing: {rel_path}")
        continue
    artifact_refs.add(rel_path)

sources = evidence.get("test_sources", {})
if not isinstance(sources, dict):
    errors.append("test_sources must be an object")
    sources = {}
source_texts = {
    name: read_source(path_text, name, errors)
    for name, path_text in sources.items()
}
runtime_math_mod = source_texts.get("runtime_math_mod", "")
runtime_evidence = source_texts.get("runtime_evidence", "")
observability = source_texts.get("observability_dashboard", "")

contract_spec = evidence.get("logging_contract", {})
if not isinstance(contract_spec, dict):
    errors.append("logging_contract must be an object")
    contract_spec = {}

jsonl_events = require_set(
    contract_spec.get("required_jsonl_events"),
    REQUIRED_JSONL_EVENTS,
    "logging_contract.required_jsonl_events",
    errors,
)
jsonl_fields = require_set(
    contract_spec.get("required_jsonl_fields"),
    REQUIRED_JSONL_FIELDS,
    "logging_contract.required_jsonl_fields",
    errors,
)
decision_paths = require_set(
    contract_spec.get("required_decision_paths"),
    REQUIRED_DECISION_PATHS,
    "logging_contract.required_decision_paths",
    errors,
)
observability_anchors = require_set(
    contract_spec.get("required_observability_exports"),
    REQUIRED_OBSERVABILITY_EXPORTS,
    "logging_contract.required_observability_exports",
    errors,
)

if "pub fn export_runtime_math_log_jsonl" not in runtime_math_mod:
    errors.append("runtime_math_mod missing export_runtime_math_log_jsonl")
if "impl RuntimeKernelFramework for RuntimeMathKernel" not in runtime_math_mod:
    errors.append("runtime_math_mod missing RuntimeKernelFramework implementation")
if "pub fn export_runtime_evidence_jsonl" not in runtime_evidence:
    errors.append("runtime_evidence missing export_runtime_evidence_jsonl")
for event in sorted(jsonl_events):
    if f'\\"event\\":\\"{event}\\"' not in runtime_math_mod and event not in runtime_math_mod:
        errors.append(f"runtime_math_log_jsonl missing event {event}")
for field in sorted(jsonl_fields):
    if f'\\"{field}\\"' not in runtime_math_mod:
        errors.append(f"runtime_math_log_jsonl missing field {field}")
for path in sorted(decision_paths):
    if path not in runtime_math_mod:
        errors.append(f"runtime_math_log_jsonl missing decision_path {path}")
for anchor in sorted(observability_anchors):
    if anchor not in observability:
        errors.append(f"observability_dashboard missing runtime export anchor {anchor}")

unit_test_count = 0
e2e_test_count = 0
for section, missing_item in REQUIRED_SECTIONS.items():
    section_value = evidence.get(section, {})
    if not isinstance(section_value, dict):
        errors.append(f"{section} must be an object")
        section_value = {}
    if section_value.get("missing_item_id") != missing_item:
        errors.append(f"{section}.missing_item_id must be {missing_item}")
    refs = section_value.get("required_test_refs", [])
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section}.required_test_refs must be a non-empty array")
        refs = []
    for ref in refs:
        source_name = ref.get("source") if isinstance(ref, dict) else None
        test_name = ref.get("name") if isinstance(ref, dict) else None
        if not isinstance(source_name, str) or not isinstance(test_name, str):
            errors.append(f"{section}.required_test_refs entries need source and name")
            continue
        source_text = source_texts.get(source_name)
        if source_text is None:
            errors.append(f"{section} references undeclared source {source_name}")
            continue
        if not function_exists(source_text, test_name):
            errors.append(f"{section} references missing test {source_name}::{test_name}")
        test_refs.add(f"{source_name}::{test_name}")
        if section == "unit_primary":
            unit_test_count += 1
        if section == "e2e_primary":
            e2e_test_count += 1
    commands = section_value.get("required_commands", [])
    if not isinstance(commands, list) or not commands:
        errors.append(f"{section}.required_commands must be a non-empty array")
    for command in commands:
        if not isinstance(command, str):
            errors.append(f"{section}.required_commands entries must be strings")
            continue
        if "cargo " in command and "rch " not in command:
            errors.append(f"{section}.required_commands must use rch for cargo: {command}")

telemetry = evidence.get("telemetry_primary", {})
if not isinstance(telemetry, dict):
    errors.append("telemetry_primary must be an object")
    telemetry = {}
if telemetry.get("missing_item_id") != "telemetry.primary":
    errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
telemetry_events = require_set(
    telemetry.get("required_events"),
    REQUIRED_TELEMETRY_EVENTS,
    "telemetry_primary.required_events",
    errors,
)
telemetry_fields = require_set(
    telemetry.get("required_fields"),
    REQUIRED_TELEMETRY_FIELDS,
    "telemetry_primary.required_fields",
    errors,
)
for ref in telemetry.get("required_test_refs", []):
    if isinstance(ref, dict) and isinstance(ref.get("source"), str) and isinstance(ref.get("name"), str):
        test_refs.add(f"{ref['source']}::{ref['name']}")

summary = {
    "jsonl_event_count": len(jsonl_events),
    "jsonl_field_count": len(jsonl_fields),
    "decision_path_count": len(decision_paths),
    "observability_anchor_count": len(observability_anchors),
    "unit_test_count": unit_test_count,
    "e2e_test_count": e2e_test_count,
    "telemetry_event_count": len(telemetry_events),
    "telemetry_field_count": len(telemetry_fields),
    "test_ref_count": len(test_refs),
    "artifact_ref_count": len(artifact_refs),
}

status = "fail" if errors else "pass"
emit(status, errors, summary, test_refs, artifact_refs)
if errors:
    print(
        "runtime_math_logging_completion_contract: FAIL " + "; ".join(errors),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "runtime_math_logging_completion_contract: PASS "
    f"jsonl_events={summary['jsonl_event_count']} "
    f"jsonl_fields={summary['jsonl_field_count']} "
    f"unit_tests={summary['unit_test_count']} "
    f"e2e_tests={summary['e2e_test_count']} "
    f"telemetry_events={summary['telemetry_event_count']}"
)
PY
