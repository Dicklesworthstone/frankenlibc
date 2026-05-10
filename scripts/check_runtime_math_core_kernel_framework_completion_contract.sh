#!/usr/bin/env bash
# check_runtime_math_core_kernel_framework_completion_contract.sh - bd-5vr.1.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_CORE_FRAMEWORK_CONTRACT:-${ROOT}/tests/conformance/runtime_math_core_kernel_framework_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_CORE_FRAMEWORK_REPORT:-${ROOT}/target/conformance/runtime_math_core_kernel_framework_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_CORE_FRAMEWORK_LOG:-${ROOT}/target/conformance/runtime_math_core_kernel_framework_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-5vr.1.1"
ORIGINAL_BEAD = "bd-5vr.1"
PASS_EVENT = "runtime_math_core_kernel_framework_completion_contract_validated"
FAIL_EVENT = "runtime_math_core_kernel_framework_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
}
REQUIRED_TELEMETRY_EVENTS = {
    PASS_EVENT,
    FAIL_EVENT,
    "runtime_decision",
    "runtime_snapshot",
}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "trait_method_count",
    "runtime_policy_wrapper_count",
    "jsonl_event_count",
    "jsonl_field_count",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}
REQUIRED_TRAIT_METHODS = {
    "evaluate",
    "calibrate",
    "snapshot",
    "evidence_contract_snapshot",
    "reverse_round_diversity_snapshot",
    "export_decision_cards_json",
    "export_runtime_math_log_jsonl",
}
REQUIRED_POLICY_WRAPPERS = {
    "runtime_kernel_snapshot",
    "runtime_evidence_contract_snapshot",
    "export_runtime_decision_cards_json",
    "export_runtime_math_log_jsonl",
}
REQUIRED_EVIDENCE_FIELDS = {
    "evidence_seqno",
    "evidence_loss_count",
    "evidence_max_epoch",
}
REQUIRED_DIVERSITY_FIELDS = {
    "total_decisions",
    "active_family_count",
    "dominant_family",
    "dominant_family_share_ppm",
    "warn_threshold_ppm",
    "error_threshold_ppm",
    "coverage_milestone_target",
    "coverage_milestone_reached",
    "state",
}
REQUIRED_JSONL_EVENTS = {
    "runtime_mode_dispatch",
    "runtime_decision",
    "runtime_evidence_emitted",
    "runtime_pressure_sensor",
    "runtime_reverse_round_math_selection",
    "runtime_reverse_round_coverage_milestone",
    "runtime_calibration",
    "runtime_snapshot",
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
    "decision_path",
    "mode",
    "api_family",
    "symbol",
    "healing_action",
    "errno",
    "latency_ns",
    "evidence_seqno",
    "artifact_refs",
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
    failure_signature = "" if status == "pass" else ";".join(errors[:6])
    report = {
        "schema_version": "runtime_math_core_kernel_framework_completion_contract.report.v1",
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
    row = {
        "timestamp": now,
        "trace_id": f"completion::{COMPLETION_DEBT_BEAD}::{status}",
        "event": PASS_EVENT if status == "pass" else FAIL_EVENT,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "trait_method_count": summary.get("trait_method_count", 0),
        "runtime_policy_wrapper_count": summary.get("runtime_policy_wrapper_count", 0),
        "jsonl_event_count": summary.get("jsonl_event_count", 0),
        "jsonl_field_count": summary.get("jsonl_field_count", 0),
        "test_refs": sorted(test_refs),
        "artifact_refs": sorted(artifact_refs),
        "failure_signature": failure_signature,
    }
    log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")


errors = []
test_refs = set()
artifact_refs = set()
contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "runtime_math_core_kernel_framework_completion_contract.v1":
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
runtime_policy = source_texts.get("runtime_policy", "")

contract_spec = evidence.get("framework_contract", {})
if not isinstance(contract_spec, dict):
    errors.append("framework_contract must be an object")
    contract_spec = {}

trait_methods = require_set(
    contract_spec.get("required_trait_methods"),
    REQUIRED_TRAIT_METHODS,
    "framework_contract.required_trait_methods",
    errors,
)
wrappers = require_set(
    contract_spec.get("required_runtime_policy_wrappers"),
    REQUIRED_POLICY_WRAPPERS,
    "framework_contract.required_runtime_policy_wrappers",
    errors,
)
evidence_fields = require_set(
    contract_spec.get("required_evidence_snapshot_fields"),
    REQUIRED_EVIDENCE_FIELDS,
    "framework_contract.required_evidence_snapshot_fields",
    errors,
)
diversity_fields = require_set(
    contract_spec.get("required_reverse_round_snapshot_fields"),
    REQUIRED_DIVERSITY_FIELDS,
    "framework_contract.required_reverse_round_snapshot_fields",
    errors,
)
jsonl_events = require_set(
    contract_spec.get("required_jsonl_events"),
    REQUIRED_JSONL_EVENTS,
    "framework_contract.required_jsonl_events",
    errors,
)
jsonl_fields = require_set(
    contract_spec.get("required_jsonl_fields"),
    REQUIRED_JSONL_FIELDS,
    "framework_contract.required_jsonl_fields",
    errors,
)

if "pub trait RuntimeKernelFramework" not in runtime_math_mod:
    errors.append("RuntimeKernelFramework trait missing from runtime_math_mod")
if "impl RuntimeKernelFramework for RuntimeMathKernel" not in runtime_math_mod:
    errors.append("RuntimeMathKernel trait implementation missing")

for method in sorted(trait_methods):
    if f"fn {method}" not in runtime_math_mod:
        errors.append(f"runtime_math_mod missing trait method marker {method}")
for wrapper in sorted(wrappers):
    if f"fn {wrapper}" not in runtime_policy:
        errors.append(f"runtime_policy missing wrapper {wrapper}")
for field in sorted(evidence_fields):
    if f"pub {field}" not in runtime_math_mod:
        errors.append(f"RuntimeEvidenceContractSnapshot missing field {field}")
for field in sorted(diversity_fields):
    if f"pub {field}" not in runtime_math_mod:
        errors.append(f"RuntimeReverseRoundDiversitySnapshot missing field {field}")
for event in sorted(jsonl_events):
    if f'\\"event\\":\\"{event}\\"' not in runtime_math_mod:
        errors.append(f"runtime_math_log_jsonl missing event {event}")
for field in sorted(jsonl_fields):
    if f'\\"{field}\\"' not in runtime_math_mod:
        errors.append(f"runtime_math_log_jsonl missing field {field}")

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
    "trait_method_count": len(trait_methods),
    "runtime_policy_wrapper_count": len(wrappers),
    "evidence_snapshot_field_count": len(evidence_fields),
    "reverse_round_snapshot_field_count": len(diversity_fields),
    "jsonl_event_count": len(jsonl_events),
    "jsonl_field_count": len(jsonl_fields),
    "telemetry_event_count": len(telemetry_events),
    "telemetry_field_count": len(telemetry_fields),
    "test_ref_count": len(test_refs),
    "artifact_ref_count": len(artifact_refs),
}

status = "fail" if errors else "pass"
emit(status, errors, summary, test_refs, artifact_refs)
if errors:
    print(
        "runtime_math_core_kernel_framework_completion_contract: FAIL "
        + "; ".join(errors),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "runtime_math_core_kernel_framework_completion_contract: PASS "
    f"trait_methods={summary['trait_method_count']} "
    f"wrappers={summary['runtime_policy_wrapper_count']} "
    f"jsonl_events={summary['jsonl_event_count']} "
    f"jsonl_fields={summary['jsonl_field_count']} "
    f"tests={summary['test_ref_count']}"
)
PY
