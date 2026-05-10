#!/usr/bin/env bash
# check_runtime_math_controller_manifest_completion_contract.sh - bd-3ot.1.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_CONTROLLER_CONTRACT:-${ROOT}/tests/conformance/runtime_math_controller_manifest_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_CONTROLLER_REPORT:-${ROOT}/target/conformance/runtime_math_controller_manifest_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_CONTROLLER_LOG:-${ROOT}/target/conformance/runtime_math_controller_manifest_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-3ot.1.1"
ORIGINAL_BEAD = "bd-3ot.1"
PASS_EVENT = "runtime_math_controller_manifest_completion_contract_validated"
FAIL_EVENT = "runtime_math_controller_manifest_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "fuzz_primary": "tests.fuzz.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_SUMMARY_ZERO_FIELDS = {
    "missing_decision_hook",
    "missing_invariant",
    "missing_fallback",
    "missing_benefit_target",
}
REQUIRED_CONTROLLER_FIELDS = {
    "module",
    "tier",
    "decision_hook",
    "invariant",
    "fallback_when_data_missing",
    "runtime_cost_target",
    "benefit_target",
}
REQUIRED_RUNTIME_COST_FIELDS = {
    "strict_hot_path_ns_max",
    "hardened_hot_path_ns_max",
    "cadence",
}
REQUIRED_POLICIES = {
    "controller_manifest: linkage_required",
    "controller_manifest: decision_target_required",
    "controller_manifest: invariant_required",
    "controller_manifest: fallback_when_data_missing_required",
    "controller_manifest: value_target_required",
    "admission: governance_classification_required",
    "admission: ablation_evidence_required",
    "tooling_contract: asupersync_dependency_required",
    "tooling_contract: frankentui_feature_required",
}
REQUIRED_TELEMETRY_EVENTS = {
    PASS_EVENT,
    FAIL_EVENT,
    "runtime_math_admission_gate",
}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "controller_count",
    "production_controller_count",
    "required_policies",
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


errors = []
contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "runtime_math_controller_manifest_completion_contract.v1":
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
loaded_artifacts = {}
for name, rel_path in artifacts.items():
    if not isinstance(rel_path, str) or not rel_path:
        errors.append(f"artifacts.{name} missing path")
        continue
    path = root / rel_path
    if not path.is_file():
        errors.append(f"artifacts.{name} path missing: {rel_path}")
        continue
    loaded_artifacts[name] = load_json(path, errors, f"artifacts.{name}")

controller_manifest = loaded_artifacts.get("controller_manifest", {})
admission_report = loaded_artifacts.get("admission_report", {})
if controller_manifest.get("schema_version") != "v1":
    errors.append("controller_manifest.schema_version must be v1")
if admission_report.get("status") != "pass":
    errors.append("admission_report.status must be pass")

contract_spec = evidence.get("controller_manifest_contract", {})
if not isinstance(contract_spec, dict):
    errors.append("controller_manifest_contract must be an object")
    contract_spec = {}
summary_zero_fields = require_set(
    contract_spec.get("required_summary_zero_fields"),
    REQUIRED_SUMMARY_ZERO_FIELDS,
    "controller_manifest_contract.required_summary_zero_fields",
    errors,
)
controller_fields = require_set(
    contract_spec.get("required_controller_fields"),
    REQUIRED_CONTROLLER_FIELDS,
    "controller_manifest_contract.required_controller_fields",
    errors,
)
runtime_cost_fields = require_set(
    contract_spec.get("required_runtime_cost_fields"),
    REQUIRED_RUNTIME_COST_FIELDS,
    "controller_manifest_contract.required_runtime_cost_fields",
    errors,
)
required_policies = require_set(
    contract_spec.get("required_policies"),
    REQUIRED_POLICIES,
    "controller_manifest_contract.required_policies",
    errors,
)

summary = controller_manifest.get("summary", {})
if not isinstance(summary, dict):
    errors.append("controller_manifest.summary must be an object")
    summary = {}
for field in sorted(REQUIRED_SUMMARY_ZERO_FIELDS):
    value = summary.get(field)
    if value != 0:
        errors.append(f"controller_manifest.summary.{field} must be 0")

controllers = controller_manifest.get("controllers")
if not isinstance(controllers, list) or not controllers:
    errors.append("controller_manifest.controllers must be a non-empty array")
    controllers = []
production_count = 0
for index, controller in enumerate(controllers):
    if not isinstance(controller, dict):
        errors.append(f"controller_manifest.controllers[{index}] must be an object")
        continue
    for field in sorted(REQUIRED_CONTROLLER_FIELDS):
        if field not in controller:
            errors.append(f"controller_manifest.controllers[{index}] missing {field}")
    cost = controller.get("runtime_cost_target")
    if not isinstance(cost, dict):
        errors.append(f"controller_manifest.controllers[{index}].runtime_cost_target must be an object")
    else:
        for field in sorted(REQUIRED_RUNTIME_COST_FIELDS):
            if field not in cost:
                errors.append(
                    f"controller_manifest.controllers[{index}].runtime_cost_target missing {field}"
                )
    if controller.get("in_production_manifest") is True:
        production_count += 1
        for field in ("decision_hook", "invariant", "fallback_when_data_missing"):
            if not controller.get(field):
                errors.append(f"production controller {controller.get('module')} missing {field}")
        if controller.get("tier") in {"production_core", "production_monitor"} and not controller.get("benefit_target"):
            errors.append(f"production controller {controller.get('module')} missing benefit_target")

report_policies = admission_report.get("policies_enforced", [])
if not isinstance(report_policies, list):
    errors.append("admission_report.policies_enforced must be an array")
    report_policy_set = set()
else:
    report_policy_set = {item for item in report_policies if isinstance(item, str)}
missing_report_policies = sorted(REQUIRED_POLICIES - report_policy_set)
if missing_report_policies:
    errors.append(f"admission_report.policies_enforced missing {','.join(missing_report_policies)}")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}
script_text = source_texts.get("admission_script", "")
for token in [
    "controller_manifest_entries",
    "decision_hook",
    "invariant",
    "fallback_when_data_missing",
    "runtime_cost_target",
    "benefit_target",
]:
    if token not in script_text:
        errors.append(f"admission_script missing token {token}")

test_refs = []
for section, missing_item_id in REQUIRED_SECTIONS.items():
    block = evidence.get(section)
    if not isinstance(block, dict):
        errors.append(f"{section} missing")
        continue
    if block.get("missing_item_id") != missing_item_id:
        errors.append(f"{section}.missing_item_id must be {missing_item_id}")
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section}.required_test_refs missing")
        continue
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section}.required_test_refs entry must be object")
            continue
        source_key = ref.get("source")
        name = ref.get("name")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"{section} references undeclared source {source_key!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_texts[source_key], name):
            errors.append(f"{section} references missing test {source_key}::{name}")
            continue
        test_refs.append(f"{source_key}::{name}")

for artifact in evidence.get("conformance_primary", {}).get("required_artifacts", []):
    if not isinstance(artifact, str) or not (root / artifact).is_file():
        errors.append(f"conformance_primary.required_artifacts missing {artifact!r}")

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

telemetry = evidence.get("telemetry_primary", {})
events = telemetry.get("required_events")
if not isinstance(events, list) or not REQUIRED_TELEMETRY_EVENTS <= {
    event for event in events if isinstance(event, str)
}:
    errors.append("telemetry_primary.required_events missing required events")
fields = telemetry.get("required_fields")
if not isinstance(fields, list) or not REQUIRED_TELEMETRY_FIELDS <= {
    field for field in fields if isinstance(field, str)
}:
    errors.append("telemetry_primary.required_fields missing required keys")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
artifact_refs.extend(sorted(value for value in artifacts.values() if isinstance(value, str)))
event = PASS_EVENT if not errors else FAIL_EVENT
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:runtime_math_controller_manifest",
    "event": event,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "controller_count": len(controllers),
    "production_controller_count": production_count,
    "required_summary_zero_fields": sorted(summary_zero_fields),
    "required_controller_fields": sorted(controller_fields),
    "required_runtime_cost_fields": sorted(runtime_cost_fields),
    "required_policies": sorted(required_policies),
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "runtime_math_controller_manifest_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "controller_count": len(controllers),
    "production_controller_count": production_count,
    "required_summary_zero_fields": sorted(summary_zero_fields),
    "required_controller_fields": sorted(controller_fields),
    "required_runtime_cost_fields": sorted(runtime_cost_fields),
    "required_policies": sorted(required_policies),
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    sys.exit(1)
PY
