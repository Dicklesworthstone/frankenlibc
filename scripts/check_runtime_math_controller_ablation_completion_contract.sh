#!/usr/bin/env bash
# check_runtime_math_controller_ablation_completion_contract.sh - bd-3ot.2.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_ABLATION_CONTRACT:-${ROOT}/tests/conformance/runtime_math_controller_ablation_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_ABLATION_REPORT:-${ROOT}/target/conformance/runtime_math_controller_ablation_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_ABLATION_LOG:-${ROOT}/target/conformance/runtime_math_controller_ablation_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-3ot.2.1"
ORIGINAL_BEAD = "bd-3ot.2"
PASS_EVENT = "runtime_math_controller_ablation_completion_contract_validated"
FAIL_EVENT = "runtime_math_controller_ablation_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "migrations_primary": "migrations.primary",
}
REQUIRED_SUMMARY_FIELDS = {
    "total_modules",
    "production_retain",
    "research_retire",
    "blocked",
    "errors",
    "warnings",
}
REQUIRED_DECISION_FIELDS = {
    "module",
    "tier",
    "decision",
    "partition",
    "reason",
    "migration_action",
}
REQUIRED_MIGRATION_FIELDS = {
    "description",
    "feature_gate",
    "total_to_retire",
    "compile_time_enforcement",
    "modules",
    "verification",
}
ALLOWED_DECISIONS = {"RETAIN", "RETIRE", "BLOCK"}


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

if contract.get("schema_version") != "runtime_math_controller_ablation_completion_contract.v1":
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
    if path.suffix == ".json" or path.name.endswith(".json"):
        loaded_artifacts[name] = load_json(path, errors, f"artifacts.{name}")

ablation_report = loaded_artifacts.get("controller_ablation_report", {})
production_manifest = loaded_artifacts.get("production_manifest", {})
math_value_ablations = loaded_artifacts.get("math_value_ablations", {})
math_value_proof = loaded_artifacts.get("math_value_proof", {})

if ablation_report.get("schema_version") != "v1":
    errors.append("controller_ablation_report.schema_version must be v1")
if ablation_report.get("bead") != ORIGINAL_BEAD:
    errors.append(f"controller_ablation_report.bead must be {ORIGINAL_BEAD}")
if ablation_report.get("status") != "pass":
    errors.append("controller_ablation_report.status must be pass")

contract_spec = evidence.get("ablation_contract", {})
if not isinstance(contract_spec, dict):
    errors.append("ablation_contract must be an object")
    contract_spec = {}
summary_fields = require_set(
    contract_spec.get("required_summary_fields"),
    REQUIRED_SUMMARY_FIELDS,
    "ablation_contract.required_summary_fields",
    errors,
)
decision_fields = require_set(
    contract_spec.get("required_decision_fields"),
    REQUIRED_DECISION_FIELDS,
    "ablation_contract.required_decision_fields",
    errors,
)
migration_fields = require_set(
    contract_spec.get("required_migration_fields"),
    REQUIRED_MIGRATION_FIELDS,
    "ablation_contract.required_migration_fields",
    errors,
)
allowed_decisions = require_set(
    contract_spec.get("allowed_decisions"),
    ALLOWED_DECISIONS,
    "ablation_contract.allowed_decisions",
    errors,
)

expected_partition = evidence.get("expected_partition", {})
if not isinstance(expected_partition, dict):
    errors.append("expected_partition must be an object")
    expected_partition = {}

summary = ablation_report.get("summary", {})
if not isinstance(summary, dict):
    errors.append("controller_ablation_report.summary must be an object")
    summary = {}
for field in sorted(REQUIRED_SUMMARY_FIELDS):
    if field not in summary:
        errors.append(f"controller_ablation_report.summary missing {field}")
for field in ("total_modules", "production_retain", "research_retire", "blocked", "errors"):
    expected_value = expected_partition.get(field)
    if isinstance(expected_value, int) and summary.get(field) != expected_value:
        errors.append(
            f"controller_ablation_report.summary.{field} expected {expected_value} got {summary.get(field)!r}"
        )

decisions = ablation_report.get("partition_decisions")
if not isinstance(decisions, list) or not decisions:
    errors.append("controller_ablation_report.partition_decisions must be a non-empty array")
    decisions = []
production_modules = set()
research_modules = set()
blocked_modules = set()
decision_modules = set()
research_plan_modules = set()
for index, decision in enumerate(decisions):
    if not isinstance(decision, dict):
        errors.append(f"partition_decisions[{index}] must be an object")
        continue
    for field in sorted(REQUIRED_DECISION_FIELDS):
        if field not in decision:
            errors.append(f"partition_decisions[{index}] missing {field}")
    module = decision.get("module")
    if isinstance(module, str):
        if module in decision_modules:
            errors.append(f"duplicate partition decision for {module}")
        decision_modules.add(module)
    value = decision.get("decision")
    tier = decision.get("tier")
    partition = decision.get("partition")
    migration_action = decision.get("migration_action", "")
    if value not in ALLOWED_DECISIONS:
        errors.append(f"partition_decisions[{index}] invalid decision {value!r}")
    if value == "RETAIN":
        if partition != "production":
            errors.append(f"retained module {module!r} must use production partition")
        if migration_action != "none":
            errors.append(f"retained module {module!r} must not have migration action")
        if isinstance(module, str):
            production_modules.add(module)
    if value == "RETIRE":
        if tier != "research":
            errors.append(f"retired module {module!r} must be research tier")
        if partition != "research_annex":
            errors.append(f"retired module {module!r} must use research_annex partition")
        if "runtime-math-research" not in str(migration_action):
            errors.append(f"retired module {module!r} missing runtime-math-research action")
        if isinstance(module, str):
            research_modules.add(module)
    if value == "BLOCK" and isinstance(module, str):
        blocked_modules.add(module)

if summary.get("total_modules") != len(decision_modules):
    errors.append("partition decision count must match summary.total_modules")
if summary.get("production_retain") != len(production_modules):
    errors.append("production retained count must match summary.production_retain")
if summary.get("research_retire") != len(research_modules):
    errors.append("research retired count must match summary.research_retire")
if summary.get("blocked") != len(blocked_modules):
    errors.append("blocked count must match summary.blocked")

migration_plan = ablation_report.get("migration_plan", {})
if not isinstance(migration_plan, dict):
    errors.append("controller_ablation_report.migration_plan must be an object")
    migration_plan = {}
for field in sorted(REQUIRED_MIGRATION_FIELDS):
    if field not in migration_plan:
        errors.append(f"controller_ablation_report.migration_plan missing {field}")

migrations = evidence.get("migrations_primary", {})
if not isinstance(migrations, dict):
    errors.append("migrations_primary must be an object")
    migrations = {}
required_feature_gate = migrations.get("required_feature_gate")
required_default_feature = migrations.get("required_default_feature")
if migration_plan.get("feature_gate") != required_feature_gate:
    errors.append(
        f"migration_plan.feature_gate must be {required_feature_gate!r}"
    )
if migration_plan.get("total_to_retire") != len(research_modules):
    errors.append("migration_plan.total_to_retire must match retired research modules")
plan_modules = migration_plan.get("modules", [])
if not isinstance(plan_modules, list):
    errors.append("migration_plan.modules must be an array")
    plan_modules = []
for row in plan_modules:
    if not isinstance(row, dict):
        errors.append("migration_plan.modules entries must be objects")
        continue
    module = row.get("module")
    action = row.get("action")
    if isinstance(module, str):
        research_plan_modules.add(module)
    if "runtime-math-research" not in str(action):
        errors.append(f"migration_plan module {module!r} missing runtime-math-research action")
if research_plan_modules != research_modules:
    errors.append("migration_plan.modules must exactly match retired research modules")

manifest_production = set(production_manifest.get("production_modules", []))
manifest_research = set(production_manifest.get("research_only_modules", []))
if manifest_production != production_modules:
    errors.append("production_manifest.production_modules must match retained production modules")
if manifest_research != research_modules:
    errors.append("production_manifest.research_only_modules must match retired research modules")
if required_default_feature not in production_manifest.get("default_feature_set", []):
    errors.append(f"production_manifest.default_feature_set missing {required_default_feature!r}")
if required_feature_gate not in production_manifest.get("optional_feature_set", []):
    errors.append(f"production_manifest.optional_feature_set missing {required_feature_gate!r}")

value_experiments = math_value_ablations.get("experiments", [])
if not isinstance(value_experiments, list):
    errors.append("math_value_ablations.experiments must be an array")
    value_experiments = []
value_modules = {
    exp.get("module")
    for exp in value_experiments
    if isinstance(exp, dict) and isinstance(exp.get("module"), str)
}
if value_modules != production_modules:
    errors.append("math_value_ablations experiments must match retained production modules")
if math_value_ablations.get("summary", {}).get("retain") != len(production_modules):
    errors.append("math_value_ablations.summary.retain must match retained production modules")

proof_modules = set()
for key in ("production_core_assessments", "production_monitor_assessments"):
    for row in math_value_proof.get(key, []):
        if isinstance(row, dict) and isinstance(row.get("module"), str):
            proof_modules.add(row["module"])
if proof_modules != production_modules:
    errors.append("math_value_proof retained assessments must match retained production modules")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}
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

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

runner_text = (root / artifacts.get("controller_ablation_runner", "")).read_text(encoding="utf-8")
for token in [
    "compute_partition_decision",
    "validate_manifest_governance_consistency",
    "migration_plan",
    "runtime-math-research",
]:
    if token not in runner_text:
        errors.append(f"controller_ablation_runner missing token {token}")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
artifact_refs.extend(sorted(value for value in artifacts.values() if isinstance(value, str)))
event = PASS_EVENT if not errors else FAIL_EVENT
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:runtime_math_controller_ablation",
    "event": event,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "total_modules": len(decision_modules),
    "production_retain": len(production_modules),
    "research_retire": len(research_modules),
    "blocked": len(blocked_modules),
    "required_summary_fields": sorted(summary_fields),
    "required_decision_fields": sorted(decision_fields),
    "required_migration_fields": sorted(migration_fields),
    "allowed_decisions": sorted(allowed_decisions),
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "runtime_math_controller_ablation_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "total_modules": len(decision_modules),
    "production_retain": len(production_modules),
    "research_retire": len(research_modules),
    "blocked": len(blocked_modules),
    "required_summary_fields": sorted(summary_fields),
    "required_decision_fields": sorted(decision_fields),
    "required_migration_fields": sorted(migration_fields),
    "allowed_decisions": sorted(allowed_decisions),
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
