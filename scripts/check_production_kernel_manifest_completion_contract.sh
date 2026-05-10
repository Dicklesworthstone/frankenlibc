#!/usr/bin/env bash
# check_production_kernel_manifest_completion_contract.sh - bd-rqn.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/production_kernel_manifest_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_REPORT:-${ROOT}/target/conformance/production_kernel_manifest_completion_contract.report.json}"
LOG="${FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_LOG:-${ROOT}/target/conformance/production_kernel_manifest_completion_contract.log.jsonl}"
GATE_TRANSCRIPT="${FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_GATE_TRANSCRIPT:-${ROOT}/target/conformance/production_kernel_manifest_completion_contract.gate.txt}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "$(dirname "${GATE_TRANSCRIPT}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${GATE_TRANSCRIPT}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
gate_transcript_path = Path(sys.argv[5])
source_commit = sys.argv[6]

COMPLETION_DEBT_BEAD = "bd-rqn.1"
ORIGINAL_BEAD = "bd-rqn"
PASS_EVENT = "production_kernel_completion_contract_validated"
FAIL_EVENT = "production_kernel_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "migrations_primary": "migrations.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_EVENTS = {
    "production_kernel_manifest_summary",
    "production_kernel_manifest_gate_replayed",
    "production_kernel_governance_gate_replayed",
    "production_kernel_classification_gate_replayed",
    "production_kernel_production_policy_gate_replayed",
    "production_kernel_admission_report_validated",
    "production_kernel_migration_validated",
    PASS_EVENT,
    FAIL_EVENT,
}
REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "mode",
    "api_family",
    "symbol",
    "outcome",
    "errno",
    "timing_ns",
    "production_module_count",
    "research_only_module_count",
    "total_runtime_math_modules",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}
REQUIRED_FEATURE_BINDINGS = {
    'default = ["runtime-math-production"]',
    "runtime-math-production = []",
    'runtime-math-research = ["runtime-math-production"]',
    "requires the `runtime-math-production` feature",
}


def rel(path: Path | str) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def read_text(path_text: Any, errors: list[str], label: str) -> str:
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"{label} missing path")
        return ""
    path = root / path_text
    if not path.is_file():
        errors.append(f"{label} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label} unreadable: {path_text}: {exc}")
        return ""


def string_set(value: Any, label: str, errors: list[str]) -> set[str]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return set()
    result = {item for item in value if isinstance(item, str)}
    if len(result) != len(value):
        errors.append(f"{label} must contain only strings")
    return result


def file_line_ref_exists(ref: Any, errors: list[str]) -> None:
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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text


def run_gate(script_rel: str, sentinel: str, event: str, errors: list[str]) -> str:
    script = root / script_rel
    started = time.perf_counter_ns()
    proc = subprocess.run(
        ["bash", str(script)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    elapsed = time.perf_counter_ns() - started
    output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        errors.append(f"{script_rel} failed with exit {proc.returncode}")
    if sentinel not in output:
        errors.append(f"{script_rel} missing sentinel {sentinel!r}")
    gate_runs.append(
        {
            "script": script_rel,
            "event": event,
            "exit_code": proc.returncode,
            "timing_ns": elapsed,
            "sentinel": sentinel,
            "output": output,
        }
    )
    return output


def source_texts(evidence: dict[str, Any], errors: list[str]) -> dict[str, str]:
    sources = evidence.get("test_sources")
    if not isinstance(sources, dict):
        errors.append("completion_debt_evidence.test_sources must be an object")
        return {}
    texts: dict[str, str] = {}
    for key, path_text in sources.items():
        texts[key] = read_text(path_text, errors, f"test_sources.{key}")
    return texts


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str], errors: list[str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_test_refs must be a non-empty array")
        return []
    normalized: list[dict[str, str]] = []
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            errors.append(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            errors.append(f"{section_name}.required_test_refs[{index}] missing source/name")
            continue
        text = texts.get(source, "")
        if not function_exists(text, name):
            errors.append(f"{section_name} references missing Rust test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def event_payload(event: str, level: str, timing_ns: int = 0) -> dict[str, Any]:
    status = "pass" if not errors else "fail"
    outcome = "pass" if level != "error" and not errors else "fail"
    return {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD}::{event}",
        "event": event,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "mode": "strict+hardened",
        "api_family": "runtime_math",
        "symbol": "production_kernel_manifest",
        "outcome": outcome,
        "errno": 0 if outcome == "pass" else 1,
        "timing_ns": timing_ns,
        "production_module_count": production_count,
        "research_only_module_count": research_count,
        "total_runtime_math_modules": total_count,
        "admission_summary": admission_summary,
        "test_refs": test_refs_by_section,
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if outcome == "pass" else "production_kernel_completion_contract_error",
        "level": level,
    }


errors: list[str] = []
gate_runs: list[dict[str, Any]] = []
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "production_kernel_manifest_completion_contract.v1":
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

artifacts = evidence.get("artifacts")
if not isinstance(artifacts, dict):
    errors.append("completion_debt_evidence.artifacts must be an object")
    artifacts = {}

artifact_refs = [rel(contract_path), rel(report_path), rel(log_path), rel(gate_transcript_path)]
loaded: dict[str, dict[str, Any]] = {}
texts: dict[str, str] = {}
for name, path_text in artifacts.items():
    if not isinstance(path_text, str):
        errors.append(f"artifacts.{name} must be a path string")
        continue
    path = root / path_text
    artifact_refs.append(path_text)
    if path.suffix == ".json":
        loaded[name] = load_json(path, errors, f"artifacts.{name}")
    else:
        texts[name] = read_text(path_text, errors, f"artifacts.{name}")

production_manifest = loaded.get("production_manifest", {})
governance = loaded.get("governance", {})
classification_matrix = loaded.get("classification_matrix", {})
admission_report = loaded.get("admission_report", {})
production_set_policy = loaded.get("production_set_policy", {})

production_modules = string_set(production_manifest.get("production_modules"), "production_modules", errors)
research_modules = string_set(production_manifest.get("research_only_modules"), "research_only_modules", errors)
production_count = len(production_modules)
research_count = len(research_modules)
total_count = len(production_modules | research_modules)
overlap = sorted(production_modules & research_modules)
if overlap:
    errors.append(f"production_modules and research_only_modules overlap: {overlap}")

minimum = evidence.get("minimum_expectations")
if not isinstance(minimum, dict):
    errors.append("minimum_expectations must be an object")
    minimum = {}
if production_manifest.get("schema_version") != minimum.get("schema_version"):
    errors.append("production manifest schema_version drifted")
if production_count != minimum.get("production_module_count"):
    errors.append(f"production module count drifted: {production_count}")
if research_count != minimum.get("research_only_module_count"):
    errors.append(f"research-only module count drifted: {research_count}")
if total_count != minimum.get("total_runtime_math_modules"):
    errors.append(f"total runtime_math module count drifted: {total_count}")
if production_manifest.get("default_feature_set") != minimum.get("default_feature_set"):
    errors.append("default_feature_set drifted")
if production_manifest.get("optional_feature_set") != minimum.get("optional_feature_set"):
    errors.append("optional_feature_set drifted")
budgets = production_manifest.get("latency_budgets_ns", {})
if budgets.get("strict_hot_path_max") != minimum.get("strict_hot_path_max_ns"):
    errors.append("strict latency budget drifted")
if budgets.get("hardened_hot_path_max") != minimum.get("hardened_hot_path_max_ns"):
    errors.append("hardened latency budget drifted")

mod_text = texts.get("runtime_math_mod", "")
code_modules = {
    line.removeprefix("pub mod ").removesuffix(";").strip()
    for line in mod_text.splitlines()
    if line.startswith("pub mod ")
}
if code_modules != production_modules | research_modules:
    errors.append(
        "runtime_math/mod.rs module set must equal production_manifest production+research union"
    )
if "RUNTIME_MATH_PRODUCTION_ENABLED" not in mod_text:
    errors.append("runtime_math/mod.rs missing RUNTIME_MATH_PRODUCTION_ENABLED")
if "RUNTIME_MATH_RESEARCH_ENABLED" not in mod_text:
    errors.append("runtime_math/mod.rs missing RUNTIME_MATH_RESEARCH_ENABLED")

cargo_text = texts.get("membrane_cargo_toml", "")
lib_text = texts.get("membrane_lib", "")
migration = evidence.get("migration_contract")
if not isinstance(migration, dict):
    errors.append("migration_contract must be an object")
    migration = {}
feature_bindings = string_set(
    migration.get("required_feature_bindings"),
    "migration_contract.required_feature_bindings",
    errors,
)
missing_feature_bindings = sorted(REQUIRED_FEATURE_BINDINGS - feature_bindings)
if missing_feature_bindings:
    errors.append(f"migration_contract.required_feature_bindings missing {missing_feature_bindings}")
for binding in REQUIRED_FEATURE_BINDINGS:
    source = lib_text if "requires the" in binding else cargo_text
    if binding not in source:
        errors.append(f"feature binding not present in source: {binding}")

classifications = governance.get("classifications", {})
if not isinstance(classifications, dict):
    errors.append("governance.classifications must be an object")
    classifications = {}
production_governance = {
    entry.get("module")
    for tier in ("production_core", "production_monitor")
    for entry in classifications.get(tier, [])
    if isinstance(entry, dict) and isinstance(entry.get("module"), str)
}
research_governance = {
    entry.get("module")
    for entry in classifications.get("research", [])
    if isinstance(entry, dict) and isinstance(entry.get("module"), str)
}
if production_governance != production_modules:
    errors.append("production_core+production_monitor governance modules must equal production manifest")
if research_governance != research_modules:
    errors.append("research governance modules must equal research_only_modules")

matrix_modules = classification_matrix.get("modules", [])
if not isinstance(matrix_modules, list):
    errors.append("classification_matrix.modules must be an array")
    matrix_modules = []
matrix_module_names = {row.get("module") for row in matrix_modules if isinstance(row, dict)}
if matrix_module_names != production_modules | research_modules:
    errors.append("classification matrix modules must equal manifest union")
for row in matrix_modules:
    if not isinstance(row, dict):
        continue
    module = row.get("module")
    if module in production_modules and row.get("in_production_manifest") is not True:
        errors.append(f"classification matrix row {module} missing production flag")
    if module in research_modules and row.get("in_research_only_manifest") is not True:
        errors.append(f"classification matrix row {module} missing research-only flag")

admission_summary = admission_report.get("summary", {})
if admission_report.get("status") != minimum.get("admission_status"):
    errors.append("admission_report.status drifted")
if admission_summary.get("total_modules") != minimum.get("total_runtime_math_modules"):
    errors.append("admission_report.summary.total_modules drifted")
if admission_summary.get("admitted") != minimum.get("admitted_count"):
    errors.append("admission_report.summary.admitted drifted")
if admission_summary.get("retired") != minimum.get("retired_count"):
    errors.append("admission_report.summary.retired drifted")
if admission_summary.get("blocked") != minimum.get("blocked_count"):
    errors.append("admission_report.summary.blocked drifted")

policy_summary = production_set_policy.get("summary", {})
if policy_summary.get("total_production_modules") != production_count:
    errors.append("production_set_policy.summary.total_production_modules drifted")
if policy_summary.get("research_tier_modules") not in (0, None):
    errors.append("production set policy should have zero research-tier modules in production")

texts_by_source = source_texts(evidence, errors)
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in REQUIRED_SECTIONS.items():
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        errors.append(f"completion_debt_evidence.{section_name} missing")
        continue
    if section.get("missing_item_id") != missing_item:
        errors.append(f"{section_name}.missing_item_id must be {missing_item}")
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts_by_source, errors)
    commands = section.get("required_commands", [])
    if not isinstance(commands, list) or not commands:
        errors.append(f"{section_name}.required_commands must be non-empty")
    for command in commands:
        if not isinstance(command, str):
            errors.append(f"{section_name}.required_commands must contain strings")
            continue
        if ("cargo " in command or "check_runtime_math_profile_gates.sh" in command) and "rch exec" not in command:
            errors.append(f"{section_name}.required_commands must offload cargo/profile gates through rch: {command}")

telemetry = evidence.get("telemetry_primary")
if not isinstance(telemetry, dict):
    errors.append("telemetry_primary must be an object")
    telemetry = {}
telemetry_events = string_set(telemetry.get("required_events"), "telemetry_primary.required_events", errors)
missing_events = sorted(REQUIRED_EVENTS - telemetry_events)
if missing_events:
    errors.append(f"telemetry_primary.required_events missing {missing_events}")
telemetry_fields = string_set(telemetry.get("required_fields"), "telemetry_primary.required_fields", errors)
missing_fields = sorted(REQUIRED_FIELDS - telemetry_fields)
if missing_fields:
    errors.append(f"telemetry_primary.required_fields missing {missing_fields}")

run_gate(
    "scripts/check_runtime_math_manifest.sh",
    "OK: runtime_math production manifest covers 69 modules (Production=25, ResearchOnly=44).",
    "production_kernel_manifest_gate_replayed",
    errors,
)
run_gate(
    "scripts/check_math_governance.sh",
    "check_math_governance: PASS",
    "production_kernel_governance_gate_replayed",
    errors,
)
run_gate(
    "scripts/check_runtime_math_classification_matrix.sh",
    "PASS: runtime_math classification matrix covers 69 modules",
    "production_kernel_classification_gate_replayed",
    errors,
)
run_gate(
    "scripts/check_math_production_set_policy.sh",
    "PASS: production-set policy gate validated 25 modules",
    "production_kernel_production_policy_gate_replayed",
    errors,
)

gate_transcript_path.write_text(
    "\n".join(
        f"--- {run['script']} exit={run['exit_code']} ---\n{run['output']}"
        for run in gate_runs
    ),
    encoding="utf-8",
)

events = [
    event_payload("production_kernel_manifest_summary", "info"),
]
for run in gate_runs:
    events.append(event_payload(run["event"], "info", int(run["timing_ns"])))
events.append(event_payload("production_kernel_admission_report_validated", "info"))
events.append(event_payload("production_kernel_migration_validated", "info"))
events.append(event_payload(PASS_EVENT if not errors else FAIL_EVENT, "info" if not errors else "error"))

for row in events:
    missing = REQUIRED_FIELDS - set(row)
    if missing:
        errors.append(f"event {row.get('event')} missing required fields {sorted(missing)}")

if errors and events[-1]["event"] != FAIL_EVENT:
    events.append(event_payload(FAIL_EVENT, "error"))
for row in events:
    row["status"] = "pass" if not errors else "fail"
    row["outcome"] = "pass" if row["event"] != FAIL_EVENT and not errors else "fail"
    row["errno"] = 0 if row["outcome"] == "pass" else 1
    row["failure_signature"] = "none" if row["outcome"] == "pass" else "production_kernel_completion_contract_error"

report = {
    "schema_version": "production_kernel_manifest_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "source_commit": source_commit,
    "status": "pass" if not errors else "fail",
    "errors": errors,
    "summary": {
        "production_module_count": production_count,
        "research_only_module_count": research_count,
        "total_runtime_math_modules": total_count,
        "admission_summary": admission_summary,
        "gate_count": len(gate_runs),
        "event_count": len(events),
    },
    "test_refs": test_refs_by_section,
    "artifact_refs": artifact_refs,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "gate_transcript_path": rel(gate_transcript_path),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print(f"FAIL: production kernel manifest completion contract errors={len(errors)} report={rel(report_path)}")
    for error in errors:
        print(f"ERROR: {error}")
    raise SystemExit(1)

print(
    "PASS: production kernel manifest completion contract "
    f"(production={production_count}, research_only={research_count}, report={rel(report_path)})"
)
PY
