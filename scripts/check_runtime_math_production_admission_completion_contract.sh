#!/usr/bin/env bash
# check_runtime_math_production_admission_completion_contract.sh - bd-3ot.4 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_CONTRACT:-$ROOT/tests/conformance/runtime_math_production_admission_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_REPORT:-$OUT_DIR/runtime_math_production_admission_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_LOG:-$OUT_DIR/runtime_math_production_admission_completion_contract.log.jsonl}"

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
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_math_production_admission_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_production_admission_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-3ot"
COMPLETION_BEAD = "bd-3ot.4"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
EXPECTED_EVENTS = {
    "runtime_math_production_admission_units_validated",
    "runtime_math_production_admission_e2e_validated",
    "runtime_math_production_admission_fuzz_validated",
    "runtime_math_production_admission_conformance_validated",
    "runtime_math_production_admission_telemetry_validated",
}
EXPECTED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_item_id",
    "child_contract_count",
    "unit_test_ref_count",
    "e2e_test_ref_count",
    "fuzz_target_count",
    "conformance_artifact_count",
    "telemetry_event_count",
    "telemetry_field_count",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def workspace_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return ROOT / path


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
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        items.append(item)
    return items


def read_text(path_text: str, label: str) -> str:
    try:
        return workspace_path(path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def check_file_line_ref(ref: str) -> None:
    if ":" not in ref:
        err(f"implementation ref missing line separator: {ref}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"implementation ref has invalid line: {ref}")
        return
    try:
        path = workspace_path(path_text)
    except ValueError as exc:
        err(str(exc))
        return
    if not path.is_file():
        err(f"implementation ref path missing: {ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        err(f"implementation ref does not point to a non-empty line: {ref}")


def require_test_ref(test_sources: dict[str, str], source_id: str, name: str) -> None:
    source_path = test_sources.get(source_id)
    if not source_path:
        err(f"unknown test source: {source_id}")
        return
    text = read_text(source_path, source_id)
    if f"fn {name}" not in text:
        err(f"test source {source_id} missing fn {name}")


def count_classification(governance: dict[str, Any], key: str) -> int:
    classifications = governance.get("classifications", {})
    if not isinstance(classifications, dict):
        return 0
    rows = classifications.get(key, [])
    return len(rows) if isinstance(rows, list) else 0


def validate_source_artifacts(manifest: dict[str, Any]) -> tuple[dict[str, pathlib.Path], dict[str, dict[str, Any]], dict[str, str]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}, {}, {}
    paths: dict[str, pathlib.Path] = {}
    loaded: dict[str, dict[str, Any]] = {}
    texts: dict[str, str] = {}
    for artifact_id, value in artifacts.items():
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        try:
            path = workspace_path(value)
        except ValueError as exc:
            err(str(exc))
            continue
        paths[artifact_id] = path
        require(path.is_file(), f"source artifact missing: {artifact_id}: {value}")
        if path.is_file() and path.suffix == ".json":
            loaded[artifact_id] = load_json(path, artifact_id)
        if path.is_file() and path.suffix in {".rs", ".sh", ".py"}:
            texts[artifact_id] = path.read_text(encoding="utf-8")
    return paths, loaded, texts


def validate_source_contract(manifest: dict[str, Any], loaded: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        err("required_source_contract must be an object")
        required = {}

    admission = loaded.get("admission_report", {})
    expected_admission = required.get("admission_report", {}) if isinstance(required.get("admission_report"), dict) else {}
    summary = admission.get("summary", {}) if isinstance(admission.get("summary"), dict) else {}
    require(admission.get("status") == expected_admission.get("status"), "admission report status drifted")
    for field in ["total_modules", "admitted", "retired", "blocked", "errors", "warnings"]:
        require(summary.get(field) == expected_admission.get(field), f"admission summary {field} drifted")

    controller = loaded.get("controller_manifest", {})
    controller_summary = controller.get("summary", {}) if isinstance(controller.get("summary"), dict) else {}
    expected_controller = required.get("controller_manifest_summary", {}) if isinstance(required.get("controller_manifest_summary"), dict) else {}
    for field, expected in expected_controller.items():
        require(controller_summary.get(field) == expected, f"controller manifest summary {field} drifted")

    governance = loaded.get("math_governance", {})
    expected_governance = required.get("math_governance", {}) if isinstance(required.get("math_governance"), dict) else {}
    governance_counts = {
        "production_core": count_classification(governance, "production_core"),
        "production_monitor": count_classification(governance, "production_monitor"),
        "research": count_classification(governance, "research"),
    }
    for field, expected in expected_governance.items():
        require(governance_counts.get(field) == expected, f"math governance {field} count drifted")

    production = loaded.get("production_manifest", {})
    expected_production = required.get("production_manifest", {}) if isinstance(required.get("production_manifest"), dict) else {}
    production_modules = production.get("production_modules", [])
    research_only_modules = production.get("research_only_modules", [])
    require(isinstance(production_modules, list) and len(production_modules) == expected_production.get("production_modules"), "production manifest production_modules count drifted")
    require(isinstance(research_only_modules, list) and len(research_only_modules) == expected_production.get("research_only_modules"), "production manifest research_only_modules count drifted")

    value = loaded.get("math_value_proof", {})
    value_summary = value.get("summary", {}) if isinstance(value.get("summary"), dict) else {}
    expected_value = required.get("math_value_proof", {}) if isinstance(required.get("math_value_proof"), dict) else {}
    for field, expected in expected_value.items():
        require(value_summary.get(field) == expected, f"math value proof summary {field} drifted")

    retirement = loaded.get("math_retirement_policy", {})
    retirement_summary = retirement.get("summary", {}) if isinstance(retirement.get("summary"), dict) else {}
    expected_retirement = required.get("math_retirement_policy", {}) if isinstance(required.get("math_retirement_policy"), dict) else {}
    for field, expected in expected_retirement.items():
        require(retirement_summary.get(field) == expected, f"math retirement policy summary {field} drifted")

    fuzz = loaded.get("fuzz_phase2_targets", {})
    expected_fuzz = required.get("fuzz_phase2", {}) if isinstance(required.get("fuzz_phase2"), dict) else {}
    fuzz_summary = fuzz.get("summary", {}) if isinstance(fuzz.get("summary"), dict) else {}
    fuzz_policy = fuzz.get("nightly_policy", {}) if isinstance(fuzz.get("nightly_policy"), dict) else {}
    targets = fuzz.get("target_assessments", []) if isinstance(fuzz.get("target_assessments"), list) else []
    target_names = {str(row.get("target", "")) for row in targets if isinstance(row, dict)}
    require(str(expected_fuzz.get("required_target")) in target_names, "fuzz runtime_math target missing from phase2 report")
    require(int(fuzz_summary.get("total_targets", 0)) >= int(expected_fuzz.get("minimum_targets", 0)), "fuzz phase2 target count below threshold")
    require(int(fuzz_policy.get("runs_per_target", 0)) == int(expected_fuzz.get("runs_per_target", -1)), "fuzz phase2 runs_per_target drifted")
    require(int(fuzz_policy.get("max_crashes", -1)) == int(expected_fuzz.get("max_crashes", -2)), "fuzz phase2 max_crashes drifted")

    return {
        "admission_modules": summary.get("total_modules", 0),
        "admitted": summary.get("admitted", 0),
        "retired": summary.get("retired", 0),
        "governance": governance_counts,
        "production_modules": len(production_modules) if isinstance(production_modules, list) else 0,
        "fuzz_targets": len(target_names),
    }


def validate_child_contracts(manifest: dict[str, Any]) -> dict[str, Any]:
    required_ids = set(as_string_list(
        manifest.get("required_source_contract", {}).get("required_child_contract_ids")
        if isinstance(manifest.get("required_source_contract"), dict)
        else None,
        "required_source_contract.required_child_contract_ids",
    ))
    evidence = manifest.get("completion_debt_evidence", {})
    child_contracts = evidence.get("child_contracts", []) if isinstance(evidence, dict) else []
    if not isinstance(child_contracts, list) or not child_contracts:
        err("child_contracts must be a non-empty array")
        return {"child_contract_count": 0, "child_contract_ids": []}
    actual_ids = {str(row.get("id", "")) for row in child_contracts if isinstance(row, dict)}
    require(actual_ids == required_ids, "child contract ids mismatch")
    for row in child_contracts:
        if not isinstance(row, dict):
            err("child_contracts entries must be objects")
            continue
        child_id = str(row.get("id", "?"))
        path_text = str(row.get("path", ""))
        try:
            path = workspace_path(path_text)
        except ValueError as exc:
            err(str(exc))
            continue
        if not path.is_file():
            err(f"child contract missing: {child_id}: {path_text}")
            continue
        child = load_json(path, f"child contract {child_id}")
        expected_schema = row.get("schema_version")
        actual_schema = child.get("schema_version", child.get("schema"))
        require(actual_schema == expected_schema, f"child contract schema drifted: {child_id}")
        expected_completion = row.get("completion_debt_bead")
        child_evidence = child.get("completion_debt_evidence", {})
        actual_completion = child.get(
            "completion_debt_bead",
            child.get(
                "bead_id",
                child_evidence.get("bead") if isinstance(child_evidence, dict) else None,
            ),
        )
        require(actual_completion == expected_completion, f"child contract completion_debt_bead drifted: {child_id}")
        covers = set(as_string_list(row.get("covers"), f"child_contracts.{child_id}.covers"))
        require(covers <= EXPECTED_MISSING_ITEMS, f"child contract {child_id} covers unknown missing item")
    return {"child_contract_count": len(child_contracts), "child_contract_ids": sorted(actual_ids)}


def validate_item_sections(manifest: dict[str, Any]) -> dict[str, Any]:
    evidence = manifest.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        err("completion_debt_evidence must be an object")
        evidence = {}
    missing_items = set(as_string_list(evidence.get("missing_items"), "completion_debt_evidence.missing_items"))
    require(missing_items == EXPECTED_MISSING_ITEMS, "missing_items mismatch")

    test_sources = evidence.get("test_sources", {})
    if not isinstance(test_sources, dict) or not test_sources:
        err("test_sources must be a non-empty object")
        test_sources = {}
    source_paths: dict[str, str] = {}
    for source_id, path_value in test_sources.items():
        if not isinstance(path_value, str) or not path_value:
            err(f"test_sources.{source_id} must be a non-empty string")
            continue
        source_paths[str(source_id)] = path_value
        try:
            require(workspace_path(path_value).is_file(), f"test source missing: {source_id}: {path_value}")
        except ValueError as exc:
            err(str(exc))

    unit_refs = 0
    e2e_refs = 0
    for section_name in ["unit_primary", "e2e_primary"]:
        section = evidence.get(section_name, {})
        if not isinstance(section, dict):
            err(f"{section_name} must be an object")
            continue
        require(section.get("missing_item_id") in EXPECTED_MISSING_ITEMS, f"{section_name}.missing_item_id invalid")
        for command in as_string_list(section.get("required_commands"), f"{section_name}.required_commands"):
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")
        for test_ref in section.get("required_test_refs", []):
            if not isinstance(test_ref, dict):
                err(f"{section_name}.required_test_refs entries must be objects")
                continue
            source = str(test_ref.get("source", ""))
            name = str(test_ref.get("name", ""))
            require_test_ref(source_paths, source, name)
            if section_name == "unit_primary":
                unit_refs += 1
            else:
                e2e_refs += 1

    fuzz = evidence.get("fuzz_primary", {})
    if not isinstance(fuzz, dict):
        err("fuzz_primary must be an object")
        fuzz = {}
    fuzz_targets = as_string_list(fuzz.get("required_targets"), "fuzz_primary.required_targets")
    require("fuzz_runtime_math" in fuzz_targets, "fuzz_runtime_math target missing from fuzz_primary")
    fuzz_command = str(fuzz.get("required_cargo_fuzz_command", ""))
    require(fuzz_command.startswith("rch exec -- "), "fuzz cargo command must be rch-backed")
    require("cargo fuzz run" in fuzz_command and "fuzz_runtime_math" in fuzz_command, "fuzz cargo command must run fuzz_runtime_math")
    require(int(fuzz.get("max_crashes", -1)) == 0, "fuzz_primary max_crashes must be zero")
    for path_text in as_string_list(fuzz.get("required_target_sources"), "fuzz_primary.required_target_sources"):
        text = read_text(path_text, "fuzz target")
        require("fuzz_target!" in text, "fuzz target source missing fuzz_target macro")
        require("RuntimeMathKernel::new_for_mode" in text, "fuzz target source missing RuntimeMathKernel construction")
        require("observe_validation_result" in text, "fuzz target source missing observation cycle")

    conformance = evidence.get("conformance_primary", {})
    if not isinstance(conformance, dict):
        err("conformance_primary must be an object")
        conformance = {}
    for checker in as_string_list(conformance.get("required_checkers"), "conformance_primary.required_checkers"):
        try:
            require(workspace_path(checker).is_file(), f"conformance checker missing: {checker}")
        except ValueError as exc:
            err(str(exc))
    conformance_artifacts = as_string_list(conformance.get("required_artifacts"), "conformance_primary.required_artifacts")
    for artifact in conformance_artifacts:
        if artifact.startswith("target/conformance/"):
            continue
        try:
            require(workspace_path(artifact).is_file(), f"conformance artifact missing: {artifact}")
        except ValueError as exc:
            err(str(exc))
    for test_ref in conformance.get("required_test_refs", []):
        if isinstance(test_ref, dict):
            require_test_ref(source_paths, str(test_ref.get("source", "")), str(test_ref.get("name", "")))

    telemetry = evidence.get("telemetry_primary", {})
    if not isinstance(telemetry, dict):
        err("telemetry_primary must be an object")
        telemetry = {}
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    require(required_events == EXPECTED_EVENTS, "telemetry required_events mismatch")
    require(required_fields == EXPECTED_FIELDS, "telemetry required_fields mismatch")
    for test_ref in telemetry.get("required_test_refs", []):
        if isinstance(test_ref, dict):
            require_test_ref(source_paths, str(test_ref.get("source", "")), str(test_ref.get("name", "")))

    for ref in as_string_list(evidence.get("implementation_refs"), "implementation_refs"):
        check_file_line_ref(ref)

    return {
        "missing_item_count": len(missing_items),
        "unit_test_ref_count": unit_refs,
        "e2e_test_ref_count": e2e_refs,
        "fuzz_target_count": len(fuzz_targets),
        "conformance_artifact_count": len(conformance_artifacts),
        "telemetry_event_count": len(required_events),
        "telemetry_field_count": len(required_fields),
    }


def event(
    name: str,
    missing_item_id: str,
    status: str,
    source_commit_value: str,
    artifact_refs: list[str],
    child_summary: dict[str, Any],
    item_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "trace_id": f"{COMPLETION_BEAD}:{name}",
        "event": name,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit_value,
        "status": status,
        "missing_item_id": missing_item_id,
        "child_contract_count": int(child_summary.get("child_contract_count", 0)),
        "unit_test_ref_count": int(item_summary.get("unit_test_ref_count", 0)),
        "e2e_test_ref_count": int(item_summary.get("e2e_test_ref_count", 0)),
        "fuzz_target_count": int(item_summary.get("fuzz_target_count", 0)),
        "conformance_artifact_count": int(item_summary.get("conformance_artifact_count", 0)),
        "telemetry_event_count": int(item_summary.get("telemetry_event_count", 0)),
        "telemetry_field_count": int(item_summary.get("telemetry_field_count", 0)),
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if status == "pass" else "runtime_math_production_admission_completion_contract_failed",
    }


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

_paths, loaded, _texts = validate_source_artifacts(manifest)
source_summary = validate_source_contract(manifest, loaded)
child_summary = validate_child_contracts(manifest)
item_summary = validate_item_sections(manifest)

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "tests/runtime_math/admission_gate_report.v1.json",
    "tests/conformance/math_value_proof.json",
    "tests/conformance/math_retirement_policy.json",
    "tests/conformance/fuzz_phase2_completion_contract.v1.json",
]
status = "fail" if errors else "pass"
commit = source_commit()
events = [
    event("runtime_math_production_admission_units_validated", "tests.unit.primary", status, commit, artifact_refs, child_summary, item_summary),
    event("runtime_math_production_admission_e2e_validated", "tests.e2e.primary", status, commit, artifact_refs, child_summary, item_summary),
    event("runtime_math_production_admission_fuzz_validated", "tests.fuzz.primary", status, commit, artifact_refs, child_summary, item_summary),
    event("runtime_math_production_admission_conformance_validated", "tests.conformance.primary", status, commit, artifact_refs, child_summary, item_summary),
    event("runtime_math_production_admission_telemetry_validated", "telemetry.primary", status, commit, artifact_refs, child_summary, item_summary),
]

for row in events:
    missing = EXPECTED_FIELDS - set(row)
    if missing:
        err(f"telemetry event {row['event']} missing fields: {sorted(missing)}")

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_summary": source_summary,
    "child_summary": child_summary,
    "item_summary": item_summary,
    "required_events": sorted(EXPECTED_EVENTS),
    "required_fields": sorted(EXPECTED_FIELDS),
    "errors": errors,
    "events": events,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print(f"runtime_math_production_admission_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "runtime_math_production_admission_completion_contract: PASS "
    f"children={child_summary['child_contract_count']} "
    f"items={item_summary['missing_item_count']} "
    f"unit_refs={item_summary['unit_test_ref_count']} "
    f"e2e_refs={item_summary['e2e_test_ref_count']} "
    f"fuzz_targets={item_summary['fuzz_target_count']} "
    f"telemetry_events={item_summary['telemetry_event_count']}"
)
PY
