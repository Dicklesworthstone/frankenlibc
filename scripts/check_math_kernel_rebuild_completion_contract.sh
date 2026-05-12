#!/usr/bin/env bash
# check_math_kernel_rebuild_completion_contract.sh - bd-kan.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATH_KERNEL_REBUILD_CONTRACT:-$ROOT/tests/conformance/math_kernel_rebuild_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_KERNEL_REBUILD_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_MATH_KERNEL_REBUILD_REPORT:-$OUT_DIR/math_kernel_rebuild_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATH_KERNEL_REBUILD_LOG:-$OUT_DIR/math_kernel_rebuild_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "math_kernel_rebuild_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "math_kernel_rebuild_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-kan"
COMPLETION_BEAD = "bd-kan.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
EXPECTED_EVENTS = {
    "math_kernel_rebuild_units_validated",
    "math_kernel_rebuild_e2e_validated",
    "math_kernel_rebuild_fuzz_validated",
    "math_kernel_rebuild_conformance_validated",
    "math_kernel_rebuild_telemetry_validated",
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
    "production_module_count",
    "research_module_count",
    "child_contract_count",
    "test_ref_count",
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
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


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
        path = workspace_path(path_text)
    except Exception as exc:
        err(f"implementation ref invalid: {ref}: {exc}")
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
    try:
        text = workspace_path(source_path).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"test source {source_id} unreadable: {exc}")
        return
    if f"fn {name}" not in text:
        err(f"test source {source_id} missing fn {name}")


def count_governance(governance: dict[str, Any], tier: str) -> int:
    classifications = governance.get("classifications", {})
    rows = classifications.get(tier, []) if isinstance(classifications, dict) else []
    return len(rows) if isinstance(rows, list) else 0


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    loaded: dict[str, dict[str, Any]] = {}
    for artifact_id, value in artifacts.items():
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        try:
            path = workspace_path(value)
        except ValueError as exc:
            err(str(exc))
            continue
        require(path.is_file(), f"source artifact missing: {artifact_id}: {value}")
        if path.is_file() and path.suffix == ".json":
            loaded[artifact_id] = load_json(path, artifact_id)
    return loaded


def validate_parent_contract(manifest: dict[str, Any], loaded: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        err("required_source_contract must be an object")
        required = {}
    parent_required = required.get("production_admission_contract", {})
    parent = loaded.get("production_admission_contract", {})
    require(parent.get("schema_version") == parent_required.get("schema_version"), "production admission contract schema drifted")
    require(parent.get("original_bead") == parent_required.get("original_bead"), "production admission original bead drifted")
    require(parent.get("completion_debt_bead") == parent_required.get("completion_debt_bead"), "production admission completion bead drifted")
    parent_evidence = parent.get("completion_debt_evidence", {})
    parent_missing = set(as_string_list(parent_evidence.get("missing_items") if isinstance(parent_evidence, dict) else None, "production_admission_contract.missing_items"))
    require(parent_missing == set(parent_required.get("required_missing_items", [])), "production admission missing_items drifted")
    child_contracts = parent_evidence.get("child_contracts", []) if isinstance(parent_evidence, dict) else []
    require(isinstance(child_contracts, list) and len(child_contracts) >= int(parent_required.get("minimum_child_contracts", 0)), "production admission child contract count below threshold")

    production = loaded.get("production_manifest", {})
    expected_production = required.get("production_manifest", {}) if isinstance(required.get("production_manifest"), dict) else {}
    production_modules = production.get("production_modules", [])
    research_modules = production.get("research_only_modules", [])
    require(isinstance(production_modules, list) and len(production_modules) == expected_production.get("production_modules"), "production manifest production module count drifted")
    require(isinstance(research_modules, list) and len(research_modules) == expected_production.get("research_only_modules"), "production manifest research module count drifted")
    require(expected_production.get("default_feature") in production.get("default_feature_set", []), "production default feature missing")
    require(expected_production.get("optional_research_feature") in production.get("optional_feature_set", []), "research optional feature missing")

    governance = loaded.get("math_governance", {})
    expected_governance = required.get("math_governance", {}) if isinstance(required.get("math_governance"), dict) else {}
    summary = governance.get("summary", {}) if isinstance(governance.get("summary"), dict) else {}
    for field in ["total_modules", "production_core", "production_monitor", "research"]:
        require(summary.get(field) == expected_governance.get(field), f"math governance summary {field} drifted")
    governance_refs = governance.get("bead_classifications", {}).get("governance", []) if isinstance(governance.get("bead_classifications"), dict) else []
    require(any(isinstance(row, dict) and row.get("bead") == expected_governance.get("governance_bead") for row in governance_refs), "math governance missing bd-kan anchor")
    require(count_governance(governance, "production_core") == expected_governance.get("production_core"), "math governance production_core rows drifted")
    require(count_governance(governance, "production_monitor") == expected_governance.get("production_monitor"), "math governance production_monitor rows drifted")
    require(count_governance(governance, "research") == expected_governance.get("research"), "math governance research rows drifted")

    value = loaded.get("math_value_proof", {})
    value_summary = value.get("summary", {}) if isinstance(value.get("summary"), dict) else {}
    expected_value = required.get("math_value_proof", {}) if isinstance(required.get("math_value_proof"), dict) else {}
    for field in ["total_modules_assessed", "all_retained", "research_modules_excluded"]:
        require(value_summary.get(field) == expected_value.get(field), f"math value proof summary {field} drifted")
    research_assessment = value.get("research_assessment", {}) if isinstance(value.get("research_assessment"), dict) else {}
    require(research_assessment.get("waiver_bead") == expected_value.get("waiver_bead"), "math value proof waiver bead drifted")

    retirement = loaded.get("math_retirement_policy", {})
    retirement_summary = retirement.get("summary", {}) if isinstance(retirement.get("summary"), dict) else {}
    expected_retirement = required.get("math_retirement_policy", {}) if isinstance(required.get("math_retirement_policy"), dict) else {}
    for field, expected in expected_retirement.items():
        require(retirement_summary.get(field) == expected, f"math retirement policy summary {field} drifted")

    fuzz_path = manifest.get("source_artifacts", {}).get("fuzz_runtime_math")
    fuzz_text = workspace_path(str(fuzz_path)).read_text(encoding="utf-8") if fuzz_path else ""
    fuzz_required = required.get("fuzz_runtime_math", {}) if isinstance(required.get("fuzz_runtime_math"), dict) else {}
    for needle in as_string_list(fuzz_required.get("required_needles"), "fuzz_runtime_math.required_needles"):
        require(needle in fuzz_text, f"fuzz_runtime_math missing required needle: {needle}")

    return {
        "production_module_count": len(production_modules) if isinstance(production_modules, list) else 0,
        "research_module_count": len(research_modules) if isinstance(research_modules, list) else 0,
        "child_contract_count": len(child_contracts) if isinstance(child_contracts, list) else 0,
    }


def validate_evidence(manifest: dict[str, Any]) -> dict[str, Any]:
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
        if isinstance(path_value, str) and path_value:
            source_paths[str(source_id)] = path_value
            require(workspace_path(path_value).is_file(), f"test source missing: {source_id}: {path_value}")
        else:
            err(f"test_sources.{source_id} must be a non-empty string")

    test_ref_count = 0
    for section_name in ["unit_primary", "e2e_primary", "fuzz_primary", "conformance_primary", "telemetry_primary"]:
        section = evidence.get(section_name, {})
        if not isinstance(section, dict):
            err(f"{section_name} must be an object")
            continue
        require(section.get("missing_item_id") in EXPECTED_MISSING_ITEMS, f"{section_name}.missing_item_id invalid")
        for command in as_string_list(section.get("required_commands", []), f"{section_name}.required_commands", allow_empty=True):
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")
        for test_ref in section.get("required_test_refs", []):
            if not isinstance(test_ref, dict):
                err(f"{section_name}.required_test_refs entries must be objects")
                continue
            require_test_ref(source_paths, str(test_ref.get("source", "")), str(test_ref.get("name", "")))
            test_ref_count += 1

    fuzz = evidence.get("fuzz_primary", {})
    fuzz_targets = as_string_list(fuzz.get("required_targets") if isinstance(fuzz, dict) else None, "fuzz_primary.required_targets")
    require("fuzz_runtime_math" in fuzz_targets, "fuzz_runtime_math target missing from fuzz_primary")
    fuzz_command = str(fuzz.get("required_cargo_fuzz_command", "")) if isinstance(fuzz, dict) else ""
    require(fuzz_command.startswith("rch exec -- "), "fuzz cargo command must be rch-backed")
    require("cargo fuzz run" in fuzz_command and "fuzz_runtime_math" in fuzz_command, "fuzz cargo command must run fuzz_runtime_math")
    require(int(fuzz.get("max_crashes", -1)) == 0 if isinstance(fuzz, dict) else False, "fuzz max_crashes must be zero")

    conformance = evidence.get("conformance_primary", {})
    conformance_artifacts = as_string_list(conformance.get("required_artifacts") if isinstance(conformance, dict) else None, "conformance_primary.required_artifacts")
    for checker in as_string_list(conformance.get("required_checkers") if isinstance(conformance, dict) else None, "conformance_primary.required_checkers"):
        require(workspace_path(checker).is_file(), f"conformance checker missing: {checker}")
    for artifact in conformance_artifacts:
        if not artifact.startswith("target/conformance/"):
            require(workspace_path(artifact).is_file(), f"conformance artifact missing: {artifact}")

    telemetry = evidence.get("telemetry_primary", {})
    telemetry_events = set(as_string_list(telemetry.get("required_events") if isinstance(telemetry, dict) else None, "telemetry_primary.required_events"))
    telemetry_fields = set(as_string_list(telemetry.get("required_fields") if isinstance(telemetry, dict) else None, "telemetry_primary.required_fields"))
    require(telemetry_events == EXPECTED_EVENTS, "telemetry required_events mismatch")
    require(telemetry_fields == EXPECTED_FIELDS, "telemetry required_fields mismatch")

    for ref in as_string_list(evidence.get("implementation_refs"), "implementation_refs"):
        check_file_line_ref(ref)

    return {
        "missing_item_count": len(missing_items),
        "test_ref_count": test_ref_count,
        "fuzz_target_count": len(fuzz_targets),
        "conformance_artifact_count": len(conformance_artifacts),
        "telemetry_event_count": len(telemetry_events),
        "telemetry_field_count": len(telemetry_fields),
    }


def event(name: str, missing_item_id: str, status: str, source_summary: dict[str, Any], item_summary: dict[str, Any], artifact_refs: list[str], commit: str) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "trace_id": f"{COMPLETION_BEAD}:{name}",
        "event": name,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": commit,
        "status": status,
        "missing_item_id": missing_item_id,
        "production_module_count": int(source_summary.get("production_module_count", 0)),
        "research_module_count": int(source_summary.get("research_module_count", 0)),
        "child_contract_count": int(source_summary.get("child_contract_count", 0)),
        "test_ref_count": int(item_summary.get("test_ref_count", 0)),
        "fuzz_target_count": int(item_summary.get("fuzz_target_count", 0)),
        "conformance_artifact_count": int(item_summary.get("conformance_artifact_count", 0)),
        "telemetry_event_count": int(item_summary.get("telemetry_event_count", 0)),
        "telemetry_field_count": int(item_summary.get("telemetry_field_count", 0)),
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if status == "pass" else "math_kernel_rebuild_completion_contract_failed",
    }


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
loaded = validate_source_artifacts(manifest)
source_summary = validate_parent_contract(manifest, loaded)
item_summary = validate_evidence(manifest)

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "tests/conformance/runtime_math_production_admission_completion_contract.v1.json",
    "tests/runtime_math/production_kernel_manifest.v1.json",
    "tests/conformance/math_governance.json",
]
status = "fail" if errors else "pass"
commit = source_commit()
events = [
    event("math_kernel_rebuild_units_validated", "tests.unit.primary", status, source_summary, item_summary, artifact_refs, commit),
    event("math_kernel_rebuild_e2e_validated", "tests.e2e.primary", status, source_summary, item_summary, artifact_refs, commit),
    event("math_kernel_rebuild_fuzz_validated", "tests.fuzz.primary", status, source_summary, item_summary, artifact_refs, commit),
    event("math_kernel_rebuild_conformance_validated", "tests.conformance.primary", status, source_summary, item_summary, artifact_refs, commit),
    event("math_kernel_rebuild_telemetry_validated", "telemetry.primary", status, source_summary, item_summary, artifact_refs, commit),
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
    "item_summary": item_summary,
    "required_events": sorted(EXPECTED_EVENTS),
    "required_fields": sorted(EXPECTED_FIELDS),
    "errors": errors,
    "events": events,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print(f"math_kernel_rebuild_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "math_kernel_rebuild_completion_contract: PASS "
    f"production={source_summary['production_module_count']} "
    f"research={source_summary['research_module_count']} "
    f"children={source_summary['child_contract_count']} "
    f"items={item_summary['missing_item_count']} "
    f"tests={item_summary['test_ref_count']} "
    f"telemetry_events={item_summary['telemetry_event_count']}"
)
PY
