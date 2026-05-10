#!/usr/bin/env bash
# check_gentoo_unit_test_contract.sh -- fail-closed Gentoo unit-test evidence gate for bd-2icq.13
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_GENTOO_UNIT_CONTRACT:-${ROOT}/tests/conformance/gentoo_unit_test_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GENTOO_UNIT_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_GENTOO_UNIT_REPORT:-${OUT_DIR}/gentoo_unit_test_contract.report.json}"
LOG="${FRANKENLIBC_GENTOO_UNIT_LOG:-${OUT_DIR}/gentoo_unit_test_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-2icq.13"
COMPLETION_DEBT_BEAD_ID = "bd-2icq.13.1"
COMPLETION_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "integration_primary": "tests.integration.primary",
    "telemetry_primary": "telemetry.primary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("contract must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def contains_test(source: str, class_name: str, test_name: str) -> bool:
    return f"class {class_name}" in source and f"def {test_name}(" in source


def validate_required_tests(
    tests: Any,
    source: str,
    errors: list[str],
    context: str,
    file_default: str | None = None,
) -> int:
    if not isinstance(tests, list) or not tests:
        errors.append(f"{context}.required_tests must be a non-empty array")
        return 0
    found = 0
    for index, item in enumerate(tests):
        if not isinstance(item, dict):
            errors.append(f"{context}.required_tests[{index}] must be an object")
            continue
        class_name = item.get("class")
        test_name = item.get("test")
        if not isinstance(class_name, str) or not isinstance(test_name, str):
            errors.append(f"{context}.required_tests[{index}] needs class and test strings")
            continue
        if file_default is not None and item.get("file", file_default) != file_default:
            file_source = read_text(str(item.get("file")), errors, f"{context}.required_tests[{index}]")
        else:
            file_source = source
        if not contains_test(file_source, class_name, test_name):
            errors.append(f"{context} missing {class_name}.{test_name}")
            continue
        if "line_ref" in item:
            validate_line_ref(item["line_ref"], errors, f"{context}.{class_name}.{test_name}.line_ref")
        found += 1
    return found


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 700:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 700")

    test_source = evidence.get("test_source")
    if not isinstance(test_source, str) or not test_source:
        errors.append("completion_debt_evidence.test_source missing")
        test_source_text = ""
    else:
        test_source_text = read_text(test_source, errors, "completion_debt_evidence.test_source")

    for section, missing_id in COMPLETION_SECTIONS.items():
        section_data = evidence.get(section)
        if not isinstance(section_data, dict):
            errors.append(f"completion_debt_evidence.{section} missing")
            continue
        if section_data.get("missing_item_id") != missing_id:
            errors.append(f"completion_debt_evidence.{section}.missing_item_id must be {missing_id}")
        rust_tests = section_data.get("required_test_names")
        if not isinstance(rust_tests, list) or not rust_tests:
            errors.append(f"completion_debt_evidence.{section}.required_test_names missing")
            continue
        for test_name in rust_tests:
            if not isinstance(test_name, str) or f"fn {test_name}(" not in test_source_text:
                errors.append(f"completion_debt_evidence.{section} references missing Rust test {test_name}")


def validate_contract(contract: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != "gentoo-unit-test-contract":
        errors.append("manifest_id must be gentoo-unit-test-contract")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")

    component_rows: list[dict[str, Any]] = []
    components = contract.get("required_components")
    if not isinstance(components, list) or not components:
        errors.append("required_components must be a non-empty array")
        components = []

    seen_components: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            errors.append("required_components entries must be objects")
            continue
        component_id = component.get("component_id")
        implementation = component.get("implementation")
        test_file = component.get("test_file")
        if not isinstance(component_id, str) or not component_id:
            errors.append("component_id missing")
            continue
        if component_id in seen_components:
            errors.append(f"duplicate component_id {component_id}")
        seen_components.add(component_id)
        if not isinstance(implementation, str) or not implementation:
            errors.append(f"{component_id}.implementation missing")
            implementation = ""
        elif not (root / implementation).is_file():
            errors.append(f"{component_id}.implementation missing file: {implementation}")
        if not isinstance(test_file, str) or not test_file:
            errors.append(f"{component_id}.test_file missing")
            test_file = ""
        test_source = read_text(test_file, errors, f"{component_id}.test_file") if test_file else ""
        test_count = test_source.count("def test_")
        min_test_count = component.get("min_test_count")
        if not isinstance(min_test_count, int) or min_test_count <= 0:
            errors.append(f"{component_id}.min_test_count must be positive integer")
            min_test_count = 0
        if test_count < min_test_count:
            errors.append(f"{component_id} has {test_count} tests, expected at least {min_test_count}")
        categories = component.get("coverage_categories")
        if not isinstance(categories, list) or not all(isinstance(item, str) and item for item in categories):
            errors.append(f"{component_id}.coverage_categories must be non-empty strings")
        found_required = validate_required_tests(
            component.get("required_tests"),
            test_source,
            errors,
            component_id,
        )
        component_rows.append({
            "component_id": component_id,
            "implementation": implementation,
            "test_file": test_file,
            "unit_test_count": test_count,
            "required_tests_found": found_required,
            "min_test_count": min_test_count,
            "coverage_categories": categories if isinstance(categories, list) else [],
        })

    required_ids = {
        "build_runner",
        "test_runner",
        "docker_integration",
        "log_parser",
        "cache_manager",
        "regression_detector",
        "flaky_detector",
        "progress_reporter",
    }
    missing_components = sorted(required_ids - seen_components)
    if missing_components:
        errors.append(f"missing required Gentoo unit components: {missing_components}")

    fixture_contract = contract.get("fixture_contract", {})
    required_files = fixture_contract.get("required_files") if isinstance(fixture_contract, dict) else None
    if not isinstance(required_files, list) or not required_files:
        errors.append("fixture_contract.required_files must be a non-empty array")
    else:
        for entry in required_files:
            path_text = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path_text, str) or not (root / path_text).is_file():
                errors.append(f"fixture_contract missing fixture: {path_text}")

    integration = contract.get("integration_contract", {})
    if not isinstance(integration, dict):
        errors.append("integration_contract must be an object")
    else:
        script = integration.get("script")
        script_text = read_text(script, errors, "integration_contract.script") if isinstance(script, str) else ""
        for needle in integration.get("required_script_needles", []):
            if not isinstance(needle, str) or needle not in script_text:
                errors.append(f"integration_contract.script missing needle {needle}")
        docker_test_file = "tests/gentoo/test_docker_integration.py"
        docker_source = read_text(docker_test_file, errors, "integration_contract.required_tests")
        validate_required_tests(
            integration.get("required_tests"),
            docker_source,
            errors,
            "integration_contract",
            file_default=docker_test_file,
        )

    telemetry = contract.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
    else:
        fields = telemetry.get("required_log_fields")
        events = telemetry.get("required_log_events")
        if not isinstance(fields, list) or not fields:
            errors.append("telemetry_contract.required_log_fields missing")
        if not isinstance(events, list) or set(events) != {"gentoo_unit_component", "gentoo_unit_contract_summary"}:
            errors.append("telemetry_contract.required_log_events drifted")

    validate_completion_evidence(contract, errors)
    return component_rows


errors: list[str] = []
warnings: list[str] = []
contract = load_json(contract_path, errors)
component_rows = validate_contract(contract, errors) if contract else []
timestamp = utc_now()

component_log_rows = []
for row in component_rows:
    component_errors = [error for error in errors if error.startswith(row["component_id"])]
    component_log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['component_id']}",
        "event": "gentoo_unit_component",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "component_id": row["component_id"],
        "test_file": row["test_file"],
        "implementation": row["implementation"],
        "unit_test_count": row["unit_test_count"],
        "status": "pass" if not component_errors else "fail",
        "artifact_refs": [row["test_file"], row["implementation"], rel(contract_path)],
        "failure_signature": "none" if not component_errors else "contract_validation_error",
    })

summary = {
    "schema_version": "gentoo_unit_test_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "component_count": len(component_rows),
    "total_unit_tests_indexed": sum(row["unit_test_count"] for row in component_rows),
    "errors": errors,
    "warnings": warnings,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}

log_rows = component_log_rows + [{
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "gentoo_unit_contract_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "component_id": None,
    "test_file": None,
    "implementation": None,
    "unit_test_count": summary["total_unit_tests_indexed"],
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
}]

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(f"gentoo_unit_test_contract: status={summary['status']} components={summary['component_count']} tests={summary['total_unit_tests_indexed']} errors={len(errors)}")
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
