#!/usr/bin/env bash
# check_gentoo_regression_detector_completion_contract.sh -- fail-closed evidence gate for bd-2icq.12.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_GENTOO_REGRESSION_CONTRACT:-${ROOT}/tests/conformance/gentoo_regression_detector_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GENTOO_REGRESSION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_GENTOO_REGRESSION_REPORT:-${OUT_DIR}/gentoo_regression_detector_completion_contract.report.json}"
LOG="${FRANKENLIBC_GENTOO_REGRESSION_LOG:-${OUT_DIR}/gentoo_regression_detector_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-2icq.12"
COMPLETION_DEBT_BEAD_ID = "bd-2icq.12.1"
MANIFEST_ID = "gentoo-regression-detector-completion-contract"
COMPLETION_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_EVENTS = {
    "gentoo_regression_detector_component",
    "gentoo_regression_detector_e2e",
    "gentoo_regression_detector_summary",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
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
        if not contains_test(source, class_name, test_name):
            errors.append(f"{context} missing {class_name}.{test_name}")
            continue
        if "line_ref" in item:
            validate_line_ref(item["line_ref"], errors, f"{context}.{class_name}.{test_name}.line_ref")
        found += 1
    return found


def validate_required_functions(
    functions: Any,
    source: str,
    errors: list[str],
    context: str,
) -> int:
    if not isinstance(functions, list) or not functions:
        errors.append(f"{context}.required_functions must be a non-empty array")
        return 0
    found = 0
    for index, item in enumerate(functions):
        if not isinstance(item, dict):
            errors.append(f"{context}.required_functions[{index}] must be an object")
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{context}.required_functions[{index}] needs name")
            continue
        if f"def {name}(" not in source and f"class {name}" not in source:
            errors.append(f"{context} missing function/class {name}")
            continue
        if "line_ref" in item:
            validate_line_ref(item["line_ref"], errors, f"{context}.{name}.line_ref")
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
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")

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

    telemetry = evidence.get("telemetry_primary")
    events = telemetry.get("required_events") if isinstance(telemetry, dict) else None
    if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
        errors.append("completion_debt_evidence.telemetry_primary.required_events drifted")


def validate_command_policy(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    allowed = runtime.get("allowed_command_prefixes")
    forbidden = runtime.get("forbidden_command_substrings")
    if not isinstance(allowed, list) or not all(isinstance(item, str) and item for item in allowed):
        errors.append("runtime_target.allowed_command_prefixes must be non-empty strings")
        allowed = []
    if not isinstance(forbidden, list) or not all(isinstance(item, str) and item for item in forbidden):
        errors.append("runtime_target.forbidden_command_substrings must be non-empty strings")
        forbidden = []
    command_fields: list[tuple[str, str]] = []
    for scenario in contract.get("e2e_primary", {}).get("scenarios", []):
        if isinstance(scenario, dict) and isinstance(scenario.get("command"), str):
            command_fields.append((str(scenario.get("scenario_id", "unknown")), scenario["command"]))
    for context, command in command_fields:
        if not any(command.startswith(prefix) for prefix in allowed):
            errors.append(f"{context} command is not allowlisted: {command}")
        for needle in forbidden:
            if needle in command:
                errors.append(f"{context} command contains forbidden substring {needle!r}")


def validate_contract(contract: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
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
            implementation_source = ""
        else:
            implementation_source = read_text(implementation, errors, f"{component_id}.implementation")
        if not isinstance(test_file, str) or not test_file:
            errors.append(f"{component_id}.test_file missing")
            test_file = ""
            test_source = ""
        else:
            test_source = read_text(test_file, errors, f"{component_id}.test_file")

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
            categories = []
        if len(categories) < 4:
            errors.append(f"{component_id}.coverage_categories must cover at least four cases")

        found_functions = validate_required_functions(
            component.get("required_functions"),
            implementation_source,
            errors,
            component_id,
        )
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
            "required_functions_found": found_functions,
            "required_tests_found": found_required,
            "min_test_count": min_test_count,
            "coverage_categories": categories,
        })

    if seen_components != {"regression_detector", "baseline_manager"}:
        errors.append(f"required_components must be exactly regression_detector and baseline_manager, got {sorted(seen_components)}")

    gate = contract.get("ci_gate_contract", {})
    if not isinstance(gate, dict):
        errors.append("ci_gate_contract must be an object")
    else:
        script = gate.get("script")
        script_text = read_text(script, errors, "ci_gate_contract.script") if isinstance(script, str) else ""
        for needle in gate.get("required_script_needles", []):
            if not isinstance(needle, str) or needle not in script_text:
                errors.append(f"ci_gate_contract.script missing needle {needle}")
        outputs = gate.get("required_outputs")
        if not isinstance(outputs, list) or len(outputs) < 3:
            errors.append("ci_gate_contract.required_outputs must include gate PASS lines")

    baseline = contract.get("baseline_contract", {})
    if not isinstance(baseline, dict):
        errors.append("baseline_contract must be an object")
    else:
        baseline_file = baseline.get("baseline_file")
        baseline_data = load_json(root / baseline_file, errors, "baseline_contract.baseline_file") if isinstance(baseline_file, str) else {}
        if baseline_data:
            if baseline_data.get("schema_version") != "v1":
                errors.append("baseline_contract baseline schema_version must be v1")
            if baseline_data.get("bead") != BEAD_ID:
                errors.append(f"baseline_contract baseline bead must be {BEAD_ID}")
            packages = baseline_data.get("packages")
            min_packages = baseline.get("min_package_count")
            if not isinstance(packages, list) or not isinstance(min_packages, int) or len(packages) < min_packages:
                errors.append("baseline_contract baseline package count below contract")
            required_fields = baseline.get("required_package_fields")
            if not isinstance(required_fields, list) or not required_fields:
                errors.append("baseline_contract.required_package_fields missing")
                required_fields = []
            for index, package in enumerate(packages if isinstance(packages, list) else []):
                if not isinstance(package, dict):
                    errors.append(f"baseline package {index} must be object")
                    continue
                for field in required_fields:
                    if isinstance(field, str) and field not in package:
                        errors.append(f"baseline package {index} missing {field}")
        readme = baseline.get("baseline_readme")
        readme_text = read_text(readme, errors, "baseline_contract.baseline_readme") if isinstance(readme, str) else ""
        for needle in baseline.get("required_readme_needles", []):
            if not isinstance(needle, str) or needle not in readme_text:
                errors.append(f"baseline_contract.readme missing needle {needle}")

    release = contract.get("release_gate_contract", {})
    if not isinstance(release, dict):
        errors.append("release_gate_contract must be an object")
    else:
        config = release.get("config")
        release_data = load_json(root / config, errors, "release_gate_contract.config") if isinstance(config, str) else {}
        gates = release_data.get("gates") if release_data else None
        if not isinstance(gates, dict):
            errors.append("release_gate_contract.config missing gates")
        for tier in release.get("required_tiers", []):
            if not isinstance(tier, str) or not isinstance(gates, dict) or tier not in gates:
                errors.append(f"release_gate_contract missing tier {tier}")
                continue
            thresholds = gates[tier].get("thresholds", {})
            for threshold in release.get("required_thresholds", []):
                if not isinstance(threshold, str) or threshold not in thresholds:
                    errors.append(f"release_gate_contract {tier} missing threshold {threshold}")

    e2e = contract.get("e2e_primary", {})
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be an object")
    else:
        if e2e.get("missing_item_id") != "tests.e2e.primary":
            errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
        scenarios = e2e.get("scenarios")
        if not isinstance(scenarios, list) or len(scenarios) < 3:
            errors.append("e2e_primary.scenarios must contain at least three scenarios")
        if isinstance(scenarios, list):
            scenario_ids = {
                scenario.get("scenario_id")
                for scenario in scenarios
                if isinstance(scenario, dict)
            }
            required = {
                "clean_current_matches_baseline",
                "blocking_current_fails_gate",
                "ci_gate_runs_all_detector_checks",
            }
            missing = sorted(required - scenario_ids)
            if missing:
                errors.append(f"e2e_primary.scenarios missing {missing}")

    telemetry = contract.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
    else:
        fields = telemetry.get("required_log_fields")
        events = telemetry.get("required_log_events")
        if not isinstance(fields, list) or len(fields) < 8:
            errors.append("telemetry_contract.required_log_fields missing")
        if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
            errors.append("telemetry_contract.required_log_events drifted")

    validate_command_policy(contract, errors)
    validate_completion_evidence(contract, errors)
    return component_rows


def clone_current_from_baseline(baseline_data: dict[str, Any]) -> dict[str, Any]:
    current = json.loads(json.dumps(baseline_data))
    current["source"] = "completion-contract-clean-current"
    return current


def make_blocking_current(baseline_data: dict[str, Any]) -> dict[str, Any]:
    current = clone_current_from_baseline(baseline_data)
    packages = current.get("packages", [])
    if not isinstance(packages, list) or len(packages) < 3:
        raise ValueError("baseline must contain at least three packages for blocking e2e scenario")

    packages[0]["build_status"] = "failed"
    packages[0]["error"] = "completion-contract synthetic build failure"

    tests = packages[1].get("tests", [])
    if not tests:
        tests = [{"name": "completion_contract_test", "passed": True}]
        packages[1]["tests"] = tests
    tests[0]["passed"] = False

    baseline_overhead = float(packages[2].get("overhead_percent", 1.0))
    packages[2]["overhead_percent"] = round(baseline_overhead + 60.0, 2)
    return current


def run_command(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_e2e_scenarios(errors: list[str], contract: dict[str, Any]) -> list[dict[str, Any]]:
    baseline_file = root / contract["baseline_contract"]["baseline_file"]
    baseline_data = load_json(baseline_file, errors, "e2e.baseline")
    rows: list[dict[str, Any]] = []
    if not baseline_data:
        return rows

    with tempfile.TemporaryDirectory(prefix="gentoo-regression-contract-") as tmp:
        tmpdir = Path(tmp)

        clean_current = tmpdir / "clean_current.json"
        clean_report = tmpdir / "clean_report.json"
        clean_current.write_text(json.dumps(clone_current_from_baseline(baseline_data), indent=2) + "\n", encoding="utf-8")
        clean = run_command([
            "python3",
            "scripts/gentoo/check_regressions.py",
            "--baseline",
            str(baseline_file),
            "--current",
            str(clean_current),
            "--output",
            str(clean_report),
        ])
        clean_errors: list[str] = []
        if clean.returncode != 0:
            clean_errors.append(f"expected exit 0, got {clean.returncode}")
        clean_data = load_json(clean_report, clean_errors, "clean_report")
        if clean_data and clean_data.get("total_regressions") != 0:
            clean_errors.append("clean scenario should have zero regressions")
        if clean_data and clean_data.get("has_blockers") is not False:
            clean_errors.append("clean scenario should not have blockers")
        errors.extend(f"clean_current_matches_baseline: {error}" for error in clean_errors)
        rows.append({
            "scenario_id": "clean_current_matches_baseline",
            "status": "pass" if not clean_errors else "fail",
            "exit_code": clean.returncode,
            "report": rel(clean_report),
            "stdout_tail": clean.stdout[-600:],
            "stderr_tail": clean.stderr[-600:],
            "failure_signature": "none" if not clean_errors else "e2e_clean_scenario_failed",
        })

        blocking_current = tmpdir / "blocking_current.json"
        blocking_report = tmpdir / "blocking_report.json"
        blocking_current.write_text(json.dumps(make_blocking_current(baseline_data), indent=2) + "\n", encoding="utf-8")
        blocking = run_command([
            "python3",
            "scripts/gentoo/check_regressions.py",
            "--baseline",
            str(baseline_file),
            "--current",
            str(blocking_current),
            "--output",
            str(blocking_report),
        ])
        blocking_errors: list[str] = []
        if blocking.returncode != 1:
            blocking_errors.append(f"expected exit 1, got {blocking.returncode}")
        blocking_data = load_json(blocking_report, blocking_errors, "blocking_report")
        if blocking_data and blocking_data.get("has_blockers") is not True:
            blocking_errors.append("blocking scenario should have blockers")
        types = set((blocking_data.get("by_type") or {}).keys()) if blocking_data else set()
        required_types = {"NEW_BUILD_FAILURE", "NEW_TEST_FAILURE", "PERFORMANCE_REGRESSION"}
        missing_types = sorted(required_types - types)
        if missing_types:
            blocking_errors.append(f"blocking scenario missing regression types {missing_types}")
        errors.extend(f"blocking_current_fails_gate: {error}" for error in blocking_errors)
        rows.append({
            "scenario_id": "blocking_current_fails_gate",
            "status": "pass" if not blocking_errors else "fail",
            "exit_code": blocking.returncode,
            "report": rel(blocking_report),
            "stdout_tail": blocking.stdout[-600:],
            "stderr_tail": blocking.stderr[-600:],
            "failure_signature": "none" if not blocking_errors else "e2e_blocking_scenario_failed",
        })

    gate = run_command(["bash", "scripts/check_regression_detector.sh"], timeout=90)
    gate_contract = contract.get("ci_gate_contract", {})
    gate_errors: list[str] = []
    if gate.returncode != 0:
        gate_errors.append(f"expected exit 0, got {gate.returncode}")
    for needle in gate_contract.get("required_outputs", []):
        if not isinstance(needle, str) or needle not in gate.stdout:
            gate_errors.append(f"gate output missing {needle}")
    errors.extend(f"ci_gate_runs_all_detector_checks: {error}" for error in gate_errors)
    rows.append({
        "scenario_id": "ci_gate_runs_all_detector_checks",
        "status": "pass" if not gate_errors else "fail",
        "exit_code": gate.returncode,
        "report": "scripts/check_regression_detector.sh",
        "stdout_tail": gate.stdout[-1000:],
        "stderr_tail": gate.stderr[-1000:],
        "failure_signature": "none" if not gate_errors else "e2e_gate_failed",
    })
    return rows


errors: list[str] = []
warnings: list[str] = []
contract = load_json(contract_path, errors, "contract")
component_rows = validate_contract(contract, errors) if contract else []
e2e_rows = run_e2e_scenarios(errors, contract) if contract and not errors else []
timestamp = utc_now()

component_log_rows = []
for row in component_rows:
    component_errors = [error for error in errors if error.startswith(row["component_id"])]
    component_log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['component_id']}",
        "event": "gentoo_regression_detector_component",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "component_id": row["component_id"],
        "scenario_id": None,
        "test_file": row["test_file"],
        "implementation": row["implementation"],
        "unit_test_count": row["unit_test_count"],
        "status": "pass" if not component_errors else "fail",
        "artifact_refs": [row["test_file"], row["implementation"], rel(contract_path)],
        "failure_signature": "none" if not component_errors else "contract_validation_error",
    })

e2e_log_rows = []
for row in e2e_rows:
    e2e_log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['scenario_id']}",
        "event": "gentoo_regression_detector_e2e",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "component_id": None,
        "scenario_id": row["scenario_id"],
        "test_file": None,
        "implementation": None,
        "unit_test_count": None,
        "status": row["status"],
        "artifact_refs": [row["report"], rel(contract_path)],
        "failure_signature": row["failure_signature"],
        "exit_code": row["exit_code"],
        "stdout_tail": row["stdout_tail"],
        "stderr_tail": row["stderr_tail"],
    })

summary = {
    "schema_version": "gentoo_regression_detector_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "component_count": len(component_rows),
    "e2e_scenario_count": len(e2e_rows),
    "total_unit_tests_indexed": sum(row["unit_test_count"] for row in component_rows),
    "errors": errors,
    "warnings": warnings,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}

summary_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "gentoo_regression_detector_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "component_id": None,
    "scenario_id": None,
    "test_file": None,
    "implementation": None,
    "unit_test_count": summary["total_unit_tests_indexed"],
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
}

log_rows = component_log_rows + e2e_log_rows + [summary_row]
report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "gentoo_regression_detector_completion_contract: "
    f"status={summary['status']} components={summary['component_count']} "
    f"e2e={summary['e2e_scenario_count']} tests={summary['total_unit_tests_indexed']} "
    f"errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
