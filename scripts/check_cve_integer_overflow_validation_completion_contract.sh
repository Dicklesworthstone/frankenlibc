#!/usr/bin/env bash
# check_cve_integer_overflow_validation_completion_contract.sh -- fail-closed gate for bd-1m5.4.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CVE_INTOVF_COMPLETION_CONTRACT:-${ROOT}/tests/cve_arena/results/integer_overflow_validation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CVE_INTOVF_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CVE_INTOVF_COMPLETION_REPORT:-${OUT_DIR}/cve_integer_overflow_validation_completion_contract.report.json}"
LOG="${FRANKENLIBC_CVE_INTOVF_COMPLETION_LOG:-${OUT_DIR}/cve_integer_overflow_validation_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${OUT_DIR}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

BEAD_ID = "bd-1m5.4"
COMPLETION_BEAD_ID = "bd-1m5.4.1"
MANIFEST_ID = "cve-integer-overflow-validation-completion-contract"
REQUIRED_EVENTS = {
    "cve_integer_overflow_component",
    "cve_integer_overflow_case",
    "cve_integer_overflow_e2e",
    "cve_integer_overflow_summary",
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


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


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


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def ensure_subset(required: list[str], actual: Any, errors: list[str], context: str) -> None:
    if not isinstance(actual, list):
        errors.append(f"{context} must compare against an array")
        return
    actual_set = {item for item in actual if isinstance(item, str)}
    missing = [item for item in required if item not in actual_set]
    if missing:
        errors.append(f"{context} missing {missing}")


def validate_command_policy(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    allowed = require_strings(runtime.get("allowed_command_prefixes"), errors, "runtime_target.allowed_command_prefixes")
    forbidden = require_strings(runtime.get("forbidden_command_substrings"), errors, "runtime_target.forbidden_command_substrings")
    command_fields: list[tuple[str, str]] = []
    e2e = contract.get("e2e_primary")
    if isinstance(e2e, dict):
        for scenario in e2e.get("scenarios", []):
            if isinstance(scenario, dict) and isinstance(scenario.get("command"), str):
                command_fields.append((str(scenario.get("scenario_id", "unknown")), scenario["command"]))
    for context, command in command_fields:
        if not any(command.startswith(prefix) for prefix in allowed):
            errors.append(f"{context} command is not allowlisted: {command}")
        for needle in forbidden:
            if needle in command:
                errors.append(f"{context} command contains forbidden substring {needle!r}")


def validate_source_artifacts(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("source_artifacts must be a non-empty array")
        return
    seen = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        if artifact_id in seen:
            errors.append(f"duplicate source artifact {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        for ref in artifact.get("required_line_refs", []):
            validate_line_ref(ref, errors, f"{artifact_id}.required_line_refs")
        rows.append({
            "event": "cve_integer_overflow_component",
            "status": "pass" if text else "fail",
            "component_id": artifact_id,
            "path": path_text,
            "timestamp": utc_now(),
        })
    required_ids = {
        "integer_overflow_generator",
        "integer_overflow_shell_gate",
        "persisted_validation_report",
        "source_harness_tests",
    }
    if seen != required_ids:
        errors.append(f"source_artifacts must be exactly {sorted(required_ids)}, got {sorted(seen)}")


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    events = evidence.get("required_events")
    if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
        errors.append("completion_debt_evidence.required_events drifted")

    unit = contract.get("unit_primary")
    if not isinstance(unit, dict) or unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary must bind tests.unit.primary")
        test_source = ""
    else:
        test_source_path = unit.get("test_source")
        test_source = read_text(test_source_path, errors, "unit_primary.test_source") if isinstance(test_source_path, str) else ""
        for test_name in require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if f"fn {test_name}(" not in test_source:
                errors.append(f"unit_primary references missing Rust test {test_name}")
        for existing in unit.get("existing_unit_tests", []):
            if not isinstance(existing, dict):
                errors.append("unit_primary.existing_unit_tests entries must be objects")
                continue
            name = existing.get("name")
            if not isinstance(name, str):
                errors.append("unit_primary.existing_unit_tests.name missing")
                continue
            if not any(name in artifact for artifact in [test_source, read_text("crates/frankenlibc-harness/tests/cve_integer_overflow_validation_test.rs", errors, "existing source test")]):
                errors.append(f"unit_primary existing test missing {name}")
            if "line_ref" in existing:
                validate_line_ref(existing["line_ref"], errors, f"unit_primary.{name}.line_ref")

    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict) or e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary must bind tests.e2e.primary")
        return
    scenarios = e2e.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 3:
        errors.append("e2e_primary.scenarios must include at least three scenarios")
        return
    scenario_ids = {item.get("scenario_id") for item in scenarios if isinstance(item, dict)}
    required = {
        "generate_isolated_integer_overflow_report",
        "compile_glibc_syslog_trigger",
        "completion_checker_runs_fail_closed",
    }
    if scenario_ids != required:
        errors.append(f"e2e_primary.scenarios must be exactly {sorted(required)}, got {sorted(str(item) for item in scenario_ids)}")


def run_generator(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        errors.append("report_contract must be an object")
        return {}
    generator = report_contract.get("generator")
    if not isinstance(generator, str) or not generator:
        errors.append("report_contract.generator missing")
        return {}
    generated_report = out_dir / "generated_integer_overflow_validation.v1.json"
    result = subprocess.run(
        ["python3", str(root / generator), "-o", str(generated_report)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=int(contract.get("runtime_target", {}).get("max_seconds", 45)),
    )
    rows.append({
        "event": "cve_integer_overflow_e2e",
        "scenario_id": "generate_isolated_integer_overflow_report",
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "artifact": rel(generated_report),
        "timestamp": utc_now(),
    })
    if result.returncode != 0:
        errors.append(f"generator failed: stdout={result.stdout} stderr={result.stderr}")
        return {}
    generated = load_json(generated_report, errors, "generated integer overflow report")
    persisted_path = root / str(report_contract.get("report_path", ""))
    persisted = load_json(persisted_path, errors, "persisted integer overflow report")
    for context, report in [("generated", generated), ("persisted", persisted)]:
        if report.get("schema_version") != "v1":
            errors.append(f"{context} report schema_version must be v1")
        if report.get("bead") != BEAD_ID:
            errors.append(f"{context} report bead must be {BEAD_ID}")
        validate_report_summary(report_contract, report, errors, context)
    return generated


def validate_report_summary(
    report_contract: dict[str, Any],
    report: dict[str, Any],
    errors: list[str],
    context: str,
) -> None:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        errors.append(f"{context} report.summary must be an object")
        return
    expected = report_contract.get("expected_summary")
    if not isinstance(expected, dict):
        errors.append("report_contract.expected_summary must be an object")
        expected = {}
    for key, expected_value in expected.items():
        if summary.get(key) != expected_value:
            errors.append(f"{context} summary.{key} expected {expected_value!r}, got {summary.get(key)!r}")
    ensure_subset(
        require_strings(report_contract.get("required_healing_actions"), errors, "report_contract.required_healing_actions"),
        summary.get("unique_healing_actions"),
        errors,
        f"{context} unique_healing_actions",
    )
    ensure_subset(
        require_strings(report_contract.get("required_overflow_patterns"), errors, "report_contract.required_overflow_patterns"),
        summary.get("overflow_patterns_covered"),
        errors,
        f"{context} overflow_patterns_covered",
    )
    matrix_contract = report_contract.get("coverage_matrix")
    matrix = report.get("coverage_matrix_check")
    if not isinstance(matrix_contract, dict) or not isinstance(matrix, dict):
        errors.append(f"{context} coverage matrix contract/report missing")
        return
    if bool(matrix.get("exists")) != bool(matrix_contract.get("required_present")):
        errors.append(f"{context} coverage matrix presence drifted")
    min_total = matrix_contract.get("min_total_cves")
    if isinstance(min_total, int) and matrix.get("total_cves_in_matrix", 0) < min_total:
        errors.append(f"{context} coverage matrix has too few CVEs")
    if matrix.get("intovf_cves_missing") != matrix_contract.get("missing_integer_overflow_cves"):
        errors.append(f"{context} coverage matrix integer-overflow missing list drifted")


def validate_cve_cases(
    contract: dict[str, Any],
    generated: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    cases = contract.get("cve_cases")
    if not isinstance(cases, list) or len(cases) < 2:
        errors.append("cve_cases must include at least two cases")
        return
    generated_tests = {
        item.get("cve_id"): item
        for item in generated.get("tests", [])
        if isinstance(item, dict) and isinstance(item.get("cve_id"), str)
    }
    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            errors.append("cve_cases entries must be objects")
            continue
        cve_id = case.get("cve_id")
        scenario_id = case.get("scenario_id")
        if not isinstance(cve_id, str) or not cve_id:
            errors.append("cve case missing cve_id")
            continue
        seen.add(cve_id)
        manifest_path = case.get("manifest_path")
        trigger_path = case.get("trigger_path")
        if not isinstance(manifest_path, str) or not isinstance(trigger_path, str):
            errors.append(f"{cve_id} missing manifest_path or trigger_path")
            continue
        manifest = load_json(root / manifest_path, errors, f"{cve_id} manifest")
        if not (root / trigger_path).is_file():
            errors.append(f"{cve_id} trigger missing: {trigger_path}")
        if manifest.get("cve_id") != cve_id:
            errors.append(f"{cve_id} manifest cve_id drifted")
        ensure_subset(require_strings(case.get("required_cwe_ids"), errors, f"{cve_id}.required_cwe_ids"), manifest.get("cwe_ids"), errors, f"{cve_id} cwe_ids")
        tsm = manifest.get("expected_tsm") or manifest.get("expected_tsm_behavior") or {}
        required_healing = require_strings(case.get("required_healing_actions"), errors, f"{cve_id}.required_healing_actions")
        if "ClampSize" not in required_healing:
            errors.append(f"{cve_id}.required_healing_actions must include ClampSize")
        ensure_subset(required_healing, tsm.get("healing_actions"), errors, f"{cve_id} manifest healing")
        ensure_subset(require_strings(case.get("required_tsm_features"), errors, f"{cve_id}.required_tsm_features"), manifest.get("tsm_features_tested"), errors, f"{cve_id} tsm_features")
        generated_case = generated_tests.get(cve_id)
        if not isinstance(generated_case, dict):
            errors.append(f"{cve_id} missing from generated report")
            continue
        ensure_subset(require_strings(case.get("required_overflow_patterns"), errors, f"{cve_id}.required_overflow_patterns"), generated_case.get("overflow_patterns"), errors, f"{cve_id} generated overflow_patterns")
        ensure_subset(required_healing, generated_case.get("healing_actions"), errors, f"{cve_id} generated healing")
        if generated_case.get("manifest_valid") is not True:
            errors.append(f"{cve_id} generated report did not mark manifest valid")
        rows.append({
            "event": "cve_integer_overflow_case",
            "status": "pass",
            "scenario_id": scenario_id,
            "cve_id": cve_id,
            "manifest_path": manifest_path,
            "trigger_path": trigger_path,
            "timestamp": utc_now(),
        })
    if seen != {"CVE-2023-6246", "CVE-2024-46461"}:
        errors.append(f"cve_cases must bind CVE-2023-6246 and CVE-2024-46461, got {sorted(seen)}")


def run_compile_e2e(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    trigger = root / "tests/cve_arena/glibc/cve_2023_6246_syslog_suite/trigger.c"
    result = subprocess.run(
        ["cc", "-c", "-fsyntax-only", str(trigger)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=int(contract.get("runtime_target", {}).get("max_seconds", 45)),
    )
    rows.append({
        "event": "cve_integer_overflow_e2e",
        "scenario_id": "compile_glibc_syslog_trigger",
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "artifact": rel(trigger),
        "timestamp": utc_now(),
    })
    if result.returncode != 0:
        errors.append(f"trigger compile failed: stdout={result.stdout} stderr={result.stderr}")


def validate_contract(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
    validate_command_policy(contract, errors)
    validate_source_artifacts(contract, errors, rows)
    validate_completion_evidence(contract, errors)
    generated = run_generator(contract, errors, rows)
    if generated:
        validate_cve_cases(contract, generated, errors, rows)
    run_compile_e2e(contract, errors, rows)
    rows.append({
        "event": "cve_integer_overflow_e2e",
        "scenario_id": "completion_checker_runs_fail_closed",
        "status": "pass",
        "exit_code": 0,
        "artifact": rel(contract_path),
        "timestamp": utc_now(),
    })
    return generated


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "completion contract")
generated = validate_contract(contract, errors, rows) if contract else {}
summary = generated.get("summary", {}) if isinstance(generated, dict) else {}

status = "pass" if not errors else "fail"
rows.append({
    "event": "cve_integer_overflow_summary",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "total_intovf_tests": summary.get("total_intovf_tests"),
    "total_issues": summary.get("total_issues"),
    "error_count": len(errors),
    "timestamp": utc_now(),
})
report = {
    "schema_version": "v1",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "contract": rel(contract_path),
    "generated_report": rel(out_dir / "generated_integer_overflow_validation.v1.json"),
    "log": rel(log_path),
    "cve_case_count": len(contract.get("cve_cases", [])) if isinstance(contract, dict) else 0,
    "e2e_scenario_count": len(contract.get("e2e_primary", {}).get("scenarios", [])) if isinstance(contract, dict) else 0,
    "summary": summary,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("cve_integer_overflow_validation_completion_contract: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "cve_integer_overflow_validation_completion_contract: PASS "
    f"cases={report['cve_case_count']} e2e={report['e2e_scenario_count']} "
    f"tests={summary.get('total_intovf_tests')} issues={summary.get('total_issues')}"
)
PY
