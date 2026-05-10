#!/usr/bin/env bash
# check_cross_report_consistency_completion_contract.sh -- fail-closed evidence gate for bd-2vv.11.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${CROSS_REPORT_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/cross_report_consistency_completion_contract.v1.json}"
OUT_DIR="${CROSS_REPORT_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${CROSS_REPORT_COMPLETION_REPORT:-${OUT_DIR}/cross_report_consistency_completion_contract.report.json}"
LOG="${CROSS_REPORT_COMPLETION_LOG:-${OUT_DIR}/cross_report_consistency_completion_contract.log.jsonl}"
GENERATED="${CROSS_REPORT_COMPLETION_GENERATED:-${OUT_DIR}/cross_report_consistency_completion_contract.generated.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")" "$(dirname "${GENERATED}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${GENERATED}" <<'PY'
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
generated_path = Path(sys.argv[5])

BEAD_ID = "bd-2vv.11"
COMPLETION_DEBT_BEAD_ID = "bd-2vv.11.1"
MANIFEST_ID = "cross-report-consistency-completion-contract"
REQUIRED_EVENTS = {
    "cross_report_completion_source",
    "cross_report_completion_unit",
    "cross_report_completion_e2e",
    "cross_report_completion_summary",
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
    for section_name in ["e2e_primary"]:
        section = contract.get(section_name)
        if not isinstance(section, dict):
            continue
        for scenario in section.get("scenarios", []):
            if not isinstance(scenario, dict) or not isinstance(scenario.get("command"), str):
                continue
            command = scenario["command"]
            scenario_id = str(scenario.get("scenario_id", "unknown"))
            if not any(command.startswith(prefix) for prefix in allowed):
                errors.append(f"{scenario_id} command is not allowlisted: {command}")
            for needle in forbidden:
                if needle in command and not command.startswith("rch cargo"):
                    errors.append(f"{scenario_id} command contains forbidden substring {needle!r}")


def validate_summary(report: dict[str, Any], invariants: dict[str, Any], errors: list[str], context: str) -> None:
    if report.get("schema_version") != invariants.get("schema_version"):
        errors.append(f"{context} schema_version drift")
    if report.get("bead") != invariants.get("bead"):
        errors.append(f"{context} bead drift")
    if report.get("consistency_hash") != invariants.get("consistency_hash"):
        errors.append(
            f"{context} consistency_hash drift: expected {invariants.get('consistency_hash')} "
            f"got {report.get('consistency_hash')}"
        )

    summary = report.get("summary")
    expected = invariants.get("summary")
    if not isinstance(summary, dict) or not isinstance(expected, dict):
        errors.append(f"{context} summary must be objects")
        return
    comparisons = {
        "overall_verdict": summary.get("overall_verdict"),
        "total_findings": summary.get("total_findings"),
        "critical": summary.get("by_severity", {}).get("critical"),
        "error": summary.get("by_severity", {}).get("error"),
        "warning": summary.get("by_severity", {}).get("warning"),
        "info": summary.get("by_severity", {}).get("info"),
        "inconsistent": summary.get("by_verdict", {}).get("inconsistent", 0),
        "pass": summary.get("by_verdict", {}).get("pass", 0),
        "reports_loaded": summary.get("reports_loaded"),
        "reports_total": summary.get("reports_total"),
    }
    for key, actual in comparisons.items():
        if actual != expected.get(key):
            errors.append(f"{context} summary {key} drift: expected {expected.get(key)} got {actual}")


def validate_report_loaded(report: dict[str, Any], invariants: dict[str, Any], errors: list[str], context: str) -> None:
    actual = report.get("reports_loaded")
    expected = invariants.get("reports_loaded")
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        errors.append(f"{context} reports_loaded must be objects")
        return
    for key, expected_value in expected.items():
        if actual.get(key) != expected_value:
            errors.append(f"{context} reports_loaded.{key} drift")


def validate_rules_and_findings(report: dict[str, Any], invariants: dict[str, Any], errors: list[str], context: str) -> None:
    rules = report.get("consistency_rules")
    if not isinstance(rules, dict):
        errors.append(f"{context} consistency_rules must be object")
        rules = {}
    for rule in invariants.get("required_rules", []):
        if rule not in rules:
            errors.append(f"{context} missing consistency rule {rule}")

    findings = report.get("findings")
    if not isinstance(findings, list):
        errors.append(f"{context} findings must be array")
        findings = []
    for required in invariants.get("required_findings", []):
        if not isinstance(required, dict):
            errors.append("required_findings entries must be objects")
            continue
        matched = False
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("rule") != required.get("rule"):
                continue
            if finding.get("verdict") != required.get("verdict"):
                continue
            if finding.get("severity") != required.get("severity"):
                continue
            symbol = required.get("required_symbol")
            if symbol is not None and symbol not in finding.get("affected_symbols", []):
                continue
            matched = True
            break
        if not matched:
            errors.append(f"{context} missing required finding {required}")


def validate_unit_primary(contract: dict[str, Any], errors: list[str]) -> int:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be object")
        return 0
    if unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary.missing_item_id must be tests.unit.primary")
    test_file = unit.get("test_file")
    source = read_text(test_file, errors, "unit_primary.test_file") if isinstance(test_file, str) else ""
    names = unit.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append("unit_primary.required_test_names must be non-empty array")
        return 0
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in source:
            errors.append(f"unit_primary references missing Rust test {name}")
    return len(names)


def validate_e2e_primary(contract: dict[str, Any], errors: list[str]) -> int:
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be object")
        return 0
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
    for key in ["gate_script", "generator"]:
        path_text = e2e.get(key)
        if not isinstance(path_text, str) or not (root / path_text).is_file():
            errors.append(f"e2e_primary.{key} missing file: {path_text}")
    scenarios = e2e.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 3:
        errors.append("e2e_primary.scenarios must contain at least three scenarios")
        return 0
    ids = {scenario.get("scenario_id") for scenario in scenarios if isinstance(scenario, dict)}
    required = {
        "completion_checker_replays_current_generator",
        "generator_emits_cross_report_snapshot",
        "rust_completion_contract_exercises_positive_and_negative_paths",
    }
    missing = sorted(required - ids)
    if missing:
        errors.append(f"e2e_primary.scenarios missing {missing}")
    return len(scenarios)


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be object")
        return
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    test_source = evidence.get("test_source")
    source = read_text(test_source, errors, "completion_debt_evidence.test_source") if isinstance(test_source, str) else ""
    names = evidence.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append("completion_debt_evidence.required_test_names must be non-empty array")
        return
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in source:
            errors.append(f"completion_debt_evidence references missing Rust test {name}")


def validate_contract(contract: dict[str, Any], errors: list[str]) -> tuple[list[dict[str, Any]], int, int]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")

    artifacts = contract.get("source_artifacts")
    source_rows: list[dict[str, Any]] = []
    if not isinstance(artifacts, dict):
        errors.append("source_artifacts must be object")
        artifacts = {}
    for artifact_id, path_text in artifacts.items():
        if not isinstance(path_text, str) or not (root / path_text).is_file():
            errors.append(f"source_artifacts.{artifact_id} missing file: {path_text}")
            status = "fail"
        else:
            status = "pass"
        source_rows.append({"artifact_id": artifact_id, "path": path_text, "status": status})

    invariants = contract.get("consistency_invariants")
    if not isinstance(invariants, dict):
        errors.append("consistency_invariants must be object")
        invariants = {}
    checked_in_report_path = artifacts.get("checked_in_report")
    checked_in_report = (
        load_json(root / checked_in_report_path, errors, "source_artifacts.checked_in_report")
        if isinstance(checked_in_report_path, str)
        else {}
    )
    if checked_in_report:
        validate_summary(checked_in_report, invariants, errors, "checked_in_report")
        validate_report_loaded(checked_in_report, invariants, errors, "checked_in_report")
        validate_rules_and_findings(checked_in_report, invariants, errors, "checked_in_report")

    checker = contract.get("checker_contract")
    if not isinstance(checker, dict):
        errors.append("checker_contract must be object")
    else:
        script = checker.get("script")
        source = read_text(script, errors, "checker_contract.script") if isinstance(script, str) else ""
        needles = checker.get("required_script_needles")
        if not isinstance(needles, list) or not needles:
            errors.append("checker_contract.required_script_needles must be non-empty array")
        else:
            for needle in needles:
                if not isinstance(needle, str) or needle not in source:
                    errors.append(f"checker_contract.script missing needle {needle}")

    unit_count = validate_unit_primary(contract, errors)
    e2e_count = validate_e2e_primary(contract, errors)
    validate_completion_evidence(contract, errors)
    validate_command_policy(contract, errors)

    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be object")
    else:
        events = telemetry.get("required_log_events")
        fields = telemetry.get("required_log_fields")
        if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
            errors.append("telemetry_contract.required_log_events drifted")
        if not isinstance(fields, list) or len(fields) < 8:
            errors.append("telemetry_contract.required_log_fields missing")

    return source_rows, unit_count, e2e_count


def run_generator(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    generator = contract.get("source_artifacts", {}).get("generator")
    invariants = contract.get("consistency_invariants", {})
    if not isinstance(generator, str):
        errors.append("source_artifacts.generator missing")
        return {
            "scenario_id": "generator_emits_cross_report_snapshot",
            "exit_code": 1,
            "status": "fail",
            "stdout_tail": "",
            "stderr_tail": "missing generator",
            "failure_signature": "missing_generator",
            "artifact_refs": [rel(generated_path)],
        }
    result = subprocess.run(
        ["python3", generator, "-o", str(generated_path)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=90,
    )
    row = {
        "scenario_id": "generator_emits_cross_report_snapshot",
        "exit_code": result.returncode,
        "status": "pass" if result.returncode == 0 else "fail",
        "stdout_tail": result.stdout[-1000:],
        "stderr_tail": result.stderr[-1000:],
        "failure_signature": "none" if result.returncode == 0 else "generator_failed",
        "artifact_refs": [generator, rel(generated_path)],
    }
    if result.returncode != 0:
        errors.append(f"generator_emits_cross_report_snapshot expected exit 0 got {result.returncode}")
        return row
    generated = load_json(generated_path, errors, "generated_report")
    if generated:
        validate_summary(generated, invariants, errors, "generated_report")
        validate_report_loaded(generated, invariants, errors, "generated_report")
        validate_rules_and_findings(generated, invariants, errors, "generated_report")
    return row


errors: list[str] = []
warnings: list[str] = []
contract = load_json(contract_path, errors, "contract")
source_rows: list[dict[str, Any]] = []
unit_count = 0
e2e_count = 0
e2e_rows: list[dict[str, Any]] = []
if contract:
    source_rows, unit_count, e2e_count = validate_contract(contract, errors)
    if not errors:
        e2e_rows = [run_generator(contract, errors)]

timestamp = utc_now()

source_log_rows = [
    {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['artifact_id']}",
        "event": "cross_report_completion_source",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "artifact_id": row["artifact_id"],
        "scenario_id": None,
        "status": row["status"],
        "artifact_refs": [row["path"], rel(contract_path)],
        "failure_signature": "none" if row["status"] == "pass" else "source_artifact_missing",
    }
    for row in source_rows
]

unit_log_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:unit-primary",
    "event": "cross_report_completion_unit",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "artifact_id": "unit_primary",
    "scenario_id": "unit_primary_binds_original_rust_tests",
    "status": "pass" if unit_count >= 7 and not errors else "fail",
    "artifact_refs": [
        "crates/frankenlibc-harness/tests/cross_report_consistency_test.rs",
        rel(contract_path),
    ],
    "failure_signature": "none" if unit_count >= 7 and not errors else "unit_primary_contract_error",
    "required_test_count": unit_count,
}

e2e_log_rows = [
    {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['scenario_id']}",
        "event": "cross_report_completion_e2e",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "artifact_id": "e2e_primary",
        "scenario_id": row["scenario_id"],
        "status": row["status"],
        "artifact_refs": row["artifact_refs"] + [rel(contract_path)],
        "failure_signature": row["failure_signature"],
        "exit_code": row["exit_code"],
        "stdout_tail": row["stdout_tail"],
        "stderr_tail": row["stderr_tail"],
    }
    for row in e2e_rows
]

summary = {
    "schema_version": "cross_report_consistency_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "source_artifact_count": len(source_rows),
    "unit_required_test_count": unit_count,
    "e2e_scenario_count": e2e_count,
    "e2e_executed_count": len(e2e_rows),
    "errors": errors,
    "warnings": warnings,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "generated_report_path": rel(generated_path),
}

summary_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "cross_report_completion_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "artifact_id": None,
    "scenario_id": None,
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path), rel(generated_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
}

log_rows = source_log_rows + [unit_log_row] + e2e_log_rows + [summary_row]
report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "cross_report_consistency_completion_contract: "
    f"status={summary['status']} sources={summary['source_artifact_count']} "
    f"unit_tests={summary['unit_required_test_count']} e2e={summary['e2e_executed_count']} "
    f"errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
print(f"generated={rel(generated_path)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
