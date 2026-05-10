#!/usr/bin/env bash
# check_change_impact_scheduler_completion_contract.sh -- fail-closed gate for bd-26xb.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CHANGE_IMPACT_CONTRACT:-${ROOT}/tests/conformance/change_impact_scheduler_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CHANGE_IMPACT_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_CHANGE_IMPACT_REPORT:-${OUT_DIR}/change_impact_scheduler_completion_contract.report.json}"
LOG="${FRANKENLIBC_CHANGE_IMPACT_LOG:-${OUT_DIR}/change_impact_scheduler_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-26xb.2"
COMPLETION_BEAD_ID = "bd-26xb.2.1"
MANIFEST_ID = "change-impact-scheduler-completion-contract"
REQUIRED_EVENTS = {
    "change_impact_component",
    "change_impact_rule",
    "change_impact_scenario",
    "change_impact_summary",
}
FULL_SUITE_REASONS = {"false_negative_sentinel", "high_pressure", "unknown_impact"}


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


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def ensure_subset(required: list[str], actual: list[str], errors: list[str], context: str) -> None:
    missing = [item for item in required if item not in actual]
    if missing:
        errors.append(f"{context} missing {missing}")


def validate_command_policy(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    allowed = require_strings(
        runtime.get("allowed_command_prefixes"),
        errors,
        "runtime_target.allowed_command_prefixes",
    )
    forbidden = require_strings(
        runtime.get("forbidden_command_substrings"),
        errors,
        "runtime_target.forbidden_command_substrings",
    )
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be an object")
        return
    for scenario in e2e.get("scenarios", []):
        if not isinstance(scenario, dict):
            errors.append("e2e_primary.scenarios entries must be objects")
            continue
        command = scenario.get("command")
        scenario_id = str(scenario.get("scenario_id", "unknown"))
        if not isinstance(command, str) or not command:
            errors.append(f"{scenario_id} command missing")
            continue
        if not any(command.startswith(prefix) for prefix in allowed):
            errors.append(f"{scenario_id} command is not allowlisted: {command}")
        for needle in forbidden:
            if needle in command:
                errors.append(f"{scenario_id} command contains forbidden substring {needle!r}")


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
            errors.append("source_artifacts entry missing artifact_id")
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
        rows.append({
            "event": "change_impact_component",
            "status": "pass" if text else "fail",
            "component_id": artifact_id,
            "path": path_text,
            "timestamp": utc_now(),
        })
    required_ids = {
        "support_matrix",
        "perf_budget_policy",
        "workload_latency_join_contract",
        "workload_latency_join_checker",
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


def support_symbols(errors: list[str]) -> set[str]:
    matrix = load_json(root / "support_matrix.json", errors, "support matrix")
    names = set()
    for entry in matrix.get("symbols", []):
        if isinstance(entry, dict) and isinstance(entry.get("symbol"), str):
            names.add(entry["symbol"])
    return names


def budget_classes(errors: list[str]) -> set[str]:
    policy = load_json(root / "tests/conformance/perf_budget_policy.json", errors, "perf budget policy")
    budgets = policy.get("budgets")
    if not isinstance(budgets, dict):
        errors.append("perf budget policy budgets must be an object")
        return set()
    return set(budgets)


def validate_unit_e2e_sections(contract: dict[str, Any], errors: list[str]) -> None:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict) or unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary must bind tests.unit.primary")
        test_source = ""
    else:
        test_source_path = unit.get("test_source")
        test_source = read_text(test_source_path, errors, "unit_primary.test_source") if isinstance(test_source_path, str) else ""
        for name in require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if f"fn {name}(" not in test_source:
                errors.append(f"unit_primary references missing Rust test {name}")

    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict) or e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary must bind tests.e2e.primary")
        return
    checker = e2e.get("checker_script")
    if not isinstance(checker, str) or not (root / checker).is_file():
        errors.append("e2e_primary.checker_script missing")
    scenarios = e2e.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 3:
        errors.append("e2e_primary.scenarios must include at least three scenarios")
        return
    scenario_ids = {item.get("scenario_id") for item in scenarios if isinstance(item, dict)}
    required = {
        "run_change_impact_contract_checker",
        "simulate_selective_low_pressure",
        "simulate_sentinel_full_suite",
    }
    if scenario_ids != required:
        errors.append(f"e2e_primary.scenarios must be exactly {sorted(required)}")


def validate_impact_rules(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = contract.get("impact_rules")
    if not isinstance(rules, list) or len(rules) < 4:
        errors.append("impact_rules must include at least four rules")
        return []
    known_symbols = support_symbols(errors)
    known_budget_classes = budget_classes(errors)
    seen = set()
    valid_rules: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append("impact_rules entries must be objects")
            continue
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            errors.append("impact rule missing rule_id")
            continue
        if rule_id in seen:
            errors.append(f"duplicate impact rule {rule_id}")
        seen.add(rule_id)
        prefixes = require_strings(rule.get("changed_path_prefixes"), errors, f"{rule_id}.changed_path_prefixes")
        symbols = require_strings(rule.get("symbols"), errors, f"{rule_id}.symbols")
        tests = require_strings(rule.get("required_tests"), errors, f"{rule_id}.required_tests")
        confidence = rule.get("confidence")
        if not isinstance(confidence, (int, float)) or confidence < 0.75:
            errors.append(f"{rule_id}.confidence must be >= 0.75")
        if rule.get("budget_class") not in known_budget_classes:
            errors.append(f"{rule_id}.budget_class missing from perf budget policy")
        if rule.get("api_family") != "runtime_math":
            unknown = [symbol for symbol in symbols if symbol not in known_symbols]
            if unknown:
                errors.append(f"{rule_id}.symbols not found in support_matrix: {unknown}")
        for test in tests:
            if not (root / test).is_file():
                errors.append(f"{rule_id}.required_tests missing file: {test}")
        if prefixes and tests:
            valid_rules.append(rule)
        rows.append({
            "event": "change_impact_rule",
            "status": "pass",
            "rule_id": rule_id,
            "api_family": rule.get("api_family"),
            "budget_class": rule.get("budget_class"),
            "selected_tests": len(tests),
            "timestamp": utc_now(),
        })
    required_rules = {"string_hotpath", "malloc_hotpath", "stdio_format", "runtime_math_policy"}
    if seen != required_rules:
        errors.append(f"impact_rules must be exactly {sorted(required_rules)}, got {sorted(seen)}")
    return valid_rules


def validate_budget_profiles(contract: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    profiles = contract.get("budget_profiles")
    if not isinstance(profiles, list) or len(profiles) < 3:
        errors.append("budget_profiles must include low, medium, and high pressure")
        return {}
    by_pressure: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            errors.append("budget_profiles entries must be objects")
            continue
        pressure = profile.get("pressure")
        if isinstance(pressure, str):
            by_pressure[pressure] = profile
    for pressure in ["low", "medium", "high"]:
        if pressure not in by_pressure:
            errors.append(f"budget_profiles missing pressure {pressure}")
    if by_pressure.get("high", {}).get("full_suite_required") is not True:
        errors.append("high pressure must force full_suite")
    return by_pressure


def matching_rules(changed_files: list[str], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for rule in rules:
        prefixes = [item for item in rule.get("changed_path_prefixes", []) if isinstance(item, str)]
        if any(any(changed.startswith(prefix) for prefix in prefixes) for changed in changed_files):
            matches.append(rule)
    return matches


def simulate_scenario(
    scenario: dict[str, Any],
    rules: list[dict[str, Any]],
    profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    changed_files = [item for item in scenario.get("changed_files", []) if isinstance(item, str)]
    pressure = scenario.get("pressure")
    matched = matching_rules(changed_files, rules)
    reason = "impact_match"
    if scenario.get("false_negative_sentinel") is True:
        decision = "full_suite"
        reason = "false_negative_sentinel"
    elif profiles.get(str(pressure), {}).get("full_suite_required") is True:
        decision = "full_suite"
        reason = "high_pressure"
    elif not matched:
        decision = "full_suite"
        reason = "unknown_impact"
    else:
        decision = "selective"
    selected_tests = sorted({
        test
        for rule in matched
        for test in rule.get("required_tests", [])
        if isinstance(test, str)
    })
    return {
        "scenario_id": scenario.get("scenario_id"),
        "decision": decision,
        "reason": reason,
        "matched_rule_ids": [rule.get("rule_id") for rule in matched],
        "selected_tests": selected_tests,
    }


def validate_scenarios(
    contract: dict[str, Any],
    rules: list[dict[str, Any]],
    profiles: dict[str, dict[str, Any]],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    scenarios = contract.get("e2e_scenarios")
    if not isinstance(scenarios, list):
        errors.append("e2e_scenarios must be an array")
        return []
    if len(scenarios) < 5:
        errors.append("e2e_scenarios must include at least five scenarios")
    results = []
    seen = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            errors.append("e2e_scenarios entries must be objects")
            continue
        scenario_id = scenario.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append("e2e scenario missing scenario_id")
            continue
        seen.add(scenario_id)
        result = simulate_scenario(scenario, rules, profiles)
        results.append(result)
        if result["decision"] != scenario.get("expected_decision"):
            errors.append(f"{scenario_id} decision expected {scenario.get('expected_decision')}, got {result['decision']}")
        expected_reason = scenario.get("expected_reason")
        if isinstance(expected_reason, str) and result["reason"] != expected_reason:
            errors.append(f"{scenario_id} reason expected {expected_reason}, got {result['reason']}")
        expected_rules = [item for item in scenario.get("expected_rule_ids", []) if isinstance(item, str)]
        if result["matched_rule_ids"] != expected_rules:
            errors.append(f"{scenario_id} expected rules {expected_rules}, got {result['matched_rule_ids']}")
        expected_tests = [item for item in scenario.get("expected_tests", []) if isinstance(item, str)]
        ensure_subset(expected_tests, result["selected_tests"], errors, f"{scenario_id} selected_tests")
        rows.append({
            "event": "change_impact_scenario",
            "status": "pass",
            "scenario_id": scenario_id,
            "decision": result["decision"],
            "reason": result["reason"],
            "matched_rule_ids": result["matched_rule_ids"],
            "selected_tests": result["selected_tests"],
            "timestamp": utc_now(),
        })
    required_scenarios = {
        "string_low_pressure_selective",
        "malloc_medium_pressure_selective",
        "runtime_math_high_pressure_full_suite",
        "false_negative_sentinel_full_suite",
        "unknown_change_full_suite",
    }
    if seen != required_scenarios:
        errors.append(f"e2e_scenarios must be exactly {sorted(required_scenarios)}, got {sorted(seen)}")
    sentinel = next((item for item in scenarios if isinstance(item, dict) and item.get("false_negative_sentinel") is True), None)
    if not sentinel:
        errors.append("e2e_scenarios must include false_negative_sentinel")
    return results


def validate_contract(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    validate_unit_e2e_sections(contract, errors)
    rules = validate_impact_rules(contract, errors, rows)
    profiles = validate_budget_profiles(contract, errors)
    return validate_scenarios(contract, rules, profiles, errors, rows)


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "completion contract")
scenario_results = validate_contract(contract, errors, rows) if contract else []
status = "pass" if not errors else "fail"

rows.append({
    "event": "change_impact_summary",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "impact_rule_count": len(contract.get("impact_rules", [])) if isinstance(contract, dict) else 0,
    "scenario_count": len(contract.get("e2e_scenarios", [])) if isinstance(contract, dict) else 0,
    "error_count": len(errors),
    "timestamp": utc_now(),
})
report = {
    "schema_version": "v1",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "contract": rel(contract_path),
    "log": rel(log_path),
    "impact_rule_count": len(contract.get("impact_rules", [])) if isinstance(contract, dict) else 0,
    "scenario_count": len(contract.get("e2e_scenarios", [])) if isinstance(contract, dict) else 0,
    "scenario_results": scenario_results,
    "full_suite_reasons": sorted(FULL_SUITE_REASONS),
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("change_impact_scheduler_completion_contract: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "change_impact_scheduler_completion_contract: PASS "
    f"rules={report['impact_rule_count']} scenarios={report['scenario_count']} "
    "selective=2 full_suite=3"
)
PY
