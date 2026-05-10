#!/usr/bin/env bash
# check_counterfactual_policy_simulator_completion_contract.sh -- fail-closed gate for bd-26xb.5.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_COUNTERFACTUAL_POLICY_CONTRACT:-${ROOT}/tests/conformance/counterfactual_policy_simulator_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_COUNTERFACTUAL_POLICY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_COUNTERFACTUAL_POLICY_REPORT:-${OUT_DIR}/counterfactual_policy_simulator_completion_contract.report.json}"
LOG="${FRANKENLIBC_COUNTERFACTUAL_POLICY_LOG:-${OUT_DIR}/counterfactual_policy_simulator_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-26xb.5"
COMPLETION_BEAD_ID = "bd-26xb.5.1"
MANIFEST_ID = "counterfactual-policy-simulator-completion-contract"
REQUIRED_EVENTS = {
    "counterfactual_source",
    "counterfactual_case",
    "promotion_decision",
    "counterfactual_summary",
}
ACCEPTANCE_LOG_FIELDS = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}
TERMINAL_ACTIONS = {"Allow", "FullValidate", "Repair", "Deny"}


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


def validate_source_artifacts(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 6:
        errors.append("source_artifacts must include the replay, policy, evidence, and regret anchors")
        return
    required_ids = {
        "runtime_evidence_replay_gate",
        "runtime_evidence_replay_checker",
        "runtime_evidence_module",
        "pareto_regret_controller",
        "proof_carrying_policy_audit",
        "policy_table_loader",
    }
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
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append({
            "event": "counterfactual_source",
            "status": "pass" if text else "fail",
            "artifact_id": artifact_id,
            "path": path_text,
            "timestamp": utc_now(),
        })
    if seen != required_ids:
        errors.append(f"source_artifacts must be exactly {sorted(required_ids)}, got {sorted(seen)}")


def validate_policy(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    policy = contract.get("promotion_policy")
    if not isinstance(policy, dict):
        errors.append("promotion_policy must be an object")
        return {}
    if policy.get("default_decision") != "block_until_counterfactual_dossier_passes":
        errors.append("promotion_policy.default_decision must block until dossier passes")
    if policy.get("strict_repair_allowed") is not False:
        errors.append("promotion_policy.strict_repair_allowed must be false")
    for field in ["max_latency_regression_ns", "max_risk_regression_ppm", "max_regret_ppm"]:
        if not isinstance(policy.get(field), int) or policy[field] < 0:
            errors.append(f"promotion_policy.{field} must be a non-negative integer")
    terminals = set(require_strings(policy.get("required_terminal_decisions"), errors, "promotion_policy.required_terminal_decisions"))
    if terminals != TERMINAL_ACTIONS:
        errors.append(f"promotion_policy.required_terminal_decisions must be {sorted(TERMINAL_ACTIONS)}")
    required_failures = {
        "none",
        "missing_counterfactual_dossier",
        "strict_repair_candidate",
        "risk_regression",
        "latency_regression",
        "regret_budget_exceeded",
    }
    failures = set(require_strings(policy.get("required_failure_signatures"), errors, "promotion_policy.required_failure_signatures"))
    if failures != required_failures:
        errors.append(f"promotion_policy.required_failure_signatures must be {sorted(required_failures)}")
    return policy


def validate_structured_log(contract: dict[str, Any], errors: list[str]) -> set[str]:
    log_contract = contract.get("structured_log_contract")
    if not isinstance(log_contract, dict):
        errors.append("structured_log_contract must be an object")
        return set()
    fields = set(require_strings(log_contract.get("required_fields"), errors, "structured_log_contract.required_fields"))
    missing = sorted(ACCEPTANCE_LOG_FIELDS - fields)
    if missing:
        errors.append(f"structured_log_contract.required_fields missing acceptance fields {missing}")
    events = set(require_strings(log_contract.get("required_events"), errors, "structured_log_contract.required_events"))
    if events != REQUIRED_EVENTS:
        errors.append(f"structured_log_contract.required_events must be {sorted(REQUIRED_EVENTS)}")
    retention = log_contract.get("retention_policy")
    if not isinstance(retention, dict) or retention.get("deterministic_names") is not True:
        errors.append("structured_log_contract.retention_policy.deterministic_names must be true")
    return fields


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    if not isinstance(evidence.get("next_audit_score_threshold"), int) or evidence["next_audit_score_threshold"] < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    missing_items = set(require_strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing_items != {"tests.unit.primary", "tests.e2e.primary"}:
        errors.append("completion_debt_evidence.missing_items_closed must close unit and e2e items")
    unit = evidence.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("completion_debt_evidence.unit_primary must be an object")
    else:
        test_source = unit.get("test_source")
        source_text = read_text(test_source, errors, "unit_primary.test_source") if isinstance(test_source, str) else ""
        for name in require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"unit_primary references missing Rust test {name}")
    e2e = evidence.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("completion_debt_evidence.e2e_primary must be an object")
    else:
        checker = e2e.get("checker_script")
        if not isinstance(checker, str) or not (root / checker).is_file():
            errors.append("e2e_primary.checker_script missing")
        test_source = evidence.get("unit_primary", {}).get("test_source")
        source_text = read_text(test_source, errors, "e2e_primary.test_source") if isinstance(test_source, str) else ""
        for name in require_strings(e2e.get("required_test_names"), errors, "e2e_primary.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"e2e_primary references missing Rust test {name}")


def required_case_number(section: dict[str, Any], field: str, errors: list[str], context: str) -> int:
    value = section.get(field)
    if not isinstance(value, int):
        errors.append(f"{context}.{field} must be an integer")
        return 0
    return value


def decide_case(case: dict[str, Any], policy: dict[str, Any], errors: list[str]) -> tuple[str, str]:
    case_id = str(case.get("case_id", "<missing>"))
    baseline = case.get("baseline")
    candidate = case.get("candidate")
    counterfactual = case.get("counterfactual")
    if not isinstance(baseline, dict) or not isinstance(candidate, dict) or not isinstance(counterfactual, dict):
        return "block_promotion", "missing_counterfactual_dossier"
    mode = case.get("mode")
    candidate_action = candidate.get("action")
    if candidate_action not in TERMINAL_ACTIONS:
        errors.append(f"{case_id}: candidate.action must be one of {sorted(TERMINAL_ACTIONS)}")
    if baseline.get("action") not in TERMINAL_ACTIONS or counterfactual.get("action") not in TERMINAL_ACTIONS:
        errors.append(f"{case_id}: baseline/counterfactual actions must be terminal decisions")
    if mode == "strict" and candidate_action == "Repair" and policy.get("strict_repair_allowed") is False:
        return "block_promotion", "strict_repair_candidate"
    baseline_risk = required_case_number(baseline, "risk_ppm", errors, f"{case_id}.baseline")
    candidate_risk = required_case_number(candidate, "risk_ppm", errors, f"{case_id}.candidate")
    risk_regression = candidate_risk - baseline_risk
    if risk_regression > int(policy.get("max_risk_regression_ppm", 0)):
        return "block_promotion", "risk_regression"
    baseline_latency = required_case_number(baseline, "latency_ns", errors, f"{case_id}.baseline")
    candidate_latency = required_case_number(candidate, "latency_ns", errors, f"{case_id}.candidate")
    latency_regression = candidate_latency - baseline_latency
    if latency_regression > int(policy.get("max_latency_regression_ns", 0)):
        return "block_promotion", "latency_regression"
    regret = required_case_number(candidate, "estimated_regret_ppm", errors, f"{case_id}.candidate")
    if regret > int(policy.get("max_regret_ppm", 0)):
        return "block_promotion", "regret_budget_exceeded"
    return "promote_candidate", "none"


def validate_cases(
    contract: dict[str, Any],
    policy: dict[str, Any],
    fields: set[str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    cases = contract.get("counterfactual_cases")
    if not isinstance(cases, list) or len(cases) < 6:
        errors.append("counterfactual_cases must include at least six deterministic scenarios")
        return []
    results = []
    decisions = set()
    failures = set()
    modes = set()
    for case in cases:
        if not isinstance(case, dict):
            errors.append("counterfactual_cases entries must be objects")
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("counterfactual case missing case_id")
            continue
        for field in ["mode", "api_family", "symbol", "decision_path", "healing_action", "errno", "artifact_refs"]:
            if field not in case:
                errors.append(f"{case_id}: missing case field {field}")
        for artifact in case.get("artifact_refs", []):
            if not isinstance(artifact, str) or not (root / artifact).exists():
                errors.append(f"{case_id}: artifact_ref missing {artifact!r}")
        decision, failure = decide_case(case, policy, errors)
        decisions.add(decision)
        failures.add(failure)
        modes.add(case.get("mode"))
        if decision != case.get("expected_promotion_decision"):
            errors.append(f"{case_id}: expected decision {case.get('expected_promotion_decision')}, got {decision}")
        if failure != case.get("expected_failure_signature"):
            errors.append(f"{case_id}: expected failure {case.get('expected_failure_signature')}, got {failure}")
        log_row = {
            "event": "counterfactual_case",
            "trace_id": f"{COMPLETION_BEAD_ID}:{case_id}",
            "mode": case.get("mode"),
            "api_family": case.get("api_family"),
            "symbol": case.get("symbol"),
            "decision_path": case.get("decision_path"),
            "healing_action": case.get("healing_action"),
            "errno": case.get("errno"),
            "latency_ns": case.get("candidate", {}).get("latency_ns") if isinstance(case.get("candidate"), dict) else None,
            "artifact_refs": case.get("artifact_refs", []),
            "counterfactual_action": case.get("counterfactual", {}).get("action") if isinstance(case.get("counterfactual"), dict) else None,
            "promotion_decision": decision,
            "failure_signature": failure,
            "timestamp": utc_now(),
        }
        missing_log_fields = sorted(field for field in fields if field not in log_row)
        if missing_log_fields:
            errors.append(f"{case_id}: emitted log row missing required fields {missing_log_fields}")
        rows.append(log_row)
        rows.append({
            "event": "promotion_decision",
            "status": "pass" if failure == "none" else "blocked",
            "case_id": case_id,
            "promotion_decision": decision,
            "failure_signature": failure,
            "timestamp": utc_now(),
        })
        results.append({
            "case_id": case_id,
            "promotion_decision": decision,
            "failure_signature": failure,
        })
    if decisions != {"promote_candidate", "block_promotion"}:
        errors.append("counterfactual_cases must cover both promote_candidate and block_promotion")
    if "strict" not in modes or "hardened" not in modes:
        errors.append("counterfactual_cases must cover strict and hardened modes")
    required_failures = {
        "none",
        "strict_repair_candidate",
        "risk_regression",
        "latency_regression",
        "regret_budget_exceeded",
    }
    if not required_failures.issubset(failures):
        errors.append(f"counterfactual_cases missing failure coverage {sorted(required_failures - failures)}")
    return results


def validate_negative_cases(contract: dict[str, Any], errors: list[str]) -> None:
    cases = contract.get("negative_cases")
    if not isinstance(cases, list) or len(cases) < 4:
        errors.append("negative_cases must include at least four fail-closed mutations")
        return
    mutations = {case.get("mutation") for case in cases if isinstance(case, dict)}
    expected = {
        "remove_counterfactual",
        "candidate_action_repair_in_strict",
        "raise_candidate_risk",
        "raise_candidate_latency",
    }
    if mutations != expected:
        errors.append(f"negative_cases mutations must be {sorted(expected)}, got {sorted(mutations)}")


def validate_contract(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
    validate_source_artifacts(contract, errors, rows)
    policy = validate_policy(contract, errors)
    fields = validate_structured_log(contract, errors)
    validate_completion_evidence(contract, errors)
    validate_negative_cases(contract, errors)
    return validate_cases(contract, policy, fields, errors, rows)


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "counterfactual completion contract")
case_results = validate_contract(contract, errors, rows) if contract else []
status = "pass" if not errors else "fail"

rows.append({
    "event": "counterfactual_summary",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "case_count": len(contract.get("counterfactual_cases", [])) if isinstance(contract, dict) else 0,
    "blocked_count": sum(1 for result in case_results if result.get("promotion_decision") == "block_promotion"),
    "promoted_count": sum(1 for result in case_results if result.get("promotion_decision") == "promote_candidate"),
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
    "case_count": len(contract.get("counterfactual_cases", [])) if isinstance(contract, dict) else 0,
    "case_results": case_results,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("counterfactual_policy_simulator_completion_contract: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "counterfactual_policy_simulator_completion_contract: PASS "
    f"cases={report['case_count']} promote=2 block=4"
)
PY
