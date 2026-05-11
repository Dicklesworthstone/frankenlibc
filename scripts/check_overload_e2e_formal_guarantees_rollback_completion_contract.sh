#!/usr/bin/env bash
# check_overload_e2e_formal_guarantees_rollback_completion_contract.sh - bd-w2c3.7.3.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_OVERLOAD_E2E_COMPLETION_CONTRACT:-$ROOT/tests/conformance/overload_e2e_formal_guarantees_rollback_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_OVERLOAD_E2E_COMPLETION_OUT_DIR:-$ROOT/target/conformance/overload_e2e_formal_guarantees_rollback_completion_contract}"
REPORT="${FRANKENLIBC_OVERLOAD_E2E_COMPLETION_REPORT:-$OUT_DIR/overload_e2e_formal_guarantees_rollback_completion_contract.report.json}"
LOG="${FRANKENLIBC_OVERLOAD_E2E_COMPLETION_LOG:-$OUT_DIR/overload_e2e_formal_guarantees_rollback_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "overload_e2e_formal_guarantees_rollback_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "overload_e2e_formal_guarantees_rollback_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.7.3"
COMPLETION_BEAD = "bd-w2c3.7.3.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_MONITORS = {"eprocess", "changepoint", "cvar", "conformal", "risk"}
EXPECTED_GUARANTEE_METRICS = {"miscoverage", "tail_risk", "regret", "divergence"}
EXPECTED_EVENTS = {
    "overload_e2e_campaign_bound",
    "overload_formal_guarantees_bound",
    "overload_rollback_triggers_bound",
    "overload_completion_contract_validated",
}
EXPECTED_SOURCE_CHECK_IDS = {
    "calibration_baseline_match",
    "pareto_regret_saturates_at_cap",
    "pareto_budget_enforcement_counter",
    "risk_family_isolation",
    "risk_adverse_rate_monotonicity",
    "real_workload_divergence_guard",
}
EXPECTED_FAIL_SIGNATURES = {
    "runtime_calibration_stale_fixture_outcomes",
    "runtime_calibration_threshold_edge_case_mismatch",
    "runtime_calibration_disabled_monitor",
    "runtime_calibration_false_positive_budget_exceeded",
    "runtime_calibration_false_negative_budget_exceeded",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def repo_path(value: Any, context: str, *, must_be_file: bool = False) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


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


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::overload-e2e-completion::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "mode": "hardened",
            "api_family": "runtime_math",
            "symbol": event,
            "decision_path": "pressure_campaign->risk_monitor_calibration->perf_rollback_gate",
            "healing_action": "ReturnSafeDefault" if status == "pass" else "None",
            "errno": 0 if status == "pass" else 1,
            "latency_ns": 0,
            "artifact_refs": artifact_refs,
            "status": status,
            "failure_signature": "none" if status == "pass" else "overload_e2e_completion_contract_failed",
            "details": details,
        }
    )


def function_exists(source_text: str, name: str) -> bool:
    return (
        f"fn {name}(" in source_text
        or f"fn {name}<" in source_text
        or f"def {name}(" in source_text
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    raw = manifest.get("source_artifacts", {})
    if not isinstance(raw, dict) or not raw:
        err("source_artifacts must be a non-empty object")
        return {}
    artifacts: dict[str, str] = {}
    for key, value in raw.items():
        if repo_path(value, f"source_artifacts.{key}", must_be_file=True) is not None and isinstance(value, str):
            artifacts[str(key)] = value
    return artifacts


def validate_impl_refs(manifest: dict[str, Any]) -> int:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 12:
        err("implementation_refs must include at least 12 concrete source anchors")
        return 0
    cache: dict[str, str] = {}
    seen = 0
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        kind = ref.get("kind")
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        if not isinstance(kind, str) or not kind:
            err(f"implementation_refs[{index}].kind must be a non-empty string")
        if not isinstance(path_text, str):
            err(f"implementation_refs[{index}].path must be a string")
            continue
        text = cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
        lines = text.splitlines()
        if not isinstance(line, int) or line <= 0:
            err(f"{path_text} ref line must be a positive integer")
        elif line > len(lines) or not lines[line - 1].strip():
            err(f"{path_text}:{line} does not point to a non-empty line")
        if not isinstance(anchor, str) or not anchor:
            err(f"{path_text}:{line} missing anchor")
        elif anchor not in text:
            err(f"{path_text} missing anchor {anchor!r}")
        seen += 1
    return seen


def validate_test_sources(manifest: dict[str, Any]) -> int:
    raw = manifest.get("test_sources", {})
    if not isinstance(raw, dict) or not raw:
        err("test_sources must be a non-empty object")
        return 0
    count = 0
    for source_id, source in raw.items():
        if not isinstance(source, dict):
            err(f"test_sources.{source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id}.path must be a string")
            continue
        text = text_for(path_text, f"test_sources.{source_id}")
        for name in strings(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            count += 1
            require(function_exists(text, name), f"test_sources.{source_id} missing required test ref {name}")
    return count


def validate_completion_coverage(manifest: dict[str, Any]) -> dict[str, Any]:
    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or len(coverage) != 2:
        err("completion_coverage must contain exactly unit and e2e sections")
        return {"coverage_count": 0}
    covered = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
    require(covered == EXPECTED_MISSING_ITEMS, f"completion_coverage item mismatch: {covered!r}")
    for section in coverage:
        if not isinstance(section, dict):
            err("completion_coverage sections must be objects")
            continue
        require(section.get("status") == "covered", f"{section.get('missing_item_id')} status must be covered")
        strings(section.get("test_refs"), f"completion_coverage.{section.get('missing_item_id')}.test_refs")
        for command in strings(section.get("validation_commands"), f"completion_coverage.{section.get('missing_item_id')}.validation_commands"):
            if "cargo " in command and not command.startswith("rch exec -- "):
                err(f"cargo validation must be rch-backed: {command}")
    return {"coverage_count": len(coverage), "missing_items": sorted(str(item) for item in covered)}


def validate_overload_campaign(required: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    compute = load_json(ROOT / artifacts.get("compute_pressure_contract", ""), "compute_pressure_contract")
    scenarios = load_json(ROOT / artifacts.get("pressure_sensing_scenarios", ""), "pressure_sensing_scenarios")
    require(compute.get("original_bead") == required.get("compute_pressure_original_bead"), "compute pressure original bead drifted")
    require(
        compute.get("completion_debt_bead") == required.get("compute_pressure_completion_bead"),
        "compute pressure completion bead drifted",
    )
    evidence = compute.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        err("compute pressure completion_debt_evidence must be an object")
        evidence = {}
    pressure = evidence.get("pressure_sensing", {})
    family = evidence.get("family_degradation", {})
    backpressure = evidence.get("backpressure", {})
    if not isinstance(pressure, dict):
        err("compute pressure pressure_sensing must be an object")
        pressure = {}
    if not isinstance(family, dict):
        err("compute pressure family_degradation must be an object")
        family = {}
    if not isinstance(backpressure, dict):
        err("compute pressure backpressure must be an object")
        backpressure = {}

    regimes = set(strings(pressure.get("required_regimes"), "overload_campaign.required_regimes"))
    modes = set(strings(pressure.get("required_modes"), "overload_campaign.required_modes"))
    expected_regimes = set(strings(required.get("required_regimes"), "required_source_contract.overload_campaign.required_regimes"))
    expected_modes = set(strings(required.get("required_modes"), "required_source_contract.overload_campaign.required_modes"))
    require(regimes == expected_regimes, "compute pressure required regimes drifted")
    require(modes == expected_modes, "compute pressure required modes drifted")

    scenario_rows = scenarios.get("scenarios", [])
    if not isinstance(scenario_rows, list):
        err("pressure_sensing_scenarios.scenarios must be an array")
        scenario_rows = []
    scenario_ids = {str(row.get("id")) for row in scenario_rows if isinstance(row, dict)}
    for scenario_id in strings(required.get("required_scenario_ids"), "overload_campaign.required_scenario_ids"):
        require(scenario_id in scenario_ids, f"pressure sensing scenario missing {scenario_id}")

    family_events = set(strings(family.get("required_events"), "compute_pressure.family_degradation.required_events"))
    for event_name in strings(required.get("required_overload_events"), "overload_campaign.required_overload_events"):
        require(event_name in family_events, f"family degradation evidence missing overload event {event_name}")
    ring_count = len(strings(backpressure.get("required_ring_ids"), "compute_pressure.backpressure.required_ring_ids"))
    require(ring_count == required.get("required_backpressure_ring_count"), "backpressure ring count drifted")

    return {
        "scenario_count": len(scenario_rows),
        "regimes": sorted(regimes),
        "modes": sorted(modes),
        "backpressure_ring_count": ring_count,
    }


def validate_formal_guarantees(required: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    metrics = set(strings(required.get("required_metrics"), "formal_guarantees.required_metrics"))
    require(metrics == EXPECTED_GUARANTEE_METRICS, f"formal guarantee metrics must be {sorted(EXPECTED_GUARANTEE_METRICS)}")

    risk_monitor = load_json(ROOT / artifacts.get("runtime_risk_monitor_contract", ""), "runtime_risk_monitor_contract")
    claim_policy = risk_monitor.get("claim_policy", {})
    if not isinstance(claim_policy, dict):
        err("runtime risk monitor claim_policy must be an object")
        claim_policy = {}
    monitors = set(strings(claim_policy.get("required_monitors"), "runtime_risk_monitor.claim_policy.required_monitors"))
    required_monitors = set(strings(required.get("required_monitors"), "formal_guarantees.required_monitors"))
    require(monitors == required_monitors == EXPECTED_MONITORS, "runtime risk monitors must cover eprocess/changepoint/cvar/conformal/risk")
    modes = set(strings(claim_policy.get("required_modes"), "runtime_risk_monitor.claim_policy.required_modes"))
    required_modes = set(strings(required.get("required_modes"), "formal_guarantees.required_modes"))
    require(modes == required_modes == {"strict", "hardened"}, "runtime risk monitor modes must cover strict+hardened")
    require(
        claim_policy.get("allowed_false_positive_count") == required.get("allowed_false_positive_count") == 0,
        "false-positive budget must be zero",
    )
    require(
        claim_policy.get("allowed_false_negative_count") == required.get("allowed_false_negative_count") == 0,
        "false-negative budget must be zero",
    )
    fail_signatures = set(strings(claim_policy.get("fail_closed_signatures"), "runtime_risk_monitor.fail_closed_signatures"))
    required_signatures = set(strings(required.get("required_fail_closed_signatures"), "formal_guarantees.required_fail_closed_signatures"))
    require(fail_signatures == required_signatures == EXPECTED_FAIL_SIGNATURES, "runtime risk fail-closed signatures drifted")
    records = risk_monitor.get("calibration_records", [])
    if not isinstance(records, list):
        err("runtime risk monitor calibration_records must be an array")
        records = []
    record_monitors = {str(row.get("monitor_id")) for row in records if isinstance(row, dict)}
    require(EXPECTED_MONITORS.issubset(record_monitors), "calibration records must include every required monitor")
    for row in records:
        if not isinstance(row, dict):
            continue
        require(row.get("false_positive_count") == 0, f"{row.get('calibration_id')} false_positive_count must be zero")
        require(row.get("false_negative_count") == 0, f"{row.get('calibration_id')} false_negative_count must be zero")
        require(row.get("failure_signature") == "none", f"{row.get('calibration_id')} should be a passing calibration row")

    risk_pareto = load_json(ROOT / artifacts.get("runtime_math_risk_pareto_contract", ""), "runtime_math_risk_pareto_contract")
    source_truth = risk_pareto.get("required_source_truth", {})
    if not isinstance(source_truth, dict):
        err("runtime math risk/pareto required_source_truth must be an object")
        source_truth = {}
    checker_truth = source_truth.get("source_checker", {})
    if not isinstance(checker_truth, dict):
        err("runtime math risk/pareto source_checker truth must be an object")
        checker_truth = {}
    check_ids = set(strings(checker_truth.get("required_check_ids"), "runtime_math_risk_pareto.required_check_ids"))
    required_check_ids = set(strings(required.get("required_risk_check_ids"), "formal_guarantees.required_risk_check_ids"))
    require(check_ids == required_check_ids == EXPECTED_SOURCE_CHECK_IDS, "risk/pareto source check ids drifted")
    coverage = risk_pareto.get("completion_coverage", [])
    if not isinstance(coverage, list):
        err("runtime math risk/pareto completion_coverage must be an array")
        coverage = []
    require(
        {section.get("missing_item_id") for section in coverage if isinstance(section, dict)} == EXPECTED_MISSING_ITEMS,
        "risk/pareto completion coverage must bind unit and e2e",
    )

    calibration = load_json(ROOT / artifacts.get("risk_pareto_calibration", ""), "risk_pareto_calibration")
    for mode in ["strict", "hardened"]:
        mode_row = calibration.get(mode, {})
        if not isinstance(mode_row, dict):
            err(f"risk_pareto_calibration missing mode {mode}")
            continue
        require(isinstance(mode_row.get("risk_summary"), dict), f"risk_pareto_calibration.{mode}.risk_summary missing")
        require(isinstance(mode_row.get("action_summary"), dict), f"risk_pareto_calibration.{mode}.action_summary missing")
    return {
        "monitors": sorted(monitors),
        "calibration_records": len(records),
        "risk_pareto_check_count": len(check_ids),
        "metrics": sorted(metrics),
    }


def validate_rollback_policy(required: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    policy = load_json(ROOT / artifacts.get("perf_attribution_policy", ""), "perf_attribution_policy")
    perf_contract = load_json(ROOT / artifacts.get("perf_regression_contract", ""), "perf_regression_contract")
    perf_gate = text_for(artifacts.get("perf_gate", ""), "perf_gate")
    scenario = text_for(artifacts.get("perf_e2e_scenario", ""), "perf_e2e_scenario")

    attribution = policy.get("attribution", {})
    if not isinstance(attribution, dict):
        err("perf attribution section must be an object")
        attribution = {}
    regression_classes = set(strings(attribution.get("regression_classes"), "perf_attribution.regression_classes"))
    for cls in strings(required.get("required_perf_regression_classes"), "rollback_policy.required_perf_regression_classes"):
        require(cls in regression_classes, f"perf attribution missing regression class {cls}")

    auto = policy.get("auto_throttle_policy", {})
    if not isinstance(auto, dict):
        err("perf auto_throttle_policy must be an object")
        auto = {}
    require(auto.get("action") == required.get("required_auto_throttle_action"), "auto-throttle action drifted")
    actions = set(strings(auto.get("actions"), "perf auto_throttle_policy.actions"))
    require(required.get("required_auto_throttle_action") in actions, "auto-throttle actions list missing skip action")
    report_fields = set(strings(auto.get("required_report_fields"), "perf auto_throttle_policy.required_report_fields"))
    for field in strings(required.get("required_report_fields"), "rollback_policy.required_report_fields"):
        require(field in report_fields, f"auto-throttle report field missing {field}")

    triage = policy.get("triage_guide", {})
    if not isinstance(triage, dict):
        err("perf triage_guide must be an object")
        triage = {}
    critical = triage.get("baseline_and_budget_violation", {})
    if not isinstance(critical, dict):
        err("baseline_and_budget_violation triage entry must be an object")
        critical = {}
    actions_text = "\n".join(strings(critical.get("actions"), "baseline_and_budget_violation.actions"))
    require(required.get("required_rollback_action_fragment") in actions_text, "critical triage must require rollback/hotfix action")

    require("should_skip_overloaded" in perf_gate, "perf_gate missing overload detection")
    require("emit_throttle_event" in perf_gate, "perf_gate missing throttle event")
    require(f"write_report \"{required.get('required_auto_throttle_status')}\"" in perf_gate, "perf_gate missing auto_throttled report")
    require("--scenario overloaded" in scenario and "auto_throttled" in scenario, "perf e2e scenario missing overloaded auto-throttle replay")

    perf_required = perf_contract.get("required_source_contract", {})
    if not isinstance(perf_required, dict):
        err("perf regression contract required_source_contract must be an object")
        perf_required = {}
    features = set(strings(perf_required.get("required_gate_features"), "perf_regression_contract.required_gate_features"))
    require("auto_throttle_replay" in features, "perf regression contract missing auto_throttle_replay feature")
    require("rch_wrapper" in features, "perf regression contract missing rch_wrapper feature")
    return {
        "regression_classes": sorted(regression_classes),
        "auto_throttle_action": auto.get("action"),
        "perf_gate_features": sorted(features),
    }


def validate_telemetry_contract(manifest: dict[str, Any], generated_events: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"required_events": 0, "required_fields": 0}
    require(telemetry.get("report_schema") == EXPECTED_REPORT_SCHEMA, "telemetry report_schema drifted")
    required_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
    require(required_events == EXPECTED_EVENTS, f"telemetry events must be {sorted(EXPECTED_EVENTS)}")
    emitted = {str(row.get("event")) for row in generated_events}
    for event_name in required_events:
        require(event_name in emitted, f"generated telemetry missing event {event_name}")
    required_fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    for row in generated_events:
        missing = required_fields - set(row)
        require(not missing, f"telemetry row {row.get('event')} missing fields {sorted(missing)}")
    structured = manifest.get("required_source_contract", {}).get("structured_logging", {})
    if isinstance(structured, dict):
        for field in strings(structured.get("required_fields"), "structured_logging.required_fields"):
            require(field in required_fields, f"structured_logging field missing from telemetry contract: {field}")
    return {"required_events": len(required_events), "required_fields": len(required_fields)}


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
audit = manifest.get("audit", {})
if not isinstance(audit, dict):
    err("audit must be an object")
    audit = {}
require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items mismatch")
require(int(audit.get("next_audit_score_threshold", 0)) >= 800, "audit.next_audit_score_threshold must be >= 800")
scorecard = audit.get("scorecard")
if isinstance(scorecard, str):
    repo_path(scorecard, "audit.scorecard", must_be_file=True)
else:
    err("audit.scorecard must be a repo-relative path")

artifacts = validate_source_artifacts(manifest)
impl_ref_count = validate_impl_refs(manifest)
test_ref_count = validate_test_sources(manifest)
coverage_summary = validate_completion_coverage(manifest)
required = manifest.get("required_source_contract", {})
if not isinstance(required, dict):
    err("required_source_contract must be an object")
    required = {}

overload_summary = validate_overload_campaign(
    required.get("overload_campaign", {}) if isinstance(required.get("overload_campaign"), dict) else {},
    artifacts,
)
formal_summary = validate_formal_guarantees(
    required.get("formal_guarantees", {}) if isinstance(required.get("formal_guarantees"), dict) else {},
    artifacts,
)
rollback_summary = validate_rollback_policy(
    required.get("rollback_policy", {}) if isinstance(required.get("rollback_policy"), dict) else {},
    artifacts,
)

status = "pass" if not errors else "fail"
artifact_refs = sorted(set(artifacts.values()))
append_event("overload_e2e_campaign_bound", status, artifact_refs, overload_summary)
append_event("overload_formal_guarantees_bound", status, artifact_refs, formal_summary)
append_event("overload_rollback_triggers_bound", status, artifact_refs, rollback_summary)
append_event(
    "overload_completion_contract_validated",
    status,
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {
        "source_commit": git_head(),
        "implementation_ref_count": impl_ref_count,
        "test_ref_count": test_ref_count,
        "coverage": coverage_summary,
        "error_count": len(errors),
    },
)
telemetry_summary = validate_telemetry_contract(manifest, events)
status = "pass" if not errors else "fail"
for row in events:
    row["status"] = status
    row["level"] = "info" if status == "pass" else "error"
    row["errno"] = 0 if status == "pass" else 1
    row["failure_signature"] = "none" if status == "pass" else "overload_e2e_completion_contract_failed"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": git_head(),
    "contract": rel(CONTRACT),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "summary": {
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
        "source_artifact_count": len(artifacts),
        "implementation_ref_count": impl_ref_count,
        "test_ref_count": test_ref_count,
        "event_count": len(events),
        "error_count": len(errors),
    },
    "overload_summary": overload_summary,
    "formal_summary": formal_summary,
    "rollback_summary": rollback_summary,
    "coverage_summary": coverage_summary,
    "telemetry_summary": telemetry_summary,
    "events": [row["event"] for row in events],
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL: overload E2E/formal-guarantees/rollback completion contract failed")
    for message in errors:
        print(f"  - {message}")
    print(f"Report: {REPORT}")
    print(f"Log: {LOG}")
    raise SystemExit(1)

print(
    "PASS: overload E2E/formal-guarantees/rollback completion contract "
    f"validated {len(artifacts)} artifacts, {impl_ref_count} refs, {test_ref_count} test refs"
)
print(f"Report: {REPORT}")
print(f"Log: {LOG}")
PY
