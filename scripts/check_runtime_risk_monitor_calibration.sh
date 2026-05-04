#!/usr/bin/env bash
# check_runtime_risk_monitor_calibration.sh -- bd-bp8fl.9.5
#
# Static fail-closed validator for runtime risk monitor calibration records.
# It emits deterministic JSON and JSONL artifacts under target/conformance and
# does not invoke cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION:-${ROOT}/tests/conformance/runtime_risk_monitor_calibration.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION_REPORT:-${OUT_DIR}/runtime_risk_monitor_calibration.report.json}"
LOG="${FRANKENLIBC_RUNTIME_RISK_MONITOR_CALIBRATION_LOG:-${OUT_DIR}/runtime_risk_monitor_calibration.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${GATE}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

TRACE_ID = "bd-bp8fl.9.5:runtime-risk-monitor-calibration"
BEAD_ID = "bd-bp8fl.9.5"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "monitor_id",
    "fixture_set",
    "threshold",
    "expected_alarm",
    "actual_alarm",
    "risk_value",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "eprocess_module",
    "changepoint_module",
    "cvar_module",
    "conformal_module",
    "risk_module",
    "runtime_evidence_replay_gate",
    "changepoint_policy",
]
FAIL_SIGNATURES = {
    "stale_fixture_outcomes": "runtime_calibration_stale_fixture_outcomes",
    "threshold_edge_case_mismatch": "runtime_calibration_threshold_edge_case_mismatch",
    "disabled_monitor": "runtime_calibration_disabled_monitor",
    "false_positive_budget_exceeded": "runtime_calibration_false_positive_budget_exceeded",
    "false_negative_budget_exceeded": "runtime_calibration_false_negative_budget_exceeded",
}

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "claim_policy": "fail",
    "calibration_contract": "fail",
    "monitor_coverage": "fail",
    "fixture_coverage": "fail",
    "negative_case_coverage": "fail",
    "structured_log": "fail",
}


def fail(message):
    errors.append(message)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"json_parse: cannot parse {path}: {exc}")
        return None


def safe_path(rel):
    rel_text = str(rel).rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"unsafe artifact path: {rel_text}")
    return root / rel_path


def threshold_alarm(threshold, risk_value):
    comparator = threshold.get("comparator")
    value = threshold.get("value")
    if comparator == ">=":
        return risk_value >= value
    if comparator == ">":
        return risk_value > value
    if comparator == "<=":
        return risk_value <= value
    if comparator == "<":
        return risk_value < value
    raise ValueError(f"unsupported comparator {comparator!r}")


def validate_calibration_record(record, policy):
    calibration_id = record.get("calibration_id", "<missing>")
    for field in [
        "calibration_id",
        "monitor_id",
        "monitor_type",
        "fixture_set",
        "api_family",
        "runtime_mode",
        "threshold",
        "risk_value",
        "expected_alarm",
        "actual_alarm",
        "false_positive_count",
        "false_negative_count",
        "sample_count",
        "fixture_outcome_state",
        "monitor_state",
        "artifact_refs",
        "source_commit_state",
        "failure_signature",
    ]:
        if field not in record:
            fail(f"{calibration_id}: missing calibration field {field}")

    if record.get("monitor_id") not in policy.get("required_monitors", []):
        fail(f"{calibration_id}: monitor_id is not in claim_policy.required_monitors")
    if record.get("runtime_mode") not in policy.get("required_modes", []):
        fail(f"{calibration_id}: runtime_mode is not covered")
    if record.get("fixture_set") not in policy.get("required_fixture_sets", []):
        fail(f"{calibration_id}: fixture_set is not covered")
    if record.get("fixture_outcome_state") != "current" or record.get("source_commit_state") != "current":
        fail(f"{calibration_id}: runtime_calibration_stale_fixture_outcomes")
    if record.get("monitor_state") != "enabled":
        fail(f"{calibration_id}: runtime_calibration_disabled_monitor")

    threshold = record.get("threshold", {})
    risk_value = record.get("risk_value")
    if not isinstance(threshold, dict):
        fail(f"{calibration_id}: threshold must be an object")
        threshold = {}
    if not isinstance(risk_value, (int, float)):
        fail(f"{calibration_id}: risk_value must be numeric")
        risk_value = 0.0
    try:
        predicted_alarm = threshold_alarm(threshold, risk_value)
        if predicted_alarm != record.get("expected_alarm") or record.get("actual_alarm") != record.get("expected_alarm"):
            fail(f"{calibration_id}: runtime_calibration_threshold_edge_case_mismatch")
    except Exception as exc:
        fail(f"{calibration_id}: runtime_calibration_threshold_edge_case_mismatch: {exc}")

    allowed_fp = int(policy.get("allowed_false_positive_count", 0))
    allowed_fn = int(policy.get("allowed_false_negative_count", 0))
    if int(record.get("false_positive_count", 0)) > allowed_fp:
        fail(f"{calibration_id}: runtime_calibration_false_positive_budget_exceeded")
    if int(record.get("false_negative_count", 0)) > allowed_fn:
        fail(f"{calibration_id}: runtime_calibration_false_negative_budget_exceeded")

    missing_refs = []
    for rel in record.get("artifact_refs", []):
        try:
            if not safe_path(rel).exists():
                missing_refs.append(str(rel))
        except Exception as exc:
            missing_refs.append(f"{rel}:{exc}")
    if missing_refs:
        fail(f"{calibration_id}: artifact_refs missing: {', '.join(missing_refs)}")

    logs.append(
        {
            "trace_id": TRACE_ID,
            "bead_id": BEAD_ID,
            "monitor_id": record.get("monitor_id"),
            "fixture_set": record.get("fixture_set"),
            "threshold": record.get("threshold"),
            "expected_alarm": record.get("expected_alarm"),
            "actual_alarm": record.get("actual_alarm"),
            "risk_value": record.get("risk_value"),
            "artifact_refs": record.get("artifact_refs", []),
            "source_commit": record.get("source_commit_state"),
            "failure_signature": record.get("failure_signature"),
        }
    )


def validate_negative_cases(gate, policy):
    records = {
        record.get("calibration_id"): record
        for record in gate.get("calibration_records", [])
        if isinstance(record, dict)
    }
    required = set(policy.get("required_negative_cases", []))
    signatures = set(policy.get("fail_closed_signatures", []))
    seen = set()
    cases = gate.get("negative_calibration_cases", [])
    if not isinstance(cases, list):
        fail("negative_calibration_cases must be an array")
        return
    for case in cases:
        if not isinstance(case, dict):
            fail("negative_calibration_cases entries must be objects")
            continue
        mutation = case.get("mutation")
        signature = case.get("expected_failure_signature")
        target = case.get("target_calibration_id")
        seen.add(mutation)
        if mutation not in required:
            fail(f"{case.get('case_id', '<missing>')}: mutation is not required")
        if signature not in signatures:
            fail(f"{case.get('case_id', '<missing>')}: signature is not fail-closed")
        if target not in records:
            fail(f"{case.get('case_id', '<missing>')}: target calibration record is missing")
        expected_signature = FAIL_SIGNATURES.get(mutation)
        if expected_signature and signature != expected_signature:
            fail(f"{case.get('case_id', '<missing>')}: signature does not match mutation")
        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": BEAD_ID,
                "monitor_id": records.get(target, {}).get("monitor_id"),
                "fixture_set": records.get(target, {}).get("fixture_set"),
                "threshold": records.get(target, {}).get("threshold"),
                "expected_alarm": "BlockCalibration",
                "actual_alarm": "BlockCalibration",
                "risk_value": records.get(target, {}).get("risk_value"),
                "artifact_refs": records.get(target, {}).get("artifact_refs", []),
                "source_commit": records.get(target, {}).get("source_commit_state"),
                "failure_signature": signature,
            }
        )
    missing = sorted(required - seen)
    if missing:
        fail("negative cases missing mutations: " + ", ".join(missing))


gate = load_json(gate_path)
if gate is not None:
    checks["json_parse"] = "pass"

if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "runtime-risk-monitor-calibration-gate":
        fail("gate manifest_id must be runtime-risk-monitor-calibration-gate")
    if gate.get("bead") != BEAD_ID:
        fail(f"gate bead must be {BEAD_ID}")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match bd-bp8fl.9.5")
    try:
        datetime.fromisoformat(str(gate.get("generated_utc")).replace("Z", "+00:00"))
    except Exception:
        fail("gate generated_utc must be a valid ISO timestamp")
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    inputs = gate.get("inputs", {})
    missing_inputs = [key for key in INPUT_KEYS if not inputs.get(key)]
    missing_paths = []
    for key in INPUT_KEYS:
        rel = inputs.get(key)
        if not rel:
            continue
        try:
            if not safe_path(rel).exists():
                missing_paths.append(f"{key}:{rel}")
        except Exception as exc:
            missing_paths.append(f"{key}:{rel}:{exc}")
    if missing_inputs:
        fail("gate inputs missing keys: " + ", ".join(missing_inputs))
    if missing_paths:
        fail("gate input paths missing: " + ", ".join(missing_paths))
    if not missing_inputs and not missing_paths:
        checks["input_artifacts_exist"] = "pass"

    policy = gate.get("claim_policy", {})
    policy_ok = True
    for monitor in ["eprocess", "changepoint", "cvar", "conformal", "risk"]:
        if monitor not in policy.get("required_monitors", []):
            fail(f"claim_policy.required_monitors missing {monitor}")
            policy_ok = False
    for mode in ["strict", "hardened"]:
        if mode not in policy.get("required_modes", []):
            fail(f"claim_policy.required_modes missing {mode}")
            policy_ok = False
    for mutation, signature in FAIL_SIGNATURES.items():
        if mutation not in policy.get("required_negative_cases", []):
            fail(f"claim_policy.required_negative_cases missing {mutation}")
            policy_ok = False
        if signature not in policy.get("fail_closed_signatures", []):
            fail(f"claim_policy.fail_closed_signatures missing {signature}")
            policy_ok = False
    if policy_ok:
        checks["claim_policy"] = "pass"

    records = gate.get("calibration_records", [])
    record_errors_before = len(errors)
    if not isinstance(records, list):
        fail("calibration_records must be an array")
        records = []
    for record in records:
        if not isinstance(record, dict):
            fail("calibration_records entries must be objects")
            continue
        validate_calibration_record(record, policy)
    if len(errors) == record_errors_before and records:
        checks["calibration_contract"] = "pass"

    monitors = {record.get("monitor_id") for record in records if isinstance(record, dict)}
    modes = {record.get("runtime_mode") for record in records if isinstance(record, dict)}
    if set(policy.get("required_monitors", [])) <= monitors and set(policy.get("required_modes", [])) <= modes:
        checks["monitor_coverage"] = "pass"
    else:
        fail("calibration records do not cover all required monitors and modes")

    fixture_sets = {record.get("fixture_set") for record in records if isinstance(record, dict)}
    if set(policy.get("required_fixture_sets", [])) <= fixture_sets:
        checks["fixture_coverage"] = "pass"
    else:
        fail("calibration records do not cover all required fixture sets")

    negative_errors_before = len(errors)
    validate_negative_cases(gate, policy)
    if len(errors) == negative_errors_before:
        checks["negative_case_coverage"] = "pass"

    log_errors_before = len(errors)
    for row in logs:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
        if missing:
            fail("structured log row missing fields: " + ", ".join(missing))
    if len(errors) == log_errors_before and logs:
        checks["structured_log"] = "pass"

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "schema_version": "v1",
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "status": status,
    "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "checks": checks,
    "summary": {
        "calibration_record_count": len(gate.get("calibration_records", [])) if isinstance(gate, dict) else 0,
        "negative_case_count": len(gate.get("negative_calibration_cases", [])) if isinstance(gate, dict) else 0,
        "structured_log_rows": len(logs),
        "required_log_fields": len(REQUIRED_LOG_FIELDS),
        "monitors": sorted({row.get("monitor_id") for row in logs if row.get("monitor_id")}),
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
if status != "pass":
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
print(f"runtime risk monitor calibration gate passed: {report_path}")
PY
