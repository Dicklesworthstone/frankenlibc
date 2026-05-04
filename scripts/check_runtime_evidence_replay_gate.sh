#!/usr/bin/env bash
# check_runtime_evidence_replay_gate.sh -- bd-bp8fl.9.4
#
# Static fail-closed validator for runtime evidence replay records and ring
# buffer snapshots. It emits deterministic JSON and JSONL artifacts under
# target/conformance and does not invoke cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_GATE:-${ROOT}/tests/conformance/runtime_evidence_replay_gate.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_REPORT:-${OUT_DIR}/runtime_evidence_replay_gate.report.json}"
LOG="${FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_LOG:-${OUT_DIR}/runtime_evidence_replay_gate.log.jsonl}"

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

TRACE_ID = "bd-bp8fl.9.4:runtime-evidence-replay"
BEAD_ID = "bd-bp8fl.9.4"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "replay_id",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "stdio_evidence_module",
    "runtime_symbol_evidence_module",
    "fpg_runtime_monitor_gate",
    "fpg_evidence_foundation_gate",
    "log_schema",
]
DECISION_TERMINALS = {
    "Allow": "allow",
    "FullValidate": "full_validate",
    "Repair": "repair",
    "Deny": "deny",
}

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "claim_policy": "fail",
    "replay_contract": "fail",
    "decision_coverage": "fail",
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


def event_sequence_numbers(event_ids):
    seqnos = []
    for event_id in event_ids:
        parts = str(event_id).split("-")
        seq = next((part for part in parts if part.isdigit()), None)
        if seq is None:
            raise ValueError(f"event id has no numeric sequence: {event_id}")
        seqnos.append(int(seq))
    return seqnos


def normalized_path_terminal(record):
    path = record.get("decision_path", [])
    if not path:
        return ""
    return str(path[-1]).replace("-", "_").lower()


def validate_replay_record(record, policy):
    replay_id = record.get("replay_id", "<missing>")
    required_fields = policy.get("required_replay_fields", [])
    for field in required_fields:
        if field not in record:
            fail(f"{replay_id}: missing replay field {field}")
    for field in ["api_family", "decision_path", "healing_action", "evidence_snapshot"]:
        if field not in record:
            fail(f"{replay_id}: missing replay field {field}")

    expected = record.get("expected_decision")
    actual = record.get("actual_decision")
    if expected not in policy.get("required_decisions", []):
        fail(f"{replay_id}: expected_decision {expected!r} is not allowed")
    if actual != expected:
        fail(f"{replay_id}: runtime_replay_decision_mismatch")
    if record.get("runtime_mode") not in policy.get("required_modes", []):
        fail(f"{replay_id}: runtime_mode is not covered")

    terminal = DECISION_TERMINALS.get(str(expected))
    if terminal is None or normalized_path_terminal(record) != terminal:
        fail(f"{replay_id}: decision_path terminal does not match {expected}")
    if expected == "Repair" and record.get("healing_action") in (None, "", "None"):
        fail(f"{replay_id}: Repair replay must carry a healing_action")

    snapshot = record.get("evidence_snapshot", {})
    event_ids = snapshot.get("event_ids", []) if isinstance(snapshot, dict) else []
    if not event_ids:
        fail(f"{replay_id}: runtime_replay_missing_event")
    else:
        try:
            seqnos = event_sequence_numbers(event_ids)
            if seqnos != sorted(seqnos):
                fail(f"{replay_id}: runtime_replay_out_of_order")
        except Exception as exc:
            fail(f"{replay_id}: runtime_replay_out_of_order: {exc}")
    if isinstance(snapshot, dict):
        start = snapshot.get("ring_sequence_start")
        end = snapshot.get("ring_sequence_end")
        if not isinstance(start, int) or not isinstance(end, int) or start > end:
            fail(f"{replay_id}: runtime_replay_out_of_order")
        if len(event_ids) != end - start + 1:
            fail(f"{replay_id}: runtime_replay_missing_event")
        if snapshot.get("snapshot_age_state") != "current" or record.get("source_commit_state") != "current":
            fail(f"{replay_id}: runtime_replay_stale_snapshot")
        if snapshot.get("redaction_state") != "none":
            fail(f"{replay_id}: runtime_replay_redacted_required_field")

    missing_refs = []
    for rel in record.get("artifact_refs", []):
        try:
            if not safe_path(rel).exists():
                missing_refs.append(str(rel))
        except Exception as exc:
            missing_refs.append(f"{rel}:{exc}")
    if missing_refs:
        fail(f"{replay_id}: artifact_refs missing: {', '.join(missing_refs)}")

    log_row = {
        "trace_id": TRACE_ID,
        "bead_id": BEAD_ID,
        "replay_id": replay_id,
        "symbol": record.get("symbol"),
        "runtime_mode": record.get("runtime_mode"),
        "replacement_level": record.get("replacement_level"),
        "expected_decision": expected,
        "actual_decision": actual,
        "artifact_refs": record.get("artifact_refs", []),
        "source_commit": record.get("source_commit_state"),
        "failure_signature": record.get("failure_signature"),
    }
    logs.append(log_row)


def validate_negative_cases(gate, policy):
    cases = gate.get("negative_replay_cases", [])
    records = {
        record.get("replay_id"): record
        for record in gate.get("replay_records", [])
        if isinstance(record, dict)
    }
    required_mutations = set(policy.get("required_negative_cases", []))
    signatures = set(policy.get("fail_closed_signatures", []))
    seen_mutations = set()

    for case in cases if isinstance(cases, list) else []:
        mutation = case.get("mutation")
        signature = case.get("expected_failure_signature")
        seen_mutations.add(mutation)
        target = case.get("target_replay_id")
        if target not in records:
            fail(f"{case.get('case_id', '<missing>')}: target replay is missing")
        if mutation not in required_mutations:
            fail(f"{case.get('case_id', '<missing>')}: mutation is not required")
        if signature not in signatures:
            fail(f"{case.get('case_id', '<missing>')}: failure signature is not fail-closed")
        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": BEAD_ID,
                "replay_id": target,
                "symbol": records.get(target, {}).get("symbol"),
                "runtime_mode": records.get(target, {}).get("runtime_mode"),
                "replacement_level": records.get(target, {}).get("replacement_level"),
                "expected_decision": "BlockReplay",
                "actual_decision": "BlockReplay",
                "artifact_refs": records.get(target, {}).get("artifact_refs", []),
                "source_commit": records.get(target, {}).get("source_commit_state"),
                "failure_signature": signature,
            }
        )

    missing = sorted(required_mutations - seen_mutations)
    if missing:
        fail("negative cases missing mutations: " + ", ".join(missing))


gate = load_json(gate_path)
if gate is not None:
    checks["json_parse"] = "pass"

if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "runtime-evidence-replay-gate":
        fail("gate manifest_id must be runtime-evidence-replay-gate")
    if gate.get("bead") != BEAD_ID:
        fail(f"gate bead must be {BEAD_ID}")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match bd-bp8fl.9.4")
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
    for decision in DECISION_TERMINALS:
        if decision not in policy.get("required_decisions", []):
            fail(f"claim_policy.required_decisions missing {decision}")
            policy_ok = False
    for mode in ["strict", "hardened"]:
        if mode not in policy.get("required_modes", []):
            fail(f"claim_policy.required_modes missing {mode}")
            policy_ok = False
    for field in policy.get("required_replay_fields", []):
        if not isinstance(field, str):
            fail("claim_policy.required_replay_fields must contain strings")
            policy_ok = False
    for signature in [
        "runtime_replay_missing_event",
        "runtime_replay_stale_snapshot",
        "runtime_replay_out_of_order",
        "runtime_replay_redacted_required_field",
        "runtime_replay_decision_mismatch",
    ]:
        if signature not in policy.get("fail_closed_signatures", []):
            fail(f"claim_policy.fail_closed_signatures missing {signature}")
            policy_ok = False
    if policy_ok:
        checks["claim_policy"] = "pass"

    replay_errors_before = len(errors)
    records = gate.get("replay_records", [])
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            fail("replay_records must contain only objects")
            continue
        validate_replay_record(record, policy)
    if len(errors) == replay_errors_before and isinstance(records, list) and records:
        checks["replay_contract"] = "pass"

    decisions = {record.get("expected_decision") for record in records if isinstance(record, dict)}
    modes = {record.get("runtime_mode") for record in records if isinstance(record, dict)}
    if set(policy.get("required_decisions", [])) <= decisions and set(policy.get("required_modes", [])) <= modes:
        checks["decision_coverage"] = "pass"
    else:
        fail("replay records do not cover all required decisions and modes")

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
        "replay_record_count": len(gate.get("replay_records", [])) if isinstance(gate, dict) else 0,
        "negative_case_count": len(gate.get("negative_replay_cases", [])) if isinstance(gate, dict) else 0,
        "structured_log_rows": len(logs),
        "required_log_fields": len(REQUIRED_LOG_FIELDS),
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
print(f"runtime evidence replay gate passed: {report_path}")
PY
