#!/usr/bin/env bash
# check_fpg_runtime_monitor_evidence_gate.sh -- bd-bp8fl.3.14
#
# Static fail-closed validator for fpg-gap-summary-runtime-monitor-evidence rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_FPG_RUNTIME_MONITOR_GATE:-${ROOT}/tests/conformance/fpg_runtime_monitor_evidence_gate.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
PARITY="${FRANKENLIBC_FEATURE_PARITY:-${ROOT}/FEATURE_PARITY.md}"
GROUPS_PATH="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_FPG_RUNTIME_MONITOR_REPORT:-${OUT_DIR}/fpg_runtime_monitor_evidence_gate.report.json}"
LOG="${FRANKENLIBC_FPG_RUNTIME_MONITOR_LOG:-${OUT_DIR}/fpg_runtime_monitor_evidence_gate.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${GATE}" "${LEDGER}" "${PARITY}" "${GROUPS_PATH}" "${OWNER_GROUPS}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
parity_path = Path(sys.argv[4])
groups_path = Path(sys.argv[5])
owner_groups_path = Path(sys.argv[6])
report_path = Path(sys.argv[7])
log_path = Path(sys.argv[8])

TRACE_ID = "bd-bp8fl.3.14:fpg-runtime-monitor-evidence"
EXPECTED_GAP_IDS = [
    "fp-gap-summary-db582a1956fa",
    "fp-gap-summary-84240b59cfd1",
    "fp-gap-summary-70370851cacb",
    "fp-gap-summary-205f8c297218",
    "fp-gap-summary-a1d7fcc3399f",
    "fp-gap-summary-10132dfe6278",
    "fp-gap-summary-b95fff14be76",
    "fp-gap-summary-09fac08213b2",
    "fp-gap-summary-26353b43713e",
    "fp-gap-summary-5dd50f7bfbf2",
    "fp-gap-summary-e9257a2a9c49",
    "fp-gap-summary-ca75128647d2",
    "fp-gap-summary-a3aed10a522c",
    "fp-gap-summary-03bcda968d0e",
    "fp-gap-summary-3c88823923b9",
    "fp-gap-summary-994260bdf05c",
    "fp-gap-summary-42c1bf789b12",
    "fp-gap-summary-e1b445fd58b5",
    "fp-gap-summary-b7a23cbbae29",
    "fp-gap-summary-99daf17ed425",
    "fp-gap-summary-b679d62602b3",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "monitor_id",
    "runtime_mode",
    "expected_decision",
    "actual_decision",
    "calibration_state",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "feature_parity",
    "feature_parity_gap_ledger",
    "feature_parity_gap_groups",
    "feature_parity_gap_owner_family_groups",
    "runtime_env_inventory",
    "optimization_proof_ledger",
    "perf_regression_attribution",
    "proof_traceability_check",
]

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "owner_group_binding": "fail",
    "group_gap_binding": "fail",
    "row_contract": "fail",
    "ledger_binding": "fail",
    "feature_parity_binding": "fail",
    "monitor_inventory": "fail",
    "replay_calibration": "fail",
    "evidence_anchors": "fail",
    "claim_policy": "fail",
    "structured_log": "fail",
}


def fail(message):
    errors.append(message)


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label}: cannot parse {path}: {exc}")
        return None


def read_text(path, label):
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        fail(f"{label}: cannot read {path}: {exc}")
        return ""


def safe_path(rel):
    rel_text = str(rel).rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"unsafe artifact path: {rel_text}")
    return root / rel_path


def resolve_field(value, field):
    current = value
    if not field:
        return current
    for part in str(field).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(field)
    return current


gate = load_json(gate_path, "gate")
ledger = load_json(ledger_path, "ledger")
groups = load_json(groups_path, "feature_parity_gap_groups")
parity_lines = read_text(parity_path, "feature_parity").splitlines()
owner_groups_text = read_text(owner_groups_path, "owner_family_groups")

if gate is not None and ledger is not None and groups is not None and parity_lines and owner_groups_text:
    checks["json_parse"] = "pass"

json_cache = {}


def anchor_json(path):
    if path not in json_cache:
        json_cache[path] = load_json(path, f"anchor {path}")
    return json_cache[path]


def check_anchor(anchor):
    rel = str(anchor.get("artifact", "")).rstrip("/")
    kind = anchor.get("kind")
    path = safe_path(rel)
    if kind == "path_exists":
        if not path.exists():
            raise AssertionError("path_missing")
    elif kind == "json_field_equals":
        actual = resolve_field(anchor_json(path), anchor.get("field"))
        if actual != anchor.get("expected_value"):
            raise AssertionError("json_field_mismatch")
    elif kind == "json_field_min":
        actual = resolve_field(anchor_json(path), anchor.get("field"))
        if not isinstance(actual, (int, float)) or actual < anchor.get("expected_value_min"):
            raise AssertionError("json_field_below_min")
    else:
        raise AssertionError(f"unknown_anchor_kind:{kind}")


if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "fpg-runtime-monitor-evidence-gate":
        fail("gate manifest_id must be fpg-runtime-monitor-evidence-gate")
    if gate.get("bead") != "bd-bp8fl.3.14":
        fail("gate bead must be bd-bp8fl.3.14")
    if gate.get("owner_family_group") != "fpg-gap-summary-runtime-monitor-evidence":
        fail("gate owner_family_group must be fpg-gap-summary-runtime-monitor-evidence")
    if gate.get("evidence_owner") != "runtime_math monitor owners":
        fail("gate evidence_owner mismatch")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match the bd-bp8fl.3.14 contract")
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
        if rel:
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
    if policy.get("default_decision") != "block_done_until_runtime_monitor_replay_and_calibration_current":
        fail("claim_policy.default_decision must block until replay/calibration evidence is current")
        policy_ok = False
    if policy.get("allow_status") != ["IN_PROGRESS"]:
        fail("claim_policy.allow_status must be exactly IN_PROGRESS")
        policy_ok = False
    if "DONE" not in policy.get("block_status_without_all_anchors", []):
        fail("claim_policy must block DONE without all anchors")
        policy_ok = False
    for level in ("L1", "L2", "L3"):
        if level not in policy.get("block_replacement_levels_without_evidence", []):
            fail(f"claim_policy must block replacement level {level}")
            policy_ok = False
    for mode in ("strict", "hardened"):
        if mode not in policy.get("required_runtime_modes", []):
            fail(f"claim_policy.required_runtime_modes missing {mode}")
            policy_ok = False

    if "fpg-gap-summary-runtime-monitor-evidence" in owner_groups_text and "`bd-bp8fl.3.14`" in owner_groups_text:
        checks["owner_group_binding"] = "pass"
    else:
        fail("owner-family groups markdown must bind fpg-gap-summary-runtime-monitor-evidence to bd-bp8fl.3.14")

    group_batches = groups.get("batches", []) if isinstance(groups, dict) else []
    batch = next((item for item in group_batches if item.get("batch_id") == "fpg-gap-summary-runtime-monitor-evidence"), None)
    if batch is None:
        fail("feature_parity_gap_groups missing fpg-gap-summary-runtime-monitor-evidence batch")
    elif batch.get("gap_ids") != EXPECTED_GAP_IDS or batch.get("gap_count") != len(EXPECTED_GAP_IDS):
        fail("feature_parity_gap_groups runtime-monitor batch must carry the 21 expected gap IDs")
    else:
        checks["group_gap_binding"] = "pass"

    rows = gate.get("rows", [])
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    if row_ids != EXPECTED_GAP_IDS:
        fail(f"gate row IDs must match runtime-monitor gap IDs in order: {row_ids!r}")
    row_contract_ok = row_ids == EXPECTED_GAP_IDS
    monitor_ok = True
    replay_ok = True
    anchors_ok = True
    ledger_ok = True
    parity_ok = True
    claim_ok = policy_ok
    ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
    ledger_by_id = {gap.get("gap_id"): gap for gap in ledger_gaps if isinstance(gap, dict)}
    allowed_calibration_states = set(policy.get("required_calibration_states", []))

    for row in rows if isinstance(rows, list) else []:
        row_errors = []
        if not isinstance(row, dict):
            fail("gate rows must contain only objects")
            row_contract_ok = False
            continue
        for field in [
            "gap_id",
            "kind",
            "section",
            "primary_key",
            "monitor_id",
            "monitor_paths",
            "feature_parity_provenance",
            "claimed_status",
            "replacement_level",
            "runtime_modes",
            "expected_decision",
            "replay_artifact",
            "calibration_artifact",
            "failure_signature",
            "evidence_anchors",
        ]:
            if field not in row:
                message = f"{row.get('gap_id', '<missing>')}: missing row field {field}"
                fail(message)
                row_errors.append(message)
                row_contract_ok = False
        gid = row.get("gap_id")
        if row.get("runtime_modes") != ["strict", "hardened"]:
            message = f"{gid}: runtime_modes must be strict+hardened"
            fail(message)
            row_errors.append(message)
            row_contract_ok = False
        if row.get("claimed_status") != "IN_PROGRESS":
            message = f"{gid}: claimed_status must remain IN_PROGRESS"
            fail(message)
            row_errors.append(message)
            claim_ok = False
        if row.get("claimed_status") in policy.get("block_status_without_all_anchors", []):
            message = f"{gid}: claimed_status {row.get('claimed_status')} is blocked"
            fail(message)
            row_errors.append(message)
            claim_ok = False
        if row.get("replacement_level") in policy.get("block_replacement_levels_without_evidence", []):
            message = f"{gid}: replacement_level {row.get('replacement_level')} is blocked"
            fail(message)
            row_errors.append(message)
            claim_ok = False

        monitor_paths = row.get("monitor_paths", [])
        if not isinstance(monitor_paths, list) or not monitor_paths:
            message = f"{gid}: monitor_paths must be a non-empty array"
            fail(message)
            row_errors.append(message)
            monitor_ok = False
        else:
            for rel in monitor_paths:
                try:
                    if not safe_path(rel).exists():
                        raise AssertionError("path_missing")
                except Exception as exc:
                    message = f"{gid}: monitor path {rel!r} failed: {exc}"
                    fail(message)
                    row_errors.append(message)
                    monitor_ok = False

        replay = row.get("replay_artifact", {})
        calibration = row.get("calibration_artifact", {})
        if not isinstance(replay, dict) or not isinstance(calibration, dict):
            message = f"{gid}: replay_artifact and calibration_artifact must be objects"
            fail(message)
            row_errors.append(message)
            replay_ok = False
        else:
            for field in policy.get("required_replay_fields", []):
                if not replay.get(field):
                    message = f"{gid}: replay_artifact.{field} must be non-empty"
                    fail(message)
                    row_errors.append(message)
                    replay_ok = False
            if replay.get("source_commit") != gate.get("source_commit"):
                message = f"{gid}: replay_artifact.source_commit is stale"
                fail(message)
                row_errors.append(message)
                replay_ok = False
            if calibration.get("state") not in allowed_calibration_states:
                message = f"{gid}: calibration_artifact.state is not allowed"
                fail(message)
                row_errors.append(message)
                replay_ok = False
            for field in ("path", "threshold"):
                if not calibration.get(field):
                    message = f"{gid}: calibration_artifact.{field} must be non-empty"
                    fail(message)
                    row_errors.append(message)
                    replay_ok = False
        if not row.get("failure_signature"):
            message = f"{gid}: failure_signature must be non-empty"
            fail(message)
            row_errors.append(message)
            replay_ok = False

        ledger_gap = ledger_by_id.get(gid)
        if ledger_gap is None:
            message = f"{gid}: missing from feature_parity_gap_ledger"
            fail(message)
            row_errors.append(message)
            ledger_ok = False
        else:
            for field in ("kind", "section", "primary_key", "status"):
                expected = row.get("claimed_status") if field == "status" else row.get(field)
                actual = ledger_gap.get(field)
                if actual != expected:
                    message = f"{gid}: ledger {field} mismatch: expected {expected!r}, actual {actual!r}"
                    fail(message)
                    row_errors.append(message)
                    ledger_ok = False

        provenance = row.get("feature_parity_provenance", {})
        line = provenance.get("line")
        contains = provenance.get("line_contains")
        if not isinstance(line, int) or line < 1 or line > len(parity_lines):
            message = f"{gid}: feature parity line is out of range: {line!r}"
            fail(message)
            row_errors.append(message)
            parity_ok = False
        elif contains not in parity_lines[line - 1]:
            message = f"{gid}: FEATURE_PARITY.md:{line} missing expected key"
            fail(message)
            row_errors.append(message)
            parity_ok = False

        artifact_refs = []
        for anchor in row.get("evidence_anchors", []):
            rel = str(anchor.get("artifact", "")).rstrip("/")
            artifact_refs.append(rel)
            try:
                check_anchor(anchor)
            except Exception as exc:
                message = f"{gid}: anchor failed for {rel} ({anchor.get('kind')}): {exc}"
                fail(message)
                row_errors.append(message)
                anchors_ok = False
        if replay:
            artifact_refs.append(replay.get("path", ""))
        if calibration:
            artifact_refs.append(calibration.get("path", ""))

        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": "bd-bp8fl.3.14",
                "gap_id": gid,
                "monitor_id": row.get("monitor_id"),
                "runtime_mode": "+".join(row.get("runtime_modes", [])),
                "expected_decision": row.get("expected_decision"),
                "actual_decision": row.get("expected_decision") if not row_errors else "claim_blocked",
                "calibration_state": calibration.get("state") if isinstance(calibration, dict) else None,
                "artifact_refs": [ref for ref in artifact_refs if ref],
                "source_commit": gate.get("source_commit"),
                "failure_signature": "; ".join(row_errors),
            }
        )

    if row_contract_ok:
        checks["row_contract"] = "pass"
    if monitor_ok:
        checks["monitor_inventory"] = "pass"
    if replay_ok:
        checks["replay_calibration"] = "pass"
    if anchors_ok:
        checks["evidence_anchors"] = "pass"
    if ledger_ok:
        checks["ledger_binding"] = "pass"
    if parity_ok:
        checks["feature_parity_binding"] = "pass"
    if claim_ok:
        checks["claim_policy"] = "pass"

missing_log_fields = []
for entry in logs:
    for field in REQUIRED_LOG_FIELDS:
        if field not in entry:
            missing_log_fields.append(field)
if logs and not missing_log_fields:
    checks["structured_log"] = "pass"
elif missing_log_fields:
    fail("structured log entries missing fields: " + ", ".join(sorted(set(missing_log_fields))))

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.3.14",
    "manifest_id": "fpg-runtime-monitor-evidence-gate",
    "status": status,
    "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "checks": checks,
    "summary": {
        "row_count": len(gate.get("rows", [])) if isinstance(gate, dict) else 0,
        "expected_gap_count": len(EXPECTED_GAP_IDS),
        "log_entry_count": len(logs),
        "error_count": len(errors),
    },
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for entry in logs:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
