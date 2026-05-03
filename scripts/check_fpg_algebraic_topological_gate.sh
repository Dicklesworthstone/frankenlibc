#!/usr/bin/env bash
# check_fpg_algebraic_topological_gate.sh -- bd-bp8fl.3.11
#
# Static fail-closed validator for fpg-proof-algebraic-topological proof rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_FPG_ALGEBRAIC_TOPOLOGICAL_GATE:-${ROOT}/tests/conformance/fpg_algebraic_topological_gate.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
PARITY="${FRANKENLIBC_FEATURE_PARITY:-${ROOT}/FEATURE_PARITY.md}"
GROUPS_PATH="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_FPG_ALGEBRAIC_TOPOLOGICAL_REPORT:-${OUT_DIR}/fpg_algebraic_topological_gate.report.json}"
LOG="${FRANKENLIBC_FPG_ALGEBRAIC_TOPOLOGICAL_LOG:-${OUT_DIR}/fpg_algebraic_topological_gate.log.jsonl}"

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

TRACE_ID = "bd-bp8fl.3.11:fpg-algebraic-topological"
EXPECTED_GAP_IDS = [
    "fp-proof-math-9c25ab032255",
    "fp-proof-math-5fa634c732ac",
    "fp-proof-math-d7e5810905ab",
    "fp-proof-math-f6429eb2d1c8",
    "fp-proof-math-37337d818152",
    "fp-proof-math-a0873d9da0f5",
    "fp-proof-math-bccf06e26bab",
    "fp-proof-math-fcb2fed207e1",
    "fp-proof-math-76cb028ebd3b",
    "fp-proof-math-7d4ac141f993",
    "fp-proof-math-7c593b074cca",
    "fp-proof-math-cecd99919641",
    "fp-proof-math-c9faf981c807",
    "fp-proof-math-1cf962a06c67",
    "fp-proof-math-58baa463bee3",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "monitor_id",
    "runtime_mode",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "feature_parity",
    "feature_parity_gap_ledger",
    "feature_parity_gap_groups",
    "feature_parity_gap_owner_family_groups",
    "proof_traceability_check",
    "sheaf_coverage",
    "math_value_proof",
    "math_governance",
    "branch_diversity_spec",
    "reverse_round_contracts",
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
    "monitor_fixture": "fail",
    "drift_signature": "fail",
    "branch_diversity": "fail",
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
        if part == "*":
            if not isinstance(current, list):
                raise KeyError(field)
            flattened = []
            for item in current:
                if isinstance(item, list):
                    flattened.extend(item)
                else:
                    flattened.append(item)
            current = flattened
        elif isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list):
            next_values = []
            for item in current:
                if isinstance(item, dict) and part in item:
                    next_values.append(item[part])
            if not next_values:
                raise KeyError(field)
            current = next_values
        else:
            raise KeyError(field)
    return current


def contains_value(actual, expected):
    if isinstance(actual, list):
        return expected in actual
    return actual == expected


gate = load_json(gate_path, "gate")
ledger = load_json(ledger_path, "ledger")
groups = load_json(groups_path, "feature_parity_gap_groups")
parity_lines = read_text(parity_path, "feature_parity").splitlines()
owner_groups_text = read_text(owner_groups_path, "owner_family_groups")

if gate is not None and ledger is not None and groups is not None and parity_lines and owner_groups_text:
    checks["json_parse"] = "pass"

json_cache = {}
text_cache = {}


def anchor_json(path):
    if path not in json_cache:
        json_cache[path] = load_json(path, f"anchor {path}")
    return json_cache[path]


def anchor_text(path):
    if path not in text_cache:
        text_cache[path] = read_text(path, f"anchor {path}")
    return text_cache[path]


def check_anchor(anchor):
    rel = str(anchor.get("artifact", "")).rstrip("/")
    kind = anchor.get("kind")
    path = safe_path(rel)
    if kind == "path_exists":
        if not path.exists():
            raise AssertionError("path_missing")
    elif kind == "text_contains":
        if anchor.get("expected_value") not in anchor_text(path):
            raise AssertionError("text_missing")
    elif kind == "json_field_equals":
        actual = resolve_field(anchor_json(path), anchor.get("field"))
        if actual != anchor.get("expected_value"):
            raise AssertionError("json_field_mismatch")
    elif kind == "json_array_contains":
        actual = resolve_field(anchor_json(path), anchor.get("field"))
        if not contains_value(actual, anchor.get("expected_value")):
            raise AssertionError("json_array_missing_value")
    else:
        raise AssertionError(f"unknown_anchor_kind:{kind}")


if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "fpg-algebraic-topological-gate":
        fail("gate manifest_id must be fpg-algebraic-topological-gate")
    if gate.get("bead") != "bd-bp8fl.3.11":
        fail("gate bead must be bd-bp8fl.3.11")
    if gate.get("owner_family_group") != "fpg-proof-algebraic-topological":
        fail("gate owner_family_group must be fpg-proof-algebraic-topological")
    if gate.get("evidence_owner") != "runtime_math algebraic/topological monitor owners":
        fail("gate evidence_owner mismatch")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match the bd-bp8fl.3.11 contract")
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
    if policy.get("default_decision") != "block_done_until_monitor_fixture_and_drift_evidence_current":
        fail("claim_policy.default_decision must block proof promotion until monitor and drift evidence is current")
        policy_ok = False
    for status in ["PLANNED", "IN_PROGRESS"]:
        if status not in policy.get("allow_status", []):
            fail(f"claim_policy.allow_status missing {status}")
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

    if "fpg-proof-algebraic-topological" in owner_groups_text and "`bd-bp8fl.3.11`" in owner_groups_text:
        checks["owner_group_binding"] = "pass"
    else:
        fail("owner-family groups markdown must bind fpg-proof-algebraic-topological to bd-bp8fl.3.11")

    group_batches = groups.get("batches", []) if isinstance(groups, dict) else []
    batch = next((item for item in group_batches if item.get("batch_id") == "fpg-proof-algebraic-topological"), None)
    if batch is None:
        fail("feature_parity_gap_groups missing fpg-proof-algebraic-topological batch")
    elif batch.get("gap_ids") != EXPECTED_GAP_IDS or batch.get("gap_count") != len(EXPECTED_GAP_IDS):
        fail("feature_parity_gap_groups algebraic-topological batch must carry the fifteen expected gap IDs")
    else:
        checks["group_gap_binding"] = "pass"

    rows = gate.get("rows", [])
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    if row_ids != EXPECTED_GAP_IDS:
        fail(f"gate row IDs must match algebraic-topological gap IDs in order: {row_ids!r}")
    row_contract_ok = row_ids == EXPECTED_GAP_IDS
    fixture_ok = True
    drift_ok = True
    branch_ok = True
    anchors_ok = True
    ledger_ok = True
    parity_ok = True
    claim_ok = policy_ok
    branch_spec = load_json(safe_path(inputs.get("branch_diversity_spec", "")), "branch_diversity_spec") if inputs.get("branch_diversity_spec") else None
    families = branch_spec.get("math_families", {}) if isinstance(branch_spec, dict) else {}
    allowed_drift = set(policy.get("required_drift_classes", []))
    min_families = policy.get("minimum_branch_families", 3)
    ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
    ledger_by_id = {gap.get("gap_id"): gap for gap in ledger_gaps if isinstance(gap, dict)}

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
            "monitor_path",
            "runtime_mode",
            "expected_decision",
            "feature_parity_provenance",
            "claimed_status",
            "replacement_level",
            "monitor_fixture",
            "drift_signature",
            "branch_obligations",
            "evidence_anchors",
        ]:
            if field not in row:
                message = f"{row.get('gap_id', '<missing>')}: missing row field {field}"
                fail(message)
                row_errors.append(message)
                row_contract_ok = False
        gid = row.get("gap_id")
        if not row.get("monitor_id") or not row.get("monitor_path"):
            message = f"{gid}: monitor_id and monitor_path must be non-empty"
            fail(message)
            row_errors.append(message)
            row_contract_ok = False
        if row.get("runtime_mode") != "strict+hardened":
            message = f"{gid}: runtime_mode must be strict+hardened"
            fail(message)
            row_errors.append(message)
            row_contract_ok = False
        if not row.get("evidence_anchors"):
            message = f"{gid}: evidence_anchors must not be empty"
            fail(message)
            row_errors.append(message)
            row_contract_ok = False

        fixture = row.get("monitor_fixture", {})
        if not isinstance(fixture, dict):
            message = f"{gid}: monitor_fixture must be an object"
            fail(message)
            row_errors.append(message)
            fixture_ok = False
        else:
            for field in ("fixture_id", "scenario", "expected_observation", "falsifiable_if"):
                if not fixture.get(field):
                    message = f"{gid}: monitor_fixture.{field} must be non-empty"
                    fail(message)
                    row_errors.append(message)
                    fixture_ok = False
            if not fixture.get("input_classes"):
                message = f"{gid}: monitor_fixture.input_classes must not be empty"
                fail(message)
                row_errors.append(message)
                fixture_ok = False

        drift = row.get("drift_signature", {})
        if not isinstance(drift, dict):
            message = f"{gid}: drift_signature must be an object"
            fail(message)
            row_errors.append(message)
            drift_ok = False
        else:
            for field in ("signature_id", "class", "signal", "threshold"):
                if not drift.get(field):
                    message = f"{gid}: drift_signature.{field} must be non-empty"
                    fail(message)
                    row_errors.append(message)
                    drift_ok = False
            if drift.get("class") not in allowed_drift:
                message = f"{gid}: drift_signature.class {drift.get('class')!r} is not allowed"
                fail(message)
                row_errors.append(message)
                drift_ok = False
            if drift.get("blocked_when_missing") is not True:
                message = f"{gid}: drift_signature.blocked_when_missing must be true"
                fail(message)
                row_errors.append(message)
                drift_ok = False

        obligations = row.get("branch_obligations", [])
        distinct_families = {ob.get("family") for ob in obligations if isinstance(ob, dict)}
        if len(distinct_families) < min_families:
            message = f"{gid}: branch_obligations must cite at least {min_families} distinct families"
            fail(message)
            row_errors.append(message)
            branch_ok = False
        for obligation in obligations:
            if not isinstance(obligation, dict):
                message = f"{gid}: branch_obligations entries must be objects"
                fail(message)
                row_errors.append(message)
                branch_ok = False
                continue
            family = obligation.get("family")
            module = obligation.get("module")
            modules = families.get(family, {}).get("modules", []) if isinstance(families, dict) else []
            if module not in modules:
                message = f"{gid}: branch family {family!r} does not list module {module!r}"
                fail(message)
                row_errors.append(message)
                branch_ok = False

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
        elif contains not in parity_lines[line - 1] or row.get("claimed_status") not in parity_lines[line - 1]:
            message = f"{gid}: FEATURE_PARITY.md:{line} missing expected key/status"
            fail(message)
            row_errors.append(message)
            parity_ok = False

        if row.get("claimed_status") in policy.get("block_status_without_all_anchors", []):
            message = f"{gid}: claimed_status {row.get('claimed_status')} is blocked without full closure evidence"
            fail(message)
            row_errors.append(message)
            claim_ok = False
        if row.get("replacement_level") in policy.get("block_replacement_levels_without_evidence", []):
            message = f"{gid}: replacement_level {row.get('replacement_level')} is blocked for algebraic-topological gaps"
            fail(message)
            row_errors.append(message)
            claim_ok = False

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

        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": "bd-bp8fl.3.11",
                "gap_id": gid,
                "monitor_id": row.get("monitor_id"),
                "runtime_mode": row.get("runtime_mode"),
                "expected_decision": row.get("expected_decision"),
                "actual_decision": row.get("expected_decision") if not row_errors else "claim_blocked",
                "artifact_refs": artifact_refs,
                "source_commit": gate.get("source_commit"),
                "failure_signature": "; ".join(row_errors),
            }
        )

    if row_contract_ok:
        checks["row_contract"] = "pass"
    if fixture_ok:
        checks["monitor_fixture"] = "pass"
    if drift_ok:
        checks["drift_signature"] = "pass"
    if branch_ok:
        checks["branch_diversity"] = "pass"
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
    "bead": "bd-bp8fl.3.11",
    "manifest_id": "fpg-algebraic-topological-gate",
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
