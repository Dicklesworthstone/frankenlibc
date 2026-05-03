#!/usr/bin/env bash
# check_fpg_coverage_interaction_gate.sh -- bd-bp8fl.3.10
#
# Static fail-closed validator for fpg-proof-coverage-interaction proof rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_FPG_COVERAGE_INTERACTION_GATE:-${ROOT}/tests/conformance/fpg_coverage_interaction_gate.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
PARITY="${FRANKENLIBC_FEATURE_PARITY:-${ROOT}/FEATURE_PARITY.md}"
GROUPS_PATH="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_FPG_COVERAGE_INTERACTION_REPORT:-${OUT_DIR}/fpg_coverage_interaction_gate.report.json}"
LOG="${FRANKENLIBC_FPG_COVERAGE_INTERACTION_LOG:-${OUT_DIR}/fpg_coverage_interaction_gate.log.jsonl}"

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

TRACE_ID = "bd-bp8fl.3.10:fpg-coverage-interaction"
EXPECTED_GAP_IDS = [
    "fp-proof-math-4577b75545e4",
    "fp-proof-math-638859dcb801",
    "fp-proof-math-77bcaf571ca9",
    "fp-proof-math-c76d1265a4b8",
    "fp-proof-math-0a9c8933d821",
    "fp-proof-math-a4fd102d5fd8",
    "fp-proof-math-25ac141c57f6",
    "fp-proof-math-0d50ca59b972",
    "fp-proof-math-d09a6233acb5",
    "fp-proof-math-080870cbbd8d",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "plan_id",
    "interaction_tuple",
    "coverage_level",
    "selected",
    "reason",
    "feature_parity_line",
    "evidence_artifact",
    "evidence_anchor",
    "evidence_verdict",
    "latency_gate",
    "equivalence_witness",
    "replacement_level",
    "claim_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "feature_parity",
    "feature_parity_gap_ledger",
    "feature_parity_gap_groups",
    "feature_parity_gap_owner_family_groups",
    "branch_diversity_spec",
    "math_value_ablations",
    "perf_regression_prevention",
    "symbol_latency_baseline",
    "optimization_proof_ledger",
    "reverse_round_contracts",
    "hardened_repair_deny_matrix",
    "setjmp_semantics_contract",
    "real_program_smoke_suite",
    "standalone_readiness_proof_matrix",
]

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "owner_group_binding": "fail",
    "row_contract": "fail",
    "ledger_binding": "fail",
    "feature_parity_binding": "fail",
    "coverage_latency_equivalence_anchors": "fail",
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


def check_anchor(row, anchor):
    rel = str(anchor.get("artifact", "")).rstrip("/")
    kind = anchor.get("kind")
    path = root / rel
    expected = anchor.get("expected_value", anchor.get("expected_value_min", "present"))
    actual = None
    verdict = "pass"
    failure_signature = ""
    try:
        if kind == "path_exists":
            actual = path.exists()
            if not actual:
                raise AssertionError("path_missing")
        elif kind == "text_contains":
            actual = anchor.get("expected_value") in anchor_text(path)
            if not actual:
                raise AssertionError("text_missing")
        elif kind == "json_field_equals":
            actual = resolve_field(anchor_json(path), anchor.get("field"))
            if actual != anchor.get("expected_value"):
                raise AssertionError("json_field_mismatch")
        elif kind == "json_field_min":
            actual = resolve_field(anchor_json(path), anchor.get("field"))
            if not isinstance(actual, (int, float)) or actual < anchor.get("expected_value_min"):
                raise AssertionError("json_field_below_min")
        elif kind == "json_array_min":
            value = resolve_field(anchor_json(path), anchor.get("field"))
            actual = len(value) if isinstance(value, list) else "not_array"
            if not isinstance(value, list) or actual < anchor.get("expected_value_min"):
                raise AssertionError("json_array_below_min")
        elif kind == "json_array_contains":
            value = resolve_field(anchor_json(path), anchor.get("field"))
            actual = value
            if not contains_value(value, anchor.get("expected_value")):
                raise AssertionError("json_array_missing_value")
        else:
            raise AssertionError(f"unknown_anchor_kind:{kind}")
    except Exception as exc:
        verdict = "fail"
        failure_signature = str(exc)
    logs.append(
        {
            "trace_id": TRACE_ID,
            "bead_id": "bd-bp8fl.3.10",
            "gap_id": row.get("gap_id"),
            "plan_id": row.get("plan_id"),
            "interaction_tuple": row.get("interaction_tuple"),
            "coverage_level": row.get("coverage_level"),
            "selected": row.get("selected"),
            "reason": row.get("reason"),
            "feature_parity_line": row.get("feature_parity_provenance", {}).get("line"),
            "evidence_artifact": rel,
            "evidence_anchor": kind if not anchor.get("field") else f"{kind}:{anchor.get('field')}",
            "evidence_verdict": verdict,
            "latency_gate": row.get("latency_gate"),
            "equivalence_witness": row.get("equivalence_witness"),
            "replacement_level": row.get("replacement_level"),
            "claim_decision": "keep_visible" if verdict == "pass" else "claim_blocked",
            "artifact_refs": [rel],
            "source_commit": gate.get("source_commit") if isinstance(gate, dict) else "",
            "failure_signature": failure_signature,
        }
    )
    if verdict != "pass":
        fail(f"{row.get('gap_id')}: anchor failed for {rel} ({kind}): {failure_signature}")
        return False
    return True


if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "fpg-coverage-interaction-gate":
        fail("gate manifest_id must be fpg-coverage-interaction-gate")
    if gate.get("bead") != "bd-bp8fl.3.10":
        fail("gate bead must be bd-bp8fl.3.10")
    if gate.get("owner_family_group") != "fpg-proof-coverage-interaction":
        fail("gate owner_family_group must be fpg-proof-coverage-interaction")
    if gate.get("evidence_owner") != "coverage, performance, ABI-layout, and low-level kernel owners":
        fail("gate evidence_owner mismatch")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match the bd-bp8fl.3.10 contract")
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
        if rel and not (root / str(rel).rstrip("/")).exists():
            missing_paths.append(f"{key}:{rel}")
    if missing_inputs:
        fail("gate inputs missing keys: " + ", ".join(missing_inputs))
    if missing_paths:
        fail("gate input paths missing: " + ", ".join(missing_paths))
    if not missing_inputs and not missing_paths:
        checks["input_artifacts_exist"] = "pass"

    policy = gate.get("claim_policy", {})
    policy_ok = True
    if policy.get("default_decision") != "block_done_until_coverage_latency_and_equivalence_evidence_current":
        fail("claim_policy.default_decision must block DONE until coverage evidence is current")
        policy_ok = False
    for witness in ["interaction_matrix", "latency_gate", "abi_kernel_equivalence_witness", "behavior_drift_guard"]:
        if witness not in policy.get("required_witness_classes", []):
            fail(f"claim_policy missing required witness class {witness}")
            policy_ok = False
    if "DONE" not in policy.get("block_status_without_all_anchors", []):
        fail("claim_policy must block DONE without all anchors")
        policy_ok = False
    for level in ("L1", "L2", "L3"):
        if level not in policy.get("block_replacement_levels_without_evidence", []):
            fail(f"claim_policy must block replacement level {level}")
            policy_ok = False

    if "fpg-proof-coverage-interaction" in owner_groups_text and "`bd-bp8fl.3.10`" in owner_groups_text:
        checks["owner_group_binding"] = "pass"
    else:
        fail("owner-family groups markdown must bind fpg-proof-coverage-interaction to bd-bp8fl.3.10")

    group_batches = groups.get("batches", []) if isinstance(groups, dict) else []
    batch = next((item for item in group_batches if item.get("batch_id") == "fpg-proof-coverage-interaction"), None)
    if batch is None:
        fail("feature_parity_gap_groups missing fpg-proof-coverage-interaction batch")
    elif batch.get("gap_ids") != EXPECTED_GAP_IDS or batch.get("gap_count") != len(EXPECTED_GAP_IDS):
        fail("feature_parity_gap_groups coverage-interaction batch must carry the ten expected gap IDs")

    rows = gate.get("rows", [])
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    if row_ids != EXPECTED_GAP_IDS:
        fail(f"gate row IDs must match coverage-interaction gap IDs in order: {row_ids!r}")
    for row in rows:
        if not isinstance(row, dict):
            fail("gate rows must contain only objects")
            continue
        for field in [
            "gap_id",
            "kind",
            "section",
            "primary_key",
            "plan_id",
            "interaction_tuple",
            "coverage_level",
            "selected",
            "reason",
            "feature_parity_provenance",
            "claimed_status",
            "replacement_level",
            "owner_bead",
            "latency_gate",
            "equivalence_witness",
            "evidence_anchors",
        ]:
            if field not in row:
                fail(f"{row.get('gap_id', '<missing>')}: missing row field {field}")
        if not row.get("interaction_tuple"):
            fail(f"{row.get('gap_id', '<missing>')}: interaction_tuple must not be empty")
        if not row.get("latency_gate") or not row.get("equivalence_witness"):
            fail(f"{row.get('gap_id', '<missing>')}: latency_gate and equivalence_witness must be non-empty")
        if not row.get("evidence_anchors"):
            fail(f"{row.get('gap_id', '<missing>')}: evidence_anchors must not be empty")
    if not any(
        needle in err
        for err in errors
        for needle in ["missing row field", "interaction_tuple must", "latency_gate", "evidence_anchors must", "row IDs"]
    ):
        checks["row_contract"] = "pass"

    ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
    ledger_by_id = {gap.get("gap_id"): gap for gap in ledger_gaps if isinstance(gap, dict)}
    ledger_ok = True
    parity_ok = True
    anchors_ok = True
    claim_ok = policy_ok

    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        gid = row.get("gap_id")
        ledger_gap = ledger_by_id.get(gid)
        if ledger_gap is None:
            fail(f"{gid}: missing from feature_parity_gap_ledger")
            ledger_ok = False
        else:
            for field in ("kind", "section", "primary_key", "status"):
                expected = row.get("claimed_status") if field == "status" else row.get(field)
                actual = ledger_gap.get(field)
                if actual != expected:
                    fail(f"{gid}: ledger {field} mismatch: expected {expected!r}, actual {actual!r}")
                    ledger_ok = False

        provenance = row.get("feature_parity_provenance", {})
        line = provenance.get("line")
        contains = provenance.get("line_contains")
        if not isinstance(line, int) or line < 1 or line > len(parity_lines):
            fail(f"{gid}: feature parity line is out of range: {line!r}")
            parity_ok = False
        elif contains not in parity_lines[line - 1]:
            fail(f"{gid}: FEATURE_PARITY.md:{line} missing expected text {contains!r}")
            parity_ok = False

        if row.get("claimed_status") in policy.get("block_status_without_all_anchors", []):
            fail(f"{gid}: claimed_status {row.get('claimed_status')} is blocked without full closure evidence")
            claim_ok = False
        if row.get("replacement_level") in policy.get("block_replacement_levels_without_evidence", []):
            fail(f"{gid}: replacement_level {row.get('replacement_level')} is blocked for coverage-interaction gaps")
            claim_ok = False

        for anchor in row.get("evidence_anchors", []):
            if not check_anchor(row, anchor):
                anchors_ok = False

    if ledger_ok:
        checks["ledger_binding"] = "pass"
    if parity_ok:
        checks["feature_parity_binding"] = "pass"
    if anchors_ok:
        checks["coverage_latency_equivalence_anchors"] = "pass"
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
    "bead": "bd-bp8fl.3.10",
    "manifest_id": "fpg-coverage-interaction-gate",
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
