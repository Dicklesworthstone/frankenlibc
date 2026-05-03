#!/usr/bin/env bash
# check_fpg_ported_surface_gate.sh -- bd-bp8fl.3.13
#
# Static fail-closed validator for the ten
# fpg-gap-summary-ported-surface-evidence rows. It emits deterministic JSON and
# JSONL artifacts under target/conformance and does not invoke cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_FPG_PORTED_SURFACE_GATE:-${ROOT}/tests/conformance/fpg_ported_surface_gate.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
PARITY="${FRANKENLIBC_FEATURE_PARITY:-${ROOT}/FEATURE_PARITY.md}"
GROUPS_PATH="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_FPG_PORTED_SURFACE_REPORT:-${OUT_DIR}/fpg_ported_surface_gate.report.json}"
LOG="${FRANKENLIBC_FPG_PORTED_SURFACE_LOG:-${OUT_DIR}/fpg_ported_surface_gate.log.jsonl}"

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

TRACE_ID = "bd-bp8fl.3.13:fpg-ported-surface"
EXPECTED_GAP_IDS = [
    "fp-gap-summary-0398e27f075e",
    "fp-gap-summary-793c83cceb16",
    "fp-gap-summary-5cbb74613755",
    "fp-gap-summary-5da3dc1c8d50",
    "fp-gap-summary-267b493369f9",
    "fp-gap-summary-17c934647652",
    "fp-gap-summary-a51012652c16",
    "fp-gap-summary-17d24896af61",
    "fp-gap-summary-161e06bc3a3d",
    "fp-gap-summary-7bd4926c4439",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "section",
    "feature_parity_line",
    "ported_surface",
    "expected",
    "actual",
    "evidence_artifact",
    "evidence_anchor",
    "evidence_verdict",
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
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "dlfcn_boundary_policy",
    "optimization_proof_ledger",
    "htm_fast_path_gate",
]

errors = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "owner_group_binding": "fail",
    "row_contract": "fail",
    "ledger_binding": "fail",
    "feature_parity_binding": "fail",
    "evidence_anchors": "fail",
    "claim_policy": "fail",
    "structured_log": "fail",
}
logs = []


def fail(message):
    errors.append(message)


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{label}: cannot parse {path}: {exc}")
        return None


gate = load_json(gate_path, "gate")
ledger = load_json(ledger_path, "ledger")
groups = load_json(groups_path, "feature_parity_gap_groups")
try:
    parity_lines = parity_path.read_text(encoding="utf-8").splitlines()
except Exception as exc:
    parity_lines = []
    fail(f"feature_parity: cannot read {parity_path}: {exc}")
try:
    owner_groups_text = owner_groups_path.read_text(encoding="utf-8")
except Exception as exc:
    owner_groups_text = ""
    fail(f"owner_family_groups: cannot read {owner_groups_path}: {exc}")

if gate is not None and ledger is not None and groups is not None and parity_lines and owner_groups_text:
    checks["json_parse"] = "pass"

if isinstance(gate, dict):
    shape_errors_before = len(errors)
    if gate.get("schema_version") != "v1":
        fail(f"gate schema_version must be v1, got {gate.get('schema_version')!r}")
    if gate.get("manifest_id") != "fpg-ported-surface-gate":
        fail("gate manifest_id must be fpg-ported-surface-gate")
    if gate.get("bead") != "bd-bp8fl.3.13":
        fail(f"gate bead must be bd-bp8fl.3.13, got {gate.get('bead')!r}")
    if gate.get("owner_family_group") != "fpg-gap-summary-ported-surface-evidence":
        fail("gate owner_family_group must be fpg-gap-summary-ported-surface-evidence")
    if gate.get("evidence_owner") != "ported core/ABI family owners":
        fail("gate evidence_owner does not match owner-family group")
    if not gate.get("source_commit"):
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match the bd-bp8fl.3.13 contract")
    try:
        datetime.fromisoformat(str(gate.get("generated_utc")).replace("Z", "+00:00"))
    except Exception:
        fail("gate generated_utc must be a valid ISO timestamp")
    if len(errors) == shape_errors_before:
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
    if policy.get("default_decision") != "block_done_until_ported_surface_evidence_current":
        fail("claim_policy.default_decision must block DONE until ported-surface evidence is current")
        policy_ok = False
    if "DONE" not in policy.get("block_status_without_all_anchors", []):
        fail("claim_policy must block DONE without all anchors")
        policy_ok = False
    for level in ("L1", "L2", "L3"):
        if level not in policy.get("block_replacement_levels_without_evidence", []):
            fail(f"claim_policy must block replacement level {level} without evidence")
            policy_ok = False

    rows = gate.get("rows", [])
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    if row_ids != EXPECTED_GAP_IDS:
        fail(f"gate row IDs must match ported-surface gap IDs in order: {row_ids!r}")
    for row in rows:
        if not isinstance(row, dict):
            fail("gate rows must contain only objects")
            continue
        for field in [
            "gap_id",
            "kind",
            "section",
            "primary_key",
            "ported_surface",
            "feature_parity_provenance",
            "claim_target",
            "claimed_status",
            "replacement_level",
            "owner_bead",
            "evidence_anchors",
        ]:
            if field not in row:
                fail(f"{row.get('gap_id', '<missing>')}: missing row field {field}")
        if not row.get("evidence_anchors"):
            fail(f"{row.get('gap_id', '<missing>')}: evidence_anchors must not be empty")
    if not any("missing row field" in err or "evidence_anchors must not be empty" in err or "row IDs" in err for err in errors):
        checks["row_contract"] = "pass"

    if "fpg-gap-summary-ported-surface-evidence" in owner_groups_text and "`bd-bp8fl.3.13`" in owner_groups_text:
        checks["owner_group_binding"] = "pass"
    else:
        fail("owner-family groups markdown must bind fpg-gap-summary-ported-surface-evidence to bd-bp8fl.3.13")

    group_batches = groups.get("batches", []) if isinstance(groups, dict) else []
    batch = next((b for b in group_batches if b.get("batch_id") == "fpg-gap-summary-ported-surface-evidence"), None)
    if batch is None:
        fail("feature_parity_gap_groups missing fpg-gap-summary-ported-surface-evidence batch")
    elif batch.get("gap_ids") != EXPECTED_GAP_IDS or batch.get("gap_count") != len(EXPECTED_GAP_IDS):
        fail("feature_parity_gap_groups ported-surface batch must carry the ten expected gap IDs")

    ledger_gaps = ledger.get("gaps", []) if isinstance(ledger, dict) else []
    ledger_by_id = {gap.get("gap_id"): gap for gap in ledger_gaps if isinstance(gap, dict)}
    ledger_ok = True
    parity_ok = True
    anchors_ok = True
    claim_ok = policy_ok
    json_cache = {}

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

    def load_anchor_json(path):
        if path not in json_cache:
            json_cache[path] = load_json(path, f"anchor {path}")
        return json_cache[path]

    def check_anchor(row, anchor):
        rel = anchor.get("artifact")
        kind = anchor.get("kind")
        path = root / str(rel).rstrip("/")
        expected = (
            anchor.get("expected_value")
            if "expected_value" in anchor
            else anchor.get("expected_value_min")
            if "expected_value_min" in anchor
            else anchor.get("expected_value_contains")
            if "expected_value_contains" in anchor
            else "present"
        )
        actual = None
        verdict = "pass"
        failure_signature = ""
        try:
            if kind == "path_exists":
                actual = path.exists()
                if not actual:
                    raise AssertionError("path_missing")
            elif kind == "text_contains":
                expected_contains = anchor.get("expected_value_contains")
                actual = expected_contains in path.read_text(encoding="utf-8")
                if not actual:
                    raise AssertionError("text_missing_expected_substring")
            elif kind == "json_field_equals":
                data = load_anchor_json(path)
                actual = resolve_field(data, anchor.get("field"))
                if actual != anchor.get("expected_value"):
                    raise AssertionError("json_field_mismatch")
            elif kind == "json_field_min":
                data = load_anchor_json(path)
                actual = resolve_field(data, anchor.get("field"))
                if not isinstance(actual, (int, float)) or actual < anchor.get("expected_value_min"):
                    raise AssertionError("json_field_below_min")
            elif kind == "json_object_min":
                data = load_anchor_json(path)
                actual_value = resolve_field(data, anchor.get("field"))
                actual = len(actual_value) if isinstance(actual_value, dict) else "not_object"
                if not isinstance(actual_value, dict) or actual < anchor.get("expected_value_min"):
                    raise AssertionError("json_object_below_min")
            else:
                raise AssertionError(f"unknown_anchor_kind:{kind}")
        except Exception as exc:
            verdict = "fail"
            failure_signature = str(exc)
        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": "bd-bp8fl.3.13",
                "gap_id": row.get("gap_id"),
                "section": row.get("section"),
                "feature_parity_line": row.get("feature_parity_provenance", {}).get("line"),
                "ported_surface": row.get("ported_surface"),
                "expected": expected,
                "actual": actual,
                "evidence_artifact": rel,
                "evidence_anchor": kind if not anchor.get("field") else f"{kind}:{anchor.get('field')}",
                "evidence_verdict": verdict,
                "replacement_level": row.get("replacement_level"),
                "claim_decision": "keep_in_progress" if verdict == "pass" else "claim_blocked",
                "artifact_refs": [rel],
                "source_commit": gate.get("source_commit"),
                "failure_signature": failure_signature,
            }
        )
        if verdict != "pass":
            fail(f"{row.get('gap_id')}: anchor failed for {rel} ({kind}): {failure_signature}")
            return False
        return True

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
            fail(f"{gid}: replacement_level {row.get('replacement_level')} is blocked for ported-surface gaps")
            claim_ok = False

        for anchor in row.get("evidence_anchors", []):
            if not check_anchor(row, anchor):
                anchors_ok = False

    if ledger_ok:
        checks["ledger_binding"] = "pass"
    if parity_ok:
        checks["feature_parity_binding"] = "pass"
    if anchors_ok:
        checks["evidence_anchors"] = "pass"
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
    "bead": "bd-bp8fl.3.13",
    "manifest_id": "fpg-ported-surface-gate",
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
