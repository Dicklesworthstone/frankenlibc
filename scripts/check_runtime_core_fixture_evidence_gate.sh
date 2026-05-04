#!/usr/bin/env bash
# check_runtime_core_fixture_evidence_gate.sh -- bd-bp8fl.3.6
#
# Static fail-closed validator for fpg-reverse-runtime-core evidence rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_RUNTIME_CORE_GATE:-${ROOT}/tests/conformance/runtime_core_fixture_evidence_gate.v1.json}"
GAP_GROUPS="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
RECON="${FRANKENLIBC_REALITY_BRIDGE_RECON:-${ROOT}/tests/conformance/reality_bridge_import_reconciliation.v1.json}"
SYMBOL_COVERAGE="${FRANKENLIBC_SYMBOL_FIXTURE_COVERAGE:-${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json}"
PER_SYMBOL="${FRANKENLIBC_PER_SYMBOL_FIXTURE_TESTS:-${ROOT}/tests/conformance/per_symbol_fixture_tests.v1.json}"
SEMANTIC_INVENTORY="${FRANKENLIBC_SEMANTIC_CONTRACT_INVENTORY:-${ROOT}/tests/conformance/semantic_contract_inventory.v1.json}"
MODE_MATRIX="${FRANKENLIBC_MODE_SEMANTICS_MATRIX:-${ROOT}/tests/conformance/mode_semantics_matrix.json}"
REPAIR_MATRIX="${FRANKENLIBC_HARDENED_REPAIR_DENY_MATRIX:-${ROOT}/tests/conformance/hardened_repair_deny_matrix.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_RUNTIME_CORE_REPORT:-${OUT_DIR}/runtime_core_fixture_evidence_gate.report.json}"
LOG="${FRANKENLIBC_RUNTIME_CORE_LOG:-${OUT_DIR}/runtime_core_fixture_evidence_gate.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${GATE}" "${GAP_GROUPS}" "${OWNER_GROUPS}" "${RECON}" "${SYMBOL_COVERAGE}" "${PER_SYMBOL}" "${SEMANTIC_INVENTORY}" "${MODE_MATRIX}" "${REPAIR_MATRIX}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
groups_path = Path(sys.argv[3])
owner_groups_path = Path(sys.argv[4])
recon_path = Path(sys.argv[5])
symbol_coverage_path = Path(sys.argv[6])
per_symbol_path = Path(sys.argv[7])
semantic_inventory_path = Path(sys.argv[8])
mode_matrix_path = Path(sys.argv[9])
repair_matrix_path = Path(sys.argv[10])
report_path = Path(sys.argv[11])
log_path = Path(sys.argv[12])

TRACE_ID = "bd-bp8fl.3.6:runtime-core-fixture-evidence"
BEAD_ID = "bd-bp8fl.3.6"
OWNER_GROUP = "fpg-reverse-runtime-core"
EXPECTED_GAP_IDS = [
    "fp-reverse-core-311e99aff4d6",
    "fp-reverse-core-a30cbdd5d2da",
    "fp-reverse-core-422dc81789ec",
    "fp-reverse-core-bbe405ff4f84",
    "fp-reverse-core-97ef5634c70b",
    "fp-reverse-core-bdb29f3d780e",
    "fp-reverse-core-d6c0faa879a5",
    "fp-reverse-core-36e1946e7f8d",
    "fp-reverse-core-afa6d92abe42",
    "fp-reverse-core-8f333dadeb11",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "expected",
    "actual",
    "errno",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "feature_parity_gap_groups",
    "feature_parity_gap_owner_family_groups",
    "reality_bridge_import_reconciliation",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "semantic_contract_inventory",
    "mode_semantics_matrix",
    "hardened_repair_deny_matrix",
]
ALLOWED_EVIDENCE_KINDS = {
    "fixture",
    "semantic_overlay",
    "fixture_and_semantic_overlay",
}

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "owner_group_binding": "fail",
    "group_gap_binding": "fail",
    "reconciliation_binding": "fail",
    "row_contract": "fail",
    "explicit_case_binding": "fail",
    "runtime_mode_evidence": "fail",
    "artifact_refs": "fail",
    "semantic_inventory_binding": "fail",
    "mode_policy_binding": "fail",
    "runner_binding": "fail",
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


def artifact_path(rel):
    rel_text = str(rel).split("#", 1)[0].rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts or not rel_text:
        raise ValueError(f"unsafe artifact path: {rel}")
    return root / rel_path


def artifact_refs_exist(refs, context):
    ok = True
    if not isinstance(refs, list) or not refs:
        fail(f"{context}: artifact_refs must be a non-empty list")
        return False
    for ref in refs:
        try:
            path = artifact_path(ref)
            if not path.exists():
                fail(f"{context}: missing artifact ref {ref}")
                ok = False
        except Exception as exc:
            fail(f"{context}: invalid artifact ref {ref}: {exc}")
            ok = False
    return ok


gate = load_json(gate_path, "gate")
groups = load_json(groups_path, "feature_parity_gap_groups")
recon = load_json(recon_path, "reality_bridge_import_reconciliation")
symbol_coverage = load_json(symbol_coverage_path, "symbol_fixture_coverage")
per_symbol = load_json(per_symbol_path, "per_symbol_fixture_tests")
semantic_inventory = load_json(semantic_inventory_path, "semantic_contract_inventory")
mode_matrix = load_json(mode_matrix_path, "mode_semantics_matrix")
repair_matrix = load_json(repair_matrix_path, "hardened_repair_deny_matrix")
owner_groups_text = read_text(owner_groups_path, "owner_family_groups")

if all(
    item is not None
    for item in (
        gate,
        groups,
        recon,
        symbol_coverage,
        per_symbol,
        semantic_inventory,
        mode_matrix,
        repair_matrix,
    )
) and owner_groups_text:
    checks["json_parse"] = "pass"

if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != "runtime-core-fixture-evidence-gate":
        fail("gate manifest_id must be runtime-core-fixture-evidence-gate")
    if gate.get("bead") != BEAD_ID:
        fail(f"gate bead must be {BEAD_ID}")
    if gate.get("owner_family_group") != OWNER_GROUP:
        fail(f"gate owner_family_group must be {OWNER_GROUP}")
    source_commit = gate.get("source_commit")
    if not isinstance(source_commit, str) or len(source_commit) < 12:
        fail("gate source_commit must be non-empty")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match bd-bp8fl.3.6 closure contract")
    try:
        datetime.fromisoformat(str(gate.get("generated_utc")).replace("Z", "+00:00"))
    except Exception:
        fail("gate generated_utc must be a valid ISO timestamp")
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    inputs = gate.get("inputs", {})
    input_ok = isinstance(inputs, dict)
    if not input_ok:
        fail("gate inputs must be an object")
    else:
        for key in INPUT_KEYS:
            rel = inputs.get(key)
            if not rel:
                fail(f"gate inputs missing {key}")
                input_ok = False
                continue
            try:
                if not artifact_path(rel).exists():
                    fail(f"gate input path missing: {key}:{rel}")
                    input_ok = False
            except Exception as exc:
                fail(f"gate input path invalid: {key}:{rel}:{exc}")
                input_ok = False
    if input_ok:
        checks["input_artifacts_exist"] = "pass"

    if OWNER_GROUP in owner_groups_text and f"`{BEAD_ID}`" in owner_groups_text:
        checks["owner_group_binding"] = "pass"
    else:
        fail(f"owner groups markdown must bind {OWNER_GROUP} to {BEAD_ID}")

    batch = None
    if isinstance(groups, dict):
        batch = next(
            (
                item
                for item in groups.get("batches", [])
                if isinstance(item, dict) and item.get("batch_id") == OWNER_GROUP
            ),
            None,
        )
    if batch is None:
        fail(f"feature_parity_gap_groups missing {OWNER_GROUP}")
    elif batch.get("gap_count") != len(EXPECTED_GAP_IDS) or batch.get("gap_ids") != EXPECTED_GAP_IDS:
        fail("feature_parity_gap_groups runtime-core batch must carry the 10 expected gap IDs")
    else:
        checks["group_gap_binding"] = "pass"

    recon_rows = {}
    if isinstance(recon, dict):
        for item in recon.get("feature_gap_import_rows", []):
            if isinstance(item, dict) and item.get("batch_id") == OWNER_GROUP:
                recon_rows[item.get("source_row_id")] = item
    recon_ok = True
    for gap_id in EXPECTED_GAP_IDS:
        item = recon_rows.get(gap_id)
        if item is None:
            fail(f"reconciliation missing {gap_id}")
            recon_ok = False
            continue
        if item.get("target_issue_id") != BEAD_ID or item.get("failure_signature") != "ok":
            fail(f"reconciliation row {gap_id} must target {BEAD_ID} with ok signature")
            recon_ok = False
    if recon_ok:
        checks["reconciliation_binding"] = "pass"

    semantic_ids = {
        item.get("id")
        for item in semantic_inventory.get("entries", [])
        if isinstance(item, dict)
    } if isinstance(semantic_inventory, dict) else set()
    mode_families = {
        item.get("family")
        for item in mode_matrix.get("families", [])
        if isinstance(item, dict)
    } if isinstance(mode_matrix, dict) else set()
    repair_ids = {
        item.get("entry_id")
        for item in repair_matrix.get("entries", [])
        if isinstance(item, dict)
    } if isinstance(repair_matrix, dict) else set()
    covered_symbols = {
        item.get("symbol")
        for item in symbol_coverage.get("symbols", [])
        if isinstance(item, dict) and item.get("covered") is True
    } if isinstance(symbol_coverage, dict) else set()
    per_symbol_names = {
        item.get("symbol")
        for item in per_symbol.get("per_symbol_report", [])
        if isinstance(item, dict)
    } if isinstance(per_symbol, dict) else set()

    rows = gate.get("rows", [])
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    row_ok = row_ids == EXPECTED_GAP_IDS
    if not row_ok:
        fail(f"gate row IDs must match runtime-core gap IDs in order: {row_ids!r}")
    explicit_ok = row_ok
    mode_ok = row_ok
    artifact_ok = row_ok
    semantic_ok = True
    policy_ok = True
    for idx, row in enumerate(rows if isinstance(rows, list) else []):
        context = f"rows[{idx}]"
        if not isinstance(row, dict):
            fail(f"{context}: row must be an object")
            row_ok = False
            continue
        gap_id = row.get("gap_id")
        api_family = row.get("api_family")
        symbol = row.get("symbol")
        if not all(isinstance(row.get(key), str) and row.get(key) for key in ("gap_id", "subsystem", "api_family", "symbol", "source_status", "evidence_kind")):
            fail(f"{context}: required string fields are missing")
            row_ok = False
        recon_row = recon_rows.get(gap_id)
        if recon_row and row.get("source_status") != recon_row.get("source_status"):
            fail(f"{context}: source_status must match reconciliation row")
            row_ok = False
        if row.get("source_status") not in ("IN_PROGRESS", "PLANNED"):
            fail(f"{context}: source_status must stay IN_PROGRESS or PLANNED")
            row_ok = False
        named_cases = row.get("named_unsupported_or_fallback_cases")
        if not isinstance(named_cases, list) or not named_cases or not all(isinstance(case, str) and case for case in named_cases):
            fail(f"{context}: unsupported or fallback cases must be named explicitly")
            explicit_ok = False
        for rel in row.get("fixture_files", []):
            try:
                if not artifact_path(rel).exists():
                    fail(f"{context}: fixture file missing {rel}")
                    artifact_ok = False
            except Exception as exc:
                fail(f"{context}: fixture file invalid {rel}: {exc}")
                artifact_ok = False
        for semantic_id in row.get("semantic_contract_ids", []):
            if semantic_id not in semantic_ids:
                fail(f"{context}: semantic contract id missing from inventory: {semantic_id}")
                semantic_ok = False
        family = row.get("mode_semantics_family")
        if family and family not in mode_families:
            fail(f"{context}: mode semantics family missing: {family}")
            policy_ok = False
        for repair_id in row.get("repair_deny_entry_ids", []):
            if repair_id not in repair_ids:
                fail(f"{context}: repair/deny entry id missing: {repair_id}")
                policy_ok = False
        if symbol not in covered_symbols and not row.get("semantic_contract_ids") and api_family != "RuntimePolicy":
            fail(f"{context}: symbol {symbol} must have fixture coverage or semantic contracts")
            artifact_ok = False
        if symbol not in per_symbol_names and api_family not in ("RuntimePolicy", "Signal"):
            fail(f"{context}: symbol {symbol} missing from per-symbol fixture report")
            artifact_ok = False

        evidence = row.get("runtime_evidence")
        if not isinstance(evidence, dict) or sorted(evidence.keys()) != ["hardened", "strict"]:
            fail(f"{context}: runtime_evidence must contain strict and hardened only")
            mode_ok = False
            continue
        for mode in ("strict", "hardened"):
            mode_context = f"{context}.{mode}"
            item = evidence.get(mode, {})
            if item.get("kind") not in ALLOWED_EVIDENCE_KINDS:
                fail(f"{mode_context}: evidence kind must be fixture or semantic overlay")
                mode_ok = False
            expected = item.get("expected")
            actual = item.get("actual")
            if not isinstance(expected, str) or not expected:
                fail(f"{mode_context}: expected must be non-empty")
                mode_ok = False
            if actual != expected:
                fail(f"{mode_context}: expected and actual evidence summaries must match")
                mode_ok = False
            if item.get("source_commit") != source_commit:
                fail(f"{mode_context}: source_commit is stale or does not match gate source_commit")
                mode_ok = False
            if not item.get("errno"):
                fail(f"{mode_context}: errno must be named")
                mode_ok = False
            if not item.get("failure_signature"):
                fail(f"{mode_context}: failure_signature must be named")
                mode_ok = False
            if not artifact_refs_exist(item.get("artifact_refs"), mode_context):
                artifact_ok = False
            if item.get("kind") != "fixture" and not row.get("named_unsupported_or_fallback_cases"):
                fail(f"{mode_context}: semantic overlay evidence requires named unsupported/fallback cases")
                explicit_ok = False
            logs.append(
                {
                    "trace_id": TRACE_ID,
                    "bead_id": BEAD_ID,
                    "gap_id": gap_id,
                    "api_family": api_family,
                    "symbol": symbol,
                    "runtime_mode": mode,
                    "expected": expected,
                    "actual": actual,
                    "errno": item.get("errno"),
                    "artifact_refs": item.get("artifact_refs", []),
                    "source_commit": item.get("source_commit"),
                    "failure_signature": item.get("failure_signature"),
                }
            )

    if row_ok:
        checks["row_contract"] = "pass"
    if explicit_ok:
        checks["explicit_case_binding"] = "pass"
    if mode_ok:
        checks["runtime_mode_evidence"] = "pass"
    if artifact_ok:
        checks["artifact_refs"] = "pass"
    if semantic_ok:
        checks["semantic_inventory_binding"] = "pass"
    if policy_ok:
        checks["mode_policy_binding"] = "pass"

    runner_ok = True
    for key in ("direct_runner", "isolated_runner"):
        runner = gate.get(key)
        if not isinstance(runner, dict) or not runner.get("command"):
            fail(f"{key}: command is required")
            runner_ok = False
            continue
        if not artifact_refs_exist(runner.get("artifact_refs"), key):
            runner_ok = False
    if runner_ok:
        checks["runner_binding"] = "pass"

    structured_ok = len(logs) == len(EXPECTED_GAP_IDS) * 2
    for idx, entry in enumerate(logs):
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in entry]
        if missing:
            fail(f"log[{idx}] missing required fields: {', '.join(missing)}")
            structured_ok = False
    if structured_ok:
        checks["structured_log"] = "pass"

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "schema_version": "v1",
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "status": status,
    "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "checks": checks,
    "summary": {
        "expected_gap_count": len(EXPECTED_GAP_IDS),
        "row_count": len(gate.get("rows", [])) if isinstance(gate, dict) else 0,
        "structured_log_rows": len(logs),
        "strict_mode_rows": sum(1 for entry in logs if entry.get("runtime_mode") == "strict"),
        "hardened_mode_rows": sum(1 for entry in logs if entry.get("runtime_mode") == "hardened"),
    },
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(entry, sort_keys=True) + "\n" for entry in logs), encoding="utf-8")

if status != "pass":
    print(f"check_runtime_core_fixture_evidence_gate: FAIL ({len(errors)} errors)", file=sys.stderr)
    for message in errors[:20]:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "check_runtime_core_fixture_evidence_gate: PASS "
    f"rows={report['summary']['row_count']} logs={report['summary']['structured_log_rows']} "
    f"report={report_path} log={log_path}"
)
PY
