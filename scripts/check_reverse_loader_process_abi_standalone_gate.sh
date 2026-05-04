#!/usr/bin/env bash
# check_reverse_loader_process_abi_standalone_gate.sh -- bd-bp8fl.3.7
#
# Static fail-closed validator for fpg-reverse-loader-process-abi evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${FRANKENLIBC_REVERSE_LOADER_GATE:-${ROOT}/tests/conformance/reverse_loader_process_abi_standalone_gate.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json}"
GAP_GROUPS="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_groups.v1.json}"
OWNER_GROUPS="${FRANKENLIBC_FEATURE_PARITY_OWNER_GROUPS:-${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md}"
STANDALONE_SMOKE="${FRANKENLIBC_STANDALONE_LINK_RUN_SMOKE:-${ROOT}/tests/conformance/standalone_link_run_smoke.v1.json}"
READINESS="${FRANKENLIBC_STANDALONE_READINESS_PROOF_MATRIX:-${ROOT}/tests/conformance/standalone_readiness_proof_matrix.v1.json}"
LOADER_AUDIT="${FRANKENLIBC_LOADER_DLFCN_RELOCATION_TLS_AUDIT:-${ROOT}/tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json}"
FENV_PACK="${FRANKENLIBC_MATH_FENV_SOFTFP_FIXTURE_PACK:-${ROOT}/tests/conformance/math_fenv_softfp_fixture_pack.v1.json}"
E2E_MANIFEST="${FRANKENLIBC_E2E_SCENARIO_MANIFEST:-${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json}"
FAILURE_MATRIX="${FRANKENLIBC_HARD_PARTS_E2E_FAILURE_MATRIX:-${ROOT}/tests/conformance/hard_parts_e2e_failure_matrix.v1.json}"
CONFORMANCE_MATRIX="${FRANKENLIBC_CONFORMANCE_MATRIX:-${ROOT}/tests/conformance/conformance_matrix.v1.json}"
VERSION_SCRIPT="${FRANKENLIBC_LIBC_VERSION_SCRIPT:-${ROOT}/crates/frankenlibc-abi/version_scripts/libc.map}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_REVERSE_LOADER_REPORT:-${OUT_DIR}/reverse_loader_process_abi_standalone_gate.report.json}"
LOG="${FRANKENLIBC_REVERSE_LOADER_LOG:-${OUT_DIR}/reverse_loader_process_abi_standalone_gate.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${GATE}" "${LEDGER}" "${GAP_GROUPS}" "${OWNER_GROUPS}" "${STANDALONE_SMOKE}" "${READINESS}" "${LOADER_AUDIT}" "${FENV_PACK}" "${E2E_MANIFEST}" "${FAILURE_MATRIX}" "${CONFORMANCE_MATRIX}" "${VERSION_SCRIPT}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
ledger_path = Path(sys.argv[3])
groups_path = Path(sys.argv[4])
owner_groups_path = Path(sys.argv[5])
standalone_smoke_path = Path(sys.argv[6])
readiness_path = Path(sys.argv[7])
loader_audit_path = Path(sys.argv[8])
fenv_pack_path = Path(sys.argv[9])
e2e_manifest_path = Path(sys.argv[10])
failure_matrix_path = Path(sys.argv[11])
conformance_matrix_path = Path(sys.argv[12])
version_script_path = Path(sys.argv[13])
report_path = Path(sys.argv[14])
log_path = Path(sys.argv[15])

TRACE_ID = "bd-bp8fl.3.7:reverse-loader-process-abi-standalone"
BEAD_ID = "bd-bp8fl.3.7"
OWNER_GROUP = "fpg-reverse-loader-process-abi"
MANIFEST_ID = "reverse-loader-process-abi-standalone-gate"
EXPECTED_GAP_IDS = [
    "fp-reverse-core-0191894bf973",
    "fp-reverse-core-c16c9c1ae7a4",
    "fp-reverse-core-83ea12557c2f",
    "fp-reverse-core-a764fe234295",
    "fp-reverse-core-3ac0cb0d65a2",
    "fp-reverse-core-757002295174",
    "fp-reverse-core-8f05cebd7805",
    "fp-reverse-core-b4b2f8e772cb",
    "fp-reverse-core-44162ed23382",
    "fp-reverse-core-a559b1461f71",
]
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "gap_id",
    "api_family",
    "symbol",
    "replacement_level",
    "runtime_mode",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
INPUT_KEYS = [
    "feature_parity_gap_ledger",
    "feature_parity_gap_groups",
    "feature_parity_gap_owner_family_groups",
    "standalone_link_run_smoke",
    "standalone_readiness_proof_matrix",
    "loader_dlfcn_relocation_tls_audit",
    "math_fenv_softfp_fixture_pack",
    "e2e_scenario_manifest",
    "hard_parts_e2e_failure_matrix",
    "conformance_matrix",
    "libc_version_script",
]
POSITIVE_SMOKE_IDS = {
    "standalone.loader_symbol_bootstrap",
    "standalone.vm_syscall_ipc",
    "standalone.diagnostics_session",
    "standalone.profiling_fenv",
}
NEGATIVE_SMOKE_ID = "standalone.loader_process_negative_missing_obligation"
ALLOWED_EVIDENCE_KIND = "standalone_link_run_and_versioned_symbol_gate"

errors = []
logs = []
checks = {
    "json_parse": "fail",
    "top_level_shape": "fail",
    "input_artifacts_exist": "fail",
    "owner_group_binding": "fail",
    "ledger_gap_binding": "fail",
    "standalone_smoke_binding": "fail",
    "readiness_blocker_binding": "fail",
    "row_contract": "fail",
    "positive_negative_evidence": "fail",
    "versioned_symbol_binding": "fail",
    "runtime_mode_evidence": "fail",
    "artifact_refs": "fail",
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


def artifact_path(ref):
    rel_text = str(ref).split("#", 1)[0].rstrip("/")
    rel_path = Path(rel_text)
    if rel_path.is_absolute() or ".." in rel_path.parts or not rel_text:
        raise ValueError(f"unsafe artifact path: {ref}")
    return root / rel_path


def refs_exist(refs, context):
    ok = True
    if not isinstance(refs, list) or not refs:
        fail(f"{context}: artifact_refs must be a non-empty list")
        return False
    for ref in refs:
        try:
            if not artifact_path(ref).exists():
                fail(f"{context}: missing artifact ref {ref}")
                ok = False
        except Exception as exc:
            fail(f"{context}: invalid artifact ref {ref}: {exc}")
            ok = False
    return ok


def list_field(value, key, context):
    items = value.get(key)
    if not isinstance(items, list):
        fail(f"{context}: {key} must be a list")
        return []
    return items


def string_field(value, key, context):
    item = value.get(key)
    if not isinstance(item, str) or not item:
        fail(f"{context}: {key} must be a non-empty string")
        return ""
    return item


gate = load_json(gate_path, "gate")
ledger = load_json(ledger_path, "feature_parity_gap_ledger")
groups = load_json(groups_path, "feature_parity_gap_groups")
standalone_smoke = load_json(standalone_smoke_path, "standalone_link_run_smoke")
readiness = load_json(readiness_path, "standalone_readiness_proof_matrix")
loader_audit = load_json(loader_audit_path, "loader_dlfcn_relocation_tls_audit")
fenv_pack = load_json(fenv_pack_path, "math_fenv_softfp_fixture_pack")
e2e_manifest = load_json(e2e_manifest_path, "e2e_scenario_manifest")
failure_matrix = load_json(failure_matrix_path, "hard_parts_e2e_failure_matrix")
conformance_matrix = load_json(conformance_matrix_path, "conformance_matrix")
owner_groups_text = read_text(owner_groups_path, "owner_family_groups")
version_script_text = read_text(version_script_path, "version_script")

if all(
    item is not None
    for item in (
        gate,
        ledger,
        groups,
        standalone_smoke,
        readiness,
        loader_audit,
        fenv_pack,
        e2e_manifest,
        failure_matrix,
        conformance_matrix,
    )
) and owner_groups_text and version_script_text:
    checks["json_parse"] = "pass"

source_commit = ""
rows = []
if isinstance(gate, dict):
    before = len(errors)
    if gate.get("schema_version") != "v1":
        fail("gate schema_version must be v1")
    if gate.get("manifest_id") != MANIFEST_ID:
        fail(f"gate manifest_id must be {MANIFEST_ID}")
    if gate.get("bead") != BEAD_ID:
        fail(f"gate bead must be {BEAD_ID}")
    if gate.get("owner_family_group") != OWNER_GROUP:
        fail(f"gate owner_family_group must be {OWNER_GROUP}")
    source_commit = gate.get("source_commit")
    if not isinstance(source_commit, str) or len(source_commit) < 12:
        fail("gate source_commit must be a non-empty commit-ish string")
    try:
        datetime.fromisoformat(str(gate.get("generated_utc")).replace("Z", "+00:00"))
    except Exception:
        fail("gate generated_utc must be valid ISO-8601")
    if gate.get("required_log_fields") != REQUIRED_LOG_FIELDS:
        fail("gate required_log_fields must match bd-bp8fl.3.7 closure contract")
    expected_ids = gate.get("expected_gap_ids")
    if expected_ids != EXPECTED_GAP_IDS:
        fail("gate expected_gap_ids must preserve the fpg-reverse-loader-process-abi gap order")
    policy = gate.get("claim_policy", {})
    if policy.get("ld_preload_evidence_accepted") is not False:
        fail("claim policy must reject LD_PRELOAD evidence")
    if policy.get("summary_only_claims_accepted") is not False:
        fail("claim policy must reject summary-only claims")
    rows = gate.get("rows", [])
    if not isinstance(rows, list):
        fail("gate rows must be a list")
        rows = []
    if len(errors) == before:
        checks["top_level_shape"] = "pass"

    input_ok = True
    inputs = gate.get("inputs")
    if not isinstance(inputs, dict):
        fail("gate inputs must be an object")
        input_ok = False
    else:
        for key in INPUT_KEYS:
            rel = inputs.get(key)
            if not isinstance(rel, str) or not rel:
                fail(f"gate input missing {key}")
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
    fail("owner family md must mention fpg-reverse-loader-process-abi and bd-bp8fl.3.7")

if isinstance(groups, dict):
    group_rows = [
        batch
        for batch in groups.get("batches", [])
        if isinstance(batch, dict) and batch.get("batch_id") == OWNER_GROUP
    ]
    if len(group_rows) != 1:
        fail("feature parity groups must contain exactly one fpg-reverse-loader-process-abi batch")
    else:
        group_ids = group_rows[0].get("gap_ids")
        if group_ids == EXPECTED_GAP_IDS and group_rows[0].get("gap_count") == len(EXPECTED_GAP_IDS):
            checks["owner_group_binding"] = "pass"
        else:
            fail("feature parity group gap_ids must match expected loader/process ABI gaps")

if isinstance(ledger, dict):
    ledger_rows = {row.get("row_id"): row for row in ledger.get("rows", []) if isinstance(row, dict)}
    ledger_ok = True
    for gap_id in EXPECTED_GAP_IDS:
        row = ledger_rows.get(gap_id)
        if not row:
            fail(f"ledger missing gap row {gap_id}")
            ledger_ok = False
            continue
        if row.get("section") != "reverse_core":
            fail(f"ledger row {gap_id} must remain in reverse_core")
            ledger_ok = False
        if row.get("status") != "PLANNED":
            fail(f"ledger row {gap_id} must remain PLANNED until executable evidence promotes it")
            ledger_ok = False
    if ledger_ok:
        checks["ledger_gap_binding"] = "pass"

smoke_rows = {}
if isinstance(standalone_smoke, dict):
    smoke_rows = {
        row.get("smoke_id"): row
        for row in standalone_smoke.get("smoke_rows", [])
        if isinstance(row, dict)
    }
    owner_groups = standalone_smoke.get("owner_family_groups", [])
    owner_group_ok = False
    for owner_group in owner_groups:
        if not isinstance(owner_group, dict) or owner_group.get("owner_bead") != BEAD_ID:
            continue
        if (
            owner_group.get("batch_id") == OWNER_GROUP
            and owner_group.get("oracle_kind") == "link_run_and_versioned_symbol_gate"
            and owner_group.get("gap_ids") == EXPECTED_GAP_IDS
            and set(owner_group.get("positive_smoke_rows", [])) == POSITIVE_SMOKE_IDS
            and owner_group.get("negative_smoke_rows") == [NEGATIVE_SMOKE_ID]
        ):
            owner_group_ok = True
    smoke_ok = owner_group_ok
    if not owner_group_ok:
        fail("standalone smoke manifest must bind bd-bp8fl.3.7 owner rows and gap IDs")
    for smoke_id in POSITIVE_SMOKE_IDS | {NEGATIVE_SMOKE_ID}:
        smoke = smoke_rows.get(smoke_id)
        if not smoke:
            fail(f"standalone smoke manifest missing {smoke_id}")
            smoke_ok = False
            continue
        if smoke.get("link_command", {}).get("profile") != "standalone_direct_link":
            fail(f"{smoke_id}: link profile must be standalone_direct_link")
            smoke_ok = False
        if smoke.get("runtime_modes") != ["strict", "hardened"]:
            fail(f"{smoke_id}: runtime_modes must be strict+hardened")
            smoke_ok = False
        forbidden = smoke.get("runtime_env", {}).get("forbidden", [])
        if "LD_PRELOAD" not in forbidden:
            fail(f"{smoke_id}: LD_PRELOAD must be forbidden")
            smoke_ok = False
        if not isinstance(smoke.get("symbol_version_requirements"), list) or not smoke.get("symbol_version_requirements"):
            fail(f"{smoke_id}: symbol_version_requirements must be non-empty")
            smoke_ok = False
    negative = smoke_rows.get(NEGATIVE_SMOKE_ID, {})
    if negative.get("negative_case") is not True:
        fail("loader_process negative smoke row must be marked negative_case")
        smoke_ok = False
    if negative.get("feature_gap_ids") != EXPECTED_GAP_IDS:
        fail("loader_process negative smoke row must cover every expected gap id")
        smoke_ok = False
    if smoke_ok:
        checks["standalone_smoke_binding"] = "pass"

if isinstance(readiness, dict):
    blocked = readiness.get("summary", {}).get("blocked_obligation_count")
    proof_rows = readiness.get("summary", {}).get("claim_blocked_proof_row_count")
    if isinstance(blocked, int) and blocked > 0 and isinstance(proof_rows, int) and proof_rows > 0:
        checks["readiness_blocker_binding"] = "pass"
    else:
        fail("standalone readiness proof matrix must keep blocked claim rows visible")

if rows:
    row_ids = [row.get("gap_id") for row in rows if isinstance(row, dict)]
    if row_ids != EXPECTED_GAP_IDS:
        fail("gate rows must preserve every expected gap id exactly once and in source order")

row_contract_ok = True
pos_neg_ok = True
symbol_ok = True
runtime_ok = True
artifact_ok = True
for row in rows:
    if not isinstance(row, dict):
        fail("each gate row must be an object")
        row_contract_ok = False
        continue
    gap_id = string_field(row, "gap_id", "row")
    context = f"row {gap_id or '<missing>'}"
    for key in ("surface", "api_family", "symbol", "source_status", "replacement_level", "evidence_kind", "negative_smoke_id"):
        string_field(row, key, context)
    if row.get("source_status") != "PLANNED":
        fail(f"{context}: source_status must remain PLANNED")
        row_contract_ok = False
    if row.get("evidence_kind") != ALLOWED_EVIDENCE_KIND:
        fail(f"{context}: evidence_kind must be {ALLOWED_EVIDENCE_KIND}")
        row_contract_ok = False
    if row.get("claim_replacement_levels") != ["L1", "L2", "L3"]:
        fail(f"{context}: claim_replacement_levels must be L1/L2/L3")
        row_contract_ok = False
    if not list_field(row, "named_unsupported_or_blocked_cases", context):
        row_contract_ok = False

    positive_smoke_ids = list_field(row, "positive_smoke_ids", context)
    if not positive_smoke_ids:
        pos_neg_ok = False
    for smoke_id in positive_smoke_ids:
        smoke = smoke_rows.get(smoke_id)
        if smoke_id not in POSITIVE_SMOKE_IDS or not smoke:
            fail(f"{context}: unknown positive smoke id {smoke_id}")
            pos_neg_ok = False
            continue
        if gap_id not in smoke.get("feature_gap_ids", []):
            fail(f"{context}: positive smoke {smoke_id} does not bind gap id")
            pos_neg_ok = False
    if row.get("negative_smoke_id") != NEGATIVE_SMOKE_ID:
        fail(f"{context}: negative_smoke_id must be {NEGATIVE_SMOKE_ID}")
        pos_neg_ok = False
    elif gap_id not in smoke_rows.get(NEGATIVE_SMOKE_ID, {}).get("feature_gap_ids", []):
        fail(f"{context}: negative smoke does not bind gap id")
        pos_neg_ok = False

    version_reqs = list_field(row, "versioned_symbol_requirements", context)
    if not version_reqs:
        symbol_ok = False
    for req in version_reqs:
        if not isinstance(req, dict):
            fail(f"{context}: versioned symbol requirement must be an object")
            symbol_ok = False
            continue
        symbol = req.get("symbol")
        version = req.get("version")
        if not isinstance(symbol, str) or not symbol or not isinstance(version, str) or not version:
            fail(f"{context}: versioned symbol requirement missing symbol/version")
            symbol_ok = False
            continue
        if symbol not in version_script_text:
            fail(f"{context}: version script does not mention symbol {symbol}")
            symbol_ok = False

    refs = list(row.get("semantic_or_fixture_refs", []))
    if not refs_exist(refs, f"{context}.semantic_or_fixture_refs"):
        artifact_ok = False

    runtime = row.get("runtime_evidence")
    if not isinstance(runtime, dict):
        fail(f"{context}: runtime_evidence must be an object")
        runtime_ok = False
        continue
    for mode in ("strict", "hardened"):
        evidence = runtime.get(mode)
        if not isinstance(evidence, dict):
            fail(f"{context}: missing {mode} runtime evidence")
            runtime_ok = False
            continue
        expected = evidence.get("expected")
        actual = evidence.get("actual")
        if not isinstance(expected, str) or not expected or expected != actual:
            fail(f"{context}: {mode} expected and actual must be equal non-empty strings")
            runtime_ok = False
        if evidence.get("source_commit") != source_commit:
            fail(f"{context}: {mode} source_commit must match gate source_commit")
            runtime_ok = False
        if not isinstance(evidence.get("failure_signature"), str) or not evidence.get("failure_signature"):
            fail(f"{context}: {mode} failure_signature must be non-empty")
            runtime_ok = False
        if not refs_exist(evidence.get("artifact_refs"), f"{context}.{mode}"):
            artifact_ok = False
        logs.append(
            {
                "trace_id": TRACE_ID,
                "bead_id": BEAD_ID,
                "gap_id": gap_id,
                "api_family": row.get("api_family"),
                "symbol": row.get("symbol"),
                "replacement_level": row.get("replacement_level"),
                "runtime_mode": mode,
                "expected": expected,
                "actual": actual,
                "artifact_refs": evidence.get("artifact_refs"),
                "source_commit": evidence.get("source_commit"),
                "failure_signature": evidence.get("failure_signature"),
            }
        )

if row_contract_ok and rows and [row.get("gap_id") for row in rows] == EXPECTED_GAP_IDS:
    checks["row_contract"] = "pass"
if pos_neg_ok and rows:
    checks["positive_negative_evidence"] = "pass"
if symbol_ok and rows:
    checks["versioned_symbol_binding"] = "pass"
if runtime_ok and rows:
    checks["runtime_mode_evidence"] = "pass"
if artifact_ok and rows:
    checks["artifact_refs"] = "pass"

if len(logs) == len(EXPECTED_GAP_IDS) * 2:
    log_ok = True
    for idx, entry in enumerate(logs):
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in entry]
        if missing:
            fail(f"structured log {idx} missing fields: {missing}")
            log_ok = False
    if log_ok:
        checks["structured_log"] = "pass"
else:
    fail("structured log must contain strict+hardened rows for each gap")

status = "pass" if not errors and all(value == "pass" for value in checks.values()) else "fail"
report = {
    "schema_version": "v1",
    "trace_id": TRACE_ID,
    "bead_id": BEAD_ID,
    "owner_family_group": OWNER_GROUP,
    "status": status,
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "summary": {
        "gap_rows": len(rows),
        "structured_log_rows": len(logs),
        "positive_smoke_rows": len(POSITIVE_SMOKE_IDS),
        "negative_smoke_rows": 1,
        "source_commit": source_commit,
    },
    "checks": checks,
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in logs),
    encoding="utf-8",
)

if status != "pass":
    for error in errors:
        print(f"check_reverse_loader_process_abi_standalone_gate: ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"check_reverse_loader_process_abi_standalone_gate: PASS rows={len(rows)} "
    f"logs={len(logs)} report={report_path} log={log_path}"
)
PY
