#!/usr/bin/env bash
# check_fpg_proof_core_safety_gate.sh -- bd-bp8fl.3.8
#
# Fail-closed gate for the seven `fpg-proof-core-safety` gaps in
# tests/conformance/feature_parity_gap_ledger.v1.json. Drives the binder at
# tests/conformance/fpg_proof_core_safety_gate.v1.json:
#   * every safety-theorem row in FEATURE_PARITY.md must remain bound to its
#     cited primary key + claimed status (PLANNED/IN_PROGRESS),
#   * every evidence anchor must resolve in proof_obligations_binder.v1.json,
#     proof_binder_validation.v1.json, mode_contract_lock.v1.json, or the
#     gap ledger,
#   * proof_binder_validation must report binder_valid=true with zero
#     violations on every cited obligation.
#
# Modes:
#   --validate-only  static structural checks only (no cargo)
#   --rch (default)  delegate the rust harness test to rch exec
#   --local          run cargo locally (only if rch is unavailable)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${ROOT}/tests/conformance/fpg_proof_core_safety_gate.v1.json"
LEDGER="${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json"
PARITY="${ROOT}/FEATURE_PARITY.md"
OWNER_GROUPS="${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md"
BINDER="${ROOT}/tests/conformance/proof_obligations_binder.v1.json"
VALIDATION="${ROOT}/tests/conformance/proof_binder_validation.v1.json"
MODE_LOCK="${ROOT}/tests/conformance/mode_contract_lock.v1.json"

MODE="rch"
case "${1:-}" in
  ""|--rch)
    MODE="rch"
    ;;
  --validate-only)
    MODE="validate-only"
    ;;
  --local)
    MODE="local"
    ;;
  -h|--help)
    cat <<USAGE
Usage: $0 [--rch | --validate-only | --local]
  --rch (default)   Run the rust harness test via 'rch exec -- cargo test'.
  --validate-only   Static structural checks (no cargo compile).
  --local           Run 'cargo test' locally (only if rch is unavailable).
USAGE
    exit 0
    ;;
  *)
    echo "$0: unknown mode ${1:-}" >&2
    exit 2
    ;;
esac

for f in "${GATE}" "${LEDGER}" "${PARITY}" "${OWNER_GROUPS}" "${BINDER}" "${VALIDATION}" "${MODE_LOCK}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 2
  fi
done

if ! python3 -c "import json,sys" >/dev/null 2>&1; then
  echo "python3 with stdlib required" >&2
  exit 2
fi

python3 - "${GATE}" "${LEDGER}" "${PARITY}" "${OWNER_GROUPS}" "${BINDER}" "${VALIDATION}" "${MODE_LOCK}" <<'PY'
import json
import sys
from pathlib import Path

(gate_path, ledger_path, parity_path, groups_path, binder_path,
 validation_path, mode_lock_path) = (Path(p) for p in sys.argv[1:8])

gate = json.loads(gate_path.read_text())
ledger = json.loads(ledger_path.read_text())
parity = parity_path.read_text().splitlines()
groups = groups_path.read_text()
binder = json.loads(binder_path.read_text())
validation = json.loads(validation_path.read_text())
mode_lock = json.loads(mode_lock_path.read_text())

errors = []

if gate.get("schema_version") != "v1":
    errors.append(f"gate schema_version != v1: {gate.get('schema_version')!r}")
if gate.get("bead") != "bd-bp8fl.3.8":
    errors.append("gate bead must be bd-bp8fl.3.8")
if gate.get("owner_family_group") != "fpg-proof-core-safety":
    errors.append("gate owner_family_group must be fpg-proof-core-safety")
if gate.get("evidence_owner") != "membrane proof and conformance-binder owners":
    errors.append("gate evidence_owner must match owner-family group")
if not gate.get("source_commit"):
    errors.append("gate source_commit must be set")

required_inputs = [
    "feature_parity",
    "feature_parity_gap_ledger",
    "feature_parity_gap_owner_family_groups",
    "proof_obligations_binder",
    "proof_binder_validation",
    "mode_contract_lock",
]
for key in required_inputs:
    rel = gate.get("inputs", {}).get(key)
    if not rel:
        errors.append(f"inputs.{key} is missing")
        continue
    abs_path = (Path(parity_path).parent / rel).resolve()
    if not abs_path.exists():
        errors.append(f"inputs.{key}: artifact not found at {rel}")

required_log_fields = [
    "trace_id",
    "bead_id",
    "gap_id",
    "section",
    "feature_parity_line",
    "claimed_status",
    "expected_status",
    "actual_status",
    "evidence_artifact",
    "evidence_anchor",
    "expected_value",
    "actual_value",
    "claim_decision",
    "replacement_level",
    "obligation_id",
    "obligation_status",
    "binder_valid",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if gate.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields must match the canonical contract")

policy = gate.get("claim_policy", {})
if policy.get("default_decision") != "block_until_proof_witness_current":
    errors.append("claim_policy.default_decision must block_until_proof_witness_current")
if "DONE" not in policy.get("block_status_without_evidence", []):
    errors.append("claim_policy must block DONE without evidence")
for level in ("L1", "L2", "L3"):
    if level not in policy.get("block_replacement_levels_without_evidence", []):
        errors.append(f"claim_policy must block replacement level {level} without evidence")
for kind in (
    "prose_only",
    "tracker_closure_only",
    "stale_obligation",
    "missing_obligation",
    "binder_invalid",
    "missing_mode_contract",
):
    if kind not in policy.get("rejected_evidence_kinds", []):
        errors.append(f"claim_policy.rejected_evidence_kinds missing {kind}")

expected_gap_ids = {
    "fp-proof-math-b821b415a5d6",
    "fp-proof-math-f3e03ea48a96",
    "fp-proof-math-0dbb786935af",
    "fp-proof-math-8c76410adba7",
    "fp-proof-math-2a49b40113a6",
    "fp-proof-math-f4c99678233a",
    "fp-proof-math-498e3ada4658",
}
rows = gate.get("rows", [])
gate_ids = {row.get("gap_id") for row in rows}
if gate_ids != expected_gap_ids:
    missing = expected_gap_ids - gate_ids
    extra = gate_ids - expected_gap_ids
    errors.append(f"gate.rows gap_ids mismatch (missing={sorted(missing)}, extra={sorted(extra)})")

ledger_index = {gap.get("gap_id"): gap for gap in ledger.get("gaps", [])}
for row in rows:
    gid = row.get("gap_id")
    ledger_gap = ledger_index.get(gid)
    if ledger_gap is None:
        errors.append(f"row {gid}: not found in feature_parity_gap_ledger")
        continue
    if ledger_gap.get("status") != row.get("claimed_status"):
        errors.append(
            f"row {gid}: claimed_status {row.get('claimed_status')!r} != ledger.status {ledger_gap.get('status')!r}"
        )

    line = row.get("feature_parity_provenance", {}).get("line")
    if not isinstance(line, int) or line < 1 or line > len(parity):
        errors.append(f"row {gid}: feature_parity_provenance.line out of range")
        continue
    line_text = parity[line - 1]
    primary = row.get("primary_key", "")
    if primary not in line_text:
        errors.append(
            f"row {gid}: FEATURE_PARITY.md:{line} missing primary_key {primary!r}"
        )
    claimed = row.get("claimed_status", "")
    if claimed and claimed not in line_text:
        errors.append(
            f"row {gid}: FEATURE_PARITY.md:{line} not {claimed} — gate must be re-run with refreshed proof witness"
        )
    if " DONE " in line_text:
        errors.append(
            f"row {gid}: FEATURE_PARITY.md:{line} now claims DONE without a proof witness"
        )

if "fpg-proof-core-safety" not in groups or "`bd-bp8fl.3.8`" not in groups:
    errors.append(
        "feature_parity_gap_owner_family_groups.v1.md must cite fpg-proof-core-safety and bd-bp8fl.3.8"
    )

if validation.get("binder_valid") is not True:
    errors.append("proof_binder_validation.binder_valid must be true")
if validation.get("total_violations", -1) != 0:
    errors.append(
        f"proof_binder_validation.total_violations must be 0; got {validation.get('total_violations')!r}"
    )
val_index = {o.get("obligation_id"): o for o in validation.get("obligations", [])}
binder_index = {o.get("id"): o for o in binder.get("obligations", [])}
for row in rows:
    gid = row.get("gap_id", "?")
    for anchor in row.get("evidence_anchors", []):
        po = anchor.get("obligation_id")
        if not po:
            continue
        val_row = val_index.get(po)
        if val_row is None:
            errors.append(
                f"row {gid}: obligation {po} cited but absent from proof_binder_validation"
            )
            continue
        if val_row.get("valid") is not True:
            errors.append(
                f"row {gid}: obligation {po} must be valid=true in proof_binder_validation"
            )
        if po not in binder_index:
            errors.append(
                f"row {gid}: obligation {po} absent from proof_obligations_binder"
            )

allowed_modes = mode_lock.get("env_contract", {}).get("allowed_values", [])
for required in ("strict", "hardened"):
    if required not in allowed_modes:
        errors.append(f"mode_contract_lock.env_contract.allowed_values missing {required}")

print(json.dumps(
    {
        "bead": "bd-bp8fl.3.8",
        "gate": "fpg-proof-core-safety",
        "rows": len(rows),
        "binder_valid": validation.get("binder_valid"),
        "total_violations": validation.get("total_violations"),
        "errors": errors,
        "status": "pass" if not errors else "fail",
    },
    indent=2,
))
sys.exit(0 if not errors else 1)
PY

if [[ "${MODE}" == "validate-only" ]]; then
  exit 0
fi

cd "${ROOT}"
if [[ "${MODE}" == "rch" ]]; then
  if ! command -v rch >/dev/null 2>&1; then
    echo "rch not available; rerun with --local if you must" >&2
    exit 2
  fi
  exec rch exec -- cargo test -p frankenlibc-harness --test fpg_proof_core_safety_gate_test
fi

exec cargo test -p frankenlibc-harness --test fpg_proof_core_safety_gate_test
