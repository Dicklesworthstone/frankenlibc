#!/usr/bin/env bash
# check_fpg_claim_control_gate.sh -- bd-bp8fl.3.5
#
# Fail-closed gate for the eight `fpg-claim-control` gaps in
# tests/conformance/feature_parity_gap_ledger.v1.json. Drives the binder at
# tests/conformance/fpg_claim_control_gate.v1.json:
#   * every macro-coverage-target row in FEATURE_PARITY.md must remain bound
#     to the cited primary key + IN_PROGRESS status,
#   * every evidence anchor must resolve in the cited source artifact at the
#     expected value/threshold,
#   * the machine_delta sentinel row must remain visible until the linked
#     POSIX/GNU completeness row can promote on machine evidence.
#
# Modes:
#   --validate-only  static structural checks only (does not invoke cargo)
#   --rch (default)  delegate the rust harness test to rch exec
#   --local          run cargo locally (only if rch is unavailable)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${ROOT}/tests/conformance/fpg_claim_control_gate.v1.json"
LEDGER="${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json"
PARITY="${ROOT}/FEATURE_PARITY.md"
OWNER_GROUPS="${ROOT}/tests/conformance/feature_parity_gap_owner_family_groups.v1.md"

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

for f in "${GATE}" "${LEDGER}" "${PARITY}" "${OWNER_GROUPS}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 2
  fi
done

if ! python3 -c "import json,sys" >/dev/null 2>&1; then
  echo "python3 with stdlib required" >&2
  exit 2
fi

python3 - "${GATE}" "${LEDGER}" "${PARITY}" "${OWNER_GROUPS}" <<'PY'
import json
import sys
from pathlib import Path

gate_path, ledger_path, parity_path, groups_path = (Path(p) for p in sys.argv[1:5])

gate = json.loads(gate_path.read_text())
ledger = json.loads(ledger_path.read_text())
parity = parity_path.read_text().splitlines()
groups = groups_path.read_text()

errors = []

if gate.get("schema_version") != "v1":
    errors.append(f"gate schema_version != v1: {gate.get('schema_version')!r}")
if gate.get("bead") != "bd-bp8fl.3.5":
    errors.append(f"gate bead != bd-bp8fl.3.5: {gate.get('bead')!r}")
if gate.get("owner_family_group") != "fpg-claim-control":
    errors.append("gate owner_family_group must be fpg-claim-control")
if gate.get("evidence_owner") != "docs/conformance release-gate owners":
    errors.append("gate evidence_owner must match owner-family group")
if not gate.get("source_commit"):
    errors.append("gate source_commit must be set")

required_inputs = [
    "feature_parity",
    "support_matrix",
    "replacement_levels",
    "reality_report",
    "semantic_contract_inventory",
    "feature_parity_gap_ledger",
    "feature_parity_gap_owner_family_groups",
    "hardened_repair_deny_matrix",
    "conformance_matrix",
    "perf_baseline_spec",
    "version_script",
]
for key in required_inputs:
    rel = gate.get("inputs", {}).get(key)
    if not rel:
        errors.append(f"inputs.{key} is missing")
        continue
    abs_path = parity_path.parent / rel if not rel.startswith("/") else Path(rel)
    abs_path = (parity_path.parent / rel).resolve()
    abs_path = (Path(parity_path).parent / rel)
    abs_path = abs_path.resolve()
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
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if gate.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields must match the canonical contract")

policy = gate.get("claim_policy", {})
if policy.get("default_decision") != "block_until_evidence_current":
    errors.append("claim_policy.default_decision must block_until_evidence_current")
if "DONE" not in policy.get("block_status_without_evidence", []):
    errors.append("claim_policy must block DONE without evidence")
for level in ("L1", "L2", "L3"):
    if level not in policy.get("block_replacement_levels_without_evidence", []):
        errors.append(f"claim_policy must block replacement level {level} without evidence")

expected_gap_ids = {
    "fp-macro-targets-fa7a23e18f01",
    "fp-macro-targets-7b75050a0f03",
    "fp-macro-targets-025864627e97",
    "fp-macro-targets-b1b8d5acbeff",
    "fp-macro-targets-b1983d62901c",
    "fp-macro-targets-556631616b22",
    "fp-macro-targets-1e330b896784",
    "gap-macro-fp-macro-targets-fa7a23e18f01",
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
    if row.get("kind") == "feature_parity_row_status":
        line_text = parity[line - 1]
        primary = row.get("primary_key", "")
        if primary not in line_text:
            errors.append(
                f"row {gid}: FEATURE_PARITY.md:{line} missing primary_key {primary!r}"
            )
        if "IN_PROGRESS" not in line_text:
            errors.append(
                f"row {gid}: FEATURE_PARITY.md:{line} not IN_PROGRESS — gate must be re-run with refreshed evidence"
            )

if "fpg-claim-control" not in groups or "`bd-bp8fl.3.5`" not in groups:
    errors.append(
        "feature_parity_gap_owner_family_groups.v1.md must cite fpg-claim-control and bd-bp8fl.3.5"
    )

print(json.dumps(
    {
        "bead": "bd-bp8fl.3.5",
        "gate": "fpg-claim-control",
        "rows": len(rows),
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
  exec rch exec -- cargo test -p frankenlibc-harness --test fpg_claim_control_gate_test
fi

exec cargo test -p frankenlibc-harness --test fpg_claim_control_gate_test
