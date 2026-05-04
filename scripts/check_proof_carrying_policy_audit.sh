#!/usr/bin/env bash
# check_proof_carrying_policy_audit.sh -- bd-bp8fl.9.3
#
# Fail-closed audit binder for the runtime_math/policy_table.rs PCPT
# loader. Refuses to advance proof-carrying policy claims when:
#   * any cited schema constant (MAGIC, HEADER_LEN, SCHEMA_VERSION_V1,
#     KEY_SPEC_ID_V1, CELL_SPEC_ID_V1, RISK/BUDGET/CONSISTENCY_BUCKETS)
#     drifts from the source pattern,
#   * any required TLV type or its missing-error variant is removed,
#   * any cited PolicyTableError variant is removed from enum or Display,
#   * any cited negative or positive test name is missing.
#
# Modes:
#   --validate-only  static structural checks only (no cargo)
#   --rch (default)  delegate the rust harness test to rch exec
#   --local          run cargo locally (only if rch is unavailable)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="${ROOT}/tests/conformance/proof_carrying_policy_audit.v1.json"
SOURCE="${ROOT}/crates/frankenlibc-membrane/src/runtime_math/policy_table.rs"
DESIGN="${ROOT}/crates/frankenlibc-membrane/src/runtime_math/proof_carrying_policy_tables.md"

MODE="rch"
case "${1:-}" in
  ""|--rch) MODE="rch" ;;
  --validate-only) MODE="validate-only" ;;
  --local) MODE="local" ;;
  -h|--help)
    cat <<USAGE
Usage: $0 [--rch | --validate-only | --local]
USAGE
    exit 0
    ;;
  *) echo "$0: unknown mode ${1:-}" >&2; exit 2 ;;
esac

for f in "${AUDIT}" "${SOURCE}" "${DESIGN}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 2
  fi
done

if ! python3 -c "import json,sys" >/dev/null 2>&1; then
  echo "python3 with stdlib required" >&2
  exit 2
fi

python3 - "${AUDIT}" "${SOURCE}" "${DESIGN}" <<'PY'
import json
import re
import sys
from pathlib import Path

audit_path, source_path, design_path = (Path(p) for p in sys.argv[1:4])
audit = json.loads(audit_path.read_text())
source = source_path.read_text()
design = design_path.read_text()

errors = []

if audit.get("schema_version") != "v1":
    errors.append("audit.schema_version must be v1")
if audit.get("bead") != "bd-bp8fl.9.3":
    errors.append("audit.bead must be bd-bp8fl.9.3")
if not audit.get("source_commit"):
    errors.append("audit.source_commit must be set")

required_log_fields = [
    "trace_id",
    "bead_id",
    "audit_row_id",
    "anchor_kind",
    "subject_path",
    "expected",
    "actual",
    "verifier_decision",
    "freshness_state",
    "policy_id",
    "proof_hash",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if audit.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields must match the canonical contract")

policy = audit.get("policy", {})
if policy.get("default_decision") != "block_until_audit_anchors_resolve":
    errors.append("policy.default_decision must be block_until_audit_anchors_resolve")
if "DONE" not in policy.get("block_status_without_evidence", []):
    errors.append("policy must block DONE without evidence")
for level in ("L1", "L2", "L3"):
    if level not in policy.get("block_replacement_levels_without_evidence", []):
        errors.append(f"policy must block replacement level {level}")
for kind in (
    "missing_constant",
    "constant_drift",
    "missing_error_variant",
    "missing_required_tlv",
    "missing_negative_test",
    "stale_source_commit",
    "verifier_failure",
):
    if kind not in policy.get("rejected_evidence_kinds", []):
        errors.append(f"rejected_evidence_kinds missing {kind}")

# Schema constants
for entry in audit.get("schema_constants", []):
    pattern = entry.get("source_pattern", "")
    if pattern not in source:
        errors.append(
            f"schema_constant {entry.get('id')}: pattern {pattern!r} not in policy_table.rs"
        )

# Required TLVs
for entry in audit.get("required_tlvs", []):
    tlv = entry.get("tlv_type", "")
    name = entry.get("name", "?")
    if tlv not in source:
        errors.append(f"required_tlv {name} ({tlv}) not referenced in policy_table.rs")
    miss = entry.get("missing_error", "")
    if miss and miss not in source:
        errors.append(f"required_tlv {name}: missing_error {miss} not in policy_table.rs")
    size = entry.get("required_size")
    if isinstance(size, int) and f"tlv.v.len() != {size}" not in source:
        errors.append(
            f"required_tlv {name}: size invariant `tlv.v.len() != {size}` not enforced"
        )

# PolicyTableError variants
enum_match = re.search(r"pub enum PolicyTableError \{(?P<body>.*?)\n\}\n", source, re.DOTALL)
if not enum_match:
    errors.append("PolicyTableError enum block not located in policy_table.rs")
    enum_body = ""
else:
    enum_body = enum_match.group("body")

for variant in audit.get("error_variants", []):
    needles = (f"    {variant},", f"    {variant} {{")
    if not any(n in enum_body for n in needles):
        errors.append(f"PolicyTableError::{variant} not present in enum body")
    if f"Self::{variant}" not in source:
        errors.append(f"PolicyTableError::{variant} not surfaced in Display impl")

# Required negative tests
for entry in audit.get("required_negative_tests", []):
    name = entry.get("test_name", "")
    if f"    fn {name}()" not in source:
        errors.append(f"required negative test {name} not present in policy_table.rs")
    variant = entry.get("error_variant", "")
    if variant and variant not in source:
        errors.append(f"required negative test {name}: variant {variant} missing")

# Required positive tests
for name in audit.get("required_positive_tests", []):
    if f"    fn {name}()" not in source:
        errors.append(f"required positive test {name} not present in policy_table.rs")

# Verification command sanity
cmd = audit.get("verification_command", "")
for marker in ("rch exec", "cargo test", "-p frankenlibc-membrane", "policy_table"):
    if marker not in cmd:
        errors.append(f"verification_command missing marker {marker!r}")

print(json.dumps(
    {
        "bead": "bd-bp8fl.9.3",
        "gate": "proof-carrying-policy-audit",
        "subject": audit.get("subject", {}).get("module"),
        "schema_constants": len(audit.get("schema_constants", [])),
        "required_tlvs": len(audit.get("required_tlvs", [])),
        "error_variants": len(audit.get("error_variants", [])),
        "required_negative_tests": len(audit.get("required_negative_tests", [])),
        "required_positive_tests": len(audit.get("required_positive_tests", [])),
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
  exec rch exec -- cargo test -p frankenlibc-harness --test proof_carrying_policy_audit_test
fi

exec cargo test -p frankenlibc-harness --test proof_carrying_policy_audit_test
