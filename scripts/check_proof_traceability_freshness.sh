#!/usr/bin/env bash
# check_proof_traceability_freshness.sh -- bd-bp8fl.9.6
#
# Refuses to advance README/FEATURE_PARITY/release proof claims unless every
# proof_obligations_binder source_ref still resolves to file:line in the
# current commit, and the snapshot envelope (proof_binder_validation +
# proof_traceability_check) agrees with the binder.
#
# Modes:
#   --validate-only  static structural and source-ref checks only (no cargo)
#   --rch (default)  delegate the rust harness test to rch exec
#   --local          run cargo locally (only if rch is unavailable)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${ROOT}/tests/conformance/proof_traceability_freshness_gate.v1.json"
BINDER="${ROOT}/tests/conformance/proof_obligations_binder.v1.json"
VALIDATION="${ROOT}/tests/conformance/proof_binder_validation.v1.json"
TRACE_CHECK="${ROOT}/tests/conformance/proof_traceability_check.json"

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
  --validate-only   Static structural + source-ref checks (no cargo compile).
  --local           Run 'cargo test' locally (only if rch is unavailable).
USAGE
    exit 0
    ;;
  *)
    echo "$0: unknown mode ${1:-}" >&2
    exit 2
    ;;
esac

for f in "${GATE}" "${BINDER}" "${VALIDATION}" "${TRACE_CHECK}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required input: $f" >&2
    exit 2
  fi
done

if ! python3 -c "import json,sys" >/dev/null 2>&1; then
  echo "python3 with stdlib required" >&2
  exit 2
fi

python3 - "${ROOT}" "${GATE}" "${BINDER}" "${VALIDATION}" "${TRACE_CHECK}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
gate = json.loads(Path(sys.argv[2]).read_text())
binder = json.loads(Path(sys.argv[3]).read_text())
validation = json.loads(Path(sys.argv[4]).read_text())
traceability = json.loads(Path(sys.argv[5]).read_text())

errors = []

if gate.get("schema_version") != "v1":
    errors.append("gate.schema_version != v1")
if gate.get("bead") != "bd-bp8fl.9.6":
    errors.append("gate.bead must be bd-bp8fl.9.6")
if not gate.get("source_commit"):
    errors.append("gate.source_commit must be set")

required_log_fields = [
    "trace_id",
    "bead_id",
    "obligation_id",
    "category",
    "source_ref",
    "ref_kind",
    "freshness_state",
    "verifier_status",
    "expected",
    "actual",
    "claim_id",
    "claim_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
]
if gate.get("required_log_fields") != required_log_fields:
    errors.append("required_log_fields must match the canonical contract")

policy = gate.get("freshness_policy", {})
if policy.get("default_decision") != "block_until_all_source_refs_resolve":
    errors.append("freshness_policy.default_decision must be block_until_all_source_refs_resolve")
for kind in ("file_line", "file_only"):
    if kind not in policy.get("ref_kinds_required", []):
        errors.append(f"ref_kinds_required missing {kind}")
for kind in (
    "stale_source_ref",
    "missing_file",
    "out_of_range_line",
    "binder_invalid",
    "obligation_count_drift",
    "envelope_violations",
):
    if kind not in policy.get("rejected_evidence_kinds", []):
        errors.append(f"rejected_evidence_kinds missing {kind}")

# Source-ref freshness re-validation.
broken = []
unique = set()
total_refs = 0
for ob in binder.get("obligations", []):
    ob_id = ob.get("id", "?")
    for ref in ob.get("source_refs", []) or []:
        total_refs += 1
        unique.add(ref)
        if ":" in ref:
            path_s, line_s = ref.rsplit(":", 1)
            try:
                line = int(line_s)
            except ValueError:
                broken.append(f"{ob_id}: malformed source_ref {ref}")
                continue
        else:
            path_s, line = ref, None
        p = root / path_s
        if not p.exists():
            broken.append(f"{ob_id}: missing_file {ref}")
            continue
        if line is None:
            continue
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                n = sum(1 for _ in fh)
        except OSError as exc:
            broken.append(f"{ob_id}: read_error {ref}: {exc}")
            continue
        if line < 1 or line > n:
            broken.append(f"{ob_id}: out_of_range {ref} (file has {n} lines)")
errors.extend(broken)
if total_refs == 0:
    errors.append("binder must declare at least one source_ref")
if not unique:
    errors.append("binder must declare at least one unique source_ref")

# Envelope drift.
env_req = policy.get("envelope_requirements", {})
if env_req.get("binder_valid") and validation.get("binder_valid") is not True:
    errors.append("proof_binder_validation.binder_valid must be true")
if env_req.get("binder_valid") and traceability.get("binder_valid") is not True:
    errors.append("proof_traceability_check.binder_valid must be true")
max_v = env_req.get("total_violations_max", 0)
if validation.get("total_violations", -1) > max_v:
    errors.append(
        f"proof_binder_validation.total_violations {validation.get('total_violations')!r} exceeds max {max_v}"
    )

binder_count = len(binder.get("obligations", []))
val_count = len(validation.get("obligations", []))
trace_count = len(traceability.get("obligations", []))
if env_req.get("obligation_count_must_match_binder"):
    if val_count != binder_count:
        errors.append(
            f"proof_binder_validation obligation count {val_count} != binder {binder_count}"
        )
    if trace_count != binder_count:
        errors.append(
            f"proof_traceability_check obligation count {trace_count} != binder {binder_count}"
        )
    if validation.get("total_obligations") != binder_count:
        errors.append(
            f"proof_binder_validation.total_obligations != binder count ({binder_count})"
        )

if env_req.get("categories_covered_must_match_binder"):
    binder_cats = sorted({ob.get("category") for ob in binder.get("obligations", []) if ob.get("category")})
    val_cats = sorted(validation.get("categories_covered", []) or [])
    if binder_cats != val_cats:
        errors.append(
            f"categories_covered drift: binder={binder_cats}, validation={val_cats}"
        )

# Category in-scope and minimums.
in_scope = set(gate.get("categories_in_scope", []))
declared = set((binder.get("categories") or {}).keys())
unscoped = declared - in_scope
if unscoped:
    errors.append(f"binder declares categories not in gate scope: {sorted(unscoped)}")
counts = {}
for ob in binder.get("obligations", []):
    c = ob.get("category")
    if c:
        counts[c] = counts.get(c, 0) + 1
for cat, min_n in (gate.get("minimum_obligations_per_category") or {}).items():
    if counts.get(cat, 0) < int(min_n):
        errors.append(
            f"category {cat}: {counts.get(cat, 0)} obligations < minimum {min_n}"
        )

print(json.dumps(
    {
        "bead": "bd-bp8fl.9.6",
        "gate": "proof-traceability-freshness",
        "binder_obligations": binder_count,
        "validation_obligations": val_count,
        "total_source_refs": total_refs,
        "unique_source_refs": len(unique),
        "broken_source_refs": len(broken),
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
  exec rch exec -- cargo test -p frankenlibc-harness --test proof_traceability_freshness_test
fi

exec cargo test -p frankenlibc-harness --test proof_traceability_freshness_test
