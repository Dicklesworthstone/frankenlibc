#!/usr/bin/env bash
# check_proof_program_e2e.sh - bd-e4phe.5 proof-program E2E gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FRANKENLIBC_PROOF_PROGRAM_E2E_MANIFEST:-${ROOT}/tests/conformance/proof_program_e2e.v1.json}"
DECISION="${FRANKENLIBC_PROOF_PROGRAM_E2E_DECISION:-}"
BINDER="${FRANKENLIBC_PROOF_PROGRAM_E2E_BINDER:-}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_PROOF_PROGRAM_E2E_REPORT:-${OUT_DIR}/proof_program_e2e.report.json}"
LOG="${FRANKENLIBC_PROOF_PROGRAM_E2E_LOG:-${OUT_DIR}/proof_program_e2e.log.jsonl}"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${MANIFEST}" "${DECISION}" "${BINDER}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
decision_override = sys.argv[3]
binder_override = sys.argv[4]
report_path = Path(sys.argv[5])
log_path = Path(sys.argv[6])

errors = []
events = []


def load_json(path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        errors.append(f"failed to load {path}: {exc}")
        return {}


def rel_path(value):
    path = Path(value)
    return path if path.is_absolute() else root / path


def require(condition, message):
    if not condition:
        errors.append(message)


def as_list(value):
    return value if isinstance(value, list) else []


def emit(event, status, details):
    row = {
        "trace_id": f"bd-e4phe.5:{event}",
        "event": event,
        "status": status,
        "bead_id": "bd-e4phe.5",
        "mode": "reframe_as_tested_invariant_catalogs",
        "claim_decision": "tested_invariant_catalog_only",
        "artifact_refs": [
            "tests/conformance/proof_program_e2e.v1.json",
            "tests/conformance/proof_program_owner_decision.v1.json",
            "tests/conformance/proof_obligations_binder.v1.json",
            "README.md",
            "FEATURE_PARITY.md",
        ],
        "failure_signature": "none" if status == "pass" else "proof_program_e2e_failed",
        "details": details,
    }
    events.append(row)


started_ns = time.monotonic_ns()
manifest = load_json(manifest_path)
inputs = manifest.get("inputs", {})
decision_path = Path(decision_override) if decision_override else rel_path(inputs.get("decision", ""))
binder_path = Path(binder_override) if binder_override else rel_path(inputs.get("binder", ""))
readme_path = rel_path(inputs.get("readme", "README.md"))
feature_parity_path = rel_path(inputs.get("feature_parity", "FEATURE_PARITY.md"))

decision = load_json(decision_path)
binder = load_json(binder_path)
readme = readme_path.read_text(encoding="utf-8", errors="replace") if readme_path.exists() else ""
feature_parity = feature_parity_path.read_text(encoding="utf-8", errors="replace") if feature_parity_path.exists() else ""

require(manifest.get("schema") == "proof_program_e2e.v1", "manifest schema mismatch")
require(manifest.get("bead") == "bd-e4phe.5", "manifest bead must be bd-e4phe.5")
require(manifest.get("mode") == "reframe_as_tested_invariant_catalogs", "manifest mode mismatch")

required_decision = manifest.get("required_decision", {})
decision_body = decision.get("decision", {})
mechanization = decision.get("mechanization_deferral", {})
claim_policy = decision.get("claim_policy", {})

require(decision_body.get("choice") == required_decision.get("choice"), "decision.choice mismatch")
require(
    decision_body.get("machine_checked_formal_proof_status")
    == required_decision.get("machine_checked_formal_proof_status"),
    "machine_checked_formal_proof_status mismatch",
)
require(
    mechanization.get("status") == required_decision.get("mechanization_status"),
    "mechanization deferral status mismatch",
)
require(mechanization.get("bead") == required_decision.get("mechanization_bead"), "mechanization bead mismatch")
require(
    "completed_machine_checked_formal_proofs" in as_list(claim_policy.get("block_public_claims")),
    "claim_policy must block completed machine-checked formal proofs",
)
future_artifacts = as_list(mechanization.get("required_future_artifacts"))
require(len(future_artifacts) == 4, "mechanization deferral must list four future theorem artifacts")
for artifact in future_artifacts:
    require(artifact.get("current_status") == "deferred", f"future artifact not deferred: {artifact}")
    require("machine-checked proof" in artifact.get("artifact_kind", ""), f"future artifact kind is not explicit: {artifact}")

emit(
    "proof_program_decision_validated",
    "pass" if not errors else "fail",
    {"future_artifacts": len(future_artifacts), "decision_path": str(decision_path)},
)

required_binder = manifest.get("required_binder", {})
obligations = as_list(binder.get("obligations"))
allowed_statuses = set(as_list(required_binder.get("allowed_statuses")))
expected_reframe_status = required_binder.get("expected_reframe_status")
target_bead = required_binder.get("required_deferred_target_bead")

require(
    binder.get("resolution_policy", {}).get("decision_artifact")
    == required_binder.get("decision_artifact"),
    "binder resolution_policy decision_artifact mismatch",
)
require(len(obligations) >= int(required_binder.get("minimum_obligations", 0)), "binder obligation count below minimum")
for obligation in obligations:
    oid = obligation.get("id", "?")
    status = obligation.get("status")
    require(status in allowed_statuses, f"{oid}: status {status!r} is not an allowed final status")
    require(status == expected_reframe_status, f"{oid}: reframe mode requires status {expected_reframe_status!r}")
    require(obligation.get("target_bead") == target_bead, f"{oid}: deferred target_bead mismatch")
    require(bool(str(obligation.get("deferred_reason", "")).strip()), f"{oid}: missing deferred_reason")
    require(bool(str(obligation.get("target_resolution", "")).strip()), f"{oid}: missing target_resolution")

emit(
    "proof_program_binder_validated",
    "pass" if not errors else "fail",
    {"obligations": len(obligations), "target_bead": target_bead},
)

combined_docs = f"{readme}\n{feature_parity}"
for phrase in as_list(manifest.get("required_source_phrases")):
    require(phrase in combined_docs, f"required proof-status phrase missing from docs: {phrase}")

for source_ref in as_list(decision.get("source_refs")):
    path = rel_path(source_ref.get("path", ""))
    line_no = int(source_ref.get("line", 0))
    expected = source_ref.get("must_contain", "")
    require(path.exists(), f"source ref path missing: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    actual = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
    require(expected in actual, f"{path}:{line_no} missing expected wording {expected!r}")

emit(
    "proof_program_doc_language_validated",
    "pass" if not errors else "fail",
    {"source_refs": len(as_list(decision.get("source_refs")))},
)

required_events = set(as_list(manifest.get("required_events")))
actual_events = {row["event"] for row in events}
require(required_events.issubset(actual_events), f"missing required events: {sorted(required_events - actual_events)}")

required_fields = set(as_list(manifest.get("required_log_fields")))
for row in events:
    missing = sorted(field for field in required_fields if field not in row)
    require(not missing, f"log row {row['event']} missing fields {missing}")

status = "pass" if not errors else "fail"
for row in events:
    if status == "fail":
        row["status"] = "fail"
        row["failure_signature"] = "proof_program_e2e_failed"

report = {
    "schema": "proof_program_e2e.report.v1",
    "status": status,
    "bead": "bd-e4phe.5",
    "mode": manifest.get("mode"),
    "errors": errors,
    "summary": {
        "future_artifacts": len(future_artifacts),
        "obligations": len(obligations),
        "source_refs": len(as_list(decision.get("source_refs"))),
        "events": len(events),
        "latency_ns": time.monotonic_ns() - started_ns,
    },
    "events": [row["event"] for row in events],
    "required_fields": sorted(required_fields),
}

log_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in events) + "\n")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if errors:
    print(f"FAIL: proof program e2e ({len(errors)} errors)", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: proof program e2e "
    f"(future_artifacts={len(future_artifacts)}, obligations={len(obligations)}, "
    f"source_refs={len(as_list(decision.get('source_refs')))}, report={report_path.relative_to(root)})"
)
PY
