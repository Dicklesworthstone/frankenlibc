#!/usr/bin/env bash
# check_standalone_readiness_matrix.sh -- CI gate for bd-bp8fl.6.6
#
# Validates that L2/L3 standalone replacement readiness is represented as
# proof obligations with explicit blockers, artifacts, tests, e2e/smoke gates,
# structured logs, and negative claim-block checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/standalone_readiness_proof_matrix.v1.json"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/standalone_readiness_proof_matrix.report.json"
LOG="${OUT_DIR}/standalone_readiness_proof_matrix.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${MATRIX}" "${LEVELS}" "${REPORT}" "${LOG}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
levels_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

errors = []
checks = {}

REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "proof_row_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "artifact_refs",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "expected_decision",
    "actual_decision",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_PROOF_ROW_FIELDS = [
    "proof_row_id",
    "surface",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "artifact_refs",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "expected_decision",
    "actual_decision",
    "failure_signature",
]
REQUIRED_OBLIGATION_FIELDS = [
    "id",
    "level",
    "dimension",
    "title",
    "requirement",
    "current_state",
    "blocker_reason",
    "evidence_artifacts",
    "check_commands",
    "unit_tests_required",
    "e2e_or_smoke_required",
    "log_fields",
    "negative_claim_tests",
]
REQUIRED_LEVELS = {"L2", "L3"}

def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return None

def repo_relative_path(ref, context):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: artifact ref must be a non-empty string")
        return None
    rel = Path(ref)
    if rel.is_absolute() or ".." in rel.parts:
        errors.append(f"{context}: artifact ref must stay repo-relative: {ref}")
        return None
    return root / rel

matrix = load_json(matrix_path)
levels = load_json(levels_path)
checks["json_parse"] = "pass" if isinstance(matrix, dict) and isinstance(levels, dict) else "fail"
if not isinstance(matrix, dict):
    matrix = {}
if not isinstance(levels, dict):
    levels = {}

if matrix.get("schema_version") == "v1" and matrix.get("bead") == "bd-bp8fl.6.6":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    errors.append("matrix must declare schema_version=v1 and bead=bd-bp8fl.6.6")

if matrix.get("required_log_fields") == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    errors.append("required_log_fields must match the standard structured log contract")

level_by_id = {entry.get("level"): entry for entry in levels.get("levels", [])}
claim_policy = matrix.get("claim_policy", {})
current_level_ok = (
    levels.get("current_level") == "L0"
    and levels.get("release_tag_policy", {}).get("current_release_level") == "L0"
    and claim_policy.get("current_level_must_remain") == "L0"
)
checks["current_level_guard"] = "pass" if current_level_ok else "fail"
if not current_level_ok:
    errors.append("current_level and current release level must remain L0 while standalone evidence is blocked")

readiness_levels = matrix.get("readiness_levels", [])
readiness_ids = {entry.get("level") for entry in readiness_levels}
readiness_ok = readiness_ids == REQUIRED_LEVELS
for entry in readiness_levels:
    level = entry.get("level")
    if entry.get("current_claim_status") != "blocked" or not entry.get("blocked_reason"):
        readiness_ok = False
        errors.append(f"{level}: readiness level must be blocked with a blocked_reason")
    if level == "L2" and level_by_id.get("L2", {}).get("status") != "planned":
        readiness_ok = False
        errors.append("replacement_levels L2 status must remain planned for this matrix")
    if level == "L3" and level_by_id.get("L3", {}).get("status") != "roadmap":
        readiness_ok = False
        errors.append("replacement_levels L3 status must remain roadmap for this matrix")
checks["readiness_levels"] = "pass" if readiness_ok else "fail"

required_proof_surfaces = set(matrix.get("required_proof_surfaces", []))
proof_rows = matrix.get("proof_rows", [])
proof_row_ids = [row.get("proof_row_id") for row in proof_rows]
proof_surfaces = Counter()
proof_rows_ok = bool(proof_rows) and len(proof_row_ids) == len(set(proof_row_ids))
claim_blocked_proof_rows = 0
missing_evidence_proof_rows = 0

for row in proof_rows:
    proof_row_id = row.get("proof_row_id", "<missing proof row id>")
    for field in REQUIRED_PROOF_ROW_FIELDS:
        if field not in row:
            proof_rows_ok = False
            errors.append(f"{proof_row_id}: missing proof row field {field}")

    surface = row.get("surface")
    if surface not in required_proof_surfaces:
        proof_rows_ok = False
        errors.append(f"{proof_row_id}: unknown proof surface {surface}")
    else:
        proof_surfaces[surface] += 1

    if row.get("replacement_level") not in REQUIRED_LEVELS:
        proof_rows_ok = False
        errors.append(f"{proof_row_id}: replacement_level must be L2 or L3")

    if row.get("expected_decision") != "claim_blocked" or row.get("actual_decision") != "claim_blocked":
        proof_rows_ok = False
        errors.append(f"{proof_row_id}: current standalone proof rows must remain claim_blocked")
    else:
        claim_blocked_proof_rows += 1

    for evidence_field in ["required_evidence", "present_evidence", "missing_evidence"]:
        if not row.get(evidence_field):
            proof_rows_ok = False
            errors.append(f"{proof_row_id}: {evidence_field} must not be empty")
    if row.get("missing_evidence"):
        missing_evidence_proof_rows += 1

    for ref in row.get("artifact_refs", []):
        artifact_path = repo_relative_path(ref, proof_row_id)
        if artifact_path is None or not artifact_path.exists():
            proof_rows_ok = False
            errors.append(f"{proof_row_id}: artifact ref does not exist: {ref}")

missing_proof_surfaces = sorted(required_proof_surfaces - set(proof_surfaces))
if missing_proof_surfaces:
    proof_rows_ok = False
    errors.append("missing proof surfaces: " + ", ".join(missing_proof_surfaces))
checks["proof_rows"] = "pass" if proof_rows_ok else "fail"

required_dimensions = set(matrix.get("required_dimensions", []))
obligations = matrix.get("obligations", [])
obligation_ids = [obligation.get("id") for obligation in obligations]
dimension_coverage = Counter()
by_level = Counter()
negative_count = 0
blocked_count = 0
obligations_ok = bool(obligations) and len(obligation_ids) == len(set(obligation_ids))

for obligation in obligations:
    oid = obligation.get("id", "<missing obligation id>")
    for field in REQUIRED_OBLIGATION_FIELDS:
        if field not in obligation:
            obligations_ok = False
            errors.append(f"{oid}: missing field {field}")

    level = obligation.get("level")
    if level not in REQUIRED_LEVELS:
        obligations_ok = False
        errors.append(f"{oid}: level must be L2 or L3")
    else:
        by_level[level] += 1

    dimensions = [obligation.get("dimension")]
    dimensions.extend(obligation.get("secondary_dimensions", []))
    for dimension in dimensions:
        if dimension not in required_dimensions:
            obligations_ok = False
            errors.append(f"{oid}: unknown dimension {dimension}")
        else:
            dimension_coverage[dimension] += 1

    if obligation.get("current_state") == "blocked":
        blocked_count += 1
    else:
        obligations_ok = False
        errors.append(f"{oid}: current_state must be blocked")

    for ref in obligation.get("evidence_artifacts", []):
        artifact_path = repo_relative_path(ref, oid)
        if artifact_path is None or not artifact_path.exists():
            obligations_ok = False
            errors.append(f"{oid}: evidence artifact does not exist: {ref}")

    for command in obligation.get("check_commands", []):
        script = command.split()[0]
        script_path = repo_relative_path(script, oid)
        if script_path is None or not script_path.exists():
            obligations_ok = False
            errors.append(f"{oid}: check command script does not exist: {script}")

    if not obligation.get("unit_tests_required"):
        obligations_ok = False
        errors.append(f"{oid}: unit_tests_required must not be empty")
    if not obligation.get("e2e_or_smoke_required"):
        obligations_ok = False
        errors.append(f"{oid}: e2e_or_smoke_required must not be empty")
    if obligation.get("log_fields") != "required_log_fields":
        obligations_ok = False
        errors.append(f"{oid}: log_fields must reference required_log_fields")

    negative_tests = obligation.get("negative_claim_tests", [])
    if not negative_tests:
        obligations_ok = False
        errors.append(f"{oid}: negative_claim_tests must not be empty")
    for test in negative_tests:
        negative_count += 1
        if test.get("expected_result") != "claim_blocked":
            obligations_ok = False
            errors.append(f"{oid}: negative test must expect claim_blocked")
        for field in ["unsupported_condition", "advertised_claim_blocked"]:
            if not test.get(field):
                obligations_ok = False
                errors.append(f"{oid}: negative test missing {field}")

checks["obligations"] = "pass" if obligations_ok else "fail"

missing_dimensions = sorted(required_dimensions - set(dimension_coverage))
if not missing_dimensions:
    checks["dimension_coverage"] = "pass"
else:
    checks["dimension_coverage"] = "fail"
    errors.append("missing required dimensions: " + ", ".join(missing_dimensions))

claim_policy_ok = (
    claim_policy.get("l2_current_claim_status") == "blocked"
    and claim_policy.get("l3_current_claim_status") == "blocked"
    and claim_policy.get("symbol_counts_are_insufficient") is True
    and claim_policy.get("missing_evidence_result") == "claim_blocked"
    and claim_policy.get("interpose_value_is_not_standalone_readiness") is True
    and negative_count >= len(obligations)
)
checks["claim_policy"] = "pass" if claim_policy_ok else "fail"
if not claim_policy_ok:
    errors.append("claim policy must block L2/L3 overclaims and require negative claim tests")

summary = matrix.get("summary", {})
summary_ok = (
    summary.get("readiness_level_count") == len(readiness_levels)
    and summary.get("proof_row_count") == len(proof_rows)
    and summary.get("obligation_count") == len(obligations)
    and summary.get("negative_claim_test_count") == negative_count
    and summary.get("blocked_obligation_count") == blocked_count
    and summary.get("claim_blocked_proof_row_count") == claim_blocked_proof_rows
    and summary.get("missing_evidence_proof_row_count") == missing_evidence_proof_rows
    and summary.get("by_level") == dict(by_level)
    and summary.get("dimension_coverage") == dict(dimension_coverage)
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    errors.append("summary counts do not match obligations, dimensions, blocked states, and negative tests")

try:
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except Exception:
    source_commit = "unknown"

status = "pass" if not errors else "fail"
artifact_refs = [
    "tests/conformance/standalone_readiness_proof_matrix.v1.json",
    "tests/conformance/replacement_levels.json",
    "target/conformance/standalone_readiness_proof_matrix.report.json",
    "target/conformance/standalone_readiness_proof_matrix.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.6.6",
    "status": status,
    "checks": checks,
    "readiness_level_count": len(readiness_levels),
    "proof_row_count": len(proof_rows),
    "obligation_count": len(obligations),
    "negative_claim_test_count": negative_count,
    "blocked_obligation_count": blocked_count,
    "claim_blocked_proof_row_count": claim_blocked_proof_rows,
    "missing_evidence_proof_row_count": missing_evidence_proof_rows,
    "proof_surface_coverage": dict(proof_surfaces),
    "missing_proof_surfaces": missing_proof_surfaces,
    "by_level": dict(by_level),
    "dimension_coverage": dict(dimension_coverage),
    "missing_dimensions": missing_dimensions,
    "errors": errors,
    "artifact_refs": artifact_refs,
    "source_commit": source_commit,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

events = []
for row in proof_rows:
    events.append(
        {
            "trace_id": f"bd-bp8fl.6.6::{row.get('proof_row_id')}",
            "bead_id": "bd-bp8fl.6.6",
            "proof_row_id": row.get("proof_row_id"),
            "scenario_id": row.get("scenario_id"),
            "runtime_mode": row.get("runtime_mode"),
            "replacement_level": row.get("replacement_level"),
            "artifact_refs": row.get("artifact_refs", []),
            "required_evidence": row.get("required_evidence", []),
            "present_evidence": row.get("present_evidence", []),
            "missing_evidence": row.get("missing_evidence", []),
            "expected_decision": row.get("expected_decision"),
            "actual_decision": row.get("actual_decision"),
            "source_commit": source_commit,
            "target_dir": str(root / "target/conformance"),
            "failure_signature": row.get("failure_signature"),
        }
    )
log_path.write_text(
    "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
