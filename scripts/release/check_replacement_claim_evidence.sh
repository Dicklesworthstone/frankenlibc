#!/usr/bin/env bash
# Release gate for replacement-level overclaims (bd-bp8fl.6.4).
#
# This gate intentionally passes for the current L0 release policy, but fails any
# L1/L2/L3 release tag or claim unless the matching evidence artifact is cited
# and currently proves the level is unblocked.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLAIMS_PATH=""
TAG="${FRANKENLIBC_RELEASE_TAG:-}"
REPORT_PATH="${FRANKENLIBC_RELEASE_CLAIM_REPORT:-${ROOT}/target/conformance/release_claim_evidence_gate.report.json}"
LOG_PATH="${FRANKENLIBC_RELEASE_CLAIM_LOG:-${ROOT}/target/conformance/release_claim_evidence_gate.log.jsonl}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --claims)
      CLAIMS_PATH="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --log)
      LOG_PATH="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/release/check_replacement_claim_evidence.sh [--claims claims.json] [--tag vX.Y.Z-LN]

Inputs:
  --claims PATH  Optional JSON: {"claims":[{"id":"release","tag":"v0.1.0-L1","claimed_level":"L1","artifact_refs":[...]}]}
  --tag TAG      Optional release tag. The suffix -L0, -L1, -L2, or -L3 is parsed as the claimed level.

Outputs:
  target/conformance/release_claim_evidence_gate.report.json
  target/conformance/release_claim_evidence_gate.log.jsonl
USAGE
      exit 0
      ;;
    *)
      echo "FAIL: unknown argument $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "${REPORT_PATH}")" "$(dirname "${LOG_PATH}")"

python3 - "$ROOT" "$CLAIMS_PATH" "$TAG" "$REPORT_PATH" "$LOG_PATH" <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
claims_path = sys.argv[2]
tag = sys.argv[3]
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])

bead_id = "bd-bp8fl.6.4"
levels_path = root / "tests/conformance/replacement_levels.json"
l1_matrix_path = root / "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json"
standalone_matrix_path = root / "tests/conformance/standalone_readiness_proof_matrix.v1.json"
level_rank = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_tag_level(value):
    match = re.search(r"-L([0-3])(?:$|[^0-9])", value or "")
    return f"L{match.group(1)}" if match else None


def rel(path):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def source_commit():
    override = os.environ.get("SOURCE_COMMIT")
    if override:
        return override
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def load_claims(levels):
    if claims_path:
        data = load_json(Path(claims_path))
        claims = data.get("claims")
        if not isinstance(claims, list):
            raise SystemExit("FAIL: claims JSON must contain a claims array")
        return claims
    if tag:
        return [
            {
                "id": "release-tag",
                "tag": tag,
                "claimed_level": parse_tag_level(tag),
                "artifact_refs": [rel(levels_path)],
            }
        ]
    policy = levels.get("release_tag_policy", {})
    return [
        {
            "id": "current-release-policy",
            "tag": policy.get("current_release_tag_example", ""),
            "claimed_level": policy.get("current_release_level", "L0"),
            "artifact_refs": [rel(levels_path)],
        }
    ]


def cited(claim, artifact):
    refs = claim.get("artifact_refs", [])
    return artifact in refs


def l1_evidence_errors(claim, current_level, current_release_level):
    errors = []
    l1_ref = rel(l1_matrix_path)
    if not cited(claim, l1_ref):
        errors.append("release_claim_missing_l1_evidence")
        return errors
    if level_rank[current_level] < level_rank["L1"]:
        errors.append("release_claim_above_current_level")
    if level_rank[current_release_level] < level_rank["L1"]:
        errors.append("release_claim_above_current_release_level")
    matrix = load_json(l1_matrix_path)
    policy = matrix.get("claim_policy", {})
    summary = matrix.get("summary", {})
    if policy.get("current_claim_status") == "blocked":
        errors.append("release_claim_l1_policy_blocked")
    if summary.get("current_gate_status") != "pass":
        errors.append("release_claim_l1_gate_not_pass")
    if summary.get("blocked_row_count", 0) != 0:
        errors.append("release_claim_l1_blocked_rows_present")
    return errors


def standalone_evidence_errors(claim, level, current_level, current_release_level):
    errors = []
    matrix_ref = rel(standalone_matrix_path)
    if not cited(claim, matrix_ref):
        errors.append(f"release_claim_missing_{level.lower()}_evidence")
        return errors
    if level_rank[current_level] < level_rank[level]:
        errors.append("release_claim_above_current_level")
    if level_rank[current_release_level] < level_rank[level]:
        errors.append("release_claim_above_current_release_level")
    matrix = load_json(standalone_matrix_path)
    policy = matrix.get("claim_policy", {})
    summary = matrix.get("summary", {})
    policy_key = f"{level.lower()}_current_claim_status"
    if policy.get(policy_key) == "blocked":
        errors.append(f"release_claim_{level.lower()}_policy_blocked")
    if summary.get("blocked_obligation_count", 0) != 0:
        errors.append(f"release_claim_{level.lower()}_blocked_obligations_present")
    return errors


levels = load_json(levels_path)
current_level = levels.get("current_level", "L0")
release_policy = levels.get("release_tag_policy", {})
current_release_level = release_policy.get("current_release_level", "L0")
claims = load_claims(levels)

rows = []
failures = []
commit = source_commit()

for claim in claims:
    claim_id = claim.get("id") or claim.get("tag") or "release-claim"
    claimed_level = claim.get("claimed_level") or parse_tag_level(claim.get("tag", ""))
    artifact_refs = claim.get("artifact_refs", [])
    failure_signatures = []

    if claimed_level not in level_rank:
        failure_signatures.append("release_claim_level_unparseable")
    else:
        if level_rank[claimed_level] >= level_rank["L1"]:
            failure_signatures.extend(
                l1_evidence_errors(claim, current_level, current_release_level)
            )
        if level_rank[claimed_level] >= level_rank["L2"]:
            failure_signatures.extend(
                standalone_evidence_errors(
                    claim, "L2", current_level, current_release_level
                )
            )
        if level_rank[claimed_level] >= level_rank["L3"]:
            failure_signatures.extend(
                standalone_evidence_errors(
                    claim, "L3", current_level, current_release_level
                )
            )

    required_evidence = [rel(levels_path)]
    if claimed_level in ("L1", "L2", "L3"):
        required_evidence.append(rel(l1_matrix_path))
    if claimed_level in ("L2", "L3"):
        required_evidence.append(rel(standalone_matrix_path))

    decision = "claim_blocked" if failure_signatures else "claim_allowed"
    row = {
        "trace_id": os.environ.get("TRACE_ID", "release-claim-evidence-gate"),
        "bead_id": bead_id,
        "release_claim_id": claim_id,
        "replacement_level": claimed_level,
        "required_evidence": required_evidence,
        "present_evidence": artifact_refs,
        "expected_decision": "claim_allowed",
        "actual_decision": decision,
        "artifact_refs": artifact_refs,
        "source_commit": commit,
        "failure_signature": ",".join(failure_signatures),
    }
    rows.append(row)
    if failure_signatures:
        failures.append(row)

report = {
    "schema_version": "v1",
    "bead": bead_id,
    "status": "fail" if failures else "pass",
    "current_level": current_level,
    "current_release_level": current_release_level,
    "claim_count": len(rows),
    "failed_claim_count": len(failures),
    "claims": rows,
    "required_evidence_files": {
        "L1": rel(l1_matrix_path),
        "L2": rel(standalone_matrix_path),
        "L3": rel(standalone_matrix_path),
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
    encoding="utf-8",
)

if failures:
    for failure in failures:
        print(
            f"FAIL: {failure['release_claim_id']} {failure['replacement_level']} "
            f"{failure['failure_signature']}"
        )
    sys.exit(1)

print(f"PASS: {len(rows)} release claim(s) have required replacement-level evidence")
PY
