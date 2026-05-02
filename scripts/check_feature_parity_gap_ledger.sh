#!/usr/bin/env bash
# check_feature_parity_gap_ledger.sh — CI gate for bd-w2c3.1.1
#
# Validates:
# 1) parser unit tests pass (malformed rows / duplicates / status transitions)
# 2) feature parity gap ledger artifact is reproducible from source
# 3) artifact has stable row IDs and no parser errors
# 4) DONE rows include machine-readable evidence audit diagnostics
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_feature_parity_gap_ledger.py"
OUT="${ROOT}/tests/conformance/feature_parity_gap_ledger.v1.json"
DONE_LOG="${FLC_FP_DONE_EVIDENCE_LOG:-${ROOT}/target/conformance/feature_parity_done_evidence.log.jsonl}"
DONE_REPORT="${FLC_FP_DONE_EVIDENCE_REPORT:-${ROOT}/target/conformance/feature_parity_done_evidence.report.json}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

if [[ ! -f "${OUT}" ]]; then
  echo "FAIL: missing gap ledger ${OUT}"
  exit 1
fi

echo "=== Feature Parity Gap Ledger Gate (bd-w2c3.1.1) ==="
(
  cd "${ROOT}"
  python3 "${GEN}" --self-test
  python3 "${GEN}" --output "${OUT}" --check
)

python3 - "${OUT}" "${DONE_LOG}" "${DONE_REPORT}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
from pathlib import Path

path = sys.argv[1]
done_log_path = Path(sys.argv[2])
done_report_path = Path(sys.argv[3])
source_commit = sys.argv[4]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

rows = payload.get("rows", [])
parse_errors = payload.get("parse_errors", [])
summary = payload.get("summary", {})
done_audit = payload.get("done_evidence_audit", [])

if not isinstance(rows, list) or not rows:
    raise SystemExit("FAIL: rows must be a non-empty array")

if parse_errors:
    print("FAIL: parser errors present in gap ledger artifact")
    for row in parse_errors[:10]:
        print(f"  - {row.get('section')}:{row.get('line')} {row.get('message')}")
    raise SystemExit(1)

ids = [row.get("row_id") for row in rows]
if any(not isinstance(x, str) or not x for x in ids):
    raise SystemExit("FAIL: every row must include non-empty row_id")

if len(ids) != len(set(ids)):
    raise SystemExit("FAIL: duplicate row_id values detected")

done_rows = [row for row in rows if row.get("status") == "DONE"]
if not isinstance(done_audit, list):
    raise SystemExit("FAIL: done_evidence_audit must be an array")
if len(done_audit) != len(done_rows):
    raise SystemExit(
        "FAIL: done_evidence_audit count must match DONE row count "
        f"(audit={len(done_audit)}, done_rows={len(done_rows)})"
    )

required_audit_keys = [
    "ledger_row_id",
    "freshness_state",
    "expected",
    "actual",
    "source_commit",
    "artifact_refs",
    "failure_signature",
]
valid_states = {
    "fresh",
    "archived",
    "missing_artifact",
    "stale_commit",
    "contradictory",
    "source_only",
    "prose_only",
}
seen_done_ids = {row["row_id"] for row in done_rows}
invalid_done = []
for audit in done_audit:
    for key in required_audit_keys:
        if key not in audit:
            raise SystemExit(f"FAIL: DONE evidence audit row missing `{key}`")
    if audit["ledger_row_id"] not in seen_done_ids:
        raise SystemExit(
            "FAIL: DONE evidence audit row references unknown ledger row "
            f"{audit['ledger_row_id']}"
        )
    if audit["freshness_state"] not in valid_states:
        raise SystemExit(
            "FAIL: unexpected DONE evidence freshness_state "
            f"{audit['freshness_state']}"
        )
    if audit.get("audit_status") != "pass":
        invalid_done.append(audit)

done_log_path.parent.mkdir(parents=True, exist_ok=True)
done_report_path.parent.mkdir(parents=True, exist_ok=True)
with done_log_path.open("w", encoding="utf-8") as log:
    for index, audit in enumerate(done_audit):
        refs = audit.get("evidence_refs", [])
        if refs:
            evidence_ref = refs[0].get("evidence_ref", "unknown")
        else:
            evidence_ref = "none"
        event = {
            "trace_id": f"bd-bp8fl.3.2-{index:04d}",
            "bead_id": "bd-bp8fl.3.2",
            "ledger_row_id": audit["ledger_row_id"],
            "evidence_ref": evidence_ref,
            "freshness_state": audit["freshness_state"],
            "expected": audit["expected"],
            "actual": audit["actual"],
            "source_commit": source_commit,
            "artifact_refs": audit["artifact_refs"],
            "failure_signature": audit["failure_signature"],
        }
        log.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

done_report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.3.2",
    "source_ledger": path,
    "source_commit": source_commit,
    "summary": {
        "done_row_count": len(done_rows),
        "audited_done_row_count": len(done_audit),
        "invalid_done_evidence_count": len(invalid_done),
        "freshness_counts": summary.get("done_evidence_freshness_counts", {}),
    },
    "invalid_done_rows": invalid_done,
    "log": done_log_path.as_posix(),
}
done_report_path.write_text(json.dumps(done_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(
    "PASS: feature parity gap ledger valid "
    f"(rows={len(rows)}, gaps={summary.get('gap_count', 0)}, "
    f"deltas={summary.get('delta_count', 0)}, "
    f"done_audited={len(done_audit)}, invalid_done={len(invalid_done)}, "
    f"done_report={done_report_path})"
)
PY
