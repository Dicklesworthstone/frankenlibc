#!/usr/bin/env bash
# check_test_obligation_dashboard.sh — CI gate for bd-3cco
#
# Validates:
# 1) dashboard artifact is reproducible from verification_matrix.
# 2) schema and blocker records are complete.
# 3) closure blockers enforce close-path policy:
#    no `closed` bead may retain missing obligations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_test_obligation_dashboard.py"
MATRIX="${FLC_TEST_OB_MATRIX:-${ROOT}/tests/conformance/verification_matrix.json}"
OUT="${FLC_TEST_OB_DASHBOARD:-${ROOT}/tests/conformance/test_obligation_dashboard.v1.json}"
TRACE_ID="bd-3cco-$(date -u +%Y%m%dT%H%M%SZ)-$$"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

python3 "${GEN}" --self-test
python3 "${GEN}" --matrix "${MATRIX}" --output "${OUT}" --check

python3 - "${OUT}" <<'PY'
import json
import sys
from collections import defaultdict

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

summary = payload.get("summary", {})
subsystems = payload.get("coverage_by_subsystem", [])
blockers = payload.get("blockers", [])
by_bead = payload.get("by_bead", [])

required_top = ["schema_version", "bead", "generated_at", "summary", "coverage_by_subsystem", "blockers", "by_bead"]
for key in required_top:
    if key not in payload:
        raise SystemExit(f"FAIL: dashboard missing key `{key}`")

if payload.get("schema_version") != "v1":
    raise SystemExit("FAIL: schema_version must be v1")
if payload.get("bead") != "bd-3cco":
    raise SystemExit("FAIL: bead field must be bd-3cco")

if not isinstance(subsystems, list) or not subsystems:
    raise SystemExit("FAIL: coverage_by_subsystem must be a non-empty array")
if not isinstance(blockers, list):
    raise SystemExit("FAIL: blockers must be an array")
if not isinstance(by_bead, list) or not by_bead:
    raise SystemExit("FAIL: by_bead must be a non-empty array")

closed_blockers = defaultdict(int)
for row in blockers:
    for key in ["bead_id", "bead_status", "blocker", "category", "coverage_status", "subsystem"]:
        if key not in row:
            raise SystemExit(f"FAIL: blocker row missing `{key}`")
    if row["bead_status"] == "closed":
        closed_blockers[row["bead_id"]] += 1

if closed_blockers:
    print("FAIL: closed bead(s) still have unresolved test obligations")
    for bead_id, count in sorted(closed_blockers.items()):
        print(f"  - {bead_id}: blocker_count={count}")
    raise SystemExit(1)

expected_entries = int(summary.get("entry_count", -1))
if expected_entries != len(by_bead):
    raise SystemExit(
        f"FAIL: summary.entry_count mismatch summary={expected_entries} actual={len(by_bead)}"
    )

expected_blockers = int(summary.get("blocker_count", -1))
if expected_blockers != len(blockers):
    raise SystemExit(
        f"FAIL: summary.blocker_count mismatch summary={expected_blockers} actual={len(blockers)}"
    )

print(
    "PASS: test obligation dashboard valid "
    f"(entries={len(by_bead)}, blockers={len(blockers)}, subsystems={len(subsystems)})"
)
PY

python3 - "${TRACE_ID}" "${OUT}" <<'PY'
import json
import sys

trace_id, path = sys.argv[1:3]
payload = json.load(open(path, "r", encoding="utf-8"))
summary = payload.get("summary", {})
event = {
    "trace_id": trace_id,
    "mode": "coverage_dashboard",
    "api_family": "verification_matrix",
    "symbol": "all",
    "decision_path": "allow",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [path],
    "coverage_entries": int(summary.get("entry_count", 0)),
    "blocker_count": int(summary.get("blocker_count", 0)),
    "subsystem_count": int(summary.get("subsystem_count", 0)),
}
print(json.dumps(event, separators=(",", ":")))
PY
