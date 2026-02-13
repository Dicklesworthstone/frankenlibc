#!/usr/bin/env bash
# check_feature_parity_gap_bead_coverage.sh — CI gate for bd-w2c3.1.3
#
# Validates:
# 1) Gap->bead coverage artifacts are reproducible.
# 2) No unresolved gap row is uncovered (missing owner bead).
# 3) Dashboard includes blocker/bottleneck sections.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_feature_parity_gap_bead_coverage.py"
OUT_JSON="${ROOT}/tests/conformance/feature_parity_gap_bead_coverage.v1.json"
OUT_MD="${ROOT}/tests/conformance/feature_parity_gap_bead_dashboard.v1.md"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

(
  cd "${ROOT}"
  python3 "${GEN}" --check
)

python3 - "${OUT_JSON}" "${OUT_MD}" <<'PY'
import json
import sys
from pathlib import Path

json_path = Path(sys.argv[1])
md_path = Path(sys.argv[2])

if not json_path.exists():
    raise SystemExit(f"FAIL: missing JSON artifact: {json_path}")
if not md_path.exists():
    raise SystemExit(f"FAIL: missing markdown artifact: {md_path}")

payload = json.loads(json_path.read_text(encoding="utf-8"))
summary = payload.get("summary", {})
rows = payload.get("rows", [])
critical = payload.get("critical_blockers", [])
bottlenecks = payload.get("dependency_bottlenecks", [])
md = md_path.read_text(encoding="utf-8")

if not isinstance(rows, list) or not rows:
    raise SystemExit("FAIL: rows must be a non-empty array")

for row in rows:
    for required in ["gap_id", "owner_bead", "source_file", "dependency_path", "expected_vs_actual"]:
        if required not in row:
            raise SystemExit(f"FAIL: row missing required key `{required}`")
    if not row.get("owner_found", False):
        raise SystemExit(
            "FAIL: uncovered active gap row found "
            f"(gap_id={row.get('gap_id')} owner_bead={row.get('owner_bead')})"
        )

if int(summary.get("uncovered_gaps", -1)) != 0:
    raise SystemExit(
        f"FAIL: summary.uncovered_gaps must be 0 (got {summary.get('uncovered_gaps')})"
    )

if not isinstance(critical, list):
    raise SystemExit("FAIL: critical_blockers must be an array")
if not isinstance(bottlenecks, list):
    raise SystemExit("FAIL: dependency_bottlenecks must be an array")

if "## Critical Blockers" not in md or "## Dependency Bottlenecks" not in md:
    raise SystemExit("FAIL: markdown dashboard missing blocker/bottleneck sections")

print(
    "PASS: feature parity gap-bead coverage valid "
    f"(gaps={summary.get('total_unresolved_gaps', 0)}, "
    f"owners={summary.get('owner_count', 0)}, "
    f"critical_blockers={summary.get('critical_blocker_count', 0)})"
)
PY
